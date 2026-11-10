//! Focused tests for redirect handling without relying on external services.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use http::StatusCode;
use http_kit::{
    Body, Endpoint, HttpError, Method, Request, Response,
    header::{HeaderValue, LOCATION},
};
use zenwave::Client;
use zenwave::redirect::{FollowRedirect, FollowRedirectError};

#[cfg(default_backend)]
mod common;
#[cfg(default_backend)]
use common::httpbin_uri;

/// An extension type with no meaning beyond proving hops carry request extensions.
#[derive(Clone)]
struct Marker;

#[derive(Clone, Debug)]
struct SeenRequest {
    method: Method,
    uri: String,
    custom_header: Option<String>,
    authorization: Option<String>,
    content_type: Option<String>,
    content_length: Option<String>,
    has_marker: bool,
    body: Vec<u8>,
}

#[derive(Default)]
struct MockState {
    responses: VecDeque<Response>,
    seen: Vec<SeenRequest>,
}

#[derive(Clone, Default)]
struct MockClient {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug, thiserror::Error, Clone, Copy)]
enum MockError {
    #[error("no more mock responses")]
    Exhausted,
}

impl HttpError for MockError {}

impl MockClient {
    fn with_responses(responses: Vec<Response>) -> Self {
        let state = MockState {
            responses: responses.into_iter().collect(),
            ..Default::default()
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn state(&self) -> Arc<Mutex<MockState>> {
        Arc::clone(&self.state)
    }
}

impl Endpoint for MockClient {
    type Error = MockError;
    fn respond(
        &mut self,
        request: &mut Request,
    ) -> impl std::future::Future<Output = Result<Response, Self::Error>> {
        let state = Arc::clone(&self.state);
        let seen = SeenRequest {
            method: request.method().clone(),
            uri: request.uri().to_string(),
            custom_header: request
                .headers()
                .get("x-test")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            authorization: request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            content_type: request
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            content_length: request
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            has_marker: request.extensions().get::<Marker>().is_some(),
            body: Vec::new(),
        };
        let body = request.body_mut().take().unwrap_or_else(|_| Body::empty());

        async move {
            let body = body.into_bytes().await.unwrap_or_default().to_vec();
            let mut state = state.lock().unwrap();
            state.seen.push(SeenRequest { body, ..seen });
            state.responses.pop_front().ok_or(MockError::Exhausted)
        }
    }
}

http_kit::impl_send_endpoint!(MockClient);

impl Client for MockClient {}

fn redirect_response(status: StatusCode, location: &str) -> Response {
    http::Response::builder()
        .status(status)
        .header(LOCATION, HeaderValue::from_str(location).unwrap())
        .body(Body::empty())
        .unwrap()
}

fn ok_response() -> Response {
    http::Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("done"))
        .unwrap()
}

#[test_executors::async_test]
async fn follow_redirect_resolves_relative_paths_and_keeps_headers() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::FOUND, "/landing"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/start/path")
        .header("x-test", "keep-me")
        .body(Body::empty())
        .unwrap();

    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert_eq!(state.seen[0].uri, "https://example.com/start/path");
    assert_eq!(state.seen[1].uri, "https://example.com/landing");
    assert_eq!(state.seen[1].custom_header.as_deref(), Some("keep-me"));
    // Method should downgrade to GET after 302
    assert_eq!(state.seen[1].method, Method::GET);
    drop(state);
}

#[test_executors::async_test]
async fn follow_redirect_strips_sensitive_headers_on_host_change() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::MOVED_PERMANENTLY, "https://example.net/next"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri("https://example.com/private")
        .header("authorization", "Bearer secret")
        .body(Body::empty())
        .unwrap();

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert_eq!(
        state.seen[0].authorization.as_deref(),
        Some("Bearer secret")
    );
    assert!(
        state.seen[1].authorization.is_none(),
        "authorization header should be cleared when host changes"
    );
    assert_eq!(state.seen[1].uri, "https://example.net/next");
    drop(state);
}

/// A 307 must re-send the request unchanged — method, body, and the payload
/// headers that describe it.
#[test_executors::async_test]
async fn temporary_redirect_replays_method_body_and_payload_headers() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::TEMPORARY_REDIRECT, "/moved"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/upload")
        .header("content-type", "application/octet-stream")
        .header("content-length", "7")
        .body(Body::from("payload"))
        .unwrap();

    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert_eq!(state.seen[1].method, Method::POST);
    assert_eq!(state.seen[1].uri, "https://example.com/moved");
    assert_eq!(state.seen[1].body, b"payload");
    assert_eq!(
        state.seen[1].content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(state.seen[1].content_length.as_deref(), Some("7"));
    drop(state);
}

/// A 308 preserves the body the same way, across repeated hops.
#[test_executors::async_test]
async fn permanent_redirect_replays_the_body_on_every_hop() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::PERMANENT_REDIRECT, "/first"),
        redirect_response(StatusCode::PERMANENT_REDIRECT, "/second"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::PUT)
        .uri("https://example.com/start")
        .body(Body::from("repeatable"))
        .unwrap();

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 3);
    assert!(
        state.seen[1..]
            .iter()
            .all(|seen| { seen.method == Method::PUT && seen.body == b"repeatable" })
    );
    drop(state);
}

/// A body that cannot be replayed cannot be redirected safely: the 307 is
/// handed back to the caller instead of followed with an emptied body.
#[test_executors::async_test]
async fn temporary_redirect_is_returned_when_the_body_cannot_be_replayed() {
    let mock = MockClient::with_responses(vec![redirect_response(
        StatusCode::TEMPORARY_REDIRECT,
        "/moved",
    )]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let stream = futures_util::stream::iter([Ok::<_, std::io::Error>(&b"payload"[..])]);
    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/upload")
        .body(Body::from_stream(stream))
        .unwrap();

    let response = client.respond(&mut request).await.unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers().get(LOCATION).unwrap(), "/moved");
    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 1, "a non-replayable body stops the chain");
    drop(state);
}

/// A 302 converts a `POST` — and only a `POST`: a `PUT` keeps its method and
/// body through the hop.
#[test_executors::async_test]
async fn found_keeps_a_put_and_its_body() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::FOUND, "/next"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::PUT)
        .uri("https://example.com/thing")
        .body(Body::from("contents"))
        .unwrap();

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert_eq!(state.seen[1].method, Method::PUT);
    assert_eq!(state.seen[1].body, b"contents");
    drop(state);
}

/// A 303 leaves `HEAD` alone — it converts every method except `GET`/`HEAD`.
#[test_executors::async_test]
async fn see_other_keeps_a_head() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::SEE_OTHER, "/head"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::HEAD)
        .uri("https://example.com/thing")
        .body(Body::empty())
        .unwrap();

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert_eq!(state.seen[1].method, Method::HEAD);
    drop(state);
}

/// The headers that describe a body must not survive the body: a `POST` that
/// a 302 turns into a `GET` sheds its payload headers with the payload.
#[test_executors::async_test]
async fn payload_headers_leave_with_the_dropped_body() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::FOUND, "/next"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/thing")
        .header("content-type", "application/json")
        .header("content-length", "2")
        .body(Body::from("{}"))
        .unwrap();

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert_eq!(state.seen[1].method, Method::GET);
    assert_eq!(state.seen[1].body, Vec::<u8>::new());
    assert!(state.seen[1].content_type.is_none());
    assert!(state.seen[1].content_length.is_none());
    drop(state);
}

/// Request extensions carry per-request state; a hop must not lose them.
#[test_executors::async_test]
async fn a_hop_carries_the_requests_extensions() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::FOUND, "/next"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri("https://example.com/thing")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(Marker);

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert!(
        state.seen[1].has_marker,
        "the extension did not reach the hop"
    );
    drop(state);
}

/// A body dropped on a downgrade stays dropped: a later 307 must not bring it
/// — or its payload headers — back.
#[test_executors::async_test]
async fn a_downgrade_keeps_the_body_dropped_through_later_hops() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::FOUND, "/middle"),
        redirect_response(StatusCode::TEMPORARY_REDIRECT, "/final"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/start")
        .header("content-type", "application/octet-stream")
        .header("content-length", "11")
        .body(Body::from("secret-data"))
        .unwrap();

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 3);
    assert_eq!(state.seen[1].method, Method::GET);
    assert_eq!(state.seen[2].method, Method::GET);
    assert_eq!(
        state.seen[2].body,
        Vec::<u8>::new(),
        "the body must not resurrect"
    );
    assert!(state.seen[2].content_type.is_none());
    assert!(state.seen[2].content_length.is_none());
    drop(state);
}

/// A 303 is a plain retrieval even when the method already is `GET`: a body —
/// replayable or not — never rides along.
#[test_executors::async_test]
async fn see_other_drops_the_body_even_when_the_method_stays_get() {
    let mock = MockClient::with_responses(vec![
        redirect_response(StatusCode::SEE_OTHER, "/next"),
        ok_response(),
    ]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);

    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri("https://example.com/thing")
        .header("content-length", "4")
        .body(Body::from("data"))
        .unwrap();

    client.respond(&mut request).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 2);
    assert_eq!(state.seen[1].method, Method::GET);
    assert_eq!(state.seen[1].body, Vec::<u8>::new());
    assert!(state.seen[1].content_length.is_none());
    drop(state);
}

fn status_response(status: StatusCode, location: Option<&str>) -> Response {
    let mut builder = http::Response::builder().status(status);
    if let Some(location) = location {
        builder = builder.header(LOCATION, HeaderValue::from_str(location).unwrap());
    }
    builder.body(Body::empty()).unwrap()
}

fn get_request(uri: &str) -> Request {
    http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// A 304 is a cache verdict, not a redirect: it must reach the caller
/// untouched, validator headers and all, after exactly one request.
#[test_executors::async_test]
async fn not_modified_without_location_is_returned() {
    let response = http::Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(http_kit::header::ETAG, "\"v1\"")
        .body(Body::empty())
        .unwrap();
    let mock = MockClient::with_responses(vec![response]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);
    let mut request = get_request("https://example.com/conditional");

    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        response
            .headers()
            .get(http_kit::header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some("\"v1\"")
    );
    assert_eq!(response.into_body().into_bytes().await.unwrap().len(), 0);

    let state = state.lock().unwrap();
    assert_eq!(state.seen.len(), 1);
    assert_eq!(state.seen[0].uri, "https://example.com/conditional");
}

/// Even carrying a Location header, a 304 is never followed.
#[test_executors::async_test]
async fn not_modified_with_location_is_not_followed() {
    let mock = MockClient::with_responses(vec![status_response(
        StatusCode::NOT_MODIFIED,
        Some("https://example.com/elsewhere"),
    )]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);
    let mut request = get_request("https://example.com/conditional");

    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(state.lock().unwrap().seen.len(), 1);
}

/// 300, 305 and 306 are not redirect statuses a client may follow —
/// they pass through whether or not a Location header is present.
#[test_executors::async_test]
async fn other_3xx_statuses_pass_through_unfollowed() {
    for (status, location) in [
        (StatusCode::MULTIPLE_CHOICES, None),
        (
            StatusCode::MULTIPLE_CHOICES,
            Some("https://example.com/next"),
        ),
        (StatusCode::USE_PROXY, None),
        (StatusCode::USE_PROXY, Some("https://example.com/next")),
        (StatusCode::from_u16(306).unwrap(), None),
        (
            StatusCode::from_u16(306).unwrap(),
            Some("https://example.com/next"),
        ),
    ] {
        let mock = MockClient::with_responses(vec![status_response(status, location)]);
        let state = mock.state();
        let mut client = FollowRedirect::new(mock);
        let mut request = get_request("https://example.com/resource");

        let response = client.respond(&mut request).await.unwrap();
        assert_eq!(
            response.status(),
            status,
            "status {status} must pass through"
        );
        assert_eq!(
            state.lock().unwrap().seen.len(),
            1,
            "status {status} must not trigger a follow-up request"
        );
    }
}

/// A plain success answers once and returns.
#[test_executors::async_test]
async fn ok_passes_through() {
    let mock = MockClient::with_responses(vec![ok_response()]);
    let state = mock.state();
    let mut client = FollowRedirect::new(mock);
    let mut request = get_request("https://example.com/data");

    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(state.lock().unwrap().seen.len(), 1);
}

/// The five redirect statuses still follow their Location: 303 always
/// rewrites to GET, 301/302 rewrite non-GET/HEAD to GET, 307/308 keep
/// the original method.
#[test_executors::async_test]
async fn redirect_statuses_with_location_are_followed() {
    for (status, expected_method) in [
        (StatusCode::MOVED_PERMANENTLY, Method::GET),
        (StatusCode::FOUND, Method::GET),
        (StatusCode::SEE_OTHER, Method::GET),
        (StatusCode::TEMPORARY_REDIRECT, Method::POST),
        (StatusCode::PERMANENT_REDIRECT, Method::POST),
    ] {
        let mock = MockClient::with_responses(vec![
            redirect_response(status, "https://example.com/next"),
            ok_response(),
        ]);
        let state = mock.state();
        let mut client = FollowRedirect::new(mock);
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/start")
            .body(Body::empty())
            .unwrap();

        let response = client.respond(&mut request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "status {status} must be followed"
        );

        let state = state.lock().unwrap();
        assert_eq!(
            state.seen.len(),
            2,
            "status {status} must issue a second request"
        );
        assert_eq!(state.seen[1].uri, "https://example.com/next");
        assert_eq!(
            state.seen[1].method, expected_method,
            "status {status} method rewriting"
        );
    }
}

/// A redirect status with no Location is still an error.
#[test_executors::async_test]
async fn redirect_status_without_location_errors() {
    for status in [
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::FOUND,
        StatusCode::SEE_OTHER,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        let mock = MockClient::with_responses(vec![status_response(status, None)]);
        let mut client = FollowRedirect::new(mock);
        let mut request = get_request("https://example.com/start");

        let result = client.respond(&mut request).await;
        assert!(
            matches!(result, Err(FollowRedirectError::MissingLocationHeader)),
            "status {status} without Location must error"
        );
    }
}

/// End to end through the real client: the fixture's /status/304 has no
/// Location, and the 304 must still come back delivered rather than error
/// as a malformed redirect.
#[cfg(default_backend)]
#[test_executors::async_test]
async fn real_client_delivers_a_304_without_location() {
    let response = zenwave::client()
        .get(httpbin_uri("/status/304"))
        .unwrap()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 304);
    assert_eq!(response.into_body().into_bytes().await.unwrap().len(), 0);
}
