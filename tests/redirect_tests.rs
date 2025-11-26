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
use zenwave::redirect::FollowRedirect;

#[derive(Clone, Debug)]
struct SeenRequest {
    method: Method,
    uri: String,
    custom_header: Option<String>,
    authorization: Option<String>,
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

impl HttpError for MockError {
    fn status(&self) -> Option<StatusCode> {
        None
    }
}

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
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.seen.push(SeenRequest {
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
        });

        state.responses.pop_front().ok_or(MockError::Exhausted)
    }
}

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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
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
