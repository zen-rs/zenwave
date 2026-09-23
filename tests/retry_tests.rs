//! Tests for retry middleware.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use http::StatusCode;
use http_kit::{Body, Endpoint, HttpError, Request, Response};
use zenwave::Client;

#[derive(Default)]
struct MockState {
    results: VecDeque<Result<Response, MockError>>,
    attempts: usize,
    /// What each attempt carried: method, URI, one header and the body.
    received: Vec<(http::Method, String, Option<String>, Vec<u8>)>,
}

#[derive(Clone, Default)]
struct MockClient {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq)]
enum MockError {
    #[error("mock network error")]
    NetworkError,
    #[error("no more mock responses")]
    Exhausted,
}

impl HttpError for MockError {}

impl MockClient {
    fn with_results(results: Vec<Result<Response, MockError>>) -> Self {
        let state = MockState {
            results: results.into_iter().collect(),
            ..MockState::default()
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
        // Like a real backend, take the request out and leave a placeholder:
        // whatever the caller holds afterwards is not what was sent.
        let placeholder = http::Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let sent = std::mem::replace(request, placeholder);
        let state = Arc::clone(&self.state);
        async move {
            let (parts, body) = sent.into_parts();
            let body = body.into_bytes().await.unwrap_or_default().to_vec();
            let mut state = state.lock().unwrap();
            state.attempts += 1;
            state.received.push((
                parts.method,
                parts.uri.to_string(),
                parts
                    .headers
                    .get("x-probe")
                    .map(|value| value.to_str().unwrap().to_owned()),
                body,
            ));
            state
                .results
                .pop_front()
                .unwrap_or(Err(MockError::Exhausted))
        }
    }
}

impl Client for MockClient {}

fn ok_response() -> Response {
    http::Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("done"))
        .unwrap()
}

#[test_executors::async_test]
async fn retry_middleware_retries_on_error() {
    let mock = MockClient::with_results(vec![
        Err(MockError::NetworkError),
        Err(MockError::NetworkError),
        Ok(ok_response()),
    ]);
    let state = mock.state();

    // Use small delay for tests
    let mut client = mock
        .retry(3)
        .min_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5));

    let mut request = http::Request::builder()
        .uri("https://example.com/")
        .body(Body::empty())
        .unwrap();

    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let attempts = state.lock().unwrap().attempts;
    assert_eq!(attempts, 3);
}

#[test_executors::async_test]
async fn retry_middleware_gives_up_after_max_retries() {
    let mock = MockClient::with_results(vec![
        Err(MockError::NetworkError),
        Err(MockError::NetworkError),
        Err(MockError::NetworkError),
        Ok(ok_response()), // Should not be reached
    ]);
    let state = mock.state();

    let mut client = mock
        .retry(2) // Only 2 retries (3 attempts total)
        .min_delay(Duration::from_millis(1));

    let mut request = http::Request::builder()
        .uri("https://example.com/")
        .body(Body::empty())
        .unwrap();

    let result = client.respond(&mut request).await;
    assert!(matches!(result, Err(MockError::NetworkError)));

    assert_eq!(state.lock().unwrap().attempts, 3); // Initial + 2 retries
}

#[test_executors::async_test]
async fn retry_resends_the_original_request() {
    let mock = MockClient::with_results(vec![
        Err(MockError::NetworkError),
        Err(MockError::NetworkError),
        Ok(ok_response()),
    ]);
    let state = mock.state();
    let mut client = mock.retry(3).min_delay(Duration::from_millis(1));

    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://example.com/upload?part=1")
        .header("x-probe", "kept")
        .body(Body::from_bytes("payload"))
        .unwrap();
    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let received = state.lock().unwrap().received.clone();
    assert_eq!(received.len(), 3);
    for attempt in &received {
        assert_eq!(
            attempt,
            &(
                http::Method::POST,
                "https://example.com/upload?part=1".to_owned(),
                Some("kept".to_owned()),
                b"payload".to_vec(),
            )
        );
    }
}

#[test_executors::async_test]
async fn retry_attempts_a_read_once_body_once() {
    let mock = MockClient::with_results(vec![Err(MockError::NetworkError), Ok(ok_response())]);
    let state = mock.state();
    let mut client = mock.retry(3).min_delay(Duration::from_millis(1));

    let mut request = http::Request::builder()
        .method(http::Method::PUT)
        .uri("https://example.com/stream")
        .body(Body::from_reader(
            futures_util::io::Cursor::new(b"streamed".to_vec()),
            8,
        ))
        .unwrap();
    let result = client.respond(&mut request).await;
    assert!(matches!(result, Err(MockError::NetworkError)));
    assert_eq!(state.lock().unwrap().attempts, 1);
}

#[test_executors::async_test]
async fn retry_over_redirects_retries_instead_of_failing_on_the_placeholder() {
    let mock = MockClient::with_results(vec![Err(MockError::NetworkError), Ok(ok_response())]);
    let state = mock.state();
    let mut client = mock
        .follow_redirect()
        .retry(2)
        .min_delay(Duration::from_millis(1));

    let mut request = http::Request::builder()
        .uri("https://crates.io/api/v1/crates?page=1")
        .body(Body::empty())
        .unwrap();
    let response = client.respond(&mut request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let received = state.lock().unwrap().received.clone();
    assert_eq!(received.len(), 2);
    assert_eq!(received[1].1, "https://crates.io/api/v1/crates?page=1");
}
