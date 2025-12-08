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
            attempts: 0,
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
    async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        state.results.pop_front().ok_or(MockError::Exhausted)?
    }
}

impl Client for MockClient {}

fn ok_response() -> Response {
    http::Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("done"))
        .unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
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
