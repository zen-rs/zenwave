use http_kit::{Endpoint, Method, Request};
use crate::backend::{HyperBackend, ClientBackend};

#[tokio::test]
async fn test_hyper_backend_creation() {
    let backend = HyperBackend::new();
    // Just ensure it can be created
    assert!(!format!("{:?}", backend).is_empty());
}

#[tokio::test]
async fn test_hyper_backend_default() {
    let backend = HyperBackend::default();
    assert!(!format!("{:?}", backend).is_empty());
}

#[tokio::test]
async fn test_hyper_backend_get_request() {
    let mut backend = HyperBackend::new();
    let mut request = Request::new(Method::GET, "https://httpbin.org/get");
    let response = backend.respond(&mut request).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_hyper_backend_post_request() {
    let mut backend = HyperBackend::new();
    let mut request = Request::new(Method::POST, "https://httpbin.org/post");
    let response = backend.respond(&mut request).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_hyper_backend_https_request() {
    let mut backend = HyperBackend::new();
    let mut request = Request::new(Method::GET, "https://httpbin.org/get");
    let response = backend.respond(&mut request).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_hyper_backend_invalid_uri() {
    let mut backend = HyperBackend::new();
    let mut request = Request::new(Method::GET, "invalid-uri");
    let response = backend.respond(&mut request).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_hyper_backend_client_backend_trait() {
    fn assert_client_backend<T: ClientBackend>(_: &T) {}
    let backend = HyperBackend::new();
    assert_client_backend(&backend);
}

// Note: WebBackend tests are more challenging to write without a browser environment
// These would typically require wasm-pack test or a specialized test runner
#[cfg(target_arch = "wasm32")]
mod web_backend_tests {
    use super::*;
    use crate::backend::WebBackend;

    #[tokio::test]
    async fn test_web_backend_creation() {
        let backend = WebBackend::new();
        // Basic creation test - we can't test much without a browser context
    }

    #[tokio::test]
    async fn test_web_backend_default() {
        let backend = WebBackend::default();
        // Basic default test
    }
}