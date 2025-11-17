//! Tests for backend implementations

#[cfg(feature = "hyper-backend")]
use http_kit::{Endpoint, Method};
#[cfg(feature = "hyper-backend")]
use zenwave::backend::{ClientBackend, HyperBackend};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
async fn test_hyper_backend_creation() {
    let backend = HyperBackend::new();
    // Just ensure it can be created
    assert!(!format!("{backend:?}").is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
async fn test_hyper_backend_default() {
    let backend = HyperBackend::default();
    assert!(!format!("{backend:?}").is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
async fn test_hyper_backend_get_request() {
    let mut backend = HyperBackend::new();
    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri("https://httpbin.org/get")
        .body(http_kit::Body::empty())
        .unwrap();
    let response = backend.respond(&mut request).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
async fn test_hyper_backend_post_request() {
    let mut backend = HyperBackend::new();
    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri("https://httpbin.org/post")
        .body(http_kit::Body::empty())
        .unwrap();
    let response = backend.respond(&mut request).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
async fn test_hyper_backend_https_request() {
    let mut backend = HyperBackend::new();
    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri("https://httpbin.org/get")
        .body(http_kit::Body::empty())
        .unwrap();
    let response = backend.respond(&mut request).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
async fn test_hyper_backend_invalid_uri() {
    let mut backend = HyperBackend::new();
    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri("invalid-uri")
        .body(http_kit::Body::empty())
        .unwrap();
    let response = backend.respond(&mut request).await;
    assert!(response.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
async fn test_hyper_backend_client_backend_trait() {
    fn assert_client_backend<T: ClientBackend>(_: &T) {}
    let backend = HyperBackend::new();
    assert_client_backend(&backend);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg(feature = "hyper-backend")]
#[cfg(not(target_arch = "wasm32"))]
async fn test_hyper_backend_request_cancellation() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 1024];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    let _ = tx.send(());
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let mut backend = HyperBackend::new();
    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}"))
        .body(http_kit::Body::empty())
        .unwrap();

    let future = backend.respond(&mut request);
    let mut future = Box::pin(future);

    let mut delay = Box::pin(tokio::time::sleep(Duration::from_millis(50)));
    tokio::select! {
        _ = &mut future => panic!("request unexpectedly completed before cancellation"),
        () = &mut delay => {},
    }
    drop(future);

    timeout(Duration::from_secs(2), rx)
        .await
        .expect("server never observed disconnect")
        .expect("cancellation signal sender dropped");
}

// Note: WebBackend tests are more challenging to write without a browser environment
// These would typically require wasm-pack test or a specialized test runner
#[cfg(target_arch = "wasm32")]
mod web_backend_tests {
    use super::*;
    use zenwave::backend::WebBackend;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    async fn test_web_backend_creation() {
        let backend = WebBackend::new();
        // Basic creation test - we can't test much without a browser context
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    async fn test_web_backend_default() {
        let backend = WebBackend::default();
        // Basic default test
    }
}
