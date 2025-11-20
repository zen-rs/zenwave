//! Tests for middleware components in Zenwave

use std::time::Duration;
use zenwave::cookie::CookieStore;

use zenwave::redirect::FollowRedirect;
use zenwave::{Body, Client, Endpoint, Middleware, Request, Response, StatusCode, client};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_cookie_store_middleware() {
    let client = client().enable_cookie();
    let mut client = client;

    // First request to set a cookie
    let response = client
        .get("https://httpbin.org/cookies/set/test/value")
        .await;
    assert!(response.is_ok());

    // Second request should include the cookie
    let response = client.get("https://httpbin.org/cookies").await;
    assert!(response.is_ok());

    let response = response.unwrap();
    let body = response.into_body().into_string().await.unwrap();
    assert!(body.contains("test"));
    assert!(body.contains("value"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_cookie_store_creation() {
    let cookie_store = CookieStore::default();
    assert!(!format!("{cookie_store:?}").is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_follow_redirect_middleware() {
    // Test with redirect middleware
    let client = client().follow_redirect();
    let mut client = client;

    // This should follow the redirect and return the final response
    let response = client.get("https://httpbin.org/redirect/1").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_follow_redirect_creation() {
    let base_client = client();
    let _redirect_client = FollowRedirect::new(base_client);
    // Just ensure it can be created
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_follow_redirect_multiple_redirects() {
    let client = client().follow_redirect();
    let mut client = client;

    // Test multiple redirects
    let response = client.get("https://httpbin.org/redirect/3").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_with_multiple_middleware() {
    let client = client().follow_redirect().enable_cookie();
    let mut client = client;

    // Test that both middleware work together
    let response = client
        .get("https://httpbin.org/redirect-to?url=/cookies/set/test/redirect")
        .await;
    assert!(response.is_ok());

    // Verify cookie was set after redirect
    let response2 = client.get("https://httpbin.org/cookies").await;
    assert!(response2.is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_without_redirect_middleware() {
    // Without redirect middleware, should get redirect response
    let mut client = client();
    let response = client.get("https://httpbin.org/redirect/1").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    // Should be a redirect status code, not success
    assert!(response.status().is_redirection());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_middleware_with_custom_middleware() {
    struct TestMiddleware;

    impl Middleware for TestMiddleware {
        async fn handle(
            &mut self,
            request: &mut Request,
            mut next: impl Endpoint,
        ) -> http_kit::Result<http_kit::Response> {
            // Add a custom header
            let header_name: http_kit::header::HeaderName = "X-Test".parse().unwrap();
            let header_value: http_kit::header::HeaderValue = "middleware-test".parse().unwrap();
            request.headers_mut().insert(header_name, header_value);
            next.respond(request).await
        }
    }

    let client = client().with(TestMiddleware);
    let mut client = client;

    let response = client.get("https://httpbin.org/headers").await;
    assert!(response.is_ok());

    let response = response.unwrap();
    let body = response.into_body().into_string().await.unwrap();
    assert!(body.contains("X-Test"));
    assert!(body.contains("middleware-test"));
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct SlowClient {
    delay: Duration,
    status: StatusCode,
}

#[cfg(not(target_arch = "wasm32"))]
impl Endpoint for SlowClient {
    async fn respond(&mut self, _request: &mut Request) -> zenwave::Result<Response> {
        tokio::time::sleep(self.delay).await;
        Ok(http::Response::builder()
            .status(self.status)
            .body(Body::empty())
            .unwrap())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Client for SlowClient {}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_timeout_middleware_success() {
    let mut client = SlowClient {
        delay: Duration::from_millis(20),
        status: StatusCode::OK,
    }
    .timeout(Duration::from_secs(1));

    let response = client
        .get("https://example.com")
        .await
        .expect("request should complete before timeout");
    assert_eq!(response.status(), StatusCode::OK);
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_timeout_middleware_triggers_gateway_timeout() {
    let mut client = SlowClient {
        delay: Duration::from_millis(200),
        status: StatusCode::OK,
    }
    .timeout(Duration::from_millis(10));

    let err = client
        .get("https://example.com")
        .await
        .expect_err("timeout should trigger before slow backend responds");

    assert_eq!(err.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        err.to_string().contains("timed out"),
        "error message should mention timeout"
    );
}
