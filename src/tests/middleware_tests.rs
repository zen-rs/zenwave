use http_kit::{Endpoint, Request, Middleware};
use crate::{Client, client};
use crate::cookie_store::CookieStore;
use crate::redirect::FollowRedirect;

#[tokio::test]
async fn test_cookie_store_middleware() {
    let client = client().enable_cookie();
    let mut client = client;
    
    // First request to set a cookie
    let response = client.get("https://httpbin.org/cookies/set/test/value").await;
    assert!(response.is_ok());
    
    // Second request should include the cookie
    let response = client.get("https://httpbin.org/cookies").await;
    assert!(response.is_ok());
    
    let response = response.unwrap();
    let body = response.into_body().into_string().await.unwrap();
    assert!(body.contains("test"));
    assert!(body.contains("value"));
}

#[tokio::test]
async fn test_cookie_store_creation() {
    let cookie_store = CookieStore::default();
    assert!(!format!("{:?}", cookie_store).is_empty());
}

#[tokio::test]
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

#[tokio::test]
async fn test_follow_redirect_creation() {
    let base_client = client();
    let _redirect_client = FollowRedirect::new(base_client);
    // Just ensure it can be created
}

#[tokio::test]
async fn test_follow_redirect_multiple_redirects() {
    let client = client().follow_redirect();
    let mut client = client;
    
    // Test multiple redirects
    let response = client.get("https://httpbin.org/redirect/3").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_client_with_multiple_middleware() {
    let client = client()
        .follow_redirect()
        .enable_cookie();
    let mut client = client;
    
    // Test that both middleware work together
    let response = client.get("https://httpbin.org/redirect-to?url=/cookies/set/test/redirect").await;
    assert!(response.is_ok());
    
    // Verify cookie was set after redirect
    let response2 = client.get("https://httpbin.org/cookies").await;
    assert!(response2.is_ok());
}

#[tokio::test]
async fn test_without_redirect_middleware() {
    // Without redirect middleware, should get redirect response
    let mut client = client();
    let response = client.get("https://httpbin.org/redirect/1").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    // Should be a redirect status code, not success
    assert!(response.status().is_redirection());
}

#[tokio::test]
async fn test_middleware_with_custom_middleware() {
    struct TestMiddleware;
    
    impl Middleware for TestMiddleware {
        async fn handle(
            &mut self, 
            request: &mut Request, 
            mut next: impl Endpoint
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
