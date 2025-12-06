//! Tests for authentication middleware and request builders

use zenwave::auth::{BasicAuth, BearerAuth};
use zenwave::{Client, client};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_bearer_auth_middleware() {
    let mut client = client().bearer_auth("test-token-123");

    // Test that the Bearer token is sent in the Authorization header
    let response = client.get("https://httpbin.org/bearer").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_bearer_auth_request_builder() {
    let mut client = client();

    // Test Bearer auth on individual request
    let response = client
        .get("https://httpbin.org/bearer")
        .bearer_auth("test-token-456")
        .await;

    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_basic_auth_middleware() {
    let mut client = client().basic_auth("testuser", Some("testpass"));

    // Test Basic auth with username and password
    let response = client
        .get("https://httpbingo.org/basic-auth/testuser/testpass")
        .await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_basic_auth_request_builder() {
    let mut client = client();

    // Test Basic auth on individual request
    let response = client
        .get("https://httpbingo.org/basic-auth/user123/pass456")
        .basic_auth("user123", Some("pass456"))
        .await;

    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_basic_auth_no_password() {
    let mut client = client();

    // Test Basic auth with only username (no password)
    let response = client
        .get("https://httpbingo.org/headers")
        .basic_auth("onlyuser", None::<String>)
        .await;

    assert!(response.is_ok());
    let response = response.unwrap();
    let body = response.into_body().into_string().await.unwrap();

    // Check that the Authorization header is present
    assert!(body.contains("Authorization"));
    assert!(body.contains("Basic"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_bearer_auth_creation() {
    let bearer_auth = BearerAuth::new("my-token");
    assert!(!format!("{bearer_auth:?}").is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_basic_auth_creation() {
    let basic_auth = BasicAuth::new("username", Some("password"));
    assert!(!format!("{basic_auth:?}").is_empty());

    let basic_auth_no_pass = BasicAuth::new("username", None::<String>);
    assert!(!format!("{basic_auth_no_pass:?}").is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_auth_headers_sent() {
    let mut client = client();

    // Test that Bearer auth header is correctly sent
    let response = client
        .get("https://httpbingo.org/headers")
        .bearer_auth("secret-token")
        .await
        .unwrap();

    let body = response.into_body().into_string().await.unwrap();
    assert!(body.contains("Bearer secret-token"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_basic_auth_encoding() {
    let mut client = client();

    // Test Basic auth encoding
    let response = client
        .get("https://httpbingo.org/headers")
        .basic_auth("testuser", Some("testpass"))
        .await
        .unwrap();

    let body = response.into_body().into_string().await.unwrap();
    // The base64 encoding of "testuser:testpass" should be present
    assert!(body.contains("Basic"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_multiple_auth_requests() {
    let mut client = client().bearer_auth("persistent-token");

    // Multiple requests should all use the same Bearer token
    for _ in 0..3 {
        let response = client.get("https://httpbingo.org/headers").await;
        assert!(response.is_ok());
        let response = response.unwrap();
        let body = response.into_body().into_string().await.unwrap();
        assert!(body.contains("Bearer persistent-token"));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_auth_with_other_middleware() {
    // Test auth combined with other middleware
    let mut client = client()
        .bearer_auth("combined-token")
        .enable_cookie()
        .follow_redirect();

    let response = client.get("https://httpbingo.org/headers").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_override_auth_per_request() {
    let mut client = client().bearer_auth("default-token");

    // The per-request auth should override the middleware auth
    let response = client
        .get("https://httpbingo.org/headers")
        .bearer_auth("override-token")
        .await
        .unwrap();

    let body = response.into_body().into_string().await.unwrap();
    // Should contain the override token, not the default one
    assert!(body.contains("Bearer override-token"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_unauthorized_access() {
    let mut client = client();

    // Test accessing an endpoint that requires auth without providing it
    let response = client.get("https://httpbin.org/bearer").await;
    assert!(
        response.is_err(),
        "expected unauthenticated access to return an error"
    );
    let err = response.unwrap_err();
    let description = format!("{err}");
    assert!(
        description.contains("401"),
        "error should mention 401 status: {description}"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_invalid_basic_auth() {
    let mut client = client();

    // Test Basic auth with wrong credentials
    let response = client
        .get("https://httpbin.org/basic-auth/correct/password")
        .basic_auth("wrong", Some("credentials"))
        .await;

    assert!(
        response.is_err(),
        "expected invalid credentials to produce an error"
    );
    let err = response.unwrap_err();
    let description = format!("{err}");
    assert!(
        description.contains("401"),
        "error should mention 401 status: {description}"
    );
}
