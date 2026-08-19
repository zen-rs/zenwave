//! Tests for authentication middleware and per-request credentials.

mod common;
use common::httpbin_uri;
use zenwave::auth::{BasicAuth, BearerAuth};
use zenwave::{Client, client};

/// base64("testuser:testpass")
const TESTUSER_TESTPASS: &str = "dGVzdHVzZXI6dGVzdHBhc3M=";

#[test_executors::async_test]
async fn bearer_auth_middleware_authenticates_every_request() {
    let mut client = client()
        .bearer_auth("test-token-123")
        .expect("token must be a valid header value");

    for attempt in 0..3 {
        let body = client
            .get(httpbin_uri("/headers"))
            .expect("uri must parse")
            .string()
            .await
            .unwrap_or_else(|error| panic!("request {attempt} must succeed: {error}"));
        assert!(
            body.contains("Bearer test-token-123"),
            "request {attempt} lost its token: {body}"
        );
    }
}

#[test_executors::async_test]
async fn bearer_auth_on_a_request_builder_sends_the_token() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .bearer_auth("secret-token")
        .expect("token must be a valid header value")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("Bearer secret-token"), "got {body}");
}

#[test_executors::async_test]
async fn basic_auth_middleware_satisfies_the_server_challenge() {
    let mut client = client()
        .basic_auth("testuser", Some("testpass"))
        .expect("credentials must encode");

    let response = client
        .get(httpbin_uri("/basic-auth/testuser/testpass"))
        .expect("uri must parse")
        .await
        .expect("correct credentials must be accepted");
    assert!(response.status().is_success());
}

#[test_executors::async_test]
async fn basic_auth_sends_the_expected_base64_credentials() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .basic_auth("testuser", Some("testpass"))
        .expect("credentials must encode")
        .string()
        .await
        .expect("request must succeed");
    assert!(
        body.contains(&format!("Basic {TESTUSER_TESTPASS}")),
        "credentials must be base64 of user:pass, got {body}"
    );
}

#[test_executors::async_test]
async fn basic_auth_without_a_password_still_sends_the_separator() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .basic_auth("onlyuser", None::<String>)
        .expect("credentials must encode")
        .string()
        .await
        .expect("request must succeed");
    // base64("onlyuser:")
    assert!(body.contains("Basic b25seXVzZXI6"), "got {body}");
}

#[test_executors::async_test]
async fn a_per_request_token_overrides_the_client_wide_one() {
    let mut client = client()
        .bearer_auth("default-token")
        .expect("token must be a valid header value");

    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .bearer_auth("override-token")
        .expect("token must be a valid header value")
        .string()
        .await
        .expect("request must succeed");

    assert!(body.contains("Bearer override-token"), "got {body}");
    assert!(
        !body.contains("Bearer default-token"),
        "the middleware token must not also be sent: {body}"
    );
}

#[test_executors::async_test]
async fn auth_middleware_composes_with_cookies() {
    let mut client = client()
        .bearer_auth("combined-token")
        .expect("token must be a valid header value")
        .enable_cookie();

    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("Bearer combined-token"), "got {body}");
}

#[test_executors::async_test]
async fn missing_credentials_surface_as_a_401_error() {
    let mut client = client();
    let error = client
        .get(httpbin_uri("/bearer"))
        .expect("uri must parse")
        .await
        .expect_err("unauthenticated access must fail");
    assert!(error.is_client_error(), "got {error:?}");
    assert_eq!(
        error.response().map(http::Response::status),
        Some(http::StatusCode::UNAUTHORIZED)
    );
}

#[test_executors::async_test]
async fn wrong_credentials_surface_as_a_401_error() {
    let mut client = client();
    let error = client
        .get(httpbin_uri("/basic-auth/correct/password"))
        .expect("uri must parse")
        .basic_auth("wrong", Some("credentials"))
        .expect("credentials must encode")
        .await
        .expect_err("invalid credentials must fail");
    assert!(error.is_client_error(), "got {error:?}");
    assert!(error.to_string().contains("401"), "got {error}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_token_that_cannot_be_a_header_is_rejected_rather_than_panicking() {
    let error = BearerAuth::new("token\nInjected: header").expect_err("a newline must be rejected");
    assert!(error.is_request_error(), "got {error:?}");

    let mut client = client();
    let error = client
        .get("http://example.com/")
        .expect("uri must parse")
        .bearer_auth("token\r\nInjected: header")
        .expect_err("a newline must be rejected");
    assert!(error.is_request_error(), "got {error:?}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn basic_credentials_are_always_encodable() {
    // Base64 output is header-safe, so even control characters must be accepted.
    BasicAuth::new("user\n", Some("pass\r")).expect("base64 output is always header safe");
}
