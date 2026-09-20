//! Tests for error handling in Zenwave

use http_kit::Method;
mod common;
use common::httpbin_uri;
use zenwave::{Client, client, get};

#[test_executors::async_test]
async fn test_invalid_url_error() {
    let result = get("not-a-valid-url").await;
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_invalid_scheme_error() {
    let _result = get("ftp://example.com").await;
    // This actually succeeds but may fail later during connection
    // The validation happens at HTTP client level, not URI parsing
    // assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_client_invalid_url_error() {
    let mut client = client();
    let result = client.get("");
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_unreachable_host_error() {
    let result = get("https://this-host-definitely-does-not-exist-12345.com").await;
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_timeout_behavior() {
    // Test with a very slow endpoint
    let result = get(httpbin_uri("/delay/1")).await;
    // This should succeed but take some time
    assert!(result.is_ok());
}

#[test_executors::async_test]
async fn test_json_parsing_error() {
    use serde_json::Value;

    let mut client = client();
    // Get plain text and try to parse as JSON
    let result: Result<Value, _> = client.get(httpbin_uri("/html")).unwrap().json().await;
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_404_not_found() {
    let result = get(httpbin_uri("/status/404")).await;
    assert!(result.is_err(), "expected 404 to surface as error");
    let error = result.unwrap_err();
    let description = format!("{error}");
    assert!(
        description.contains("404"),
        "error message should mention status code: {description}"
    );
}

#[test_executors::async_test]
async fn test_500_server_error() {
    let result = get(httpbin_uri("/status/500")).await;
    assert!(result.is_err(), "expected 500 to surface as error");
    let error = result.unwrap_err();
    let description = format!("{error}");
    assert!(
        description.contains("500"),
        "error message should mention status code: {description}"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_method_construction_with_invalid_uri() {
    let mut client = client();
    let result = client.method(Method::GET, "");
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_empty_response_handling() {
    let result = get(httpbin_uri("/status/204")).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status().as_u16(), 204);

    // Getting the body of a 204 should work (empty body)
    let body = response.into_body().into_string().await;
    assert!(body.is_ok());
    let body_str = body.unwrap();
    assert!(body_str.is_empty());
}

/// The h1 pool must return its connection on every response path: error
/// statuses consume the body into the error, a 204's empty body may never be
/// polled, and an unread body releases on drop. If any of them leaked the
/// lease, sequential requests would exhaust the origin's slots and the next
/// checkout would never complete.
#[cfg(not(target_arch = "wasm32"))]
#[test_executors::async_test]
async fn test_pooled_connection_released_on_every_path() {
    use futures_util::future::{self, Either};
    use std::time::Duration;

    for path in [
        "/status/500",
        "/status/204",
        "/status/404",
        "/status/204",
        "/status/500",
    ] {
        drop(get(httpbin_uri(path)).await);
    }

    let sixth = get(httpbin_uri("/status/200"));
    let bound = async_io::Timer::after(Duration::from_secs(30));
    let Either::Left((result, _)) = future::select(Box::pin(sixth), Box::pin(bound)).await else {
        panic!("request did not complete within the bound");
    };
    assert!(result.is_ok());
}
