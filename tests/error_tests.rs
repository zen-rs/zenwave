//! Tests for error handling in Zenwave

use http_kit::Method;
mod common;
use common::httpbin_uri;
use zenwave::{Client, client, get};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_invalid_url_error() {
    let result = get("not-a-valid-url").await;
    assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_invalid_scheme_error() {
    // Use a non-routable IP to avoid slow connection timeouts
    // 192.0.2.1 is TEST-NET-1, guaranteed to be non-routable
    let result = get("ftp://192.0.2.1").await;
    // Invalid scheme should fail (either at validation or connection)
    assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_invalid_url_error() {
    let mut client = client();
    let result = client.get("not-a-valid-url").await;
    assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_unreachable_host_error() {
    let result = get("https://this-host-definitely-does-not-exist-12345.com").await;
    assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_timeout_behavior() {
    // Test with a very slow endpoint
    let result = get(httpbin_uri("/delay/1")).await;
    // This should succeed but take some time
    assert!(result.is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_json_parsing_error() {
    use serde_json::Value;

    let mut client = client();
    // Get plain text and try to parse as JSON
    let result: Result<Value, _> = client.get(httpbin_uri("/html")).json().await;
    assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
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
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_method_construction_with_invalid_uri() {
    // Empty string causes panic in request construction
    // This is a validation issue in http-kit, so we expect a panic
    let result = std::panic::catch_unwind(|| {
        let mut client = client();
        let _request_builder = client.method(Method::GET, "");
    });
    assert!(result.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
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
