//! Tests for client functionality

use http_kit::Method;
use zenwave::{Client, client};

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_get_method() {
    let mut client = client();
    let request_builder = client.get("https://httpbin.org/get");
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_post_method() {
    let mut client = client();
    let request_builder = client.post("https://httpbin.org/post");
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_put_method() {
    let mut client = client();
    let request_builder = client.put("https://httpbin.org/put");
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_delete_method() {
    let mut client = client();
    let request_builder = client.delete("https://httpbin.org/delete");
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_method_generic() {
    let mut client = client();
    let request_builder = client.method(Method::GET, "https://httpbin.org/get");
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_request_builder_string() {
    let mut client = client();
    let response_string = client.get("https://httpbin.org/get").string().await;
    assert!(response_string.is_ok());
    let string = response_string.unwrap();
    assert!(!string.is_empty());
    assert!(string.contains("httpbin"));
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_request_builder_bytes() {
    let mut client = client();
    let response_bytes = client.get("https://httpbin.org/get").bytes().await;
    assert!(response_bytes.is_ok());
    let bytes = response_bytes.unwrap();
    assert!(!bytes.is_empty());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_request_builder_json() {
    use serde_json::Value;

    let mut client = client();
    let response_json: Result<Value, _> = client.get("https://httpbin.org/json").json().await;
    assert!(response_json.is_ok());
    let json = response_json.unwrap();
    assert!(json.is_object());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_with_middleware() {
    let client = client().enable_cookie();
    let mut client = client;
    let response = client
        .get("https://httpbin.org/cookies/set/test/value")
        .await;
    assert!(response.is_ok());

    // Follow up request should include cookie
    let response2 = client.get("https://httpbin.org/cookies").await;
    assert!(response2.is_ok());
}

#[ignore = "requires network access"]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_client_follow_redirect() {
    let client = client().follow_redirect();
    let mut client = client;
    let response = client.get("https://httpbin.org/redirect/1").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_invalid_uri() {
    let mut client = client();
    let response = client.get("invalid-uri").await;
    assert!(response.is_err());
}
