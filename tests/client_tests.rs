//! Tests for client functionality

use http_kit::Method;
mod common;
use common::httpbin_uri;
use zenwave::{Client, client};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_get_method() {
    let mut client = client();
    let request_builder = client.get(httpbin_uri("/get")).unwrap();
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_post_method() {
    let mut client = client();
    let request_builder = client.post(httpbin_uri("/post")).unwrap();
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_put_method() {
    let mut client = client();
    let request_builder = client.put(httpbin_uri("/put")).unwrap();
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_delete_method() {
    let mut client = client();
    let request_builder = client.delete(httpbin_uri("/delete")).unwrap();
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_method_generic() {
    let mut client = client();
    let request_builder = client.method(Method::GET, httpbin_uri("/get")).unwrap();
    let response = request_builder.await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_request_builder_string() {
    let mut client = client();
    let response_string = client.get(httpbin_uri("/get")).unwrap().string().await;
    assert!(response_string.is_ok());
    let string = response_string.unwrap();
    assert!(!string.is_empty());
    assert!(string.contains("httpbin"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_request_builder_bytes() {
    let mut client = client();
    let response_bytes = client.get(httpbin_uri("/get")).unwrap().bytes().await;
    assert!(response_bytes.is_ok());
    let bytes = response_bytes.unwrap();
    assert!(!bytes.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_request_builder_json() {
    use serde_json::Value;

    let mut client = client();
    let response_json: Result<Value, _> = client.get(httpbin_uri("/json")).unwrap().json().await;
    assert!(response_json.is_ok());
    let json = response_json.unwrap();
    assert!(json.is_object());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_with_middleware() {
    let mut client = client().enable_cookie();
    let response = client.get(httpbin_uri("/cookies/set/test/value")).unwrap().await;
    assert!(response.is_ok());

    // Follow up request should include cookie
    let response2 = client.get(httpbin_uri("/cookies")).unwrap().await;
    assert!(response2.is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_client_follow_redirect() {
    let mut client = client().follow_redirect();
    let response = client.get(httpbin_uri("/redirect/1")).unwrap().await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_invalid_uri() {
    let mut client = client();
    let response = client.get("invalid-uri").unwrap().await;
    assert!(response.is_err());
}
