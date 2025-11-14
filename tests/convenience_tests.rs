//! Tests for convenience functions in Zenwave

use zenwave::{delete, get, post, put};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_convenience_get() {
    let response = get("https://httpbin.org/get").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_convenience_post() {
    let response = post("https://httpbin.org/post").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_convenience_put() {
    let response = put("https://httpbin.org/put").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_convenience_delete() {
    let response = delete("https://httpbin.org/delete").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_convenience_get_invalid_uri() {
    let response = get("invalid-uri").await;
    assert!(response.is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_convenience_get_response_text() {
    let response = get("https://httpbin.org/get").await.unwrap();
    let text = response.into_body().into_string().await;
    assert!(text.is_ok());
    let text = text.unwrap();
    assert!(!text.is_empty());
    assert!(text.contains("httpbin"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_convenience_get_response_json() {
    use serde_json::Value;

    let response = get("https://httpbin.org/json").await.unwrap();
    let json: Result<Value, _> = response.into_body().into_json().await;
    assert!(json.is_ok());
    let json = json.unwrap();
    assert!(json.is_object());
}
