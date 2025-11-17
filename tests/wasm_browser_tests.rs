#![cfg(target_arch = "wasm32")]

use serde_json::Value;
use zenwave::{Client, client, get};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// Ensure a simple GET request works end-to-end in the browser.
#[wasm_bindgen_test::wasm_bindgen_test]
async fn wasm_get_smoke_test() {
    let response = get("https://httpbin.org/json").await.unwrap();
    assert!(response.status().is_success());

    let json: Value = response.into_body().into_json().await.unwrap();
    assert!(json.is_object());
}

/// Ensure browser builds can compose request builders in wasm.
#[wasm_bindgen_test::wasm_bindgen_test]
async fn wasm_request_builder_with_custom_header() {
    let mut client = client();
    let response = client
        .get("https://httpbin.org/get")
        .header("x-zenwave-browser", "compat-check")
        .await
        .unwrap();

    assert!(response.status().is_success());
}
