#![allow(missing_docs)]
//! Browser-based integration tests for the WASM backend.

#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use serde_json::Value;
    use zenwave::{Client, client, get};

    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    /// Ensure a simple GET request works end-to-end in the browser.
    #[wasm_bindgen_test]
    async fn wasm_get_smoke_test() {
        let response = get("https://httpbin.org/json").await.unwrap();
        assert!(response.status().is_success());

        let json: Value = response.into_body().into_json().await.unwrap();
        assert!(json.is_object());
    }

    /// Ensure browser builds can compose request builders in wasm.
    #[wasm_bindgen_test]
    async fn wasm_request_builder_with_custom_header() {
        let mut client = client();

        let response = client
            .request("GET", "https://httpbin.org/headers")
            .header("X-Test", "wasm")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());

        let body: Value = response.into_body().into_json().await.unwrap();
        let headers = body
            .get("headers")
            .expect("headers present")
            .as_object()
            .expect("headers object");
        assert_eq!(
            headers.get("X-Test").map(Value::as_str).flatten(),
            Some("wasm")
        );
    }
}
