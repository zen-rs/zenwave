#![allow(missing_docs)]
//! Browser-based integration tests for the WASM backend.

#[cfg(target_arch = "wasm32")]
mod common;

#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use serde_json::Value;
    use zenwave::{Client, Method, client, get};
    use super::common::httpbin_uri;

    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    /// Ensure a simple GET request works end-to-end in the browser.
    #[wasm_bindgen_test]
    async fn wasm_get_smoke_test() {
        let response = get(httpbin_uri("/json")).await.unwrap();
        assert!(response.status().is_success());

        let json: Value = response.into_body().into_json().await.unwrap();
        assert!(json.is_object());
    }

    /// Ensure browser builds can compose request builders in wasm.
    #[wasm_bindgen_test]
    async fn wasm_request_builder_with_custom_header() {
        let mut client = client();

        let response = client
            .method(Method::GET, httpbin_uri("/headers"))
            .header("X-Test", "wasm")
            .await
            .unwrap();
        assert!(response.status().is_success());

        let body: Value = response.into_body().into_json().await.unwrap();
        let headers = body
            .get("headers")
            .expect("headers present")
            .as_object()
            .expect("headers object");
        let x_test = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("x-test"))
            .and_then(|(_, value)| value.as_str());
        assert_eq!(x_test, Some("wasm"));
    }
}
