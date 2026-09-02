#![allow(missing_docs)]
//! Browser-based integration tests for the WASM backend.

#[cfg(target_arch = "wasm32")]
mod common;

#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use super::common::httpbin_uri;
    use serde_json::Value;
    use zenwave::{Client, Method, client, get};

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

    /// A JSON request body reaches the server intact.
    ///
    /// The body must go out as bytes: a `ReadableStream` request body is
    /// refused by Firefox and Safari and never pulled by a Cloudflare
    /// Worker, so this is the test that fails when the backend regresses
    /// to streaming an already-buffered body.
    #[wasm_bindgen_test]
    async fn wasm_post_json_body_round_trips() {
        let mut client = client();
        let payload = serde_json::json!({ "grant_type": "authorization_code", "code": "wasm" });

        let response = client
            .post(httpbin_uri("/post"))
            .unwrap()
            .json_body(&payload)
            .unwrap()
            .await
            .unwrap();
        assert!(response.status().is_success());

        let echoed: Value = response.into_body().into_json().await.unwrap();
        assert_eq!(echoed.get("json"), Some(&payload));
    }

    /// A raw bytes body reaches the server intact, so uploads are not
    /// silently re-encoded on the way out.
    ///
    /// Sent as `text/plain` so httpbin echoes it verbatim under `data`; a
    /// binary media type comes back as a base64 data URL instead.
    #[wasm_bindgen_test]
    async fn wasm_put_bytes_body_round_trips() {
        let mut client = client();
        let payload = b"zenwave sends bytes, not streams".to_vec();

        let response = client
            .put(httpbin_uri("/put"))
            .unwrap()
            .header("Content-Type", "text/plain")
            .unwrap()
            .bytes_body(payload.clone())
            .await
            .unwrap();
        assert!(response.status().is_success());

        let echoed: Value = response.into_body().into_json().await.unwrap();
        let data = echoed
            .get("data")
            .and_then(Value::as_str)
            .expect("httpbin echoes the body under `data`");
        assert_eq!(data.as_bytes(), payload.as_slice());
    }

    /// Ensure browser builds can compose request builders in wasm.
    #[wasm_bindgen_test]
    async fn wasm_request_builder_with_custom_header() {
        let mut client = client();

        let response = client
            .method(Method::GET, httpbin_uri("/headers"))
            .unwrap()
            .header("X-Test", "wasm")
            .unwrap()
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
            .and_then(|(_, value)| {
                // httpbingo.org returns arrays, httpbin.org returns strings
                value
                    .as_str()
                    .or_else(|| value.as_array().and_then(|arr| arr.first()?.as_str()))
            });
        assert_eq!(x_test, Some("wasm"));
    }
}
