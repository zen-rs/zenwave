#![allow(missing_docs)]
//! The WASM backend inside a dedicated web worker, where no `window` exists.
//!
//! Cloudflare Workers, service workers and web workers all run without a
//! `Window`; the backend must find `fetch` on whatever `globalThis` is. This
//! suite is the browser-runnable stand-in for a Cloudflare Worker.

#[cfg(target_arch = "wasm32")]
mod common;

#[cfg(target_arch = "wasm32")]
mod worker_tests {
    use super::common::httpbin_uri;
    use serde_json::Value;
    use zenwave::{Client, client, get};

    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_dedicated_worker);

    /// A GET works with no `window` in scope.
    #[wasm_bindgen_test]
    async fn worker_get_smoke_test() {
        let response = get(httpbin_uri("/json")).await.unwrap();
        assert!(response.status().is_success());

        let json: Value = response.into_body().into_json().await.unwrap();
        assert!(json.is_object());
    }

    /// A POST with a JSON body round-trips from a worker scope.
    #[wasm_bindgen_test]
    async fn worker_post_json_body_round_trips() {
        let mut client = client();
        let payload = serde_json::json!({ "grant_type": "refresh_token", "scope": "worker" });

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
}
