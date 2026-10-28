#![allow(missing_docs)]
//! Browser-based integration tests for the WASM backend.

#[cfg(target_arch = "wasm32")]
mod common;

#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use super::common::httpbin_uri;
    #[cfg(feature = "ws")]
    use super::common::websocket_uri;
    use serde_json::Value;
    #[cfg(feature = "ws")]
    use zenwave::websocket::{WebSocketConfig, WebSocketError, connect_with};
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

    /// A text message over the configured limit is never delivered: the
    /// receiver gets the same `ConnectionFailed` error shape the native
    /// tungstenite path reports, and the socket is closed.
    #[wasm_bindgen_test]
    #[cfg(feature = "ws")]
    async fn wasm_websocket_rejects_text_over_limit() {
        let socket = connect_with(
            websocket_uri("/ws/echo"),
            &zenwave::Transport::system(),
            WebSocketConfig::default().with_max_message_size(Some(64)),
        )
        .await
        .unwrap();

        socket.send_text("x".repeat(128)).await.unwrap();
        match socket.recv().await {
            Err(WebSocketError::ConnectionFailed(_)) => {}
            other => panic!("expected size-limit error, got {other:?}"),
        }
        assert!(socket.recv().await.unwrap().is_none());
    }

    /// A binary message over the configured limit is rejected and the
    /// socket closes, just like the text case.
    #[wasm_bindgen_test]
    #[cfg(feature = "ws")]
    async fn wasm_websocket_rejects_binary_over_limit() {
        let socket = connect_with(
            websocket_uri("/ws/echo"),
            &zenwave::Transport::system(),
            WebSocketConfig::default().with_max_frame_size(Some(64)),
        )
        .await
        .unwrap();

        socket.send_binary(vec![0x42_u8; 128]).await.unwrap();
        match socket.recv().await {
            Err(WebSocketError::ConnectionFailed(_)) => {}
            other => panic!("expected size-limit error, got {other:?}"),
        }
        assert!(socket.recv().await.unwrap().is_none());
    }

    /// Text and binary messages within the limit echo back unchanged.
    #[wasm_bindgen_test]
    #[cfg(feature = "ws")]
    async fn wasm_websocket_echoes_within_limit() {
        let socket = connect_with(
            websocket_uri("/ws/echo"),
            &zenwave::Transport::system(),
            WebSocketConfig::default().with_max_message_size(Some(1024)),
        )
        .await
        .unwrap();

        socket.send_text("hello fixture").await.unwrap();
        let message = socket.recv().await.unwrap().expect("echo message");
        assert_eq!(message.as_text(), Some("hello fixture"));

        socket.send_binary(vec![1_u8, 2, 3, 4]).await.unwrap();
        let message = socket.recv().await.unwrap().expect("echo message");
        assert_eq!(message.as_bytes(), Some(&[1_u8, 2, 3, 4][..]));

        socket.close().await.unwrap();
    }
}
