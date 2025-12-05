#![cfg(not(target_arch = "wasm32"))]
#![allow(missing_docs)]

use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_net::TcpListener;
use async_std::future::timeout;
use async_tungstenite::{accept_async, tungstenite::Message};
use futures_util::StreamExt;
use zenwave::websocket::{WebSocketConfig, WebSocketError};

fn public_echo_servers() -> Vec<String> {
    if let Ok(url) = env::var("ZENWAVE_WEBSOCKET_ECHO_URL") {
        return vec![url];
    }

    vec![
        "wss://echo.websocket.events".to_string(),
        "wss://ws.ifelse.io".to_string(),
        // Public demo channel; messages are echoed back to sender.
        "wss://echo.piesocket.com/v3/channel_1?api_key=demo&notify_self=1".to_string(),
    ]
}

#[async_std::test]
async fn websocket_echo_roundtrip() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping websocket_echo_roundtrip: {err}");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();

    let server = async_std::task::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        if let Some(Ok(message)) = ws.next().await {
            assert_eq!(message, Message::Text("hello world".into()));
            ws.send(Message::Text("hello world".into())).await.unwrap();
        }
    });

    let mut client = zenwave::websocket::connect(format!("ws://{addr}"))
        .await
        .unwrap();
    client.send_text("hello world").await.unwrap();
    let response = client.recv().await.unwrap();
    assert_eq!(response.unwrap().as_text(), Some("hello world"));
    client.close().await.unwrap();

    server.await;
}

#[async_std::test]
async fn websocket_respects_max_message_size_config() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping websocket_respects_max_message_size_config: {err}");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();

    let server = async_std::task::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let payload = vec![0u8; 2048];
        let _ = ws.send(Message::Binary(payload.into())).await;
        let _ = ws.close(None).await;
    });

    let config = WebSocketConfig::default().with_max_message_size(Some(1024));
    let mut client = zenwave::websocket::connect_with_config(format!("ws://{addr}"), config)
        .await
        .unwrap();

    match client.recv().await {
        Err(WebSocketError::ConnectionFailed(_)) => {}
        Ok(message) => panic!("expected message size limit failure, got {message:?}"),
        Err(other) => panic!("unexpected error: {other:?}"),
    }

    server.await;
}

#[async_std::test]
async fn websocket_public_echo_service_roundtrip() {
    let payload = format!(
        "zenwave-public-echo-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time predates UNIX_EPOCH")
            .as_millis()
    );
    let mut last_error = None;

    for url in public_echo_servers() {
        match attempt_public_echo(&url, payload.as_str()).await {
            Ok(()) => return,
            Err(err) => {
                eprintln!("public websocket echo attempt failed for {url}: {err}");
                last_error = Some(err);
            }
        }
    }

    eprintln!(
        "skipping websocket_public_echo_service_roundtrip: all public endpoints failed ({last_error:?})"
    );
}

async fn attempt_public_echo(url: &str, payload: &str) -> Result<(), String> {
    let mut client = zenwave::websocket::connect(url)
        .await
        .map_err(|err| format!("connect error: {err}"))?;

    client
        .send_text(payload)
        .await
        .map_err(|err| format!("send error: {err}"))?;

    timeout(Duration::from_secs(10), async {
        loop {
            let Some(message) = client.recv().await.map_err(|err| format!("{err}"))? else {
                return Err("connection closed before echo received".to_string());
            };

            // Some public echo services send a banner on connect; ignore until our payload arrives.
            if message.as_text() == Some(payload) {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| "timeout waiting for echo".to_string())??;

    client
        .close()
        .await
        .map_err(|err| format!("close error: {err}"))?;

    Ok(())
}
