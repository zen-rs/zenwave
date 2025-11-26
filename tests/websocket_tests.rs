#![cfg(not(target_arch = "wasm32"))]
#![allow(missing_docs)]

use async_net::TcpListener;
use async_tungstenite::{accept_async, tungstenite::Message};
use futures_util::StreamExt;

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
