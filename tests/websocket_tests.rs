#![cfg(not(target_arch = "wasm32"))]
#![allow(missing_docs)]
use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_net::TcpListener;
use async_std::future::timeout;
use async_tungstenite::{
    accept_async,
    tungstenite::{
        Message,
        protocol::frame::{
            Frame,
            coding::{Data as OpData, OpCode},
        },
    },
};
use futures_util::{
    StreamExt,
    io::{AsyncRead, AsyncWrite},
};
use zenwave::websocket::{WebSocketConfig, WebSocketError};

fn public_echo_servers() -> Vec<String> {
    if let Ok(url) = env::var("ZENWAVE_WEBSOCKET_ECHO_URL") {
        return vec![url];
    }

    vec![
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

    let client = zenwave::websocket::connect(format!("ws://{addr}"))
        .await
        .unwrap();
    client.send_text("hello world").await.unwrap();
    let response = client.recv().await.unwrap();
    assert_eq!(response.unwrap().as_text(), Some("hello world"));
    client.close().await.unwrap();

    server.await;
}

#[async_std::test]
async fn websocket_split_roundtrip() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping websocket_split_roundtrip: {err}");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();

    let server = async_std::task::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        if let Some(Ok(Message::Text(text))) = ws.next().await {
            ws.send(Message::Text(text)).await.unwrap();
            let _ = ws.close(None).await;
        }
    });

    let client = zenwave::websocket::connect(format!("ws://{addr}"))
        .await
        .unwrap();
    let (sender, receiver) = client.split();

    let send_task = async_std::task::spawn({
        let sender = sender.clone();
        async move { sender.send_text("hello world").await.unwrap() }
    });
    let recv_task = async_std::task::spawn(async move { receiver.recv().await.unwrap() });

    send_task.await;
    let message = recv_task.await.unwrap();
    assert_eq!(message.as_text(), Some("hello world"));

    let _ = sender.close().await;
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
    let client = zenwave::websocket::connect_with_config(format!("ws://{addr}"), config)
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
async fn websocket_binary_roundtrip() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping websocket_binary_roundtrip: {err}");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();

    let server = async_std::task::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        if let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Binary(payload) => {
                    assert_eq!(payload, vec![1, 2, 3, 4]);
                    ws.send(Message::Binary(payload)).await.unwrap();
                }
                other => panic!("expected binary frame, got {other:?}"),
            }
        }
    });

    let client = zenwave::websocket::connect(format!("ws://{addr}"))
        .await
        .unwrap();
    client.send_binary(vec![1_u8, 2, 3, 4]).await.unwrap();

    let response = client.recv().await.unwrap();
    let bytes = response.unwrap();
    assert_eq!(bytes.as_bytes(), Some(&[1_u8, 2, 3, 4][..]));

    client.close().await.unwrap();
    server.await;
}

#[async_std::test]
async fn websocket_handles_server_ping() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping websocket_handles_server_ping: {err}");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();

    let server = async_std::task::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        ws.send(Message::Ping(b"are you there?".to_vec().into()))
            .await
            .unwrap();
        ws.send(Message::Text("pong-after-ping".into()))
            .await
            .unwrap();
        let _ = ws.close(None).await;
    });

    let client = zenwave::websocket::connect(format!("ws://{addr}"))
        .await
        .unwrap();

    let message = timeout(Duration::from_secs(5), async { client.recv().await })
        .await
        .expect("timeout waiting for server message")
        .expect("websocket read failed")
        .expect("websocket closed before payload");
    assert_eq!(message.as_text(), Some("pong-after-ping"));

    client.close().await.unwrap();
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

async fn send_fragmented_binary<S>(
    ws: &mut async_tungstenite::WebSocketStream<S>,
    payload: &[u8],
    chunk_size: usize,
) -> async_tungstenite::tungstenite::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut offset = 0;
    let mut first = true;

    while offset < payload.len() {
        let end = (offset + chunk_size).min(payload.len());
        let opcode = if first {
            OpCode::Data(OpData::Binary)
        } else {
            OpCode::Data(OpData::Continue)
        };
        let frame = Frame::message(payload[offset..end].to_vec(), opcode, end == payload.len());
        ws.send(Message::Frame(frame)).await?;

        first = false;
        offset = end;
    }
    Ok(())
}

const MB: usize = 1024 * 1024;

#[async_std::test]
async fn websocket_accepts_64mb_message_by_default() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping websocket_accepts_64mb_message_by_default: {err}");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();

    let server = async_std::task::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let payload = vec![0x42u8; 64 * MB];
        let _ = send_fragmented_binary(&mut ws, &payload, 8 * MB).await;
        let _ = ws.close(None).await;
    });

    let client = zenwave::websocket::connect(format!("ws://{addr}"))
        .await
        .unwrap();

    let message = timeout(Duration::from_secs(30), async { client.recv().await })
        .await
        .expect("timeout waiting for 64MB payload")
        .expect("websocket read failed")
        .expect("websocket closed before payload");
    assert_eq!(message.as_bytes().map(<[u8]>::len), Some(64 * MB));

    client.close().await.unwrap();
    server.await;
}

#[async_std::test]
async fn websocket_rejects_128mb_message_by_default() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping websocket_rejects_128mb_message_by_default: {err}");
            return;
        }
    };
    let addr = listener.local_addr().unwrap();

    let server = async_std::task::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let payload = vec![0x24u8; 128 * MB];
        let _ = send_fragmented_binary(&mut ws, &payload, 8 * MB).await;
        let _ = ws.close(None).await;
    });

    let client = zenwave::websocket::connect(format!("ws://{addr}"))
        .await
        .unwrap();

    match timeout(Duration::from_secs(30), async { client.recv().await })
        .await
        .expect("timeout waiting for 128MB payload")
    {
        Err(WebSocketError::ConnectionFailed(_)) => {}
        other => panic!("expected connection failure for oversized frame, got {other:?}"),
    }

    let _ = client.close().await;
    server.await;
}

async fn attempt_public_echo(url: &str, payload: &str) -> Result<(), String> {
    let client = zenwave::websocket::connect(url)
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
