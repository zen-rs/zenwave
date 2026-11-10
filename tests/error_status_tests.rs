//! Every backend returns an error status as the response it is: `Ok`, its
//! body and trailers intact. The streaming backends (hyper and the native
//! one) hand it over as soon as its head arrives, before the server has
//! finished the body; libcurl and `URLSession` deliver a response only once
//! it is complete, and neither surfaces trailers.
#![cfg(not(target_arch = "wasm32"))]

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};

use futures_util::StreamExt as _;
use http_kit::{BodyFrame, Method, Response, header::HeaderMap};
use zenwave::{Client, Proxy, Transport};

/// The upstream's refusal, in Chinese, Japanese and Korean, split over two
/// chunks.
const FIRST: &str = "上游拒绝了请求。";
const SECOND: &str = "上流が拒否しました。업스트림이 거부했습니다.";

/// How long the server holds the rest of its body for the client to show it
/// already has the response. A buffering backend runs into it.
const HOLD: Duration = Duration::from_secs(10);

/// A one-shot upstream answering `502` with a chunked body and a trailer.
struct Upstream {
    uri: String,
    /// Tells the server the client holds the response head.
    received: mpsc::Sender<()>,
    /// Whether that word came before the server gave up holding the body.
    released: mpsc::Receiver<bool>,
}

impl Upstream {
    /// `hold`: keep the second chunk back until the client has the head.
    fn start(hold: bool) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the upstream");
        let uri = format!("http://{}/refusal", listener.local_addr().unwrap());
        let (received, received_rx) = mpsc::channel();
        let (released_tx, released) = mpsc::channel();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept the client");
            read_head(&mut socket);
            let head = "HTTP/1.1 502 Bad Gateway\r\n\
                content-type: text/plain; charset=utf-8\r\n\
                transfer-encoding: chunked\r\n\
                trailer: x-upstream-status\r\n\
                connection: close\r\n\r\n";
            socket.write_all(head.as_bytes()).unwrap();
            socket.write_all(&chunk(FIRST)).unwrap();
            socket.flush().unwrap();
            let in_time = !hold || received_rx.recv_timeout(HOLD).is_ok();
            socket.write_all(&chunk(SECOND)).unwrap();
            socket
                .write_all(b"0\r\nx-upstream-status: refused\r\n\r\n")
                .unwrap();
            socket.flush().unwrap();
            released_tx.send(in_time).unwrap();
        });
        Self {
            uri,
            received,
            released,
        }
    }
}

fn chunk(text: &str) -> Vec<u8> {
    let mut bytes = format!("{:x}\r\n", text.len()).into_bytes();
    bytes.extend_from_slice(text.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes
}

fn read_head(socket: &mut TcpStream) {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = socket.read(&mut byte).expect("read the request head");
        assert_ne!(read, 0, "the request ended before its head did");
        head.push(byte[0]);
    }
}

fn transport() -> Transport {
    Transport::builder()
        .proxy(Proxy::none())
        .build()
        .expect("transport builds")
}

/// The body's data and its trailers, read frame by frame.
async fn frames(response: Response) -> (String, Option<HeaderMap>) {
    let mut body = response.into_body();
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.next().await {
        match frame.expect("the body streams to its end") {
            BodyFrame::Data(bytes) => data.extend_from_slice(&bytes),
            BodyFrame::Trailers(fields) => trailers = Some(fields),
            other => panic!("unexpected frame {other:?}"),
        }
    }
    (
        String::from_utf8(data).expect("the body is UTF-8"),
        trailers,
    )
}

/// Sends a GET for the upstream's refusal through `backend`.
async fn refusal<B>(backend: &mut B, uri: &str) -> Response
where
    B: Client,
    B::Error: std::fmt::Debug,
{
    let mut request = http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(http_kit::Body::empty())
        .unwrap();
    backend
        .respond_send(&mut request)
        .await
        .expect("a 502 is a response, not an error")
}

/// A streaming backend: the `502` arrives while its body is still held,
/// and its trailers come after the data.
#[cfg(any(
    feature = "hyper-backend",
    feature = "native-compio",
    feature = "native-tokio"
))]
async fn streams<B>(mut backend: B)
where
    B: Client,
    B::Error: std::fmt::Debug,
{
    let upstream = Upstream::start(true);
    let response = refusal(&mut backend, &upstream.uri).await;
    assert_eq!(response.status().as_u16(), 502);
    upstream.received.send(()).unwrap();
    let (data, trailers) = frames(response).await;
    assert!(
        upstream.released.recv().unwrap(),
        "the response must arrive before the upstream finished its body"
    );
    assert_eq!(data, format!("{FIRST}{SECOND}"));
    let trailers = trailers.expect("the trailers reach the caller");
    assert_eq!(trailers["x-upstream-status"], "refused");
}

/// A backend that delivers whole responses: the `502` and its full body.
#[cfg(any(
    feature = "curl-backend",
    all(target_vendor = "apple", feature = "apple-backend")
))]
async fn answers<B>(mut backend: B)
where
    B: Client,
    B::Error: std::fmt::Debug,
{
    let upstream = Upstream::start(false);
    let response = refusal(&mut backend, &upstream.uri).await;
    assert_eq!(response.status().as_u16(), 502);
    // The server did not hold its body, so the word arrives too late to
    // matter; it is sent only to finish the exchange the same way.
    upstream.received.send(()).ok();
    let (data, _) = frames(response).await;
    assert!(upstream.released.recv().unwrap());
    assert_eq!(data, format!("{FIRST}{SECOND}"));
}

#[cfg(feature = "hyper-backend")]
#[test_executors::async_test]
async fn hyper_streams_an_error_status() {
    streams(zenwave::backend::HyperBackend::new(transport())).await;
}

#[cfg(feature = "native-compio")]
#[test_executors::async_test]
async fn native_on_compio_streams_an_error_status() {
    use zenwave::backend::{Compio, NativeBackend};
    streams(NativeBackend::with_driver::<Compio>(transport())).await;
}

#[cfg(feature = "native-tokio")]
#[test_executors::async_test]
async fn native_on_tokio_streams_an_error_status() {
    use zenwave::backend::{NativeBackend, Tokio};
    streams(NativeBackend::with_driver::<Tokio>(transport())).await;
}

#[cfg(feature = "curl-backend")]
#[test_executors::async_test]
async fn curl_answers_an_error_status() {
    answers(zenwave::backend::CurlBackend::new(transport())).await;
}

#[cfg(all(target_vendor = "apple", feature = "apple-backend"))]
#[test_executors::async_test]
async fn apple_answers_an_error_status() {
    answers(zenwave::backend::AppleBackend::new(transport())).await;
}
