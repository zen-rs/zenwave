mod rt;

use core::future::Future;
#[cfg(feature = "http2")]
use std::time::Duration;
use std::{
    mem::replace,
    pin::Pin,
    task::{Context, Poll},
};

use executor_core::{AnyExecutor, Executor};
use futures_util::{Stream, TryStreamExt};
use http::{StatusCode, uri::Scheme};
use http_body_util::BodyDataStream;
use http_kit::{Endpoint, HttpError, Method, Request, Response};
use hyper::{body::Incoming, client::conn::TrySendError, http};
use rt::Spawner;
use tracing::{debug, warn};

use crate::{
    Client, Transport,
    error::HttpErrorResponse,
    transport::{
        connect::{Protocol, Protocols, Target, Via, connect},
        pool::{Checkout, DialPermit, H1Lease, Origin, Pool},
        stream::HyperIo,
    },
};

/// h2 keepalive: a PING every 30 s, the connection dropped 10 s after a
/// ping goes unanswered.
#[cfg(feature = "http2")]
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(feature = "http2")]
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

// Consumed by the connection pool (#69); today only its own tests dial h3.
#[cfg(http3)]
#[allow(dead_code)]
pub mod h3;

/// Hyper-based HTTP client backend powered by `async-io`/`async-net`.
#[derive(Debug)]
pub struct HyperBackend {
    transport: Transport,
    spawner: Spawner,
}

impl HyperBackend {
    /// Create a backend that connects through `transport`.
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            spawner: Spawner::new(None),
        }
    }

    /// Create a backend that connects through `transport` and drives its
    /// connections on `executor` instead of a dedicated thread per request.
    #[must_use]
    pub fn with_executor(transport: Transport, executor: impl Executor + 'static) -> Self {
        Self {
            transport,
            spawner: Spawner::new(Some(AnyExecutor::new(executor))),
        }
    }

    /// Dial a fresh connection for `origin` under `permit`, run the
    /// negotiated handshake on it, pool it, and send `request`. A failure on
    /// a fresh connection surfaces to the caller — only reuse failures retry,
    /// and the caller owns that decision.
    async fn dial_and_send(
        &self,
        origin: &Origin,
        permit: DialPermit,
        mut request: http::Request<http_kit::Body>,
    ) -> Result<(http::Response<Incoming>, Option<H1Lease>), crate::Error> {
        let connection = connect(
            &self.transport,
            Target {
                host: &origin.host,
                port: origin.port,
                tls: origin.scheme == Scheme::HTTPS,
                tunnel_plaintext: false,
                protocols: Protocols::Http2OrHttp1,
            },
        )
        .await?;
        match connection.protocol {
            Protocol::Http1 => {
                let (sender, driver) = hyper::client::conn::http1::Builder::new()
                    .handshake(HyperIo(connection.stream))
                    .await
                    .map_err(HyperError::Connection)?;
                // The driver runs once for the connection's life, not per
                // request.
                self.spawner.spawn(drive(driver));
                let lease = Pool::insert_h1(permit, sender, connection.via).await;
                shape_h1_request(&mut request, lease.via())?;
                lease
                    .send(request)
                    .await
                    .map(|(response, lease)| (response, Some(lease)))
                    .map_err(|error| HyperError::Connection(error.into_error()).into())
            }
            #[cfg(feature = "http2")]
            Protocol::Http2 => {
                let mut builder = hyper::client::conn::http2::Builder::new(self.spawner.clone());
                builder
                    .timer(rt::Timer)
                    .keep_alive_interval(KEEP_ALIVE_INTERVAL)
                    .keep_alive_timeout(KEEP_ALIVE_TIMEOUT);
                let (mut sender, driver) = builder
                    .handshake(HyperIo(connection.stream))
                    .await
                    .map_err(HyperError::Connection)?;
                self.spawner.spawn(drive(driver));
                // Ready before pooling: the handle is shared as soon as it
                // is stored.
                sender.ready().await.map_err(HyperError::Connection)?;
                Pool::insert_h2(permit, sender.clone()).await;
                let response = sender
                    .try_send_request(request)
                    .await
                    .map_err(|error| HyperError::Connection(error.into_error()))?;
                Ok((response, None))
            }
        }
    }
}

impl Default for HyperBackend {
    fn default() -> Self {
        Self::new(Transport::system())
    }
}

#[derive(Debug)]
pub enum HyperError {
    Connection(hyper::Error),
    #[cfg(http3)]
    Http3(Box<dyn core::error::Error + Send + Sync>),
    InvalidUri(String),
    Remote {
        status: StatusCode,
        body: Option<String>,
        raw_response: Box<Response>,
    },
}

impl HyperError {
    /// Wrap a QUIC or h3 protocol error.
    #[cfg(http3)]
    #[allow(dead_code)] // used by `h3` once the pool (#69) dials h3 connections
    pub(crate) fn http3(error: impl Into<Box<dyn core::error::Error + Send + Sync>>) -> Self {
        Self::Http3(error.into())
    }
}

impl core::fmt::Display for HyperError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "connection error: {err}"),
            #[cfg(http3)]
            Self::Http3(err) => write!(f, "http/3 error: {err}"),
            Self::InvalidUri(uri) => write!(f, "invalid uri: {uri}"),
            Self::Remote { status, body, .. } => {
                if let Some(body) = body {
                    write!(f, "remote error: {status} - {body}")
                } else {
                    write!(f, "remote error: {status}")
                }
            }
        }
    }
}

impl core::error::Error for HyperError {}

impl HttpError for HyperError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Remote { status, .. } => *status,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// Convert HyperError to unified zenwave::Error
impl From<HyperError> for crate::Error {
    fn from(err: HyperError) -> Self {
        match err {
            HyperError::Remote {
                status,
                body,
                raw_response,
            } => Self::Http {
                status,
                message: body.clone().unwrap_or_else(|| {
                    status
                        .canonical_reason()
                        .unwrap_or("Unknown error")
                        .to_string()
                }),
                response: Box::new(HttpErrorResponse {
                    response: *raw_response,
                    body_text: body,
                }),
            },
            HyperError::Connection(e) => Self::Transport(Box::new(e)),
            #[cfg(http3)]
            HyperError::Http3(e) => Self::Transport(e),
            HyperError::InvalidUri(uri) => Self::InvalidUri(uri),
        }
    }
}

impl Endpoint for HyperBackend {
    type Error = crate::Error;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(http_kit::Body::empty())
            .unwrap();
        let mut request: http::Request<http_kit::Body> = replace(request, dummy_request);
        // The absolute URI, kept so a request taken back from a dead
        // connection can be reshaped for whichever checkout serves the retry.
        let uri = request.uri().clone();

        let origin = {
            let uri = request.uri();
            let host = uri
                .host()
                .ok_or_else(|| HyperError::InvalidUri(uri.to_string()))?;
            let scheme = match uri.scheme_str().unwrap_or("http") {
                "https" => Scheme::HTTPS,
                "http" => Scheme::HTTP,
                other => return Err(HyperError::InvalidUri(other.to_string()).into()),
            };
            Origin {
                host: host.to_owned(),
                port: uri
                    .port_u16()
                    .unwrap_or(if scheme == Scheme::HTTPS { 443 } else { 80 }),
                scheme,
            }
        };

        let mut retried = false;
        let (response, lease) = loop {
            let checkout = self.transport.pool().checkout(origin.clone()).await;
            match checkout {
                #[cfg(feature = "http2")]
                // The URI stays absolute: hyper derives `:scheme` and
                // `:authority` from it.
                Checkout::H2(mut sender) => {
                    match send_or_retry(sender.try_send_request(request).await, retried)? {
                        Sent::Done(response) => break (response, None),
                        Sent::Retry(unsent) => {
                            retried = true;
                            request = *unsent;
                            *request.uri_mut() = uri.clone();
                        }
                    }
                }
                Checkout::H1(lease) => {
                    shape_h1_request(&mut request, lease.via())?;
                    let sent = send_or_retry(lease.send(request).await, retried)?;
                    match sent {
                        Sent::Done((response, lease)) => break (response, Some(lease)),
                        Sent::Retry(unsent) => {
                            retried = true;
                            request = *unsent;
                            *request.uri_mut() = uri.clone();
                        }
                    }
                }
                Checkout::Dial(permit) => {
                    break self.dial_and_send(&origin, permit, request).await?;
                }
            }
        };

        let mut response = response.map(|body| {
            let stream = BodyDataStream::new(body)
                .map_err(|error| http_kit::BodyError::Other(Box::new(error)));
            match lease {
                // The h1 connection is reusable once the body is finished or
                // dropped, so the lease rides along with it.
                Some(lease) => http_kit::Body::from_stream(LeaseReturn::new(stream, lease)),
                None => http_kit::Body::from_stream(stream),
            }
        });

        debug!(
            status = %response.status(),
            headers = ?response.headers(),
            "HyperBackend received response"
        );

        let is_error = response.status().is_client_error() || response.status().is_server_error();

        if is_error {
            let error_msg: Option<String> = response
                .body_mut()
                .as_str()
                .await
                .ok()
                .map(std::borrow::ToOwned::to_owned);
            return Err(HyperError::Remote {
                status: response.status(),
                body: error_msg,
                raw_response: Box::new(response),
            }
            .into());
        }

        Ok(response)
    }
}

/// The outcome of a send on a pooled connection.
enum Sent<T> {
    /// The send completed. For h1 the payload pairs the response with the
    /// returned lease; for h2 it is just the response.
    Done(T),
    /// The pooled connection died before the request was written and this
    /// was the first reuse failure — retry once on a fresh dial.
    Retry(Box<http::Request<http_kit::Body>>),
}

/// Classify a pooled-connection send: the success payload, the request back
/// when hyper never wrote it (`TrySendError::take_message` only yields it
/// for unstarted requests), or a hard error.
fn send_or_retry<T>(
    result: Result<T, TrySendError<http::Request<http_kit::Body>>>,
    retried: bool,
) -> Result<Sent<T>, HyperError> {
    match result {
        Ok(done) => Ok(Sent::Done(done)),
        Err(mut error) => match error.take_message() {
            Some(unsent) if !retried => Ok(Sent::Retry(Box::new(unsent))),
            _ => Err(HyperError::Connection(error.into_error())),
        },
    }
}

/// Shape an h1 request for the path its connection took: origin-form and a
/// `Host` header for direct connections, absolute-form plus the proxy's
/// `Proxy-Authorization` through a forward proxy.
fn shape_h1_request(
    request: &mut http::Request<http_kit::Body>,
    via: &Via,
) -> Result<(), HyperError> {
    if request.headers().get(http::header::HOST).is_none()
        && let Some(authority) = request.uri().authority()
        && let Ok(value) = http::header::HeaderValue::from_str(authority.as_str())
    {
        request.headers_mut().insert(http::header::HOST, value);
    }
    match via {
        Via::Direct => {
            let origin_form = request
                .uri()
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            *request.uri_mut() = origin_form
                .parse()
                .map_err(|err| HyperError::InvalidUri(format!("{origin_form}: {err}")))?;
        }
        Via::HttpProxy { authorization } => {
            // Absolute-form request line: the proxy needs the full URI.
            if let Some(authorization) = authorization {
                request
                    .headers_mut()
                    .insert(http::header::PROXY_AUTHORIZATION, authorization.clone());
            }
        }
    }
    Ok(())
}

/// An h1 response body that returns its connection's lease to the pool when
/// the body ends or is dropped, whichever comes first.
struct LeaseReturn<S> {
    inner: S,
    lease: Option<H1Lease>,
}

impl<S> LeaseReturn<S> {
    const fn new(inner: S, lease: H1Lease) -> Self {
        Self {
            inner,
            lease: Some(lease),
        }
    }
}

impl<S: Stream + Unpin> Stream for LeaseReturn<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self { inner, lease } = self.get_mut();
        let poll = Pin::new(inner).poll_next(cx);
        if matches!(poll, Poll::Ready(None))
            && let Some(lease) = lease.take()
        {
            lease.release();
        }
        poll
    }
}

impl<S> Drop for LeaseReturn<S> {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.release();
        }
    }
}

/// Drive a hyper connection future to completion in the background while the
/// caller consumes its response body.
async fn drive(connection: impl Future<Output = Result<(), hyper::Error>>) {
    if let Err(err) = connection.await {
        warn!(error = %err, "hyper connection error");
    }
}

impl Client for HyperBackend {}

#[cfg(test)]
mod tests {
    use super::HyperBackend;
    use crate::{Client as _, ResponseExt as _, Transport, client_with};
    use futures_util::{StreamExt as _, future::Either};
    use std::{
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener, TcpStream},
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    const STREAMING_TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct TestStreamingServer {
        address: SocketAddr,
        release_first: mpsc::Sender<()>,
        first_written: mpsc::Receiver<()>,
        release_second: mpsc::Sender<()>,
        worker: thread::JoinHandle<()>,
    }

    impl TestStreamingServer {
        fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test server must bind");
            let address = listener.local_addr().expect("test address must exist");
            let (release_first, release_first_rx) = mpsc::channel();
            let (first_written_tx, first_written) = mpsc::channel();
            let (release_second, release_second_rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                serve_streaming_responses(
                    &listener,
                    &release_first_rx,
                    &first_written_tx,
                    &release_second_rx,
                );
            });
            Self {
                address,
                release_first,
                first_written,
                release_second,
                worker,
            }
        }

        fn finish(self) {
            self.worker.join().expect("test server must finish");
        }
    }

    fn serve_streaming_responses(
        listener: &TcpListener,
        release_first: &mpsc::Receiver<()>,
        first_written: &mpsc::Sender<()>,
        release_second: &mpsc::Receiver<()>,
    ) {
        let (mut socket, _) = listener.accept().expect("test request must arrive");
        socket
            .set_nodelay(true)
            .expect("streaming test socket must disable Nagle buffering");
        read_http_request(&mut socket);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 276\r\nConnection: close\r\n\r\n")
            .expect("response header must write");
        socket.flush().expect("response header must flush");
        release_first
            .recv()
            .expect("test must release the first response fragment");
        socket
            .write_all(&[0xA5; 138])
            .expect("first response fragment must write");
        socket.flush().expect("first response bytes must flush");
        first_written
            .send(())
            .expect("first-fragment signal must send");
        release_second
            .recv()
            .expect("test must release the response tail");
        socket
            .write_all(&[0x5A; 138])
            .expect("response tail must write");
    }

    fn read_http_request(socket: &mut std::net::TcpStream) -> Vec<u8> {
        let mut request = [0_u8; 4_096];
        let mut filled = 0_usize;
        loop {
            let read = socket
                .read(&mut request[filled..])
                .expect("test request must be readable");
            assert_ne!(read, 0, "test request ended before its HTTP header");
            filled += read;
            if request[..filled]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                return request[..filled].to_vec();
            }
            assert!(
                filled < request.len(),
                "test request exceeded its explicit header bound"
            );
        }
    }

    #[test]
    fn plaintext_requests_speak_http1_in_origin_form() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test server must bind");
        let address = listener.local_addr().expect("test address must exist");
        let worker = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("test request must arrive");
            let request = read_http_request(&mut socket);
            let head = String::from_utf8(request).expect("request head is ASCII");
            let request_line = head.lines().next().expect("request has a first line");
            assert_eq!(request_line, "GET /plaintext HTTP/1.1");
            assert!(
                head.lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("host: ")),
                "h1 requests must carry a Host header"
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("response must write");
        });

        let mut client = HyperBackend::default();
        let response = futures_executor::block_on(async {
            client
                .get(format!("http://{address}/plaintext"))
                .expect("test request must build")
                .await
        })
        .expect("plaintext request must succeed");
        assert_eq!(response.status(), http::StatusCode::OK);
        worker.join().expect("test server must finish");
    }

    #[test]
    fn response_headers_arrive_before_a_streaming_body_completes() {
        let server = TestStreamingServer::start();

        let mut client = HyperBackend::default();
        let response = futures_executor::block_on(async {
            let response = client
                .get(format!("http://{}/stream", server.address))
                .expect("test request must build")
                .into_future();
            futures_util::pin_mut!(response);
            let timeout = async_io::Timer::after(STREAMING_TEST_TIMEOUT);
            futures_util::pin_mut!(timeout);
            match futures_util::future::select(response, timeout).await {
                Either::Left((response, _)) => Some(response.expect("test request must succeed")),
                Either::Right(_) => None,
            }
        });
        let Some(response) = response else {
            server
                .release_first
                .send(())
                .expect("timed-out test must unblock its server");
            server
                .release_second
                .send(())
                .expect("timed-out test must release the response tail");
            server.finish();
            panic!("response headers did not arrive before body completion");
        };
        let mut body = response.into_body();
        let (first_result_tx, first_result_rx) = mpsc::sync_channel(1);
        let body_worker = thread::spawn(move || {
            let first = futures_executor::block_on(body.next());
            first_result_tx
                .send((body, first))
                .expect("first body result must send");
        });
        server
            .release_first
            .send(())
            .expect("test must release the first response fragment");
        server
            .first_written
            .recv()
            .expect("server must write the first response fragment");
        let (mut body, first) = match first_result_rx.recv_timeout(STREAMING_TEST_TIMEOUT) {
            Ok(result) => result,
            Err(error) => {
                server
                    .release_second
                    .send(())
                    .expect("timed-out test must release the response tail");
                let (_, result) = first_result_rx
                    .recv()
                    .expect("released body poll must complete");
                body_worker.join().expect("body worker must finish");
                server.finish();
                panic!(
                    "first response fragment was buffered until completion ({error}); released poll result: {result:?}"
                );
            }
        };
        let first = first
            .expect("response must contain a first body chunk")
            .expect("first body chunk must be valid");
        assert_eq!(first.as_ref(), &[0xA5; 138]);
        server
            .release_second
            .send(())
            .expect("test must release the response tail");
        let second = futures_executor::block_on(body.next())
            .expect("response must contain a second body chunk")
            .expect("second body chunk must be valid");
        assert_eq!(second.as_ref(), &[0x5A; 138]);
        assert!(futures_executor::block_on(body.next()).is_none());
        body_worker.join().expect("body worker must finish");
        server.finish();
    }

    /// Read one request head; `false` once the peer goes away.
    fn read_request_head(socket: &mut TcpStream) -> bool {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            match socket.read(&mut byte) {
                Ok(0) | Err(_) => return false,
                Ok(_) => {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        return true;
                    }
                }
            }
        }
    }

    /// A plaintext h1 server that counts accepted connections. Each accepted
    /// socket is served on its own thread: `respond` answers every request
    /// and says whether to keep the connection open.
    fn counting_h1_server(
        respond: impl Fn(&mut TcpStream) -> bool + Send + Sync + 'static,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test server must bind");
        let address = listener.local_addr().expect("test address must exist");
        let accepts = Arc::new(AtomicUsize::new(0));
        let respond = Arc::new(respond);
        let accept_count = accepts.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut socket) = stream else {
                    break;
                };
                accept_count.fetch_add(1, Ordering::SeqCst);
                let respond = respond.clone();
                thread::spawn(move || {
                    while read_request_head(&mut socket) {
                        if !respond(&mut socket) {
                            break;
                        }
                    }
                });
            }
        });
        (address, accepts)
    }

    fn respond_ok(socket: &mut TcpStream) -> bool {
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .expect("response must write");
        true
    }

    #[test]
    fn sequential_h1_requests_reuse_one_connection() {
        let (address, accepts) = counting_h1_server(respond_ok);
        futures_executor::block_on(async {
            let mut client = HyperBackend::default();
            for _ in 0..3 {
                let response = client
                    .get(format!("http://{address}/"))
                    .expect("test request must build")
                    .await
                    .expect("test request must succeed");
                // Returning the body returns the connection to the pool.
                drop(response);
            }
        });
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "sequential h1 requests must reuse one connection"
        );
    }

    #[test]
    fn clients_over_one_transport_share_connections() {
        let (address, accepts) = counting_h1_server(respond_ok);
        futures_executor::block_on(async {
            let transport = Transport::builder()
                .build()
                .expect("test transport must build");
            let mut first = client_with(transport.clone());
            let mut second = client_with(transport);
            drop(
                first
                    .get(format!("http://{address}/"))
                    .expect("test request must build")
                    .await
                    .expect("first request must succeed"),
            );
            second
                .get(format!("http://{address}/"))
                .expect("test request must build")
                .await
                .expect("second request must succeed");
        });
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "clients over one transport must share pooled connections"
        );
    }

    #[test]
    fn concurrent_h1_requests_are_capped_per_origin() {
        const CONCURRENT: usize = 8;
        // Each request is held until `MAX_H1_PER_ORIGIN` have arrived: with
        // the cap honored the sixth arrival releases every response and the
        // two queued requests reuse freed connections; without it the server
        // would see eight sockets.
        let arrivals = Arc::new((Mutex::new(0_usize), Condvar::new()));
        let cap = crate::transport::pool::MAX_H1_PER_ORIGIN;
        let (address, accepts) = counting_h1_server(move |socket| {
            let (count, released) = &*arrivals;
            let mut arrived = count.lock().expect("arrivals lock must hold");
            *arrived += 1;
            if *arrived >= cap {
                released.notify_all();
            }
            while *arrived < cap {
                arrived = released.wait(arrived).expect("arrivals wait must hold");
            }
            drop(arrived);
            respond_ok(socket)
        });
        futures_executor::block_on(async {
            let transport = Transport::builder()
                .build()
                .expect("test transport must build");
            futures_util::future::join_all((0..CONCURRENT).map(|_| {
                let mut client = client_with(transport.clone());
                let uri = format!("http://{address}/");
                async move {
                    client
                        .get(uri)
                        .expect("test request must build")
                        .await
                        .expect("capped request must succeed")
                        .into_string()
                        .await
                        .expect("response body must read");
                }
            }))
            .await;
        });
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            crate::transport::pool::MAX_H1_PER_ORIGIN,
            "eight concurrent h1 requests must open at most six connections"
        );
    }

    #[test]
    fn server_closed_connections_are_not_reused() {
        let close_next = Arc::new(AtomicBool::new(true));
        let (address, accepts) = counting_h1_server(move |socket| {
            if close_next.swap(false, Ordering::SeqCst) {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .expect("response must write");
                return false;
            }
            respond_ok(socket)
        });
        futures_executor::block_on(async {
            let mut client = HyperBackend::default();
            for _ in 0..2 {
                let response = client
                    .get(format!("http://{address}/"))
                    .expect("test request must build")
                    .await
                    .expect("request on a fresh connection must succeed");
                drop(response);
            }
        });
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            2,
            "a closed idle connection must not be handed out again"
        );
    }

    #[test]
    fn dropped_bodies_release_their_connection() {
        let partial_once = Arc::new(AtomicBool::new(true));
        let (address, accepts) = counting_h1_server(move |socket| {
            if partial_once.swap(false, Ordering::SeqCst) {
                // Advertise a body the socket never delivers, then close:
                // the connection cannot carry another request.
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\npartial")
                    .expect("response must write");
                return false;
            }
            respond_ok(socket)
        });
        futures_executor::block_on(async {
            let mut client = HyperBackend::default();
            let response = client
                .get(format!("http://{address}/"))
                .expect("test request must build")
                .await
                .expect("response headers must arrive");
            // Abandon the body; the lease returns, sees the dead sender, and
            // the next request dials a fresh connection.
            drop(response);
            client
                .get(format!("http://{address}/"))
                .expect("test request must build")
                .await
                .expect("request after a dropped body must succeed");
        });
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            2,
            "an abandoned-body connection must be dialed past"
        );
    }

    #[cfg(feature = "http2")]
    mod http2 {
        use std::{
            convert::Infallible,
            net::SocketAddr,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
                mpsc,
            },
            thread,
            time::Duration,
        };

        use async_io::block_on;
        use async_net::{TcpListener, TcpStream};
        use futures_rustls::TlsAcceptor;
        use http::{Version, header::HOST};
        use http_body_util::{BodyExt, Full};
        use hyper::{
            body::{Bytes, Incoming},
            service::service_fn,
        };
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair,
        };
        use rustls::{
            ServerConfig,
            crypto::ring,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use time::{Duration as TimeDelta, OffsetDateTime};

        use super::super::{HyperBackend, rt::Spawner};
        use crate::{Client as _, ResponseExt as _, Transport, transport::stream::HyperIo};

        const TEST_TIMEOUT: Duration = Duration::from_secs(10);

        /// What the server observed on one request.
        #[derive(Debug)]
        struct Observed {
            version: Version,
            authority: Option<String>,
            host: Option<String>,
            body: Vec<u8>,
        }

        /// A TLS server that speaks h2 or h1 depending on the negotiated ALPN
        /// and reports every request it sees.
        struct AlpnServer {
            address: SocketAddr,
            ca_der: Vec<u8>,
            accepts: Arc<AtomicUsize>,
            observed: mpsc::Receiver<Observed>,
        }

        impl AlpnServer {
            /// Start a server offering `alpn_protocols`, in preference order.
            fn start(alpn_protocols: &[&[u8]]) -> Self {
                let (ca_der, mut config) = server_config();
                config.alpn_protocols = alpn_protocols
                    .iter()
                    .map(|protocol| protocol.to_vec())
                    .collect();
                let acceptor = TlsAcceptor::from(Arc::new(config));
                let (listener, address) = block_on(async {
                    let listener = TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect("test listener must bind");
                    let address = listener.local_addr().expect("test address must exist");
                    (listener, address)
                });
                let (observed_tx, observed) = mpsc::channel();
                let accepts = Arc::new(AtomicUsize::new(0));
                let accept_count = accepts.clone();
                thread::spawn(move || {
                    block_on(async move {
                        while let Ok((tcp, _)) = listener.accept().await {
                            accept_count.fetch_add(1, Ordering::SeqCst);
                            let acceptor = acceptor.clone();
                            let observed_tx = observed_tx.clone();
                            thread::spawn(move || block_on(serve(acceptor, tcp, observed_tx)));
                        }
                    });
                });
                Self {
                    address,
                    ca_der,
                    accepts,
                    observed,
                }
            }

            /// How many TCP connections the server has accepted.
            fn accept_count(&self) -> usize {
                self.accepts.load(Ordering::SeqCst)
            }

            fn transport(&self) -> Transport {
                Transport::builder()
                    .extra_root_certificate_der(self.ca_der.clone())
                    .build()
                    .expect("test transport must build")
            }

            fn uri(&self, path: &str) -> String {
                format!("https://localhost:{}{}", self.address.port(), path)
            }

            /// The next request the server saw.
            fn next_request(&self) -> Observed {
                self.observed
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("server must see the request")
            }
        }

        /// A throwaway CA and a leaf certificate for localhost, signed by it.
        fn server_config() -> (Vec<u8>, ServerConfig) {
            let now = OffsetDateTime::now_utc();
            let ca_key = KeyPair::generate().expect("generate CA key");
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "zenwave test CA");
            ca_params.not_before = now - TimeDelta::days(1);
            ca_params.not_after = now + TimeDelta::days(365);
            let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
            let issuer = Issuer::new(ca_params, ca_key);

            let leaf_key = KeyPair::generate().expect("generate leaf key");
            let mut leaf_params =
                CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                    .expect("leaf params");
            leaf_params
                .distinguished_name
                .push(DnType::CommonName, "localhost");
            leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            leaf_params.not_before = now - TimeDelta::days(1);
            leaf_params.not_after = now + TimeDelta::days(365);
            let leaf = leaf_params
                .signed_by(&leaf_key, &issuer)
                .expect("sign leaf certificate");

            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
            let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![leaf.der().clone()], key)
                .expect("server certificate");
            (ca_cert.der().to_vec(), config)
        }

        /// Accept TLS on `tcp` and serve every request on the connection with
        /// the HTTP version ALPN negotiated.
        async fn serve(acceptor: TlsAcceptor, tcp: TcpStream, observed: mpsc::Sender<Observed>) {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            let service = service_fn(move |request: hyper::Request<Incoming>| {
                let observed = observed.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let body = body
                        .collect()
                        .await
                        .expect("request body must be readable")
                        .to_bytes()
                        .to_vec();
                    observed
                        .send(Observed {
                            version: parts.version,
                            authority: parts
                                .uri
                                .authority()
                                .map(|authority| authority.as_str().to_owned()),
                            host: parts
                                .headers
                                .get(HOST)
                                .map(|value| value.to_str().expect("Host is ASCII").to_owned()),
                            body,
                        })
                        .expect("observed channel must be open");
                    Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(
                        b"zenwave",
                    ))))
                }
            });
            let io = HyperIo(tls);
            let _ = match negotiated.as_deref() {
                Some(b"h2") => {
                    hyper::server::conn::http2::Builder::new(Spawner::new(None))
                        .serve_connection(io, service)
                        .await
                }
                _ => {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                }
            };
        }

        #[test]
        fn https_requests_negotiate_http2_through_alpn() {
            let server = AlpnServer::start(&[b"h2", b"http/1.1"]);
            let mut client = HyperBackend::new(server.transport());

            block_on(async {
                let response = client
                    .post(server.uri("/echo"))
                    .expect("test request must build")
                    .bytes_body(b"streaming body".to_vec())
                    .await
                    .expect("h2 request must succeed");
                assert_eq!(
                    &*response.into_string().await.expect("body must read"),
                    "zenwave"
                );
                // A second request negotiates h2 again (connection reuse is
                // issue #68's connection pool, not part of this change).
                client
                    .get(server.uri("/second"))
                    .expect("test request must build")
                    .await
                    .expect("second h2 request must succeed");
            });

            let first = server.next_request();
            assert_eq!(first.version, Version::HTTP_2);
            assert_eq!(
                first.authority.as_deref(),
                Some(format!("localhost:{}", server.address.port()).as_str()),
                "the server must see :authority, derived from the absolute URI"
            );
            assert_eq!(first.host, None, "h2 requests carry no Host header");
            assert_eq!(first.body, b"streaming body");

            let second = server.next_request();
            assert_eq!(second.version, Version::HTTP_2);
        }

        #[test]
        fn http1_only_servers_still_work() {
            let server = AlpnServer::start(&[b"http/1.1"]);
            let mut client = HyperBackend::new(server.transport());

            block_on(async {
                client
                    .get(server.uri("/"))
                    .expect("test request must build")
                    .await
                    .expect("h1 request must succeed");
            });

            let observed = server.next_request();
            assert_eq!(observed.version, Version::HTTP_11);
        }

        #[test]
        fn concurrent_h2_requests_coalesce_on_one_connection() {
            const CONCURRENT: usize = 4;
            let server = AlpnServer::start(&[b"h2"]);
            let transport = server.transport();
            let uri = server.uri("/");

            block_on(async {
                futures_util::future::join_all((0..CONCURRENT).map(|_| {
                    let mut client = HyperBackend::new(transport.clone());
                    let uri = uri.clone();
                    async move {
                        client
                            .get(uri)
                            .expect("test request must build")
                            .await
                            .expect("h2 request must succeed");
                    }
                }))
                .await;
            });

            for _ in 0..CONCURRENT {
                assert_eq!(server.next_request().version, Version::HTTP_2);
            }
            assert_eq!(
                server.accept_count(),
                1,
                "concurrent h2 requests must share one connection"
            );
        }
    }
}
