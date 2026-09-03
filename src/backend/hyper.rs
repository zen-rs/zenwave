use core::future::Future;
use std::{mem::replace, thread};

use async_io::block_on;
use executor_core::{AnyExecutor, Executor};
use futures_util::TryStreamExt;
use http::StatusCode;
use http_body_util::BodyDataStream;
use http_kit::{Endpoint, HttpError, Method, Request, Response};
use hyper::http;
use tracing::{debug, warn};

use crate::{
    Client, Transport,
    error::HttpErrorResponse,
    transport::{
        connect::{Target, connect},
        stream::HyperIo,
    },
};

/// Hyper-based HTTP client backend powered by `async-io`/`async-net`.
#[derive(Debug)]
pub struct HyperBackend {
    transport: Transport,
    executor: Option<AnyExecutor>,
}

impl HyperBackend {
    /// Create a backend that connects through `transport`.
    #[must_use]
    pub const fn new(transport: Transport) -> Self {
        Self {
            transport,
            executor: None,
        }
    }

    /// Create a backend that connects through `transport` and drives its
    /// connections on `executor` instead of a dedicated thread per request.
    #[must_use]
    pub fn with_executor(transport: Transport, executor: impl Executor + 'static) -> Self {
        Self {
            transport,
            executor: Some(AnyExecutor::new(executor)),
        }
    }

    fn spawn_background(&self, fut: impl Future<Output = ()> + Send + 'static) {
        if let Some(executor) = &self.executor {
            executor.spawn(fut).detach();
        } else {
            thread::spawn(move || {
                block_on(fut);
            });
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
    InvalidUri(String),
    Remote {
        status: StatusCode,
        body: Option<String>,
        raw_response: Box<Response>,
    },
}

impl core::fmt::Display for HyperError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "connection error: {err}"),
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

        // Ensure Host header is present (required by hyper 1.0 / HTTP 1.1)
        if request.headers().get(http::header::HOST).is_none()
            && let Some(authority) = request.uri().authority()
            && let Ok(value) = http::header::HeaderValue::from_str(authority.as_str())
        {
            request.headers_mut().insert(http::header::HOST, value);
        }
        let stream = {
            let uri = request.uri();
            let host = uri
                .host()
                .ok_or_else(|| HyperError::InvalidUri(uri.to_string()))?;
            let tls = match uri.scheme_str().unwrap_or("http") {
                "https" => true,
                "http" => false,
                other => return Err(HyperError::InvalidUri(other.to_string()).into()),
            };
            let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
            connect(&self.transport, Target { host, port, tls }).await?
        };
        let origin_form = request
            .uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        *request.uri_mut() = origin_form
            .parse()
            .map_err(|err| HyperError::InvalidUri(format!("{origin_form}: {err}")))?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(HyperIo(stream))
            .await
            .map_err(HyperError::Connection)?;

        // Drive the connection in the background while the caller consumes its body.
        self.spawn_background(async move {
            if let Err(err) = connection.await {
                warn!(error = %err, "hyper connection error");
            }
        });

        let response = sender
            .send_request(request)
            .await
            .map_err(HyperError::Connection)?;

        let mut response = response.map(|body| {
            let stream = BodyDataStream::new(body)
                .map_err(|error| http_kit::BodyError::Other(Box::new(error)));
            http_kit::Body::from_stream(stream)
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

impl Client for HyperBackend {}

#[cfg(test)]
mod tests {
    use super::HyperBackend;
    use crate::Client as _;
    use futures_util::{StreamExt as _, future::Either};
    use std::{
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        sync::mpsc,
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

    fn read_http_request(socket: &mut std::net::TcpStream) {
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
                return;
            }
            assert!(
                filled < request.len(),
                "test request exceeded its explicit header bound"
            );
        }
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
}
