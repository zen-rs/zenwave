use async_io::{Timer, block_on};
use async_net::TcpStream;
use core::future::Future;
use dns_lookup::{AddrFamily, AddrInfoHints, SockType, getaddrinfo};
use executor_core::{AnyExecutor, Executor};
use futures_channel::mpsc::{UnboundedReceiver, unbounded};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::FutureExt;
use futures_util::TryStreamExt;
use futures_util::future::{Either, pending, select};
use futures_util::pin_mut;
use futures_util::stream::{FuturesUnordered, StreamExt};
use http::StatusCode;
use http_body_util::BodyDataStream;
use http_kit::{Endpoint, HttpError, Request, Response};
use hyper::http;
use std::{
    collections::{HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::LazyLock,
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

use crate::{Client, error::HttpErrorResponse};

/// Hyper-based HTTP client backend powered by `async-io`/`async-net`.
#[derive(Debug, Default)]
pub struct HyperBackend {
    executor: Option<AnyExecutor>,
    #[cfg(feature = "proxy")]
    proxy: Option<crate::Proxy>,
}

impl HyperBackend {
    /// Create a new `HyperBackend`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a `HyperBackend` that uses the provided executor for background tasks.
    #[must_use]
    pub fn with_executor(executor: impl Executor + 'static) -> Self {
        Self {
            executor: Some(AnyExecutor::new(executor)),
            #[cfg(feature = "proxy")]
            proxy: None,
        }
    }

    /// Route requests through `proxy` when it matches the destination.
    ///
    /// `http` destinations are sent to the proxy in absolute form; `https`
    /// destinations are tunnelled with `CONNECT` before the TLS handshake.
    #[cfg(feature = "proxy")]
    #[must_use]
    pub const fn with_proxy(proxy: crate::Proxy) -> Self {
        Self {
            executor: None,
            proxy: Some(proxy),
        }
    }

    /// Replace the proxy matcher on this backend.
    #[cfg(feature = "proxy")]
    #[must_use]
    pub fn proxy(mut self, proxy: crate::Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Proxy hop for `uri`, when one applies.
    #[cfg(feature = "proxy")]
    fn proxy_for(&self, uri: &http::Uri) -> Option<crate::proxy::Intercept> {
        self.proxy.as_ref()?.intercept(uri)
    }

    fn spawn_background(&self, fut: impl Future<Output = ()> + Send + 'static) {
        if let Some(executor) = &self.executor {
            executor.spawn(fut).detach();
        } else {
            shared_driver().spawn(Box::pin(fut));
        }
    }
}

/// Background task that drives hyper connections when no executor was provided.
///
/// Every in-flight response needs its connection polled while the caller reads
/// the body. Spawning one thread per request made that cost an OS thread per
/// request, so all connections share a single driver thread instead.
struct SharedDriver {
    sender: futures_channel::mpsc::UnboundedSender<BoxedTask>,
}

type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send>>;

impl SharedDriver {
    fn start() -> Self {
        let (sender, receiver) = unbounded::<BoxedTask>();
        thread::Builder::new()
            .name("zenwave-hyper-driver".to_string())
            .spawn(move || {
                // Polls every submitted connection concurrently on this one
                // thread, and only returns once the sender is dropped.
                block_on(receiver.for_each_concurrent(None, |task| task));
            })
            .expect("zenwave must be able to start its connection driver thread");
        Self { sender }
    }

    fn spawn(&self, task: BoxedTask) {
        // The driver outlives the process, so a send only fails if its thread
        // panicked; fall back to a dedicated thread in that case.
        if let Err(err) = self.sender.unbounded_send(task) {
            warn!("connection driver unavailable, falling back to a thread");
            let task = err.into_inner();
            thread::spawn(move || block_on(task));
        }
    }
}

fn shared_driver() -> &'static SharedDriver {
    static DRIVER: LazyLock<SharedDriver> = LazyLock::new(SharedDriver::start);
    &DRIVER
}

/// Failure modes of the hyper transport.
#[derive(Debug)]
pub enum HyperError {
    /// The HTTP/1 connection or exchange failed.
    Connection(hyper::Error),
    /// Connecting to or reading from the socket failed.
    Io(std::io::Error),
    /// An `https` URL was requested but no TLS feature is enabled.
    TlsNotAvailable,
    /// The request URI was missing a host or otherwise unusable.
    InvalidUri(String),
    /// A proxy scheme this backend cannot speak, such as SOCKS.
    #[cfg(feature = "proxy")]
    UnsupportedProxyScheme(String),
    /// The server answered with a 4xx or 5xx status.
    Remote {
        /// Status the server returned.
        status: StatusCode,
        /// Prefix of the response body, when it was valid UTF-8.
        body: Option<String>,
        /// The response, with its body already consumed.
        raw_response: Box<Response>,
    },
}

impl core::fmt::Display for HyperError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "connection error: {err}"),
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::TlsNotAvailable => write!(f, "TLS requested but no TLS feature enabled"),
            Self::InvalidUri(uri) => write!(f, "invalid uri: {uri}"),
            #[cfg(feature = "proxy")]
            Self::UnsupportedProxyScheme(scheme) => write!(
                f,
                "proxy scheme `{scheme}` is not supported by the hyper backend; \
                 enable the `curl-backend` feature for SOCKS proxies"
            ),
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
            // These come from DNS resolution, connecting, and socket reads, so
            // they belong to the transport layer rather than to file I/O.
            HyperError::Io(e) => Self::Transport(Box::new(e)),
            HyperError::TlsNotAvailable => {
                Self::Tls(Box::new(std::io::Error::other("TLS not available")))
            }
            HyperError::InvalidUri(uri) => Self::InvalidUri(uri),
            #[cfg(feature = "proxy")]
            HyperError::UnsupportedProxyScheme(scheme) => Self::InvalidRequest(format!(
                "proxy scheme `{scheme}` is not supported by the hyper backend"
            )),
        }
    }
}

impl Endpoint for HyperBackend {
    type Error = crate::Error;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        // Send a copy so the caller's request keeps its method, URI, and headers.
        // Middleware such as `Retry` and `FollowRedirect` inspect and re-send it
        // after this call returns; only the body is consumed.
        let body = request
            .body_mut()
            .take()
            .unwrap_or_else(|_| http_kit::Body::empty());
        let mut outgoing = http::Request::new(body);
        *outgoing.method_mut() = request.method().clone();
        *outgoing.uri_mut() = request.uri().clone();
        *outgoing.version_mut() = request.version();
        *outgoing.headers_mut() = request.headers().clone();

        super::apply_default_user_agent(outgoing.headers_mut());

        // Ensure Host header is present (required by hyper 1.0 / HTTP 1.1)
        if outgoing.headers().get(http::header::HOST).is_none()
            && let Some(authority) = outgoing.uri().authority()
            && let Ok(value) = http::header::HeaderValue::from_str(authority.as_str())
        {
            outgoing.headers_mut().insert(http::header::HOST, value);
        }
        #[cfg(feature = "proxy")]
        let intercept = self.proxy_for(outgoing.uri());
        #[cfg(not(feature = "proxy"))]
        let intercept: Option<()> = None;

        let connection = connect(&outgoing, intercept.as_ref()).await?;

        // A plain-HTTP request through a proxy keeps its absolute-form URI so the
        // proxy knows which origin to forward it to; everything else uses
        // origin-form, as HTTP/1.1 requires on a direct connection.
        if connection.keep_absolute_form {
            #[cfg(feature = "proxy")]
            if let Some(intercept) = &intercept
                && let Some(credentials) = intercept.basic_auth()
            {
                outgoing
                    .headers_mut()
                    .insert(http::header::PROXY_AUTHORIZATION, credentials.clone());
            }
        } else {
            let origin_form = outgoing
                .uri()
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            *outgoing.uri_mut() = origin_form
                .parse()
                .map_err(|err| HyperError::InvalidUri(format!("{origin_form}: {err}")))?;
        }
        let stream = connection.stream;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(stream)
            .await
            .map_err(HyperError::Connection)?;

        // Drive the connection in the background while the caller consumes its body.
        self.spawn_background(async move {
            if let Err(err) = connection.await {
                warn!(error = %err, "hyper connection error");
            }
        });

        let response = sender
            .send_request(outgoing)
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
            let error_msg = read_error_body(response.body_mut()).await;
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

// RFC 8305 defaults: Resolution Delay = 50ms, First Address Family Count = 1,
// Connection Attempt Delay = 250ms.
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
const FIRST_ADDRESS_FAMILY_COUNT: usize = 1;
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest error-response body captured into the returned error message.
///
/// A failing server can answer with an arbitrarily large page, so only a prefix
/// is kept for diagnostics.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Read up to [`MAX_ERROR_BODY_BYTES`] of an error body as UTF-8 text.
async fn read_error_body(body: &mut http_kit::Body) -> Option<String> {
    let mut collected: Vec<u8> = Vec::new();
    while let Some(Ok(chunk)) = body.next().await {
        let remaining = MAX_ERROR_BODY_BYTES.saturating_sub(collected.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        collected.extend_from_slice(&chunk[..take]);
    }
    if collected.is_empty() {
        return None;
    }
    String::from_utf8(collected).ok()
}

/// An established transport, plus how the request line must be written on it.
struct Connection {
    stream: MaybeTlsStream,
    /// True when the request must keep its absolute-form URI (plain HTTP via a proxy).
    keep_absolute_form: bool,
}

/// Destination parsed out of a request URI.
struct Destination {
    host: String,
    port: u16,
    use_tls: bool,
}

impl Destination {
    fn from_uri(uri: &http::Uri) -> Result<Self, HyperError> {
        let host = uri
            .host()
            .ok_or_else(|| HyperError::InvalidUri(uri.to_string()))?
            .to_string();
        let scheme = uri.scheme_str().unwrap_or("http");
        let use_tls = match scheme {
            "https" => true,
            "http" => false,
            other => return Err(HyperError::InvalidUri(other.to_string())),
        };
        Ok(Self {
            port: uri.port_u16().unwrap_or(if use_tls { 443 } else { 80 }),
            host,
            use_tls,
        })
    }
}

/// Open a transport for `request`, tunnelling through `intercept` when given.
#[cfg(feature = "proxy")]
async fn connect(
    request: &http::Request<http_kit::Body>,
    intercept: Option<&crate::proxy::Intercept>,
) -> Result<Connection, HyperError> {
    let destination = Destination::from_uri(request.uri())?;

    let Some(intercept) = intercept else {
        return connect_direct(&destination).await;
    };

    // This backend speaks HTTP proxying only; SOCKS needs the curl backend.
    let proxy_scheme = intercept.uri().scheme_str().unwrap_or("http");
    if !matches!(proxy_scheme, "http" | "https") {
        return Err(HyperError::UnsupportedProxyScheme(proxy_scheme.to_string()));
    }

    let proxy_host = intercept
        .host()
        .ok_or_else(|| HyperError::InvalidUri(intercept.uri().to_string()))?;
    let stream = open_socket(proxy_host, intercept.port()).await?;

    if destination.use_tls {
        // The proxy cannot see inside TLS, so ask it for a raw tunnel first.
        let tunnel = establish_tunnel(stream, &destination, intercept).await?;
        return Ok(Connection {
            stream: wrap_tls(destination.host, tunnel).await?,
            keep_absolute_form: false,
        });
    }

    // Plain HTTP is forwarded by the proxy itself, using the absolute-form URI.
    Ok(Connection {
        stream: MaybeTlsStream::Plain(stream),
        keep_absolute_form: true,
    })
}

/// Open a transport for `request`. Without the `proxy` feature there is no hop.
#[cfg(not(feature = "proxy"))]
async fn connect(
    request: &http::Request<http_kit::Body>,
    _intercept: Option<&()>,
) -> Result<Connection, HyperError> {
    connect_direct(&Destination::from_uri(request.uri())?).await
}

/// Connect straight to the destination, negotiating TLS when it asks for it.
async fn connect_direct(destination: &Destination) -> Result<Connection, HyperError> {
    let stream = open_socket(&destination.host, destination.port).await?;
    let stream = if destination.use_tls {
        wrap_tls(destination.host.clone(), stream).await?
    } else {
        MaybeTlsStream::Plain(stream)
    };
    Ok(Connection {
        stream,
        keep_absolute_form: false,
    })
}

/// Open a TCP connection with Nagle disabled.
async fn open_socket(host: &str, port: u16) -> Result<TcpStream, HyperError> {
    let stream = connect_happy_eyeballs(host, port)
        .await
        .map_err(HyperError::Io)?;
    stream.set_nodelay(true).map_err(HyperError::Io)?;
    Ok(stream)
}

/// Ask the proxy to tunnel to `destination` with `CONNECT`.
#[cfg(feature = "proxy")]
async fn establish_tunnel(
    mut stream: TcpStream,
    destination: &Destination,
    intercept: &crate::proxy::Intercept,
) -> Result<TcpStream, HyperError> {
    use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};

    let authority = format!("{}:{}", destination.host, destination.port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n",);
    if let Some(credentials) = intercept.basic_auth()
        && let Ok(value) = credentials.to_str()
    {
        request.push_str("Proxy-Authorization: ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(HyperError::Io)?;
    stream.flush().await.map_err(HyperError::Io)?;

    // Read one byte at a time: a buffered read could consume the first bytes of
    // the tunnelled TLS handshake, which belong to the stream we hand back.
    let mut response = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_CONNECT_RESPONSE_BYTES {
            return Err(HyperError::Io(io::Error::other(
                "proxy CONNECT response headers exceeded their bound",
            )));
        }
        match stream.read(&mut byte).await.map_err(HyperError::Io)? {
            0 => {
                return Err(HyperError::Io(io::Error::other(
                    "proxy closed the connection during CONNECT",
                )));
            }
            _ => response.push(byte[0]),
        }
    }

    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_string())
        .unwrap_or_default();
    // "HTTP/1.1 200 Connection established"
    let succeeded = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code));
    if !succeeded {
        return Err(HyperError::Io(io::Error::other(format!(
            "proxy refused CONNECT: {status_line}"
        ))));
    }

    Ok(stream)
}

/// Largest `CONNECT` response header block accepted from a proxy.
#[cfg(feature = "proxy")]
const MAX_CONNECT_RESPONSE_BYTES: usize = 8 * 1024;

// Negotiate TLS for `host` over an established stream.
//
// One definition is compiled per TLS configuration. When both `native-tls` and
// `rustls` are enabled (as `default-backend` does), Apple platforms use
// native-tls so the system keychain applies, and everything else uses rustls
// with the system certificate store.

/// Negotiate TLS using the platform's native stack.
#[cfg(any(
    all(feature = "native-tls", feature = "rustls", target_vendor = "apple"),
    all(feature = "native-tls", not(feature = "rustls")),
))]
async fn wrap_tls(host: String, stream: TcpStream) -> Result<MaybeTlsStream, HyperError> {
    connect_native_tls(&host, stream).await
}

/// Negotiate TLS using rustls with system certificates.
#[cfg(any(
    all(
        feature = "native-tls",
        feature = "rustls",
        not(target_vendor = "apple")
    ),
    all(feature = "rustls", not(feature = "native-tls")),
))]
async fn wrap_tls(host: String, stream: TcpStream) -> Result<MaybeTlsStream, HyperError> {
    connect_rustls(host, stream).await
}

/// Reject `https` when the crate was built without any TLS backend.
#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
#[allow(clippy::unused_async)]
async fn wrap_tls(_host: String, _stream: TcpStream) -> Result<MaybeTlsStream, HyperError> {
    Err(HyperError::TlsNotAvailable)
}

/// Perform the native-tls handshake.
#[cfg(feature = "native-tls")]
#[allow(dead_code)] // Unused on non-Apple targets when both TLS features are enabled.
async fn connect_native_tls(host: &str, stream: TcpStream) -> Result<MaybeTlsStream, HyperError> {
    let connector = async_native_tls::TlsConnector::new();
    let tls = connector
        .connect(host, stream)
        .await
        .map_err(|err| HyperError::Io(std::io::Error::other(err)))?;
    Ok(MaybeTlsStream::Native(tls))
}

async fn connect_happy_eyeballs(host: &str, port: u16) -> io::Result<TcpStream> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return connect_with_timeout(addr)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("{addr}: {error}")));
    }

    let mut state = HappyEyeballsState::new();
    let mut attempts = FuturesUnordered::new();
    let mut resolver = start_resolution(host, port);
    let mut resolver_closed = false;

    loop {
        state.rebuild_pending();

        if let Some(addr) = state.pop_next_attempt(Instant::now()) {
            let attempt: AttemptFuture = Box::pin(connect_attempt(addr));
            attempts.push(attempt);
            continue;
        }

        if state.is_terminal(&attempts) {
            return Err(state.into_connect_error());
        }

        let resolver_event = async {
            if resolver_closed {
                pending::<Option<ResolutionEvent>>().await
            } else {
                resolver.next().await
            }
        };
        let resolution_delay = timer_at(state.resolution_delay_deadline);
        let next_attempt_due = timer_at(state.next_attempt_deadline());

        pin_mut!(resolver_event);
        pin_mut!(resolution_delay);
        pin_mut!(next_attempt_due);

        let attempt_result = async {
            match attempts.next().await {
                Some(outcome) => outcome,
                None => pending::<AttemptOutcome>().await,
            }
        }
        .fuse();
        pin_mut!(attempt_result);

        futures_util::select_biased! {
            outcome = attempt_result => {
                match outcome.result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => state.record_attempt_failure(outcome.addr, &error),
                }
            }
            message = resolver_event.fuse() => {
                if let Some(message) = message { state.apply_resolution(message) } else {
                    resolver_closed = true;
                    state.mark_resolution_stream_closed();
                }
            }
            () = resolution_delay.fuse() => {
                state.open_resolution_gate();
            }
            () = next_attempt_due.fuse() => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AddressFamilyKind {
    Ipv6,
    Ipv4,
}

#[derive(Debug)]
enum ResolutionEventKind {
    Family {
        family: AddressFamilyKind,
        result: ResolutionResult,
    },
    SortedSnapshot(ResolutionResult),
}

#[derive(Debug)]
struct ResolutionEvent {
    kind: ResolutionEventKind,
}

#[derive(Debug)]
enum ResolutionResult {
    Addresses(Vec<SocketAddr>),
    Empty,
    Failed(String),
}

#[derive(Debug)]
enum FamilyResolution {
    Pending,
    Ready(Vec<SocketAddr>),
    Empty,
    Failed(String),
}

impl FamilyResolution {
    fn addrs(&self) -> &[SocketAddr] {
        match self {
            Self::Ready(addrs) => addrs,
            Self::Pending | Self::Empty | Self::Failed(_) => &[],
        }
    }

    const fn is_finished(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    const fn is_positive(&self) -> bool {
        matches!(self, Self::Ready(addrs) if !addrs.is_empty())
    }

    fn failure_message(&self, family: AddressFamilyKind) -> Option<String> {
        match self {
            Self::Failed(message) => Some(format!("{family:?} resolution failed: {message}")),
            Self::Empty => Some(format!("{family:?} resolution returned no addresses")),
            Self::Pending | Self::Ready(_) => None,
        }
    }
}

#[derive(Debug)]
struct AttemptOutcome {
    addr: SocketAddr,
    result: io::Result<TcpStream>,
}

type AttemptFuture = Pin<Box<dyn Future<Output = AttemptOutcome> + Send>>;

#[derive(Debug)]
struct HappyEyeballsState {
    ipv6: FamilyResolution,
    ipv4: FamilyResolution,
    sorted_snapshot: Option<Vec<SocketAddr>>,
    first_positive_family: Option<AddressFamilyKind>,
    resolution_delay_deadline: Option<Instant>,
    pending: VecDeque<SocketAddr>,
    attempted: HashSet<SocketAddr>,
    last_attempt_started_at: Option<Instant>,
    attempt_failures: Vec<String>,
}

impl HappyEyeballsState {
    fn new() -> Self {
        Self {
            ipv6: FamilyResolution::Pending,
            ipv4: FamilyResolution::Pending,
            sorted_snapshot: None,
            first_positive_family: None,
            resolution_delay_deadline: None,
            pending: VecDeque::new(),
            attempted: HashSet::new(),
            last_attempt_started_at: None,
            attempt_failures: Vec::new(),
        }
    }

    fn apply_resolution(&mut self, event: ResolutionEvent) {
        match event.kind {
            ResolutionEventKind::Family { family, result } => {
                let resolution = match result {
                    ResolutionResult::Addresses(addrs) => FamilyResolution::Ready(addrs),
                    ResolutionResult::Empty => FamilyResolution::Empty,
                    ResolutionResult::Failed(message) => FamilyResolution::Failed(message),
                };
                match family {
                    AddressFamilyKind::Ipv6 => {
                        let ipv6_became_positive = !self.ipv6.is_positive()
                            && matches!(&resolution, FamilyResolution::Ready(_));
                        self.ipv6 = resolution;
                        if ipv6_became_positive {
                            if self.attempted.is_empty() {
                                self.first_positive_family = Some(AddressFamilyKind::Ipv6);
                            } else {
                                self.first_positive_family
                                    .get_or_insert(AddressFamilyKind::Ipv6);
                            }
                            self.resolution_delay_deadline = None;
                        } else if self.ipv6.is_finished() && self.ipv4.is_positive() {
                            self.resolution_delay_deadline = None;
                        }
                    }
                    AddressFamilyKind::Ipv4 => {
                        let ipv4_became_positive = !self.ipv4.is_positive()
                            && matches!(&resolution, FamilyResolution::Ready(_));
                        self.ipv4 = resolution;
                        if ipv4_became_positive && self.first_positive_family.is_none() {
                            self.first_positive_family = Some(AddressFamilyKind::Ipv4);
                            if !self.ipv6.is_finished() {
                                self.resolution_delay_deadline =
                                    Some(Instant::now() + RESOLUTION_DELAY);
                            }
                        }
                    }
                }
            }
            ResolutionEventKind::SortedSnapshot(result) => match result {
                ResolutionResult::Addresses(addrs) => self.sorted_snapshot = Some(addrs),
                ResolutionResult::Empty => self.sorted_snapshot = Some(Vec::new()),
                ResolutionResult::Failed(_) => self.sorted_snapshot = None,
            },
        }
    }

    fn rebuild_pending(&mut self) {
        let ordered = self.ordered_candidates();
        self.pending = ordered
            .into_iter()
            .filter(|addr| !self.attempted.contains(addr))
            .collect();
    }

    fn ordered_candidates(&self) -> Vec<SocketAddr> {
        let available = self.available_set();
        if available.is_empty() {
            return Vec::new();
        }

        if let Some(snapshot) = &self.sorted_snapshot {
            let ordered = dedup_socket_addrs(
                snapshot
                    .iter()
                    .copied()
                    .filter(|addr| available.contains(addr))
                    .collect(),
            );
            if !ordered.is_empty() {
                return ordered;
            }
        }

        let ipv6 = self.ipv6.addrs();
        let ipv4 = self.ipv4.addrs();
        match self
            .first_positive_family
            .unwrap_or(AddressFamilyKind::Ipv6)
        {
            AddressFamilyKind::Ipv6 => {
                interleave_address_families(ipv6, ipv4, FIRST_ADDRESS_FAMILY_COUNT)
            }
            AddressFamilyKind::Ipv4 => {
                interleave_address_families(ipv4, ipv6, FIRST_ADDRESS_FAMILY_COUNT)
            }
        }
    }

    fn available_set(&self) -> HashSet<SocketAddr> {
        self.ipv6
            .addrs()
            .iter()
            .chain(self.ipv4.addrs())
            .copied()
            .collect()
    }

    fn pop_next_attempt(&mut self, now: Instant) -> Option<SocketAddr> {
        if !self.can_start_attempt(now) {
            return None;
        }

        let addr = self.pending.pop_front()?;
        self.attempted.insert(addr);
        self.last_attempt_started_at = Some(now);
        self.attempt_failures
            .retain(|failure| !failure.starts_with(&format!("{addr}:")));
        Some(addr)
    }

    fn can_start_attempt(&self, now: Instant) -> bool {
        if self.pending.is_empty() {
            return false;
        }

        if self.attempted.is_empty() {
            return self.initial_attempt_gate_open(now);
        }

        self.next_attempt_deadline()
            .is_some_and(|deadline| now >= deadline)
    }

    fn initial_attempt_gate_open(&self, now: Instant) -> bool {
        if self.ipv6.is_positive() {
            return true;
        }

        if !self.ipv4.is_positive() {
            return false;
        }

        if self.ipv6.is_finished() {
            return true;
        }

        self.resolution_delay_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    fn next_attempt_deadline(&self) -> Option<Instant> {
        if self.attempted.is_empty() || self.pending.is_empty() {
            return None;
        }
        self.last_attempt_started_at
            .map(|started_at| started_at + CONNECTION_ATTEMPT_DELAY)
    }

    const fn open_resolution_gate(&mut self) {
        self.resolution_delay_deadline = None;
    }

    fn record_attempt_failure(&mut self, addr: SocketAddr, error: &io::Error) {
        self.attempt_failures.push(format!("{addr}: {error}"));
    }

    fn mark_resolution_stream_closed(&mut self) {
        if matches!(self.ipv6, FamilyResolution::Pending) {
            self.ipv6 = FamilyResolution::Failed(
                "resolver stream closed before IPv6 result was delivered".to_string(),
            );
        }
        if matches!(self.ipv4, FamilyResolution::Pending) {
            self.ipv4 = FamilyResolution::Failed(
                "resolver stream closed before IPv4 result was delivered".to_string(),
            );
        }
    }

    const fn resolution_complete(&self) -> bool {
        self.ipv6.is_finished() && self.ipv4.is_finished()
    }

    fn is_terminal(&self, attempts: &FuturesUnordered<AttemptFuture>) -> bool {
        attempts.is_empty() && self.pending.is_empty() && self.resolution_complete()
    }

    fn into_connect_error(self) -> io::Error {
        let mut diagnostics = Vec::new();
        if let Some(message) = self.ipv6.failure_message(AddressFamilyKind::Ipv6) {
            diagnostics.push(message);
        }
        if let Some(message) = self.ipv4.failure_message(AddressFamilyKind::Ipv4) {
            diagnostics.push(message);
        }
        diagnostics.extend(self.attempt_failures);

        io::Error::other(format!(
            "RFC 8305 connection setup failed: {}",
            diagnostics.join("; ")
        ))
    }
}

async fn connect_attempt(addr: SocketAddr) -> AttemptOutcome {
    AttemptOutcome {
        addr,
        result: connect_with_timeout(addr).await,
    }
}

async fn connect_with_timeout(addr: SocketAddr) -> io::Result<TcpStream> {
    let connect = TcpStream::connect(addr);
    let timeout = async {
        Timer::after(CONNECT_TIMEOUT).await;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out connecting to {addr}"),
        ))
    };

    pin_mut!(connect);
    pin_mut!(timeout);

    match select(connect, timeout).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

fn start_resolution(host: &str, port: u16) -> UnboundedReceiver<ResolutionEvent> {
    let (sender, receiver) = unbounded();
    for query in [
        ResolveQuery::Family(AddressFamilyKind::Ipv6),
        ResolveQuery::Family(AddressFamilyKind::Ipv4),
        ResolveQuery::SortedSnapshot,
    ] {
        spawn_blocking_resolution(host.to_string(), port, query, sender.clone());
    }
    drop(sender);
    receiver
}

#[derive(Clone, Copy, Debug)]
enum ResolveQuery {
    Family(AddressFamilyKind),
    SortedSnapshot,
}

fn spawn_blocking_resolution(
    host: String,
    port: u16,
    query: ResolveQuery,
    sender: futures_channel::mpsc::UnboundedSender<ResolutionEvent>,
) {
    thread::spawn(move || {
        let result = match query {
            ResolveQuery::Family(family) => resolve_family_blocking(&host, port, Some(family)),
            ResolveQuery::SortedSnapshot => resolve_family_blocking(&host, port, None),
        };
        let kind = match query {
            ResolveQuery::Family(family) => ResolutionEventKind::Family { family, result },
            ResolveQuery::SortedSnapshot => ResolutionEventKind::SortedSnapshot(result),
        };
        let _ = sender.unbounded_send(ResolutionEvent { kind });
    });
}

fn resolve_family_blocking(
    host: &str,
    port: u16,
    family: Option<AddressFamilyKind>,
) -> ResolutionResult {
    let service = port.to_string();
    let hints = AddrInfoHints {
        address: family.map_or(0, |family| match family {
            AddressFamilyKind::Ipv6 => AddrFamily::Inet6.into(),
            AddressFamilyKind::Ipv4 => AddrFamily::Inet.into(),
        }),
        socktype: SockType::Stream.into(),
        ..AddrInfoHints::default()
    };

    match getaddrinfo(Some(host), Some(service.as_str()), Some(hints)) {
        Ok(iter) => match iter.collect::<io::Result<Vec<_>>>() {
            Ok(entries) => {
                let addrs =
                    dedup_socket_addrs(entries.into_iter().map(|entry| entry.sockaddr).collect());
                if addrs.is_empty() {
                    ResolutionResult::Empty
                } else {
                    ResolutionResult::Addresses(addrs)
                }
            }
            Err(error) => ResolutionResult::Failed(error.to_string()),
        },
        Err(error) => ResolutionResult::Failed(format!("{error:?}")),
    }
}

fn dedup_socket_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if seen.insert(addr) {
            deduped.push(addr);
        }
    }
    deduped
}

fn interleave_address_families(
    primary: &[SocketAddr],
    secondary: &[SocketAddr],
    first_family_count: usize,
) -> Vec<SocketAddr> {
    assert!(
        first_family_count > 0,
        "first address family count must be greater than zero",
    );

    let mut ordered = Vec::with_capacity(primary.len() + secondary.len());
    let mut primary_index = 0;
    let mut secondary_index = 0;

    while primary_index < primary.len() || secondary_index < secondary.len() {
        for _ in 0..first_family_count {
            if let Some(addr) = primary.get(primary_index) {
                ordered.push(*addr);
                primary_index += 1;
            }
        }

        if let Some(addr) = secondary.get(secondary_index) {
            ordered.push(*addr);
            secondary_index += 1;
        }

        if primary_index >= primary.len() && secondary_index < secondary.len() {
            ordered.extend_from_slice(&secondary[secondary_index..]);
            break;
        }
        if secondary_index >= secondary.len() && primary_index < primary.len() {
            ordered.extend_from_slice(&primary[primary_index..]);
            break;
        }
    }

    ordered
}

async fn timer_at(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => {
            Timer::at(deadline).await;
        }
        None => pending::<()>().await,
    }
}

/// Perform the rustls handshake, trusting the system certificate store.
#[cfg(feature = "rustls")]
#[allow(dead_code)] // Unused on Apple targets when both TLS features are enabled.
async fn connect_rustls(host: String, stream: TcpStream) -> Result<MaybeTlsStream, HyperError> {
    use std::sync::Arc;

    use futures_rustls::{
        TlsConnector,
        client::TlsStream as RustlsStream,
        rustls::{self, pki_types::ServerName},
    };

    // Load system certificates
    let mut root_store = rustls::RootCertStore::empty();

    // Load system certificates (rustls-native-certs returns CertificateResult with certs and errors)
    let cert_result = rustls_native_certs::load_native_certs();
    for cert in cert_result.certs {
        // Ignore invalid certificates, just skip them
        let _ = root_store.add(cert);
    }

    // If no system certs were loaded, fall back to webpki roots
    if root_store.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.clone())
        .map_err(|err| HyperError::Io(std::io::Error::other(err)))?;

    let stream: RustlsStream<TcpStream> = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| HyperError::Io(std::io::Error::other(err)))?;
    Ok(MaybeTlsStream::Rustls(Box::new(stream)))
}

enum MaybeTlsStream {
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    #[allow(dead_code)]
    // Used on Apple platforms; unused on non-Apple when both TLS features enabled
    Native(async_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls")]
    #[allow(dead_code)]
    // Used on non-Apple platforms; unused on Apple when both TLS features enabled
    Rustls(Box<futures_rustls::client::TlsStream<TcpStream>>),
}

impl Unpin for MaybeTlsStream {}

impl hyper::rt::Read for MaybeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let slice = unsafe { buf.as_mut() };
        let bytes = unsafe { &mut *(std::ptr::from_mut(slice) as *mut [u8]) };

        let result = match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, bytes),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_read(cx, bytes),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_read(cx, bytes),
        };

        match result {
            Poll::Ready(Ok(n)) => {
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::rt::Write for MaybeTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_close(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamilyKind, HappyEyeballsState, HyperBackend, ResolutionEvent, ResolutionEventKind,
        ResolutionResult, connect_happy_eyeballs, interleave_address_families,
    };
    use crate::Client as _;
    use futures_util::{StreamExt as _, future::Either};
    use std::{
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
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

        let mut client = HyperBackend::new();
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

    #[test]
    fn interleaves_addresses_with_first_family_count() {
        let ipv6 = vec![
            "[2001:db8::1]:443"
                .parse::<SocketAddr>()
                .expect("valid IPv6"),
            "[2001:db8::2]:443"
                .parse::<SocketAddr>()
                .expect("valid IPv6"),
        ];
        let ipv4 = vec![
            "203.0.113.10:443"
                .parse::<SocketAddr>()
                .expect("valid IPv4"),
            "203.0.113.11:443"
                .parse::<SocketAddr>()
                .expect("valid IPv4"),
        ];
        assert_eq!(
            interleave_address_families(&ipv6, &ipv4, 1),
            vec![
                "[2001:db8::1]:443".parse().expect("valid IPv6"),
                "203.0.113.10:443".parse().expect("valid IPv4"),
                "[2001:db8::2]:443".parse().expect("valid IPv6"),
                "203.0.113.11:443".parse().expect("valid IPv4"),
            ]
        );
    }

    #[test]
    fn promotes_ipv6_when_aaaa_arrives_during_resolution_delay() {
        let mut state = HappyEyeballsState::new();
        state.apply_resolution(ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv4,
                result: ResolutionResult::Addresses(vec![
                    "203.0.113.10:443"
                        .parse::<SocketAddr>()
                        .expect("valid IPv4"),
                ]),
            },
        });
        state.apply_resolution(ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv6,
                result: ResolutionResult::Addresses(vec![
                    "[2001:db8::1]:443"
                        .parse::<SocketAddr>()
                        .expect("valid IPv6"),
                ]),
            },
        });

        let ordered = state.ordered_candidates();
        assert_eq!(state.first_positive_family, Some(AddressFamilyKind::Ipv6));
        assert_eq!(
            ordered.first().copied(),
            Some("[2001:db8::1]:443".parse().expect("valid IPv6"))
        );
    }

    #[test]
    fn holds_ipv4_until_resolution_delay_expires_when_aaaa_is_still_pending() {
        let mut state = HappyEyeballsState::new();
        state.apply_resolution(ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv4,
                result: ResolutionResult::Addresses(vec![
                    "203.0.113.10:443"
                        .parse::<SocketAddr>()
                        .expect("valid IPv4"),
                ]),
            },
        });

        assert_eq!(state.first_positive_family, Some(AddressFamilyKind::Ipv4));
        assert!(
            state.resolution_delay_deadline.is_some(),
            "A responses must wait for the resolution delay while AAAA remains pending",
        );
        assert!(
            !state.initial_attempt_gate_open(Instant::now()),
            "IPv4 must not start immediately while AAAA is still pending",
        );
    }

    #[test]
    fn literal_ip_connect_does_not_report_opposite_family_resolution() {
        let error = smol::block_on(connect_happy_eyeballs("127.0.0.1", 9))
            .expect_err("discard port should not accept connections in tests");
        let message = error.to_string();
        assert!(
            !message.contains("Ipv6 resolution"),
            "literal IPv4 must not run DNS or report IPv6 resolution: {message}",
        );
        assert!(
            message.contains("127.0.0.1:9"),
            "literal IP connection error should name the attempted socket address: {message}",
        );
    }
}
