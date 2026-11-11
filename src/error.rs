//! Unified error types for zenwave HTTP client.
//!
//! This module provides a single, unified error type [`Error`] that encompasses
//! all possible errors that can occur during HTTP operations. This includes:
//! - HTTP server errors (4xx/5xx responses, for a caller that opted into
//!   [`crate::ErrorForStatus`])
//! - Failures to connect, which say which phase failed and why
//!   ([`ConnectError`], [`ConnectFailure`])
//! - Failures of the exchange once connected ([`ExchangeError`],
//!   [`ExchangeFailure`])
//! - Deadlines that passed ([`TimedOut`])
//! - Request/response parsing errors
//! - Middleware-specific errors (timeout, redirect, authentication, etc.)
//!
//! A caller tells why a request failed by matching, never by downcasting:
//! every failure keeps the engine's own error as a typed [`Cause`], and the
//! classification a caller needs (a name that does not resolve, a refused
//! connection, an untrusted certificate, a received alert, a body that ends
//! early) is a variant.
//!
//! The [`Error`] type implements [`http_kit::HttpError`] trait and provides
//! rich helper methods for error classification and handling.

#[cfg(unix_socket)]
use std::path::PathBuf;
use std::{error::Error as StdError, fmt, io, net::SocketAddr, sync::Arc};

use http_kit::{BodyError, ReceiveError, Response, StatusCode};
use thiserror::Error;

/// Unified error type for all zenwave operations.
#[derive(Debug, Error)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// HTTP server returned an error response (4xx/5xx status code).
    ///
    /// No backend produces this: a backend returns every response it
    /// receives. It comes from a caller opting in, through
    /// [`crate::ErrorForStatus`] (`Client::error_for_status`) or
    /// [`crate::ResponseExt::error_for_status`]. The response body may contain
    /// additional error details that can be deserialized using
    /// [`Error::deserialize_http_error`].
    #[error("HTTP error {status}: {message}")]
    Http {
        /// HTTP status code
        status: StatusCode,
        /// Error message (extracted from response body or default message)
        message: String,
        /// Full HTTP error response details
        #[source]
        response: Box<HttpErrorResponse>,
    },

    /// No connection to the origin (or to the proxy in front of it) could be
    /// made: resolution, TCP, a proxy's tunnel, TLS or QUIC failed.
    #[error(transparent)]
    Connect(Box<ConnectError>),

    /// The connection failed, or the peer broke the protocol, while the
    /// request and its response were exchanged.
    #[error(transparent)]
    Exchange(Box<ExchangeError>),

    /// A deadline passed.
    #[error("timed out: {0}")]
    Timeout(TimedOut),

    /// The client or its transport is misconfigured, or the backend cannot do
    /// what the request asks.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The backend's connection pool has stopped, so nothing can be sent.
    #[error("the backend's connection pool has stopped")]
    Stopped,

    /// Too many redirects were followed.
    #[error("too many redirects (max {max})")]
    TooManyRedirects {
        /// Maximum number of redirects allowed
        max: u32,
    },

    /// Invalid redirect Location header.
    #[error("invalid redirect location")]
    InvalidRedirectLocation,

    /// URI parsing error.
    #[error("invalid URI: {0}")]
    InvalidUri(String),

    /// Request construction error (invalid headers, body, etc.).
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Response body parsing error (JSON, form, string, etc.).
    #[error("failed to parse response body: {0}")]
    BodyParse(#[source] BodyError),

    /// Response body exceeded the caller-provided in-memory limit.
    #[error("response body exceeds the {limit}-byte limit")]
    ResponseBodyTooLarge {
        /// Maximum response body size accepted by the caller.
        limit: usize,
    },

    /// Cookie management error.
    #[error("cookie error: {0}")]
    Cookie(#[from] CookieErrorKind),

    /// `OAuth2` authentication error.
    #[error("OAuth2 error: {0}")]
    OAuth2(#[from] OAuth2ErrorKind),

    /// File download error.
    #[error("download error: {0}")]
    Download(#[from] DownloadErrorKind),

    /// WebSocket error.
    #[error("websocket error: {0}")]
    WebSocket(#[from] WebSocketErrorKind),

    /// I/O error (file operations, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other uncategorized error.
    #[error("other error: {0}")]
    Other(#[source] Box<dyn StdError + Send + Sync>),
}

/// HTTP error response details.
///
/// Contains the full HTTP response and cached body text for errors
/// returned by the server (4xx/5xx status codes).
#[derive(Debug)]
pub struct HttpErrorResponse {
    /// Complete HTTP response (including headers, body, etc.)
    pub response: Response,
    /// Response body as text (if available and UTF-8)
    pub body_text: Option<String>,
}

impl StdError for HttpErrorResponse {}

impl std::fmt::Display for HttpErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP response with status {}", self.response.status())
    }
}

/// A deadline that passed.
///
/// Which one, so a caller can map it onto its own vocabulary: a name server
/// that never answered is not a server that never sent a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TimedOut {
    /// No connection was ready within the connect timeout; `during` is the
    /// phase the connection was in when the deadline passed.
    #[error("no connection within the connect timeout (during {during})")]
    Connect {
        /// The phase of the connection that had not completed.
        during: ConnectPhase,
    },
    /// The response head did not arrive within its deadline.
    #[error("the response head did not arrive within its deadline")]
    ResponseHead,
    /// The response body stalled past its idle deadline.
    #[error("the response body stalled past its idle deadline")]
    BodyIdle,
    /// The request did not finish within the [`Timeout`](crate::Timeout)
    /// middleware's deadline.
    #[error("the request did not finish within its deadline")]
    Request,
}

/// What a connection that is not ready yet was doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectPhase {
    /// Waiting for a free slot in the pool: no dial was running for the
    /// request.
    Queued,
    /// Resolving the host name.
    Resolve,
    /// Opening the TCP connection, racing the addresses.
    Tcp,
    /// Negotiating with a proxy: a `CONNECT` tunnel or a SOCKS5 handshake.
    Proxy,
    /// The TLS handshake.
    Tls,
    /// The QUIC handshake.
    Quic,
}

impl fmt::Display for ConnectPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Queued => "queued",
            Self::Resolve => "resolution",
            Self::Tcp => "TCP",
            Self::Proxy => "proxy negotiation",
            Self::Tls => "TLS",
            Self::Quic => "QUIC",
        })
    }
}

/// The hop a connect failure happened on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hop {
    /// The origin the request is for.
    Origin,
    /// A proxy in front of it.
    Proxy,
}

impl fmt::Display for Hop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Origin => "origin",
            Self::Proxy => "proxy",
        })
    }
}

/// No connection could be made.
#[derive(Debug, Error)]
#[error("connecting to the {hop} {host}:{port}: {failure}")]
#[non_exhaustive]
pub struct ConnectError {
    /// Which hop failed.
    pub hop: Hop,
    /// The host that hop was being reached at.
    pub host: String,
    /// The port that hop was being reached at.
    pub port: u16,
    /// What failed.
    #[source]
    pub failure: ConnectFailure,
}

impl ConnectError {
    /// A failure to connect to `host`:`port`, the `hop` of the route.
    #[must_use]
    pub fn new(hop: Hop, host: impl Into<String>, port: u16, failure: ConnectFailure) -> Self {
        Self {
            hop,
            host: host.into(),
            port,
            failure,
        }
    }
}

/// Why a connection could not be made.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConnectFailure {
    /// The host name gave no address.
    #[error(transparent)]
    Resolve(ResolveError),
    /// Every address was tried and none connected.
    #[error(transparent)]
    Tcp(TcpFailure),
    /// The unix domain socket could not be connected.
    #[cfg(unix_socket)]
    #[error("unix domain socket {path}: {error}", path = .path.display())]
    Unix {
        /// The socket's path.
        path: PathBuf,
        /// What the connect reported.
        #[source]
        error: io::Error,
    },
    /// The TLS handshake failed.
    #[error(transparent)]
    Tls(TlsError),
    /// The HTTP proxy refused or broke the `CONNECT` tunnel.
    #[error(transparent)]
    Tunnel(TunnelError),
    /// The SOCKS5 proxy refused or broke the handshake.
    #[error(transparent)]
    Socks(SocksError),
    /// The QUIC handshake failed.
    #[cfg(any(http3, native_h3))]
    #[error("QUIC: {0}")]
    Quic(#[source] Cause),
}

/// Why a host name gave no address.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ResolveError {
    /// The name does not exist, or has no address of the families asked for.
    #[error("the name has no address")]
    NoAddress,
    /// The resolver failed: every answer was an error other than a missing
    /// name. The first is kept typed, the rest as they came.
    #[error("the resolver failed: {first}")]
    Failed {
        /// The first failure.
        #[source]
        first: io::Error,
        /// The failures after it.
        rest: Vec<io::Error>,
    },
    /// The engine reported the failure as one error, not per address.
    #[error("the lookup failed: {0}")]
    Lookup(#[source] Cause),
}

/// Every address was tried and every attempt failed (RFC 8305).
#[derive(Debug, Error)]
#[error("every connection attempt failed{}", Attempt::summary(.attempts))]
#[non_exhaustive]
pub struct TcpFailure {
    /// The attempts, in the order they started.
    pub attempts: Vec<Attempt>,
}

impl TcpFailure {
    /// A failure of `attempts`.
    #[must_use]
    pub const fn new(attempts: Vec<Attempt>) -> Self {
        Self { attempts }
    }
}

/// One TCP connection attempt that failed.
#[derive(Debug)]
#[non_exhaustive]
pub struct Attempt {
    /// The address tried; `None` when the engine does not report which
    /// (libcurl, `URLSession`).
    pub addr: Option<SocketAddr>,
    /// What the attempt reported.
    pub error: io::Error,
}

impl Attempt {
    /// An attempt at `addr` that failed with `error`.
    #[must_use]
    pub const fn new(addr: Option<SocketAddr>, error: io::Error) -> Self {
        Self { addr, error }
    }

    /// The attempts as `: addr: error; addr: error`, or nothing for none.
    fn summary(attempts: &[Self]) -> String {
        let mut text = String::new();
        for (index, attempt) in attempts.iter().enumerate() {
            text.push_str(if index == 0 { ": " } else { "; " });
            if let Some(addr) = attempt.addr {
                text.push_str(&addr.to_string());
                text.push_str(": ");
            }
            text.push_str(&attempt.error.to_string());
        }
        text
    }
}

/// The TLS handshake failed.
#[derive(Debug, Error)]
#[error("{failure}: {cause}")]
#[non_exhaustive]
pub struct TlsError {
    /// What kind of failure.
    pub failure: TlsFailure,
    /// The engine's own error.
    #[source]
    pub cause: Cause,
}

impl TlsError {
    /// A TLS failure of kind `failure`, reported by the engine as `cause`.
    #[must_use]
    pub const fn new(failure: TlsFailure, cause: Cause) -> Self {
        Self { failure, cause }
    }
}

/// Which way a TLS handshake failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TlsFailure {
    /// The peer's certificate did not verify for the server name, or none
    /// was presented.
    #[error("the server's certificate did not verify")]
    Certificate,
    /// The peer sent a fatal alert: its RFC 8446 §6 description code.
    #[error("the server sent TLS alert {alert}")]
    AlertReceived {
        /// The alert's description code.
        alert: u8,
    },
    /// Any other TLS protocol failure, during the handshake or after.
    #[error("TLS protocol failure")]
    Protocol,
    /// The engine reports no classification (`native-tls`, libcurl's and
    /// `URLSession`'s TLS): `native-tls` reports no typed verification
    /// outcome, so its failures are unclassified and the cause carries the
    /// platform error.
    #[error("TLS failure")]
    Unclassified,
}

/// An HTTP proxy refused or broke a `CONNECT` tunnel.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// The proxy answered `CONNECT` with a non-2xx status.
    #[error("the proxy refused CONNECT with status {0}")]
    Rejected(StatusCode),
    /// The proxy did not follow the tunnel protocol.
    #[error("the proxy broke the tunnel protocol: {0}")]
    Protocol(&'static str),
    /// The connection to the proxy failed while the tunnel was negotiated.
    #[error("the connection to the proxy failed during CONNECT: {0}")]
    Connection(#[source] Cause),
}

/// A SOCKS5 proxy refused or broke the handshake.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SocksError {
    /// The proxy's RFC 1928 §6 reply field, when not `succeeded`.
    #[error("the SOCKS5 proxy replied {0:#04x}")]
    Reply(u8),
    /// The proxy did not follow the protocol, or the request cannot be
    /// expressed in it.
    #[error("the SOCKS5 proxy broke the protocol: {0}")]
    Protocol(&'static str),
    /// The proxy requires credentials it was not given, or refused them.
    #[error("the SOCKS5 proxy refused the credentials")]
    Auth,
    /// The connection to the proxy failed during the handshake.
    #[error("the connection to the SOCKS5 proxy failed: {0}")]
    Io(#[source] io::Error),
}

/// The connection failed, or the peer broke the protocol, during an
/// exchange.
#[derive(Debug, Error)]
#[error("{failure}: {cause}")]
#[non_exhaustive]
pub struct ExchangeError {
    /// What kind of failure.
    pub failure: ExchangeFailure,
    /// The engine's own error.
    #[source]
    pub cause: Cause,
}

impl ExchangeError {
    /// An exchange failure of kind `failure`, reported by the engine as
    /// `cause`.
    #[must_use]
    pub const fn new(failure: ExchangeFailure, cause: Cause) -> Self {
        Self { failure, cause }
    }
}

/// How an exchange failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ExchangeFailure {
    /// The connection closed or reset before any byte of the response.
    #[error("the connection closed before the response")]
    Terminated,
    /// The response (head or body) ended early.
    #[error("the response ended early")]
    Incomplete,
    /// The response head is larger than the client accepts.
    #[error("the response head exceeds {limit} bytes")]
    HeadTooLarge {
        /// The limit.
        limit: usize,
    },
    /// The response head has more fields than the client accepts.
    #[error("the response head has more than {limit} fields")]
    TooManyFields {
        /// The limit.
        limit: usize,
    },
    /// A transfer coding the client cannot decode.
    #[error("unsupported transfer coding")]
    TransferCoding,
    /// The response violates HTTP: a malformed head or body framing, or an
    /// upgrade nobody asked for.
    #[error("the response violates HTTP")]
    Protocol,
    /// The trailer section exceeds the client's limit.
    #[error("the trailers exceed {limit} bytes")]
    TrailersTooLarge {
        /// The limit.
        limit: usize,
    },
    /// The trailer section has more fields than the client accepts.
    #[error("the trailers have more than {limit} fields")]
    TooManyTrailers {
        /// The limit.
        limit: usize,
    },
    /// The request cannot be framed as given: its own `Content-Length` or
    /// `Transfer-Encoding`, or no host.
    #[error("the request cannot be framed")]
    InvalidRequest,
    /// The request body failed while it was being sent.
    #[error("the request body failed")]
    RequestBody,
    /// The request body's length differs from its `Content-Length`.
    #[error("the request body differs from its Content-Length of {declared}")]
    RequestBodyLength {
        /// The announced length.
        declared: u64,
    },
    /// A TLS-layer failure on the established connection.
    #[error("TLS failure on the connection")]
    Tls,
    /// A socket failure none of the above names.
    #[error("the connection failed")]
    Io,
}

/// Where a failure came from, typed per engine.
///
/// A variant exists only with the feature that brings its engine in.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Cause {
    /// A socket or file operation failed.
    #[error(transparent)]
    Io(Arc<io::Error>),
    /// A response body a peer was sending ended early.
    #[error(transparent)]
    Receive(ReceiveError),
    /// The native backend's HTTP/1.1 client.
    #[cfg(native_backend)]
    #[error(transparent)]
    H1(http_kit_h1::Error),
    /// The native backend's TLS handshake.
    #[cfg(native_backend)]
    #[error(transparent)]
    Handshake(http_kit_tls::HandshakeError),
    /// The native backend's HTTP/3 client.
    #[cfg(native_h3)]
    #[error(transparent)]
    H3(http_kit_h3::Error),
    /// rustls.
    #[cfg(tls_rustls)]
    #[error(transparent)]
    Rustls(rustls::Error),
    /// The platform's TLS library through `native-tls`.
    #[cfg(tls_native)]
    #[error(transparent)]
    NativeTls(native_tls::Error),
    /// A PEM document that is not one.
    #[cfg(native)]
    #[error(transparent)]
    Pem(rustls_pki_types::pem::Error),
    /// hyper.
    #[cfg(connector)]
    #[error(transparent)]
    Hyper(hyper::Error),
    /// quinn's connection setup, before any packet.
    #[cfg(http3)]
    #[error(transparent)]
    QuinnConnect(quinn::ConnectError),
    /// quinn's connection, once established or while it was.
    #[cfg(http3)]
    #[error(transparent)]
    Quinn(quinn::ConnectionError),
    /// The `h3` crate's connection errors.
    #[cfg(http3)]
    #[error(transparent)]
    H3Connection(h3::error::ConnectionError),
    /// The `h3` crate's stream errors.
    #[cfg(http3)]
    #[error(transparent)]
    H3Stream(h3::error::StreamError),
    /// libcurl.
    #[cfg(all(reactor, feature = "curl-backend"))]
    #[error(transparent)]
    Curl(curl::Error),
    /// `URLSession`: an `NSError`.
    #[cfg(apple_backend)]
    #[error("{domain} {code}: {description}")]
    UrlSession {
        /// The error's `NSError` domain.
        domain: String,
        /// The error's `NSError` code.
        code: isize,
        /// Its description, with the chain of underlying errors.
        description: String,
    },
    /// The hickory resolver.
    #[cfg(all(https_lookup, not(target_os = "android")))]
    #[error(transparent)]
    Hickory(hickory_resolver::net::NetError),
    /// A DNS message or name hickory could not handle.
    #[cfg(https_lookup)]
    #[error(transparent)]
    DnsProto(hickory_proto::ProtoError),
    /// The browser's `fetch`.
    #[cfg(browser)]
    #[error("{0}")]
    Js(String),
    /// A message, where the engine has no error value of its own.
    #[error("{0}")]
    Detail(String),
}

impl From<io::Error> for Cause {
    fn from(error: io::Error) -> Self {
        Self::Io(Arc::new(error))
    }
}

#[cfg(tls_rustls)]
impl From<rustls::Error> for Cause {
    fn from(error: rustls::Error) -> Self {
        Self::Rustls(error)
    }
}

#[cfg(tls_native)]
impl From<native_tls::Error> for Cause {
    fn from(error: native_tls::Error) -> Self {
        Self::NativeTls(error)
    }
}

#[cfg(tls_rustls)]
impl TlsFailure {
    /// How rustls's error classifies: a certificate that did not verify, a
    /// received alert, or any other protocol failure.
    pub(crate) fn of_rustls(error: &rustls::Error) -> Self {
        match error {
            rustls::Error::InvalidCertificate(_)
            | rustls::Error::NoCertificatesPresented
            | rustls::Error::InvalidCertRevocationList(_) => Self::Certificate,
            // RFC 8446 §6: the alert's description is one byte.
            rustls::Error::AlertReceived(description) => Self::AlertReceived {
                alert: u8::from(*description),
            },
            _ => Self::Protocol,
        }
    }
}

/// The client, its transport or the request is not usable as configured.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The trust store could not be loaded, or a certificate in it is
    /// unusable.
    #[error("trust store: {0}")]
    TrustStore(#[source] Cause),
    /// The TLS engine could not be configured.
    #[error("TLS configuration: {0}")]
    Tls(#[source] Cause),
    /// The kernel TLS probe failed.
    #[cfg(all(feature = "native-kernel-tls", target_os = "linux"))]
    #[error("kernel TLS probe: {0}")]
    KernelTls(#[source] io::Error),
    /// The proxy URI uses a scheme this backend cannot speak.
    #[error("unsupported proxy scheme `{0}`")]
    ProxyScheme(String),
    /// The proxy URI names no host.
    #[error("proxy URI has no host")]
    ProxyHost,
    /// The OneCRL refresh could not be set up.
    #[cfg(onecrl)]
    #[error("OneCRL: {0}")]
    OneCrl(#[source] io::Error),
    /// The backend does not implement what the request or transport asks.
    #[error("{what} is not supported by this backend")]
    Unsupported {
        /// What is not supported.
        what: &'static str,
    },
}

/// Cookie-related errors.
#[derive(Debug, Error)]
pub enum CookieErrorKind {
    /// Failed to load cookies from disk.
    #[error("failed to load cookies from disk: {0}")]
    LoadFailed(#[source] std::io::Error),

    /// Failed to parse cookie data.
    #[error("failed to parse cookies: {0}")]
    ParseFailed(#[source] cookie_store::Error),

    /// Failed to persist cookies to disk.
    #[error("failed to persist cookies: {0}")]
    PersistFailed(#[source] cookie_store::Error),

    /// Invalid cookie header.
    #[error("invalid cookie header")]
    InvalidHeader,
}

/// OAuth2-related errors.
#[derive(Debug, Error)]
pub enum OAuth2ErrorKind {
    /// Failed to fetch `OAuth2` token.
    #[error("failed to fetch token: {0}")]
    TokenFetchFailed(String),

    /// Token endpoint returned an error.
    #[error("token endpoint returned error: {status} - {message}")]
    TokenEndpointError {
        /// HTTP status code from token endpoint
        status: StatusCode,
        /// Error message
        message: String,
    },

    /// Invalid token response format.
    #[error("invalid token response: {0}")]
    InvalidTokenResponse(String),
}

/// Download-related errors.
#[derive(Debug, Error)]
pub enum DownloadErrorKind {
    /// Server returned an error status.
    #[error("upstream returned error: {0}")]
    UpstreamError(StatusCode),

    /// File system error during download.
    #[error("file system error: {0}")]
    FileSystem(#[source] std::io::Error),

    /// Failed to read response body.
    #[error("failed to read response body: {0}")]
    BodyRead(String),
}

/// WebSocket-related errors.
#[derive(Debug, Error)]
pub enum WebSocketErrorKind {
    /// Failed to encode payload.
    #[error("failed to encode payload: {0}")]
    EncodeFailed(#[source] serde_json::Error),

    /// Unsupported URI scheme.
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),

    /// WebSocket connection failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
}

impl Error {
    /// A TLS configuration failure: the engine could not be built from the
    /// transport's settings.
    #[cfg(any(tls_engine, http3, native_h3, all(reactor, feature = "curl-backend")))]
    pub(crate) fn tls_config(cause: impl Into<Cause>) -> Self {
        Self::Config(ConfigError::Tls(cause.into()))
    }

    /// A trust-store failure.
    #[cfg(native)]
    pub(crate) fn trust_store(cause: impl Into<Cause>) -> Self {
        Self::Config(ConfigError::TrustStore(cause.into()))
    }

    /// A failure to connect to `host`:`port`, the `hop` of the route.
    #[cfg(native)]
    pub(crate) fn connect(
        hop: Hop,
        host: impl Into<String>,
        port: u16,
        failure: ConnectFailure,
    ) -> Self {
        Self::Connect(Box::new(ConnectError::new(hop, host, port, failure)))
    }

    /// An exchange failure.
    pub(crate) fn exchange(failure: ExchangeFailure, cause: Cause) -> Self {
        Self::Exchange(Box::new(ExchangeError::new(failure, cause)))
    }

    /// Check if this is a connect or exchange failure: the network, not the
    /// request or the configuration, is what broke.
    #[must_use]
    pub const fn is_network_error(&self) -> bool {
        matches!(self, Self::Connect(_) | Self::Exchange(_))
    }

    /// Check if a deadline passed.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    /// Check if this failure could succeed on another attempt.
    ///
    /// A failed connection, a broken exchange, a timeout or an I/O error may
    /// be transient; anything else — a malformed request, a refused
    /// credential, an HTTP error status, a certificate that does not verify,
    /// a received TLS alert, a refused tunnel — fails the same way every
    /// time.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Connect(error) => !matches!(
                error.failure,
                ConnectFailure::Tls(TlsError {
                    failure: TlsFailure::Certificate | TlsFailure::AlertReceived { .. },
                    ..
                }) | ConnectFailure::Tunnel(TunnelError::Rejected(_))
            ),
            Self::Exchange(error) => matches!(
                error.failure,
                ExchangeFailure::Terminated | ExchangeFailure::Incomplete | ExchangeFailure::Io
            ),
            Self::Timeout(_) | Self::Io(_) => true,
            _ => false,
        }
    }

    /// Check if this is a client error (4xx HTTP status).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(self, Self::Http { status, .. } if status.is_client_error())
    }

    /// Check if this is a server error (5xx HTTP status).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        matches!(self, Self::Http { status, .. } if status.is_server_error())
    }

    /// Check if this is a redirect-related error.
    #[must_use]
    pub const fn is_redirect_error(&self) -> bool {
        matches!(
            self,
            Self::TooManyRedirects { .. } | Self::InvalidRedirectLocation
        )
    }

    /// Check if this is a request construction error.
    #[must_use]
    pub const fn is_request_error(&self) -> bool {
        matches!(self, Self::InvalidRequest(_) | Self::InvalidUri(_))
    }

    /// Get the response body text (if this is an HTTP error).
    #[must_use]
    pub fn response_body(&self) -> Option<&str> {
        match self {
            Self::Http { response, .. } => response.body_text.as_deref(),
            _ => None,
        }
    }

    /// Get the full HTTP response (if this is an HTTP error).
    #[must_use]
    pub const fn response(&self) -> Option<&Response> {
        match self {
            Self::Http { response, .. } => Some(&response.response),
            _ => None,
        }
    }

    /// Attempt to deserialize the HTTP error response body as a specific type.
    ///
    /// This is useful for APIs that return structured error responses.
    ///
    /// # Example
    /// ```no_run
    /// use serde::Deserialize;
    /// use zenwave::Client;
    ///
    /// #[derive(Deserialize)]
    /// struct ApiError {
    ///     code: String,
    ///     message: String,
    /// }
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = zenwave::client().error_for_status();
    /// let result = client.get("https://api.example.com/data")?.await;
    /// match result.map_err(zenwave::Error::from) {
    ///     Err(e) => {
    ///         if let Some(api_err) = e.deserialize_http_error::<ApiError>() {
    ///             println!("API error: {} - {}", api_err.code, api_err.message);
    ///         }
    ///     }
    ///     Ok(_response) => {}
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn deserialize_http_error<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        match self {
            Self::Http { response, .. } => response
                .body_text
                .as_ref()
                .and_then(|text| serde_json::from_str(text).ok()),
            _ => None,
        }
    }

    /// Get the error category/kind.
    ///
    /// Useful for logging and monitoring.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::Http { .. } => ErrorKind::Http,
            Self::Connect(_) => ErrorKind::Connect,
            Self::Exchange(_) => ErrorKind::Exchange,
            Self::Timeout(_) => ErrorKind::Timeout,
            Self::Config(_) => ErrorKind::Config,
            Self::Stopped => ErrorKind::Stopped,
            Self::TooManyRedirects { .. } | Self::InvalidRedirectLocation => ErrorKind::Redirect,
            Self::InvalidUri(_) | Self::InvalidRequest(_) => ErrorKind::Request,
            Self::BodyParse(_) => ErrorKind::BodyParse,
            Self::ResponseBodyTooLarge { .. } => ErrorKind::ResponseBodyLimit,
            Self::Cookie(_) => ErrorKind::Cookie,
            Self::OAuth2(_) => ErrorKind::OAuth2,
            Self::Download(_) => ErrorKind::Download,
            Self::WebSocket(_) => ErrorKind::WebSocket,
            Self::Io(_) => ErrorKind::Io,
            Self::Other(_) => ErrorKind::Other,
        }
    }
}

/// Error category labels.
///
/// Used for classifying errors for logging, monitoring, and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// HTTP server error
    Http,
    /// No connection could be made
    Connect,
    /// The exchange on a connection failed
    Exchange,
    /// Timeout error
    Timeout,
    /// Misconfiguration, or a request the backend does not support
    Config,
    /// The backend's connection pool has stopped
    Stopped,
    /// Redirect error
    Redirect,
    /// Request construction error
    Request,
    /// Response body parsing error
    BodyParse,
    /// Response body exceeded a caller-provided size limit
    ResponseBodyLimit,
    /// Cookie management error
    Cookie,
    /// `OAuth2` authentication error
    OAuth2,
    /// Download error
    Download,
    /// WebSocket error
    WebSocket,
    /// I/O error
    Io,
    /// Other/uncategorized error
    Other,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Connect => write!(f, "connect"),
            Self::Exchange => write!(f, "exchange"),
            Self::Timeout => write!(f, "timeout"),
            Self::Config => write!(f, "config"),
            Self::Stopped => write!(f, "stopped"),
            Self::Redirect => write!(f, "redirect"),
            Self::Request => write!(f, "request"),
            Self::BodyParse => write!(f, "body_parse"),
            Self::ResponseBodyLimit => write!(f, "response_body_limit"),
            Self::Cookie => write!(f, "cookie"),
            Self::OAuth2 => write!(f, "oauth2"),
            Self::Download => write!(f, "download"),
            Self::WebSocket => write!(f, "websocket"),
            Self::Io => write!(f, "io"),
            Self::Other => write!(f, "other"),
        }
    }
}

// Implement http_kit::HttpError trait for Error
impl http_kit::HttpError for Error {
    fn status(&self) -> StatusCode {
        match self {
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::Connect(_) | Self::Exchange(_) => StatusCode::BAD_GATEWAY,
            Self::Http { status, .. }
            | Self::OAuth2(OAuth2ErrorKind::TokenEndpointError { status, .. })
            | Self::Download(DownloadErrorKind::UpstreamError(status)) => *status,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// A body that failed under a reader: a stalled one is a deadline that
/// passed, one that ended early is a failed exchange, anything else is a body
/// that could not be parsed.
impl From<BodyError> for Error {
    fn from(error: BodyError) -> Self {
        match error {
            BodyError::Receive(receive) => Self::from(receive),
            error => Self::BodyParse(error),
        }
    }
}

impl From<ReceiveError> for Error {
    fn from(error: ReceiveError) -> Self {
        let failure = match &error {
            ReceiveError::Stalled => return Self::Timeout(TimedOut::BodyIdle),
            ReceiveError::Incomplete => ExchangeFailure::Incomplete,
            ReceiveError::Framing { .. } => ExchangeFailure::Protocol,
            ReceiveError::TrailersTooLarge { limit } => {
                ExchangeFailure::TrailersTooLarge { limit: *limit }
            }
            ReceiveError::TooManyTrailers { limit } => {
                ExchangeFailure::TooManyTrailers { limit: *limit }
            }
            // The connection failed under the body; `ReceiveError` is
            // non-exhaustive, so a variant added later is a failure of the
            // connection until this maps it.
            _ => ExchangeFailure::Io,
        };
        Self::exchange(failure, Cause::Receive(error))
    }
}

// Generic conversion from MiddlewareError to Error
impl<E, M> From<http_kit::middleware::MiddlewareError<E, M>> for Error
where
    E: Into<Self>,
    M: Into<Self>,
{
    fn from(err: http_kit::middleware::MiddlewareError<E, M>) -> Self {
        match err {
            http_kit::middleware::MiddlewareError::Endpoint(e) => e.into(),
            http_kit::middleware::MiddlewareError::Middleware(m) => m.into(),
        }
    }
}
