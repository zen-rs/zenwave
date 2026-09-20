mod rt;

use core::future::Future;
#[cfg(any(feature = "http2", http3))]
use std::time::Duration;
#[cfg(http3)]
use std::time::Instant;
use std::{
    mem::replace,
    pin::Pin,
    task::{Context, Poll},
};

use executor_core::{AnyExecutor, Executor};
use futures_util::{Stream, TryStreamExt};
#[cfg(http3)]
use futures_util::{
    future::{Either, select},
    pin_mut,
};
use http::{StatusCode, uri::Scheme};
use http_body_util::BodyDataStream;
use http_kit::{Endpoint, HttpError, Method, Request, Response};
use hyper::{body::Incoming, client::conn::TrySendError, http};
use rt::Spawner;
use tracing::{debug, warn};

#[cfg(http3)]
use crate::transport::{
    Spawn,
    connect::proxied,
    happy_eyeballs,
    pool::{H3, HttpsRr},
    quic,
};
use crate::{
    Client, Transport,
    error::HttpErrorResponse,
    transport::{
        connect::{Protocol, Protocols, Target, Via, connect},
        hyper_io::HyperIo,
        pool::{Checkout, DialPermit, H1Lease, Origin, Pool, Reuse},
    },
};

/// h2 keepalive: a PING every 30 s, the connection dropped 10 s after a
/// ping goes unanswered.
#[cfg(feature = "http2")]
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(feature = "http2")]
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(http3)]
pub mod alt_svc;
#[cfg(http3)]
pub mod h3;
#[cfg(all(test, any(feature = "http2", http3)))]
pub mod test_support;

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

    /// Dial a fresh connection for `origin` under `permit` — a QUIC/TCP race
    /// when the origin advertised h3, plain TCP otherwise — then pool the
    /// winner and send `request`. A failure on a fresh connection surfaces
    /// to the caller — only reuse failures retry, and the caller owns that
    /// decision.
    async fn dial_and_send(
        &self,
        origin: &Origin,
        permit: DialPermit,
        request: http::Request<http_kit::Body>,
        #[cfg(http3)] h3_port: Option<u16>,
    ) -> Result<(http::Response<http_kit::Body>, Option<H1Lease>), crate::Error> {
        #[cfg(http3)]
        if let Some(h3_port) = h3_port {
            return self
                .race_dial_and_send(origin, permit, h3_port, request)
                .await;
        }
        let dialed = self.dial_tcp(origin).await?;
        self.send_on_dialed(permit, dialed, request).await
    }

    /// Connect to `origin` over TCP — through a proxy when the rules say so —
    /// and run the negotiated hyper handshake.
    async fn dial_tcp(&self, origin: &Origin) -> Result<DialedTcp, crate::Error> {
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
                Ok(DialedTcp::H1 {
                    sender,
                    via: connection.via,
                })
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
                Ok(DialedTcp::H2 { sender })
            }
        }
    }

    /// Pool `dialed` under `permit` and send `request` on it.
    async fn send_on_dialed(
        &self,
        permit: DialPermit,
        dialed: DialedTcp,
        mut request: http::Request<http_kit::Body>,
    ) -> Result<(http::Response<http_kit::Body>, Option<H1Lease>), crate::Error> {
        match dialed {
            DialedTcp::H1 { sender, via } => {
                shape_h1_request(&mut request, &via)?;
                let (response, lease) = Pool::insert_h1(permit, sender, via)
                    .await
                    .send(request)
                    .await
                    .map_err(|error| HyperError::Connection(error.into_error()))?;
                Ok((into_body(response), Some(lease)))
            }
            #[cfg(feature = "http2")]
            DialedTcp::H2 { mut sender } => {
                Pool::insert_h2(permit, sender.clone());
                let response = sender
                    .try_send_request(request)
                    .await
                    .map_err(|error| HyperError::Connection(error.into_error()))?;
                Ok((into_body(response), None))
            }
        }
    }

    /// Race a QUIC handshake against the TCP dial for `origin`; the first
    /// success serves the request. A TCP loser is dropped; a QUIC loser is
    /// detached and finishes inside the connect timeout — a win lands in the
    /// pool, a loss puts the origin into QUIC backoff.
    #[cfg(http3)]
    async fn race_dial_and_send(
        &self,
        origin: &Origin,
        permit: DialPermit,
        h3_port: u16,
        request: http::Request<http_kit::Body>,
    ) -> Result<(http::Response<http_kit::Body>, Option<H1Lease>), crate::Error> {
        let entry = permit.entry();
        // The QUIC side owns everything it needs: if TCP wins, the loser
        // keeps running detached until its deadline.
        let quic = Box::pin({
            let transport = self.transport.clone();
            let spawn = self.spawner.as_spawn();
            let host = origin.host.clone();
            let timeout = entry.h3_connect_timeout();
            async move { quic_dial(&transport, spawn, &host, h3_port, timeout).await }
        });
        let tcp = self.dial_tcp(origin);
        pin_mut!(tcp);
        match select(quic, tcp).await {
            Either::Left((result, tcp)) => match result {
                Ok(mut connection) => {
                    // The in-flight TCP dial closes when the loser future
                    // drops with this scope.
                    Pool::insert_h3(permit, connection.clone());
                    let response = connection
                        .request(request)
                        .await
                        .map_err(h3::SendError::into_error)?;
                    Ok((response, None))
                }
                Err(error) => {
                    debug!(%error, "QUIC dial lost; finishing over TCP");
                    entry.mark_h3_broken(Instant::now());
                    self.send_on_dialed(permit, tcp.await?, request).await
                }
            },
            Either::Right((dialed, quic)) => match dialed {
                Ok(dialed) => {
                    // The QUIC loser keeps running detached: a dead UDP path
                    // only becomes visible when its deadline passes.
                    self.spawner.spawn(async move {
                        match quic.await {
                            Ok(connection) => entry.insert_h3(connection),
                            Err(error) => {
                                debug!(%error, "detached QUIC dial failed");
                                entry.mark_h3_broken(Instant::now());
                            }
                        }
                    });
                    self.send_on_dialed(permit, dialed, request).await
                }
                Err(error) => match quic.await {
                    Ok(mut connection) => {
                        Pool::insert_h3(permit, connection.clone());
                        let response = connection
                            .request(request)
                            .await
                            .map_err(h3::SendError::into_error)?;
                        Ok((response, None))
                    }
                    Err(quic_error) => {
                        debug!(error = %quic_error, "QUIC dial failed with TCP");
                        entry.mark_h3_broken(Instant::now());
                        Err(error)
                    }
                },
            },
        }
    }

    /// Issue `origin`'s HTTPS record lookup when the pool marks discovery
    /// due. It runs concurrently with the dial that triggered it and lands
    /// in the entry for a later checkout; a failed lookup caches a negative
    /// answer rather than failing the request.
    #[cfg(http3)]
    fn start_h3_discovery(&self, origin: &Origin, permit: &DialPermit) {
        let entry = permit.entry();
        if !entry.begin_h3_discovery(Instant::now()) {
            return;
        }
        let transport = self.transport.clone();
        let spawn = self.spawner.as_spawn();
        let host = origin.host.clone();
        let port = origin.port;
        self.spawner.spawn(async move {
            let now = Instant::now();
            let rr = match transport.https_record(spawn, &host, port).await {
                Ok(Some(record)) => HttpsRr {
                    h3: record.alpn.iter().any(|alpn| alpn == "h3"),
                    port: record.port,
                    expires: now + record.ttl,
                },
                Ok(None) => HttpsRr::negative(now),
                Err(error) => {
                    debug!(%host, port, %error, "HTTPS record lookup failed");
                    HttpsRr::negative(now)
                }
            };
            entry.insert_https_rr(rr);
            entry.finish_h3_discovery();
        });
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
    pub(crate) fn http3(error: impl Into<Box<dyn core::error::Error + Send + Sync>>) -> Self {
        Self::Http3(error.into())
    }
}

/// A freshly connected TCP connection after its hyper handshake.
enum DialedTcp {
    /// HTTP/1.1 — exclusive; pooled by leasing.
    H1 {
        sender: hyper::client::conn::http1::SendRequest<http_kit::Body>,
        via: Via,
    },
    /// HTTP/2 — shared; pooled by cloning.
    #[cfg(feature = "http2")]
    H2 {
        sender: hyper::client::conn::http2::SendRequest<http_kit::Body>,
    },
}

/// A QUIC handshake to `host`:`h3_port` on the transport's shared endpoint.
/// The resolved addresses are tried in the order `happy_eyeballs` would dial
/// TCP — getaddrinfo's RFC 6724 ordering — with `timeout` covering all of
/// them together.
#[cfg(http3)]
async fn quic_dial(
    transport: &Transport,
    spawn: Spawn,
    host: &str,
    h3_port: u16,
    timeout: Duration,
) -> Result<h3::H3Connection, crate::Error> {
    let addrs = happy_eyeballs::resolve(host, h3_port)
        .await
        .map_err(|error| crate::Error::Transport(Box::new(error)))?;
    let endpoint = transport.quic_endpoint(spawn.clone())?;
    let config = quic::client_config(transport.tls().client_config())?;
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempt = h3::H3Connection::connect(endpoint, config.clone(), addr, host, &spawn);
        let timer = async_io::Timer::after(remaining);
        pin_mut!(attempt);
        pin_mut!(timer);
        match select(attempt, timer).await {
            Either::Left((result, _)) => match result {
                Ok(connection) => return Ok(connection),
                Err(error) => last_error = Some(error),
            },
            Either::Right(_) => break,
        }
    }
    Err(last_error.unwrap_or_else(|| {
        crate::Error::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("QUIC connect to {host}:{h3_port} timed out"),
        )))
    }))
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

/// The request's authority as a pool origin.
fn request_origin(uri: &http::Uri) -> Result<Origin, HyperError> {
    let host = uri
        .host()
        .ok_or_else(|| HyperError::InvalidUri(uri.to_string()))?;
    let scheme = match uri.scheme_str().unwrap_or("http") {
        "https" => Scheme::HTTPS,
        "http" => Scheme::HTTP,
        other => return Err(HyperError::InvalidUri(other.to_string())),
    };
    Ok(Origin {
        host: host.to_owned(),
        port: uri
            .port_u16()
            .unwrap_or(if scheme == Scheme::HTTPS { 443 } else { 80 }),
        scheme,
    })
}

impl HyperBackend {
    /// h3 only ever serves a direct TLS origin: QUIC bypasses proxies, so a
    /// proxied or plaintext request never sees the pool's h3 paths.
    #[cfg(http3)]
    fn h3_gate(&self, origin: &Origin) -> Result<H3, crate::Error> {
        let proxied = proxied(
            &self.transport,
            Target {
                host: &origin.host,
                port: origin.port,
                tls: true,
                tunnel_plaintext: false,
                protocols: Protocols::Http2OrHttp1,
            },
        )?;
        Ok(if origin.scheme == Scheme::HTTPS && !proxied {
            H3::Allowed
        } else {
            H3::Blocked
        })
    }

    /// Feed the response's `Alt-Svc` headers into the origin's entry — an
    /// advertisement only counts where QUIC could ever be dialed, and a
    /// malformed value is logged and ignored, never a request failure.
    #[cfg(http3)]
    fn record_alt_svc(&self, origin: &Origin, h3: H3, response: &http_kit::Response) {
        if !matches!(h3, H3::Allowed) {
            return;
        }
        let entry = self.transport.pool().entry(origin);
        let now = Instant::now();
        for value in response.headers().get_all(http::header::ALT_SVC) {
            if let Ok(value) = value.to_str() {
                entry.insert_alt_svc(&origin.host, value, now);
            } else {
                debug!(?value, "ignoring non-ASCII Alt-Svc header");
            }
        }
    }

    /// Wrap the h1 lease around its body's tail, harvest `Alt-Svc`, and turn
    /// an error status into [`HyperError::Remote`].
    async fn finish_response(
        &self,
        #[cfg(http3)] origin: &Origin,
        #[cfg(http3)] h3: H3,
        response: http::Response<http_kit::Body>,
        lease: Option<H1Lease>,
    ) -> Result<Response, crate::Error> {
        #[cfg(http3)]
        self.record_alt_svc(origin, h3, &response);

        let mut response = response.map(|body| match lease {
            // The h1 connection is reusable once the body is finished or
            // dropped, so the lease rides along with it.
            Some(lease) => http_kit::Body::from_stream(LeaseReturn::new(body, lease)),
            None => body,
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

        let origin = request_origin(&uri)?;

        #[cfg(http3)]
        let h3 = self.h3_gate(&origin)?;

        let mut retried = false;
        let (response, lease) = loop {
            // The retry after a pooled connection refused the request dials
            // fresh rather than reusing another connection from the pool.
            let checkout = self
                .transport
                .pool()
                .checkout(
                    origin.clone(),
                    if retried {
                        Reuse::FreshDial
                    } else {
                        Reuse::Pooled
                    },
                    #[cfg(http3)]
                    h3,
                )
                .await;
            #[cfg(http3)]
            let h3_port = checkout.h3_port();
            match checkout {
                #[cfg(http3)]
                // The URI stays absolute: h3 requests carry `:scheme` and
                // `:authority`.
                Checkout::H3(mut connection) => {
                    match send_or_retry(connection.request(request).await, retried)? {
                        Sent::Done(response) => break (response, None),
                        Sent::Retry(unsent) => {
                            retried = true;
                            request = *unsent;
                            *request.uri_mut() = uri.clone();
                        }
                    }
                }
                #[cfg(feature = "http2")]
                // The URI stays absolute: hyper derives `:scheme` and
                // `:authority` from it.
                Checkout::H2(mut sender) => {
                    match send_or_retry(sender.try_send_request(request).await, retried)? {
                        Sent::Done(response) => break (into_body(response), None),
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
                        Sent::Done((response, lease)) => break (into_body(response), Some(lease)),
                        Sent::Retry(unsent) => {
                            retried = true;
                            request = *unsent;
                            *request.uri_mut() = uri.clone();
                        }
                    }
                }
                Checkout::Dial { permit, .. } => {
                    // A first dial to a direct TLS origin kicks off its HTTPS
                    // record lookup; the answer lands in the pool for later
                    // checkouts.
                    #[cfg(http3)]
                    if matches!(h3, H3::Allowed) {
                        self.start_h3_discovery(&origin, &permit);
                    }
                    break self
                        .dial_and_send(
                            &origin,
                            permit,
                            request,
                            #[cfg(http3)]
                            h3_port,
                        )
                        .await?;
                }
            }
        };

        self.finish_response(
            #[cfg(http3)]
            &origin,
            #[cfg(http3)]
            h3,
            response,
            lease,
        )
        .await
    }
}

/// A response body repacked as `http_kit::Body`.
fn into_body(response: http::Response<Incoming>) -> http::Response<http_kit::Body> {
    response.map(|body| {
        http_kit::Body::from_stream(
            BodyDataStream::new(body).map_err(|error| http_kit::BodyError::Other(Box::new(error))),
        )
    })
}

/// The outcome of a send on a pooled connection.
enum Sent<T> {
    /// The send completed. For h1 the payload pairs the response with the
    /// returned lease; for h2 and h3 it is just the response.
    Done(T),
    /// The pooled connection died before the request was written and this
    /// was the first reuse failure — retry once on a fresh dial.
    Retry(Box<http::Request<http_kit::Body>>),
}

/// A send failure that can hand the request back when the connection died
/// before writing it — hyper's `TrySendError` and h3's `SendError` share
/// the shape.
trait Unsent {
    /// The request, when nothing of it reached the connection.
    fn take_request(&mut self) -> Option<http::Request<http_kit::Body>>;
    /// The error itself, as a crate error.
    fn into_error(self) -> crate::Error;
}

impl Unsent for TrySendError<http::Request<http_kit::Body>> {
    fn take_request(&mut self) -> Option<http::Request<http_kit::Body>> {
        self.take_message()
    }

    fn into_error(self) -> crate::Error {
        HyperError::Connection(self.into_error()).into()
    }
}

#[cfg(http3)]
impl Unsent for h3::SendError {
    fn take_request(&mut self) -> Option<http::Request<http_kit::Body>> {
        self.take_request()
    }

    fn into_error(self) -> crate::Error {
        self.into_error()
    }
}

/// Classify a pooled-connection send: the success payload, the request back
/// when the connection never wrote it (`take_request` only yields it for
/// unstarted requests), or a hard error.
fn send_or_retry<T, E: Unsent>(
    result: Result<T, E>,
    retried: bool,
) -> Result<Sent<T>, crate::Error> {
    match result {
        Ok(done) => Ok(Sent::Done(done)),
        Err(mut error) => match error.take_request() {
            Some(unsent) if !retried => Ok(Sent::Retry(Box::new(unsent))),
            _ => Err(error.into_error()),
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
            let second = client
                .get(format!("http://{address}/"))
                .expect("test request must build")
                .into_future();
            futures_util::pin_mut!(second);
            let timeout = async_io::Timer::after(STREAMING_TEST_TIMEOUT);
            futures_util::pin_mut!(timeout);
            match futures_util::future::select(second, timeout).await {
                Either::Left((response, _)) => {
                    response.expect("request after a dropped body must succeed");
                }
                Either::Right(_) => {
                    panic!("request after a dropped body did not complete")
                }
            }
        });
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            2,
            "an abandoned-body connection must be dialed past"
        );
    }

    #[cfg(feature = "http2")]
    mod http2 {
        use async_io::block_on;
        use http::Version;

        use super::super::{
            HyperBackend,
            test_support::{TestCa, TlsServer},
        };
        use crate::{Client as _, ResponseExt as _};

        #[test]
        fn https_requests_negotiate_http2_through_alpn() {
            let ca = TestCa::new();
            let server = TlsServer::start(&ca, &[b"h2", b"http/1.1"]);
            let mut client = HyperBackend::new(ca.transport());

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
                Some(format!("localhost:{}", server.addr().port()).as_str()),
                "the server must see :authority, derived from the absolute URI"
            );
            assert_eq!(first.host, None, "h2 requests carry no Host header");
            assert_eq!(first.body, b"streaming body");

            let second = server.next_request();
            assert_eq!(second.version, Version::HTTP_2);
        }

        #[test]
        fn http1_only_servers_still_work() {
            let ca = TestCa::new();
            let server = TlsServer::start(&ca, &[b"http/1.1"]);
            let mut client = HyperBackend::new(ca.transport());

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
            let ca = TestCa::new();
            let server = TlsServer::start(&ca, &[b"h2"]);
            let transport = ca.transport();
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

    /// The QUIC/TCP race tests of issue #69: Alt-Svc and HTTPS-RR discovery,
    /// QUIC failure backoff, and eviction of a dead h3 handle.
    #[cfg(http3)]
    mod h3_discovery {
        use std::{
            net::UdpSocket,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            thread,
            time::{Duration, Instant},
        };

        use hickory_proto::op::ResponseCode;
        use http::uri::Scheme;

        use super::super::{
            HyperBackend,
            test_support::{H3Server, TestCa, TlsServer, block_on_test, wait_until},
        };
        use crate::{
            Client as _, Proxy, Transport,
            transport::{
                dns::{
                    self,
                    test_support::{answer, resolver_config, serve},
                },
                pool::{HttpsRr, Origin},
            },
        };

        /// The TCP leg's TLS handshake stalls this long, so the QUIC racer
        /// to a live h3 server wins deterministically on loopback.
        const TCP_STALL: Duration = Duration::from_millis(500);

        fn https_origin(host: &str, port: u16) -> Origin {
            Origin {
                scheme: Scheme::HTTPS,
                host: host.to_owned(),
                port,
            }
        }

        /// The `x-zenwave-protocol` the fixture answered with — `Some("h3")`
        /// from the QUIC server, absent over TCP.
        fn protocol(response: &http_kit::Response) -> Option<String> {
            response
                .headers()
                .get("x-zenwave-protocol")
                .map(|value| value.to_str().expect("marker header is ASCII").to_owned())
        }

        /// a. An `Alt-Svc` advertisement upgrades the origin: the first
        /// request rides TCP and caches the advertisement, the second races
        /// QUIC — which wins while the TCP handshake is stalled — and the
        /// third reuses the pooled h3 handle.
        #[test]
        fn alt_svc_upgrades_the_origin_to_h3() {
            let ca = TestCa::new();
            let h3 = H3Server::start(&ca);
            let tcp = TlsServer::serve(
                &ca,
                &[b"h2", b"http/1.1"],
                Some(format!(r#"h3=":{}"; ma=60"#, h3.addr().port())),
                TCP_STALL,
            );
            let mut client = HyperBackend::new(ca.transport());

            block_on_test(async {
                let first = client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("first request must succeed over TCP");
                assert_eq!(protocol(&first), None, "the first request rides TCP");

                let second = client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("the h3 racer must serve the second request");
                assert_eq!(
                    protocol(&second),
                    Some("h3".to_owned()),
                    "the advertised h3 must win the race"
                );
                wait_until(|| h3.served() == 1).await;
                assert_eq!(h3.connection_count(), 1);

                let third = client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("the pooled h3 handle must serve the third request");
                assert_eq!(protocol(&third), Some("h3".to_owned()));
                wait_until(|| h3.served() == 2).await;
                assert_eq!(
                    h3.connection_count(),
                    1,
                    "the pooled h3 handle multiplexes instead of redialing"
                );
            });
        }

        /// b. HTTPS-record discovery upgrades the origin. A `localhost`
        /// name cannot carry a wire HTTPS answer — RFC 6761 resolvers
        /// (hickory included) answer `*.localhost` in-process — so the first
        /// dial's lookup lands a negative answer, which is itself the
        /// observable that discovery ran. A positive answer is then planted
        /// exactly as the lookup lands it, and the next request must ride
        /// h3. The wire side — the `_port._https.` query name and answer
        /// parsing — is covered by the dns module's own tests.
        #[test]
        fn https_record_upgrades_the_origin_to_h3() {
            let ca = TestCa::new();
            let h3 = H3Server::start(&ca);
            let tcp = TlsServer::serve(&ca, &[b"h2", b"http/1.1"], None, TCP_STALL);
            let tcp_port = tcp.addr().port();

            // The resolver only has to be reachable for the lookup to land;
            // `localhost`'s answer is generated before the wire anyway.
            let (dns_server, _queried) =
                serve(|query| answer(query, ResponseCode::NoError, vec![]));
            let (config, options) = resolver_config(dns_server);
            let transport = Transport::builder()
                .proxy(Proxy::none())
                .extra_root_certificate_der(ca.ca_der.to_vec())
                .dns_config(dns::Config::new(config, options))
                .build()
                .expect("transport builds");
            let mut client = HyperBackend::new(transport.clone());
            let entry = transport.pool().entry(&https_origin("localhost", tcp_port));

            block_on_test(async {
                client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("first request must succeed over TCP");
                // The lookup runs detached; its answer lands on the entry.
                wait_until(|| entry.https_rr().is_some()).await;

                // A positive answer — as `insert_https_rr` receives it from
                // the lookup — makes the origin an h3 candidate.
                entry.insert_https_rr(HttpsRr {
                    h3: true,
                    port: Some(h3.addr().port()),
                    expires: Instant::now() + Duration::from_secs(60),
                });

                let second = client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("the discovered h3 must serve the second request");
                assert_eq!(protocol(&second), Some("h3".to_owned()));
                wait_until(|| h3.served() == 1).await;

                let third = client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("the pooled h3 handle must serve the third request");
                assert_eq!(protocol(&third), Some("h3".to_owned()));
                assert_eq!(
                    h3.connection_count(),
                    1,
                    "the pooled h3 handle multiplexes instead of redialing"
                );
            });
        }

        /// c. QUIC to a dead UDP port loses to TCP; the detached loser's
        /// failure puts the origin into backoff and the next request sends
        /// no datagram at all. The origin is an IPv4 literal so the racer's
        /// datagrams always land on the counting socket.
        #[test]
        fn a_dead_udp_port_falls_back_and_backs_off() {
            let ca = TestCa::new();
            let udp = UdpSocket::bind(("127.0.0.1", 0)).expect("counting socket binds");
            let udp_port = udp.local_addr().expect("counting address").port();
            let datagrams = Arc::new(AtomicUsize::new(0));
            thread::spawn({
                let datagrams = datagrams.clone();
                move || {
                    let mut buffer = [0_u8; 2048];
                    while udp.recv(&mut buffer).is_ok() {
                        datagrams.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });

            let tcp = TlsServer::serve(
                &ca,
                &[b"h2", b"http/1.1"],
                Some(format!(r#"h3=":{udp_port}"; ma=60"#)),
                Duration::ZERO,
            );
            let transport = ca.transport();
            let origin = https_origin("127.0.0.1", tcp.addr().port());
            let entry = transport.pool().entry(&origin);
            entry.set_h3_timeouts(Duration::from_millis(300), Duration::from_secs(60));
            let mut client = HyperBackend::new(transport);
            let uri = format!("https://127.0.0.1:{}/", tcp.addr().port());

            block_on_test(async {
                client
                    .get(uri.clone())
                    .expect("test request must build")
                    .await
                    .expect("first request must succeed over TCP");
                // The advertisement is cached now; this request races QUIC
                // against TCP. TCP wins at once and the QUIC loser runs
                // detached to its injected deadline.
                client
                    .get(uri.clone())
                    .expect("test request must build")
                    .await
                    .expect("the race must fall back to TCP");
                wait_until(|| entry.h3_broken_until().is_some()).await;
                let sent = datagrams.load(Ordering::SeqCst);
                assert!(sent > 0, "the QUIC racer must have sent Initial datagrams");

                client
                    .get(uri)
                    .expect("test request must build")
                    .await
                    .expect("the backoff request must succeed over TCP");
                // Give a stray dial a moment to show up, then check nothing
                // left the endpoint.
                async_io::Timer::after(Duration::from_millis(100)).await;
                assert_eq!(
                    datagrams.load(Ordering::SeqCst),
                    sent,
                    "QUIC backoff must keep the origin on TCP"
                );
            });
        }

        /// e. When the h3 server's QUIC endpoint closes, the pooled handle's
        /// driver ends, `is_closed` evicts it at the next checkout, and the
        /// request is served over TCP.
        #[test]
        fn a_dead_h3_connection_is_evicted_and_tcp_serves() {
            let ca = TestCa::new();
            let h3 = H3Server::start(&ca);
            let tcp = TlsServer::serve(
                &ca,
                &[b"h2", b"http/1.1"],
                Some(format!(r#"h3=":{}"; ma=60"#, h3.addr().port())),
                TCP_STALL,
            );
            let transport = ca.transport();
            let entry = transport
                .pool()
                .entry(&https_origin("localhost", tcp.addr().port()));
            let mut client = HyperBackend::new(transport);

            block_on_test(async {
                client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("first request must succeed over TCP");
                let second = client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("the upgrade must reach h3");
                assert_eq!(protocol(&second), Some("h3".to_owned()));

                h3.close();
                wait_until(|| {
                    entry
                        .h3_connection()
                        .is_some_and(|connection| connection.is_closed())
                })
                .await;

                let third = client
                    .get(tcp.uri("/hello"))
                    .expect("test request must build")
                    .await
                    .expect("the fallback must succeed");
                assert_eq!(
                    protocol(&third),
                    None,
                    "a dead h3 connection must fall back to TCP"
                );
                assert!(
                    entry.h3_connection().is_none(),
                    "the dead handle must be evicted at checkout"
                );
            });
        }
    }
}
