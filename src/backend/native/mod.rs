//! The runtime-neutral backend: HTTP/1.1 through `http-kit-h1` and, with
//! `native-http3`, HTTP/3 through `http-kit-h3`, over `http-kit-io`'s
//! owned-buffer sockets, with TLS through `http-kit-tls`.
//!
//! Connections live in a per-thread pool ([`pool`]) on whichever runtime
//! drives it: the caller's own thread, for a thread-per-core server, or a
//! driver thread the backend starts on compio or tokio for callers on no
//! runtime. The backend itself is only a handle to that pool, so it is
//! `Send` and `Sync` and its request futures are `Send`, like every other
//! backend's.
//!
//! Every transport feature runs on the same code as the hyper backend's:
//! the proxy route (an HTTPS proxy's tunnel carrying the origin's TLS
//! inside its own), unix domain sockets, happy eyeballs, SOCKS5, the TLS
//! verifier (platform verification, extra roots and OneCRL, for HTTP/3 as
//! for TCP), and the HTTP/3 discovery policy with its QUIC/TCP race.

// The pool's futures run on the pool's thread: `http-kit-io` sockets are
// deliberately not `Send`, and nothing below crosses a thread but the
// `Send` handles a request holds.
#[expect(clippy::future_not_send)]
mod connect;
#[cfg(native_h3)]
#[expect(clippy::future_not_send)]
mod h3;
#[expect(clippy::future_not_send)]
mod pool;
#[cfg(native_driver)]
mod runtime;
// A switched stream and the futures that claim it stay on the connection's
// thread, so they are deliberately not `Send`.
#[expect(clippy::future_not_send)]
mod upgrade;

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use executor_core::{LocalExecutor, Task as _};
use futures_util::Stream;
#[cfg(native_h3)]
use http::uri::Scheme;
use http_kit::{
    Body, BodyError, BodyFrame, Deadlines, Endpoint, FrameSource, Method, PipeOffer, ReceiveError,
    Request, Response,
};

use connect::H1Send;
pub use connect::{NativeIo, NativeResolve, QuicBind, UnixDial};
use pool::{Command, Grant, Want};
pub use pool::{PoolClock, PoolHandle, PoolSleep};
#[cfg(feature = "native-compio")]
pub use runtime::Compio;
#[cfg(native_driver)]
pub use runtime::Driver;
#[cfg(feature = "native-tokio")]
pub use runtime::Tokio;
pub use upgrade::{Switched, Upgrade};

use super::shared::{received, replayable_request, request_origin, shape_h1_request, take_request};
use crate::{
    Client, Error, Transport,
    clock::Clocked,
    transport::route::{Origin, Via},
};

/// HTTP client backend on `http-kit-io`, runtime-neutral.
///
/// Requests go to a connection pool that lives on one thread:
///
/// - [`NativeBackend::on_current_thread`] starts the pool on the calling
///   thread's runtime. A thread-per-core application builds one backend per
///   thread this way, and each thread keeps its own connections.
/// - [`NativeBackend::new`] (and `Default`) uses a pool on a driver thread
///   of its own, one per [`Transport`] and runtime, for callers that are
///   not on a runtime at all.
///
/// Clones share their pool.
#[derive(Clone)]
pub struct NativeBackend {
    transport: Transport,
    pool: PoolHandle,
}

impl fmt::Debug for NativeBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBackend")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl NativeBackend {
    /// A backend whose pool runs on the current thread: `io` is the
    /// thread's `http-kit-io` implementation, `resolver` resolves the names
    /// it dials ([`Getaddrinfo`](crate::dns::Getaddrinfo) on a host with a
    /// system resolver) and `executor` is the thread's local executor, which
    /// runs the pool until every clone of the backend is dropped.
    ///
    /// Must be called on a thread where `io`'s runtime is running.
    pub fn on_current_thread<I, R, E>(
        transport: Transport,
        io: I,
        resolver: R,
        executor: &E,
    ) -> Self
    where
        I: NativeIo,
        R: NativeResolve,
        E: LocalExecutor,
    {
        let (pool, receiver) = PoolHandle::channel();
        executor
            .spawn_local(pool::run(io, resolver, transport.downgrade(), receiver))
            .detach();
        Self { transport, pool }
    }

    /// A backend over `transport` whose pool runs on a driver thread with
    /// runtime `D`, started by the first such backend over this transport
    /// and shared by every later one.
    ///
    /// # Panics
    ///
    /// Panics when the driver thread or its runtime cannot be started.
    #[cfg(native_driver)]
    #[must_use]
    pub fn with_driver<D: Driver>(transport: Transport) -> Self {
        let pool = D::pool(&transport).clone();
        Self { transport, pool }
    }

    /// A backend over `transport` on the default driver runtime: compio
    /// when `native-compio` is enabled, tokio otherwise.
    ///
    /// # Panics
    ///
    /// Panics when the driver thread or its runtime cannot be started.
    #[cfg(native_driver)]
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self::with_driver::<runtime::DefaultDriver>(transport)
    }

    /// Whether a request to `origin` may go over HTTP/3: only to a direct
    /// TLS origin, since QUIC bypasses proxies and unix sockets.
    #[cfg(native_h3)]
    fn h3_use(&self, origin: &Origin) -> Result<pool::H3Use, Error> {
        use crate::transport::route::{Protocols, proxied};
        #[cfg(unix_socket)]
        if self.transport.unix_socket().is_some() {
            return Ok(pool::H3Use::Blocked);
        }
        let direct = !proxied(
            self.transport.proxy(),
            crate::transport::route::Target {
                host: &origin.host,
                port: origin.port,
                tls: true,
                tunnel_plaintext: false,
                protocols: Protocols::Http1,
            },
        )?;
        Ok(if origin.scheme == Scheme::HTTPS && direct {
            pool::H3Use::Allowed
        } else {
            pool::H3Use::Blocked
        })
    }

    /// Sends `request` on a leased HTTP/1.1 connection, handing it back for
    /// a fresh dial when a connection reused from the pool fails under it:
    /// whatever the request, when none of it was written (the connection
    /// had stopped taking requests); an idempotent one with a replayable
    /// body also when it was written, since the server may have closed the
    /// idle connection as the request went out.
    ///
    /// A fresh connection's failure is the request's: dialing again for a
    /// server that drops new connections would never end.
    ///
    /// A response that switched the connection (a `101`, or a `2xx` to
    /// `CONNECT`) carries the connection's [`Upgrade`], and the connection
    /// leaves the pool: it no longer speaks HTTP.
    async fn send_h1(
        &self,
        origin: &Origin,
        mut request: http::Request<Body>,
        send: H1Send,
        via: Via,
        reused: bool,
    ) -> Result<Result<Response, http::Request<Body>>, Error> {
        let lease = H1Lease {
            send: Some(send),
            via: via.clone(),
            origin: origin.clone(),
            pool: self.pool.clone(),
        };
        let replay = (reused && idempotent(request.method()))
            .then(|| replayable_request(&request))
            .flatten();
        let connect = request.method() == Method::CONNECT;
        shape_h1_request(&mut request, &via)?;
        if let Some(timeout) = self.transport.read_timeout() {
            // The transport's one read timeout, as the connection's two
            // receive deadlines.
            request.extensions_mut().insert(
                Deadlines::default()
                    .with_response_head(timeout)
                    .with_body_idle(timeout),
            );
        }
        let sender = lease.send.as_ref().expect("a new lease holds its sender");
        let mut failure = match sender.requests.try_send(request).await {
            Ok(mut response) => {
                let status = response.status();
                if status == http::StatusCode::SWITCHING_PROTOCOLS
                    || (connect && status.is_success())
                {
                    response.extensions_mut().insert(sender.upgrade.clone());
                    // Dropped unreleased, the lease is discarded.
                    drop(lease);
                    return Ok(Ok(response));
                }
                return Ok(Ok(
                    response.map(|body| Body::from_source(LeaseReturn::new(body, lease)))
                ));
            }
            Err(failure) => failure,
        };
        if matches!(failure.error(), http_kit_h1::Error::Timeout(_)) {
            // The read timeout closed the connection: no retry, since the
            // server may have the request.
            return Err(Error::Timeout);
        }
        if reused {
            if let Some(unsent) = failure.take_request() {
                tracing::debug!(
                    host = %origin.host,
                    error = %failure,
                    "reused connection took none of the request; dialing fresh"
                );
                return Ok(Err(unsent));
            }
            if let Some(replay) = replay
                && matches!(
                    failure.error(),
                    http_kit_h1::Error::ConnectionClosed | http_kit_h1::Error::Io(_)
                )
            {
                tracing::debug!(
                    host = %origin.host,
                    error = %failure,
                    "reused connection failed under an idempotent request; dialing fresh"
                );
                return Ok(Err(replay));
            }
        }
        Err(Error::Transport(Box::new(failure.into_error())))
    }

    /// Sends `request` on the origin's HTTP/3 connection, whose handshake
    /// has completed.
    #[cfg(native_h3)]
    async fn send_h3(
        &self,
        request: http::Request<Body>,
        send: http_kit_h3::SendRequest,
    ) -> Result<Response, Error> {
        let response = send.send(request).await.map_err(h3::h3_error)?;
        Ok(response.map(|body| keep_pool(body, &self.pool)))
    }
}

/// Whether `method` is idempotent (RFC 9110 §9.2.2): one a client may send
/// again after a connection failed under it.
const fn idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

#[cfg(native_driver)]
impl Default for NativeBackend {
    fn default() -> Self {
        Self::new(Transport::system())
    }
}

impl Endpoint for NativeBackend {
    type Error = Error;

    async fn respond(&mut self, slot: &mut Request) -> Result<Response, Self::Error> {
        let mut request = take_request(slot);
        // The absolute URI, kept so a request handed back can be reshaped for
        // whichever connection serves the retry.
        let uri = request.uri().clone();
        let origin = request_origin(&uri)?;
        let mut fresh = false;
        #[cfg(native_h3)]
        let h3 = self.h3_use(&origin)?;
        loop {
            let want = Want {
                fresh,
                #[cfg(native_h3)]
                h3,
            };
            let sent = match self.pool.checkout(origin.clone(), want).await? {
                Grant::H1 { send, via, reused } => {
                    let sent = self.send_h1(&origin, request, send, via, reused).await?;
                    if sent.is_err() {
                        fresh = true;
                    }
                    sent
                }
                #[cfg(native_h3)]
                Grant::H3(send) => Ok(self.send_h3(request, send).await?),
            };
            match sent {
                Ok(response) => {
                    #[cfg(native_h3)]
                    if h3 != pool::H3Use::Blocked {
                        h3::report_alt_svc(&self.pool, &origin, response.headers());
                    }
                    received(&response);
                    return Ok(response);
                }
                Err(unsent) => {
                    request = unsent;
                    *request.uri_mut() = uri.clone();
                }
            }
        }
    }
}

http_kit::impl_send_endpoint!(NativeBackend);

impl Client for NativeBackend {}

impl Clocked for NativeBackend {
    type Clock = PoolClock;

    fn clock(&self) -> PoolClock {
        PoolClock::new(self.pool.clone())
    }
}

/// An HTTP/1.1 connection leased from the pool: back to the pool when its
/// response body ends, discarded when it is dropped first.
struct H1Lease {
    send: Option<H1Send>,
    via: Via,
    origin: Origin,
    pool: PoolHandle,
}

impl H1Lease {
    fn release(mut self) {
        if let Some(send) = self.send.take() {
            self.pool.send(Command::Release {
                origin: self.origin.clone(),
                send,
                via: self.via.clone(),
            });
        }
    }
}

impl Drop for H1Lease {
    fn drop(&mut self) {
        if self.send.take().is_some() {
            self.pool.send(Command::Discard {
                origin: self.origin.clone(),
            });
        }
    }
}

/// An HTTP/1.1 response body that returns its connection's lease when it
/// ends. Dropped unfinished, the lease is discarded: the connection still
/// holds the rest of the body. A read the read timeout cut short fails as
/// [`timed_out`].
///
/// The consumer's [`PipeOffer`] passes through to the connection's body, so
/// a consumer that can splice receives the body as `BodyFrame::Pipe` frames.
struct LeaseReturn {
    inner: Body,
    lease: Option<H1Lease>,
}

impl LeaseReturn {
    const fn new(inner: Body, lease: H1Lease) -> Self {
        Self {
            inner,
            lease: Some(lease),
        }
    }
}

impl FrameSource for LeaseReturn {
    fn poll_next_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        offer: Option<&mut PipeOffer>,
    ) -> Poll<Option<Result<BodyFrame, BodyError>>> {
        let Self { inner, lease } = self.get_mut();
        match poll_offering(inner, cx, offer) {
            Poll::Ready(None) => {
                if let Some(lease) = lease.take() {
                    lease.release();
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) if is_body_timeout(&error) => {
                Poll::Ready(Some(Err(timed_out())))
            }
            poll => poll,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Polls `body` for its next frame, with the consumer's `offer` when it made
/// one.
fn poll_offering(
    body: &mut Body,
    cx: &mut Context<'_>,
    offer: Option<&mut PipeOffer>,
) -> Poll<Option<Result<BodyFrame, BodyError>>> {
    match offer {
        Some(offer) => Pin::new(body).poll_frame_offering(cx, offer),
        None => Pin::new(body).poll_next(cx),
    }
}

/// Whether `error` is the HTTP/1.1 client's body-idle deadline expiring
/// during the body.
const fn is_body_timeout(error: &BodyError) -> bool {
    matches!(error, BodyError::Receive(ReceiveError::Stalled))
}

/// How a body read the read timeout cut short fails: an I/O timeout, as
/// every reader of bytes recognises one, carrying [`Error::Timeout`].
fn timed_out() -> BodyError {
    BodyError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        Error::Timeout,
    ))
}

/// An HTTP/3 response body that keeps the pool, and with it the
/// connection's driver, running until the body is done.
#[cfg(native_h3)]
fn keep_pool(body: Body, pool: &PoolHandle) -> Body {
    Body::from_source(KeepPool {
        inner: body,
        _pool: pool.clone(),
    })
}

/// The consumer's [`PipeOffer`] passes through to the connection's body.
#[cfg(native_h3)]
struct KeepPool {
    inner: Body,
    _pool: PoolHandle,
}

#[cfg(native_h3)]
impl FrameSource for KeepPool {
    fn poll_next_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        offer: Option<&mut PipeOffer>,
    ) -> Poll<Option<Result<BodyFrame, BodyError>>> {
        poll_offering(&mut self.get_mut().inner, cx, offer)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

#[cfg(all(test, native_driver))]
#[expect(
    clippy::future_not_send,
    reason = "the scenario runs on one runtime thread, as the pool's connections do"
)]
mod tests {
    use http_kit_io::{Listen, Listener as _};

    use super::*;
    use crate::Proxy;

    /// An order in Chinese, Japanese and Korean.
    const ORDER: &str = "订单：一杯茶。注文：お茶を一杯。주문: 차 한 잔.";

    /// A sender whose connection takes no request: its driver is dropped
    /// before it ran, as when a connection stops while it sits idle.
    async fn stopped<I: NativeIo + Listen>(io: &I) -> H1Send {
        let listener = io
            .bind_tcp("127.0.0.1:0".parse().expect("loopback"))
            .expect("bind");
        let addr = listener.local_addr().expect("local address");
        let (stream, accepted) = futures_util::join!(io.connect(addr), listener.accept());
        accepted.expect("accept");
        let (send, connection) = http_kit_h1::handshake_stream(
            stream.expect("connect"),
            io.clone(),
            http_kit_h1::ClientConfig::default(),
        );
        drop(connection);
        H1Send {
            requests: send,
            upgrade: upgrade::channel().0,
        }
    }

    fn post() -> http::Request<Body> {
        let mut request = http::Request::new(Body::from_bytes(ORDER.as_bytes().to_vec()));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = "http://127.0.0.1:9/orders".parse().expect("URI");
        request
    }

    /// A POST that a reused connection took none of comes back for another
    /// connection, body intact; on a fresh connection the same failure is
    /// the request's.
    async fn unsent_requests_come_back<I: NativeIo + Listen>(io: I) {
        // A pool that never runs: the leases' reports go nowhere.
        let (pool, _receiver) = PoolHandle::channel();
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .build()
            .expect("transport builds");
        let backend = NativeBackend { transport, pool };
        let origin = request_origin(&post().uri().clone()).expect("origin");

        let sent = backend
            .send_h1(&origin, post(), stopped(&io).await, Via::Direct, true)
            .await;
        let Ok(Err(returned)) = sent else {
            panic!("the unsent POST must come back, got {sent:?}");
        };
        assert_eq!(returned.method(), Method::POST);
        let body = returned.into_body().into_bytes().await.expect("body reads");
        assert_eq!(body.as_ref(), ORDER.as_bytes());

        let sent = backend
            .send_h1(&origin, post(), stopped(&io).await, Via::Direct, false)
            .await;
        assert!(
            sent.is_err(),
            "a fresh connection's failure is the request's"
        );
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn unsent_requests_come_back_on_compio() {
        compio::runtime::Runtime::new()
            .expect("compio runtime")
            .block_on(unsent_requests_come_back(Compio::default()));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn unsent_requests_come_back_on_tokio() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(unsent_requests_come_back(Tokio));
    }
}
