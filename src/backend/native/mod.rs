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
//! the proxy route, happy eyeballs, SOCKS5, the TLS verifier (platform
//! verification and OneCRL), and the HTTP/3 discovery policy. What
//! `http-kit` cannot carry yet fails with an error that names it: a unix
//! domain socket, and TLS inside TLS through an HTTPS proxy.

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

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use executor_core::{LocalExecutor, Task as _};
use futures_util::Stream;
#[cfg(native_h3)]
use http::uri::Scheme;
use http_kit::{Body, Endpoint, Method, Request, Response};

pub use connect::NativeIo;
pub use pool::PoolHandle;
use pool::{Command, Grant, Want};
#[cfg(feature = "native-compio")]
pub use runtime::Compio;
#[cfg(native_driver)]
pub use runtime::Driver;
#[cfg(feature = "native-tokio")]
pub use runtime::Tokio;

use super::shared::{
    error_for_status, replayable_request, request_origin, shape_h1_request, take_request,
};
use crate::{
    Client, Error, Transport,
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
    /// thread's `http-kit-io` implementation and `executor` the thread's
    /// local executor, which runs the pool until every clone of the backend
    /// is dropped.
    ///
    /// Must be called on a thread where `io`'s runtime is running.
    pub fn on_current_thread<I, E>(transport: Transport, io: I, executor: &E) -> Self
    where
        I: NativeIo,
        E: LocalExecutor,
    {
        let (pool, receiver) = PoolHandle::channel();
        executor
            .spawn_local(pool::run(io, transport.downgrade(), receiver))
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

    /// Whether `request` to `origin` may go over HTTP/3, and how: only a
    /// direct TLS origin, since QUIC bypasses proxies and unix sockets.
    #[cfg(native_h3)]
    fn h3_use(&self, origin: &Origin, request: &http::Request<Body>) -> Result<pool::H3Use, Error> {
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
        Ok(if origin.scheme != Scheme::HTTPS || !direct {
            pool::H3Use::Blocked
        } else if idempotent(request.method()) && request.body().try_clone().is_some() {
            pool::H3Use::Any
        } else {
            pool::H3Use::Proven
        })
    }

    /// Sends `request` on a leased HTTP/1.1 connection. A connection reused
    /// from the pool may have been closed by the server while it sat idle;
    /// an idempotent request with a replayable body is handed back for one
    /// more try on a fresh dial.
    async fn send_h1(
        &self,
        origin: &Origin,
        mut request: http::Request<Body>,
        send: http_kit_h1::SendRequest,
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
        shape_h1_request(&mut request, &via)?;
        let sender = lease.send.as_ref().expect("a new lease holds its sender");
        match (sender.send(request).await, replay) {
            (Ok(response), _) => {
                Ok(Ok(response.map(|body| {
                    Body::from_frames(LeaseReturn::new(body, lease))
                })))
            }
            (Err(http_kit_h1::Error::ConnectionClosed), Some(replay)) => {
                tracing::debug!(host = %origin.host, "reused connection closed; dialing fresh");
                Ok(Err(replay))
            }
            (Err(error), _) => Err(Error::Transport(Box::new(error))),
        }
    }

    /// Sends `request` on the origin's HTTP/3 connection. On an unproven
    /// connection a failure, or the pool abandoning it, hands the request
    /// back for TCP.
    #[cfg(native_h3)]
    async fn send_h3(
        &self,
        origin: &Origin,
        request: http::Request<Body>,
        grant: h3::H3Grant,
    ) -> Result<Result<Response, http::Request<Body>>, Error> {
        use futures_util::future::{Either, select};

        let h3::H3Grant {
            send,
            generation,
            verdict,
        } = grant;
        let Some(verdict) = verdict else {
            let response = send.send(request).await.map_err(h3::h3_error)?;
            return Ok(Ok(response.map(|body| keep_pool(body, &self.pool))));
        };
        let replay = replayable_request(&request)
            .expect("only a replayable request is granted an unproven connection");
        let abandoned = async {
            if verdict.await.is_err() {
                // Proven meanwhile: the request keeps its connection.
                std::future::pending::<()>().await;
            }
        };
        let sent = {
            let sending = send.send(request);
            futures_util::pin_mut!(sending, abandoned);
            match select(sending, abandoned).await {
                Either::Left((sent, _)) => sent.ok(),
                Either::Right(((), _)) => None,
            }
        };
        let report = match &sent {
            Some(_) => h3::H3Report::Proven {
                origin: origin.clone(),
                generation,
            },
            None => h3::H3Report::Failed {
                origin: origin.clone(),
                generation,
            },
        };
        self.pool.send(Command::H3(report));
        Ok(sent
            .map(|response| response.map(|body| keep_pool(body, &self.pool)))
            .ok_or(replay))
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
        loop {
            #[cfg(native_h3)]
            let h3 = self.h3_use(&origin, &request)?;
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
                Grant::H3(grant) => self.send_h3(&origin, request, grant).await?,
            };
            match sent {
                Ok(response) => {
                    #[cfg(native_h3)]
                    if h3 != pool::H3Use::Blocked {
                        h3::report_alt_svc(&self.pool, &origin, response.headers());
                    }
                    return error_for_status(response).await;
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

/// An HTTP/1.1 connection leased from the pool: back to the pool when its
/// response body ends, discarded when it is dropped first.
struct H1Lease {
    send: Option<http_kit_h1::SendRequest>,
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
/// holds the rest of the body.
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

/// An HTTP/3 response body that keeps the pool, and with it the
/// connection's driver, running until the body is done.
#[cfg(native_h3)]
fn keep_pool(body: Body, pool: &PoolHandle) -> Body {
    Body::from_frames(KeepPool {
        inner: body,
        _pool: pool.clone(),
    })
}

#[cfg(native_h3)]
struct KeepPool<S> {
    inner: S,
    _pool: PoolHandle,
}

#[cfg(native_h3)]
impl<S: Stream + Unpin> Stream for KeepPool<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}
