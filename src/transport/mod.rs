//! Connection-level configuration shared by every backend.
//!
//! A [`Transport`] describes how bytes reach a server: which proxy, if any,
//! sits in between, and which root certificates are trusted when a TLS
//! connection is opened. Every backend is constructed from one, and
//! [`Transport::system`] is what [`zenwave::client()`](crate::client) uses:
//! the operating system's proxy settings and trust store, the latter
//! evaluated by the platform (Security.framework on Apple systems,
//! `CryptoAPI` on Windows, the Android trust manager, the system CA bundle on
//! Linux and the BSDs) and, in a browser or a Cloudflare Worker, whatever the
//! runtime itself decides.
//!
//! Building a transport is where trust material is loaded and validated, so
//! it is done once and the result is cheap to clone and share.
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(not(target_arch = "wasm32"))]
//! # {
//! use zenwave::Transport;
//!
//! let corporate_ca = std::fs::read("/etc/ssl/corp-root.pem")?;
//! let transport = Transport::builder()
//!     .extra_root_certificates_pem(&corporate_ca)?
//!     .build()?;
//! # let _ = transport;
//! # }
//! # Ok(())
//! # }
//! ```

use std::fmt;
#[cfg(unix_socket)]
use std::path::{Path, PathBuf};
#[cfg(native)]
use std::sync::Arc;
#[cfg(any(onecrl, native_backend))]
use std::time::Duration;
#[cfg(any(all(connector, feature = "hyper-backend"), native_h3))]
use std::{future::Future, pin::Pin};

#[cfg(native)]
use rustls_pki_types::{CertificateDer, pem::PemObject};

use crate::Error;

// RFC 7838 Alt-Svc parsing, for HTTP/3 discovery.
#[cfg(https_rr)]
pub(crate) mod alt_svc;
#[cfg(android_verifier)]
mod android;
#[cfg(feature = "curl-backend")]
mod ca_bundle;
#[cfg(connector)]
pub(crate) mod connect;
// The per-origin HTTP/3 knowledge both h3 paths keep.
#[cfg(https_rr)]
pub(crate) mod discovery;
// HTTPS records only feed HTTP/3 discovery, so the resolver exists only
// where a backend can dial QUIC.
#[cfg(https_rr)]
pub(crate) mod dns;
// Generic over the dialer: its futures are `Send` exactly when the dialer's
// are — the async-net dialer's are, an `http-kit-io` one's are not.
#[cfg(dialer)]
#[expect(clippy::future_not_send)]
pub(crate) mod happy_eyeballs;
// Kept `crate::`-free so `tests/common` can include the same file for its
// hyper test server.
#[cfg(connector)]
pub(crate) mod hyper_io;
#[cfg(tls_native)]
pub(crate) mod native_tls_stream;
// The OneCRL baseline, wrapped around the webpki verifiers (`tls` engine).
#[cfg(onecrl)]
mod onecrl;
// The hyper backend's per-origin connection pool; other backends pool through
// their platform.
#[cfg(all(connector, feature = "hyper-backend"))]
pub(crate) mod pool;
#[cfg(native)]
pub mod proxy;
// Consumed by the hyper backend's h3 connections and, for the endpoint, the
// connection pool.
#[cfg(http3)]
pub(crate) mod quic;
// Which legs a connection takes through the proxy rules, for every connector.
#[cfg(dialer)]
pub(crate) mod route;
#[cfg(dialer)]
pub(crate) mod socks5;
#[cfg(connector)]
pub(crate) mod stream;
#[cfg(tls_engine)]
pub(crate) mod tls;
#[cfg(connector)]
mod tunnel;

#[cfg(native)]
pub use proxy::{Proxy, ProxyBuilder};

/// Schedules the futures a DNS resolver or QUIC driver runs in the
/// background. The backend supplies its own spawner so that work runs
/// wherever connection drivers already run; `dns` and `quic` share it.
#[cfg(https_rr)]
pub(crate) type Spawn = Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>;

/// Runs `future` to completion on a thread of its own, on async-io's
/// reactor: the background work of a caller that has no executor of its
/// own to hand it.
#[cfg(any(all(connector, feature = "hyper-backend"), native_h3))]
pub(crate) fn spawn_thread(future: Pin<Box<dyn Future<Output = ()> + Send>>) {
    std::thread::spawn(move || async_io::block_on(future));
}

/// How connections are established: trusted roots and, on native platforms,
/// the TLS engine configured with them.
///
/// Cheap to clone; all clones share one configuration.
#[derive(Clone)]
pub struct Transport {
    #[cfg(native)]
    inner: Arc<Inner>,
}

#[cfg(native)]
struct Inner {
    proxy: Proxy,
    extra_roots: Vec<CertificateDer<'static>>,
    /// The unix domain socket every connection dials instead of a host:port,
    /// when the transport was built with one.
    #[cfg(unix_socket)]
    unix_socket: Option<PathBuf>,
    /// The bound on one connection attempt, when set.
    #[cfg(native_backend)]
    connect_timeout: Option<Duration>,
    /// The bound on each wait for bytes from the server, when set.
    #[cfg(native_backend)]
    read_timeout: Option<Duration>,
    /// Platform roots plus extras as PEM, for libcurl. `None` without extras.
    #[cfg(feature = "curl-backend")]
    ca_bundle: Option<Vec<u8>>,
    #[cfg(tls_engine)]
    tls: tls::TlsConnector,
    /// Connections the hyper backend reuses, keyed by origin.
    #[cfg(all(connector, feature = "hyper-backend"))]
    pool: pool::Pool,
    /// QUIC endpoint shared by every h3 connection, bound on first use.
    #[cfg(http3)]
    quic: once_cell::sync::OnceCell<quinn::Endpoint>,
    /// The resolver configuration read once at build; on Android the unit
    /// config — `DnsResolver` is configured by the OS.
    #[cfg(https_rr)]
    dns: dns::Config,
    /// The hickory resolver over `dns`, built on first lookup so its runtime
    /// takes the caller's [`Spawn`]; kept for its pooled name-server
    /// connections and TTL response cache.
    #[cfg(all(https_rr, not(target_os = "android")))]
    resolver: once_cell::sync::OnceCell<dns::HickoryResolver>,
    /// The native backend's pool on its own driver thread, one per runtime,
    /// started by the first `NativeBackend::new` over this transport.
    #[cfg(all(native_backend, feature = "native-compio"))]
    native_compio: std::sync::OnceLock<crate::backend::native::PoolHandle>,
    #[cfg(all(native_backend, feature = "native-tokio"))]
    native_tokio: std::sync::OnceLock<crate::backend::native::PoolHandle>,
}

impl Transport {
    /// The platform default: system proxy settings and the system trust store.
    ///
    /// The configuration is built on first use and shared by every later
    /// call, so [`zenwave::get`](crate::get) and friends do not reload the
    /// trust store per request.
    ///
    /// # Panics
    ///
    /// Panics when the system trust store cannot be initialised, for example
    /// on Android before the JVM has been registered through `ndk-context`. Use
    /// [`Transport::builder`] and [`TransportBuilder::build`] to handle that
    /// as an error instead.
    #[cfg(native)]
    #[must_use]
    pub fn system() -> Self {
        // Immutable, computed once: the one process-wide value zenwave keeps.
        static SYSTEM: std::sync::OnceLock<Transport> = std::sync::OnceLock::new();
        SYSTEM
            .get_or_init(|| {
                Self::builder().build().unwrap_or_else(|error| {
                    panic!("zenwave: the system transport cannot be initialised: {error}")
                })
            })
            .clone()
    }

    /// The platform default: system proxy settings and the system trust store.
    ///
    /// On wasm32 the browser owns proxying and trust, so the transport
    /// carries no configuration at all.
    #[cfg(not(native))]
    #[must_use]
    pub const fn system() -> Self {
        Self {}
    }

    /// Start describing a custom transport.
    #[must_use]
    pub fn builder() -> TransportBuilder {
        TransportBuilder::default()
    }

    /// The proxy rules connections follow.
    #[cfg(native)]
    #[allow(dead_code)] // consumed by the curl and Apple backends
    pub(crate) fn proxy(&self) -> &Proxy {
        &self.inner.proxy
    }

    /// Root certificates trusted in addition to the platform's.
    #[cfg(native)]
    #[allow(dead_code)] // consumed by the curl and Apple backends
    pub(crate) fn extra_roots(&self) -> &[CertificateDer<'static>] {
        &self.inner.extra_roots
    }

    /// The unix domain socket every connection dials, when the transport was
    /// built with one.
    #[cfg(unix_socket)]
    pub(crate) fn unix_socket(&self) -> Option<&Path> {
        self.inner.unix_socket.as_deref()
    }

    /// How long one connection attempt may take, when bounded
    /// ([`TransportBuilder::connect_timeout`]).
    #[cfg(native_backend)]
    pub(crate) fn connect_timeout(&self) -> Option<Duration> {
        self.inner.connect_timeout
    }

    /// How long each wait for bytes from the server may take, when bounded
    /// ([`TransportBuilder::read_timeout`]).
    #[cfg(native_backend)]
    pub(crate) fn read_timeout(&self) -> Option<Duration> {
        self.inner.read_timeout
    }

    #[cfg(tls_engine)]
    pub(crate) fn tls(&self) -> &tls::TlsConnector {
        &self.inner.tls
    }

    /// The full PEM bundle libcurl should trust, when extra roots were added.
    #[cfg(feature = "curl-backend")]
    pub(crate) fn ca_bundle(&self) -> Option<&[u8]> {
        self.inner.ca_bundle.as_deref()
    }

    /// The connection pool hyper backends check out of; shared by every
    /// backend and `zenwave` convenience call over this transport.
    #[cfg(all(connector, feature = "hyper-backend"))]
    pub(crate) fn pool(&self) -> &pool::Pool {
        &self.inner.pool
    }

    /// The QUIC endpoint h3 connections share, bound on first use. `spawn`
    /// schedules the futures quinn drives in the background.
    #[cfg(http3)]
    pub(crate) fn quic_endpoint(&self, spawn: Spawn) -> Result<&quinn::Endpoint, Error> {
        self.inner.quic.get_or_try_init(|| quic::endpoint(spawn))
    }

    /// A handle that does not keep the transport alive: a native pool holds
    /// one, so a transport that owns the pool's driver can still drop.
    #[cfg(native_backend)]
    pub(crate) fn downgrade(&self) -> WeakTransport {
        WeakTransport(Arc::downgrade(&self.inner))
    }

    /// The native pool driven by compio on its own thread, started on first
    /// use.
    #[cfg(all(native_backend, feature = "native-compio"))]
    pub(crate) fn native_compio(
        &self,
        start: impl FnOnce() -> crate::backend::native::PoolHandle,
    ) -> &crate::backend::native::PoolHandle {
        self.inner.native_compio.get_or_init(start)
    }

    /// The native pool driven by tokio on its own thread, started on first
    /// use.
    #[cfg(all(native_backend, feature = "native-tokio"))]
    pub(crate) fn native_tokio(
        &self,
        start: impl FnOnce() -> crate::backend::native::PoolHandle,
    ) -> &crate::backend::native::PoolHandle {
        self.inner.native_tokio.get_or_init(start)
    }

    /// The HTTPS (SVCB) record for `host`:`port`, resolved through the
    /// transport's DNS resolver. `spawn` schedules the futures the resolver
    /// drives in the background.
    #[cfg(https_rr)]
    pub(crate) async fn https_record(
        &self,
        spawn: Spawn,
        host: &str,
        port: u16,
    ) -> Result<Option<dns::HttpsRecord>, Error> {
        dns::https_record(&self.inner, spawn, host, port).await
    }
}

/// A [`Transport`] that does not keep its configuration alive.
#[cfg(native_backend)]
#[derive(Clone)]
pub(crate) struct WeakTransport(std::sync::Weak<Inner>);

#[cfg(native_backend)]
impl WeakTransport {
    /// The transport, while anything else still holds it.
    pub(crate) fn upgrade(&self) -> Option<Transport> {
        self.0.upgrade().map(|inner| Transport { inner })
    }
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Transport");
        #[cfg(native)]
        debug
            .field("proxy", &self.inner.proxy)
            .field("extra_roots", &self.inner.extra_roots.len());
        #[cfg(unix_socket)]
        debug.field("unix_socket", &self.inner.unix_socket);
        #[cfg(native_backend)]
        debug
            .field("connect_timeout", &self.inner.connect_timeout)
            .field("read_timeout", &self.inner.read_timeout);
        debug.finish_non_exhaustive()
    }
}

/// Builder for [`Transport`].
///
/// Trust material is parsed as it is added and the TLS engine is configured
/// by [`build`](Self::build); every failure is reported there rather than at
/// the first request.
#[derive(Default)]
pub struct TransportBuilder {
    #[cfg(native)]
    proxy: Option<Proxy>,
    #[cfg(native)]
    extra_roots: Vec<CertificateDer<'static>>,
    #[cfg(unix_socket)]
    unix_socket: Option<PathBuf>,
    #[cfg(native_backend)]
    connect_timeout: Option<Duration>,
    #[cfg(native_backend)]
    read_timeout: Option<Duration>,
    /// OneCRL additions refresh — enabled by [`Self::onecrl_refresh`].
    #[cfg(onecrl)]
    onecrl: onecrl::refresh::Refresh,
    /// Resolver configuration override — tests point it at an in-process
    /// DNS server instead of the system's.
    #[cfg(all(https_rr, not(target_os = "android")))]
    dns: Option<dns::Config>,
    /// Wraps the TLS verifier — tests observe what a handshake presents.
    #[cfg(all(test, tls_rustls))]
    verifier_wrap: Option<tls::VerifierWrap>,
}

#[cfg(all(test, tls_rustls))]
impl TransportBuilder {
    /// Runs every handshake's verifier through `wrap`, which receives the
    /// transport's own verifier.
    #[allow(dead_code)] // only the native backend's tests, with a runtime, use it
    pub(crate) fn wrap_verifier(
        mut self,
        wrap: impl FnOnce(
            Arc<dyn rustls::client::danger::ServerCertVerifier>,
        ) -> Arc<dyn rustls::client::danger::ServerCertVerifier>
        + 'static,
    ) -> Self {
        self.verifier_wrap = Some(Box::new(wrap));
        self
    }
}

impl fmt::Debug for TransportBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("TransportBuilder");
        #[cfg(native)]
        debug
            .field("proxy", &self.proxy)
            .field("extra_roots", &self.extra_roots.len());
        #[cfg(unix_socket)]
        debug.field("unix_socket", &self.unix_socket);
        #[cfg(native_backend)]
        debug
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout);
        #[cfg(onecrl)]
        debug.field("onecrl_refresh", &self.onecrl.interval);
        debug.finish_non_exhaustive()
    }
}

impl TransportBuilder {
    /// Follow these proxy rules instead of [`Proxy::system`].
    #[cfg(native)]
    #[must_use]
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Trust every `CERTIFICATE` block in `pem` in addition to the platform roots.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the input is not PEM or holds no certificate.
    #[cfg(native)]
    pub fn extra_root_certificates_pem(mut self, pem: &[u8]) -> Result<Self, Error> {
        let before = self.extra_roots.len();
        for certificate in CertificateDer::pem_slice_iter(pem) {
            self.extra_roots.push(certificate.map_err(Error::tls)?);
        }
        if self.extra_roots.len() == before {
            return Err(Error::tls("PEM input holds no CERTIFICATE block"));
        }
        Ok(self)
    }

    /// Trust one DER-encoded certificate in addition to the platform roots.
    #[cfg(native)]
    #[must_use]
    pub fn extra_root_certificate_der(mut self, der: impl Into<Vec<u8>>) -> Self {
        self.extra_roots.push(CertificateDer::from(der.into()));
        self
    }

    /// Route every connection through the unix domain socket at `path` — the
    /// `curl --unix-socket` model: request URIs stay ordinary
    /// `http(s)://host/path`, so `Host` headers and TLS server names keep
    /// their usual meaning, and an `https` request wraps the socket's byte
    /// stream in TLS.
    ///
    /// Proxy rules do not apply: no proxy can reach a local socket. The
    /// hyper and curl backends serve such a transport; `URLSession` cannot
    /// and reports an error per request.
    #[cfg(unix_socket)]
    #[must_use]
    pub fn unix_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.unix_socket = Some(path.into());
        self
    }

    /// Bound each connection attempt by `timeout`: resolving the host, the
    /// TCP connect (every address happy eyeballs races), a proxy's TLS
    /// handshake and `CONNECT` tunnel or SOCKS5 handshake, and the origin's
    /// TLS handshake, together; for HTTP/3, the QUIC handshake. An attempt
    /// that takes longer fails with [`Error::Timeout`].
    ///
    /// Off unless set. Applied by the native backend
    /// ([`NativeBackend`](crate::backend::NativeBackend)); a caller that
    /// needs several bounds builds one transport, and one backend, per
    /// bound.
    #[cfg(native_backend)]
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Bound each wait for bytes from the server by `timeout`, on an
    /// HTTP/1.1 connection over any route (direct, TLS, a proxy's tunnel, a
    /// unix domain socket): the wait for the response head, which starts
    /// when the request does (interim `1xx` responses included), and each
    /// wait for more of the response body. Every read that yields data
    /// starts the next wait afresh, so a slow body that keeps arriving
    /// takes as long as it needs. The bound is on the socket, not on a
    /// consumer slow to read the body. HTTP/3 response reads are not
    /// timed.
    ///
    /// A wait that runs out closes the connection and fails the request
    /// with [`Error::Timeout`], never retried since the server may have the
    /// request; during the body, the body's read fails with
    /// an [`std::io::Error`] of kind [`TimedOut`](std::io::ErrorKind::TimedOut)
    /// whose inner error is [`Error::Timeout`]. An idle pooled connection
    /// is not waiting and is never timed, and a stream a `101` handed over
    /// ([`Switched`](crate::backend::Switched)) belongs to its owner and is
    /// not timed either.
    ///
    /// Off unless set. Applied by the native backend's HTTP/1.1
    /// connections ([`NativeBackend`](crate::backend::NativeBackend)).
    #[cfg(native_backend)]
    #[must_use]
    pub const fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    /// Keep the OneCRL blocklist current past the
    /// compiled baseline: every `interval`, fetch the
    /// Remote Settings changes since the newest record
    /// seen, add them to the lookup, and persist them
    /// under `dirs::cache_dir()/zenwave/onecrl/` so the
    /// next process starts from them. On Android the
    /// cache directory is the app's `Context.getCacheDir()`.
    #[cfg(onecrl)]
    #[must_use]
    pub const fn onecrl_refresh(mut self, interval: Duration) -> Self {
        self.onecrl.interval = Some(interval);
        self
    }

    /// Point OneCRL refresh at `endpoint`, persisting under `cache_dir`
    /// instead of the platform cache directory — a constructor for tests,
    /// not a runtime hook.
    #[cfg(all(onecrl, test))]
    #[must_use]
    pub(crate) fn onecrl_refresh_endpoint(
        mut self,
        endpoint: &str,
        cache_dir: std::path::PathBuf,
    ) -> Self {
        endpoint.clone_into(&mut self.onecrl.endpoint);
        self.onecrl.cache_dir = Some(cache_dir);
        self
    }

    /// Resolve through `config` instead of the system resolver
    /// configuration — a constructor for tests, not a runtime hook.
    #[cfg(all(https_rr, not(target_os = "android")))]
    #[allow(dead_code)] // only the h3 discovery tests override the configuration
    #[must_use]
    pub(crate) fn dns_config(mut self, config: dns::Config) -> Self {
        self.dns = Some(config);
        self
    }

    /// Load trust material and configure the TLS engine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when a certificate cannot be parsed or the
    /// platform trust store cannot be initialised. With OneCRL refresh
    /// enabled it also fails with [`Error::Io`] when the platform has no
    /// cache directory for the persisted additions.
    #[cfg(native)]
    pub fn build(self) -> Result<Transport, Error> {
        {
            // Resolving the refresh plan here — not on the refresher thread —
            // lets `build` report a missing cache directory.
            #[cfg(onecrl)]
            let refresh = self.onecrl.resolve()?.map(|plan| {
                (
                    plan,
                    Arc::new(arc_swap::ArcSwap::from_pointee(onecrl::Additions::default())),
                )
            });
            #[cfg(tls_engine)]
            let tls = tls::TlsConnector::new(
                &self.extra_roots,
                #[cfg(onecrl)]
                refresh.as_ref().map(|(_, additions)| Arc::clone(additions)),
                #[cfg(all(test, tls_rustls))]
                self.verifier_wrap,
            )?;
            #[cfg(feature = "curl-backend")]
            let ca_bundle = if self.extra_roots.is_empty() {
                None
            } else {
                Some(ca_bundle::platform_roots_with(&self.extra_roots)?)
            };
            // HTTPS records only feed HTTP/3 discovery: a host without a
            // resolver configuration (minimal containers, musl static
            // binaries) still resolves names through `getaddrinfo`, so
            // `build` records the failure and `https_record` reports it
            // per lookup.
            #[cfg(all(https_rr, not(target_os = "android")))]
            let dns = self.dns.unwrap_or_else(|| {
                let config = dns::Config::system();
                if let dns::Config::Unavailable(reason) = &config {
                    tracing::warn!("system DNS resolver configuration unavailable: {reason}");
                }
                config
            });
            #[cfg(all(https_rr, target_os = "android"))]
            let dns = dns::Config;
            let transport = Transport {
                inner: Arc::new(Inner {
                    proxy: self.proxy.unwrap_or_else(Proxy::system),
                    extra_roots: self.extra_roots,
                    #[cfg(unix_socket)]
                    unix_socket: self.unix_socket,
                    #[cfg(native_backend)]
                    connect_timeout: self.connect_timeout,
                    #[cfg(native_backend)]
                    read_timeout: self.read_timeout,
                    #[cfg(feature = "curl-backend")]
                    ca_bundle,
                    #[cfg(tls_engine)]
                    tls,
                    #[cfg(all(connector, feature = "hyper-backend"))]
                    pool: pool::Pool::new(),
                    #[cfg(http3)]
                    quic: once_cell::sync::OnceCell::new(),
                    #[cfg(https_rr)]
                    dns,
                    #[cfg(all(https_rr, not(target_os = "android")))]
                    resolver: once_cell::sync::OnceCell::new(),
                    #[cfg(all(native_backend, feature = "native-compio"))]
                    native_compio: std::sync::OnceLock::new(),
                    #[cfg(all(native_backend, feature = "native-tokio"))]
                    native_tokio: std::sync::OnceLock::new(),
                }),
            };
            // The refresher holds a `Weak`; spawning after `inner` exists also
            // covers the thread failing to start as a build error.
            #[cfg(onecrl)]
            if let Some((plan, additions)) = refresh {
                onecrl::refresh::spawn(&transport.inner, additions, plan)?;
            }
            Ok(transport)
        }
    }

    /// Build the transport. The browser owns proxying and trust, so there
    /// is nothing to load.
    ///
    /// # Errors
    ///
    /// Never fails on wasm32; the `Result` keeps the native signature.
    #[cfg(not(native))]
    pub const fn build(self) -> Result<Transport, Error> {
        Ok(Transport {})
    }
}
