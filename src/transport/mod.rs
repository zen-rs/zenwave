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
#[cfg(native)]
use std::sync::Arc;
#[cfg(connector)]
use std::{future::Future, pin::Pin};

#[cfg(native)]
use rustls_pki_types::{CertificateDer, pem::PemObject};

use crate::Error;

#[cfg(android_verifier)]
mod android;
#[cfg(feature = "curl-backend")]
mod ca_bundle;
#[cfg(connector)]
pub(crate) mod connect;
#[cfg(connector)]
pub(crate) mod dns;
#[cfg(connector)]
mod happy_eyeballs;
#[cfg(tls_native)]
pub(crate) mod native_tls_stream;
#[cfg(native)]
pub mod proxy;
// Consumed by the hyper backend's h3 connections and, for the endpoint, the
// connection pool (#69).
#[cfg(http3)]
#[allow(dead_code)]
pub(crate) mod quic;
#[cfg(connector)]
mod socks5;
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
/// wherever connection drivers already run; [`dns`] and [`quic`] share it.
#[cfg(connector)]
pub(crate) type Spawn = Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>;

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
    /// Platform roots plus extras as PEM, for libcurl. `None` without extras.
    #[cfg(feature = "curl-backend")]
    ca_bundle: Option<Vec<u8>>,
    #[cfg(tls_engine)]
    tls: tls::TlsConnector,
    /// QUIC endpoint shared by every h3 connection, bound on first use.
    #[cfg(http3)]
    #[allow(dead_code)] // read through `quic_endpoint`, used by the pool (#69)
    quic: once_cell::sync::OnceCell<quinn::Endpoint>,
    /// The resolver configuration read once at build; on Android the unit
    /// config — `DnsResolver` is configured by the OS.
    #[cfg(connector)]
    dns: dns::Config,
    /// The hickory resolver over `dns`, built on first lookup so its runtime
    /// takes the caller's [`Spawn`]; kept for its pooled name-server
    /// connections and TTL response cache.
    #[cfg(all(connector, not(target_os = "android")))]
    resolver: once_cell::sync::OnceCell<dns::HickoryResolver>,
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
    #[must_use]
    pub fn system() -> Self {
        #[cfg(native)]
        {
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
        #[cfg(not(native))]
        {
            Self {}
        }
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

    #[cfg(tls_engine)]
    pub(crate) fn tls(&self) -> &tls::TlsConnector {
        &self.inner.tls
    }

    /// The full PEM bundle libcurl should trust, when extra roots were added.
    #[cfg(feature = "curl-backend")]
    pub(crate) fn ca_bundle(&self) -> Option<&[u8]> {
        self.inner.ca_bundle.as_deref()
    }

    /// The QUIC endpoint h3 connections share, bound on first use. `spawn`
    /// schedules the futures quinn drives in the background.
    #[cfg(http3)]
    #[allow(dead_code)] // the connection pool (#69) calls this per h3 dial
    pub(crate) fn quic_endpoint(&self, spawn: Spawn) -> Result<&quinn::Endpoint, Error> {
        self.inner.quic.get_or_try_init(|| quic::endpoint(spawn))
    }

    /// The HTTPS (SVCB) record for `host`:`port`, resolved through the
    /// transport's DNS resolver. `spawn` schedules the futures the resolver
    /// drives in the background.
    #[cfg(connector)]
    #[allow(dead_code)] // the connection pool's h3 discovery calls this (#69)
    pub(crate) async fn https_record(
        &self,
        spawn: Spawn,
        host: &str,
        port: u16,
    ) -> Result<Option<dns::HttpsRecord>, Error> {
        dns::https_record(&self.inner, spawn, host, port).await
    }
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Transport");
        #[cfg(native)]
        debug
            .field("proxy", &self.inner.proxy)
            .field("extra_roots", &self.inner.extra_roots.len());
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
    /// Resolver configuration override — tests point it at an in-process
    /// DNS server instead of the system's.
    #[cfg(all(connector, not(target_os = "android")))]
    dns: Option<dns::Config>,
}

impl fmt::Debug for TransportBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("TransportBuilder");
        #[cfg(native)]
        debug
            .field("proxy", &self.proxy)
            .field("extra_roots", &self.extra_roots.len());
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

    /// Resolve through `config` instead of the system resolver
    /// configuration — a constructor for tests, not a runtime hook.
    #[cfg(all(connector, not(target_os = "android")))]
    #[allow(dead_code)] // only the dns unit tests override the configuration
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
    /// platform trust store cannot be initialised.
    pub fn build(self) -> Result<Transport, Error> {
        #[cfg(native)]
        {
            #[cfg(tls_engine)]
            let tls = tls::TlsConnector::new(&self.extra_roots)?;
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
            #[cfg(all(connector, not(target_os = "android")))]
            let dns = self.dns.unwrap_or_else(|| {
                let config = dns::Config::system();
                if let dns::Config::Unavailable(reason) = &config {
                    tracing::warn!("system DNS resolver configuration unavailable: {reason}");
                }
                config
            });
            #[cfg(all(connector, target_os = "android"))]
            let dns = dns::Config;
            Ok(Transport {
                inner: Arc::new(Inner {
                    proxy: self.proxy.unwrap_or_else(Proxy::system),
                    extra_roots: self.extra_roots,
                    #[cfg(feature = "curl-backend")]
                    ca_bundle,
                    #[cfg(tls_engine)]
                    tls,
                    #[cfg(http3)]
                    quic: once_cell::sync::OnceCell::new(),
                    #[cfg(connector)]
                    dns,
                    #[cfg(all(connector, not(target_os = "android")))]
                    resolver: once_cell::sync::OnceCell::new(),
                }),
            })
        }
        #[cfg(not(native))]
        {
            Ok(Transport {})
        }
    }
}
