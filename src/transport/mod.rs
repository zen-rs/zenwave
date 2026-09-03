//! Connection-level configuration shared by every backend.
//!
//! A [`Transport`] describes how bytes reach a server: which root
//! certificates are trusted when a TLS connection is opened. Every backend is
//! constructed from one, and [`Transport::system`] is what
//! [`zenwave::client()`](crate::client) uses: the operating system's trust
//! store, evaluated by the platform (Security.framework on Apple systems,
//! `CryptoAPI` on Windows, the Android trust manager, the system CA bundle on
//! Linux and the BSDs) and, in a browser or a Cloudflare Worker, whatever the
//! runtime itself trusts.
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

#[cfg(native)]
use rustls_pki_types::{CertificateDer, pem::PemObject};

use crate::Error;

#[cfg(android_verifier)]
mod android;
#[cfg(connector)]
pub(crate) mod connect;
#[cfg(connector)]
mod happy_eyeballs;
#[cfg(connector)]
pub(crate) mod stream;
#[cfg(tls_engine)]
pub(crate) mod tls;

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
    #[cfg(native)]
    extra_roots: Vec<CertificateDer<'static>>,
    #[cfg(tls_engine)]
    tls: tls::TlsConnector,
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
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Transport");
        #[cfg(native)]
        debug.field("extra_roots", &self.inner.extra_roots.len());
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
    extra_roots: Vec<CertificateDer<'static>>,
}

impl fmt::Debug for TransportBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("TransportBuilder");
        #[cfg(native)]
        debug.field("extra_roots", &self.extra_roots.len());
        debug.finish_non_exhaustive()
    }
}

impl TransportBuilder {
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
            Ok(Transport {
                inner: Arc::new(Inner {
                    extra_roots: self.extra_roots,
                    #[cfg(tls_engine)]
                    tls,
                }),
            })
        }
        #[cfg(not(native))]
        {
            Ok(Transport {})
        }
    }
}
