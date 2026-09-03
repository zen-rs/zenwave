//! The TLS engine selected by the `rustls` or `native-tls` feature.
//!
//! Both engines expose the same two operations: build a connector from the
//! extra roots once, and wrap an established byte stream in TLS.

#[cfg(tls_rustls)]
mod engine {
    use std::sync::Arc;

    use futures_io::{AsyncRead, AsyncWrite};
    use rustls::{ClientConfig, crypto::ring, pki_types::ServerName};
    use rustls_pki_types::CertificateDer;
    use rustls_platform_verifier::Verifier;

    use crate::Error;

    pub type TlsStream<S> = futures_rustls::client::TlsStream<S>;

    /// The platform verifier, extended with `extra_roots`.
    #[cfg(not(android_verifier))]
    fn verifier(
        extra_roots: &[CertificateDer<'static>],
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, Error> {
        let verifier = if extra_roots.is_empty() {
            Verifier::new(provider)
        } else {
            Verifier::new_with_extra_roots(extra_roots.iter().cloned(), provider)
        }
        .map_err(Error::tls)?;
        Ok(Arc::new(verifier))
    }

    /// The Android trust manager cannot take extra anchors, so extra roots are
    /// checked by webpki when the platform rejects a chain.
    #[cfg(android_verifier)]
    fn verifier(
        extra_roots: &[CertificateDer<'static>],
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, Error> {
        super::super::android::ensure_initialized()?;
        let platform = Verifier::new(Arc::clone(&provider)).map_err(Error::tls)?;
        if extra_roots.is_empty() {
            return Ok(Arc::new(platform));
        }
        let mut store = rustls::RootCertStore::empty();
        for root in extra_roots {
            store.add(root.clone()).map_err(Error::tls)?;
        }
        let extra =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider)
                .build()
                .map_err(Error::tls)?;
        Ok(Arc::new(super::super::android::PlatformOrExtraRoots {
            platform,
            extra,
        }))
    }

    /// rustls with certificate verification delegated to the operating system.
    #[derive(Clone)]
    pub struct TlsConnector {
        inner: futures_rustls::TlsConnector,
    }

    impl TlsConnector {
        pub fn new(extra_roots: &[CertificateDer<'static>]) -> Result<Self, Error> {
            let provider = Arc::new(ring::default_provider());
            let verifier = verifier(extra_roots, Arc::clone(&provider))?;
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(Error::tls)?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            Ok(Self {
                inner: futures_rustls::TlsConnector::from(Arc::new(config)),
            })
        }

        pub async fn connect<S>(&self, host: &str, stream: S) -> Result<TlsStream<S>, Error>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            let server_name = ServerName::try_from(host.to_owned()).map_err(Error::tls)?;
            self.inner
                .connect(server_name, stream)
                .await
                .map_err(Error::tls)
        }
    }
}

#[cfg(tls_native)]
mod engine {
    use std::sync::Arc;

    use futures_io::{AsyncRead, AsyncWrite};
    use rustls_pki_types::CertificateDer;

    use crate::Error;

    pub type TlsStream<S> = async_native_tls::TlsStream<S>;

    /// The platform's native TLS library through `native-tls`.
    #[derive(Clone)]
    pub struct TlsConnector {
        inner: Arc<async_native_tls::TlsConnector>,
    }

    impl TlsConnector {
        pub fn new(extra_roots: &[CertificateDer<'static>]) -> Result<Self, Error> {
            let mut connector = async_native_tls::TlsConnector::new();
            for root in extra_roots {
                let certificate = native_tls::Certificate::from_der(root).map_err(Error::tls)?;
                connector = connector.add_root_certificate(certificate);
            }
            Ok(Self {
                inner: Arc::new(connector),
            })
        }

        pub async fn connect<S>(&self, host: &str, stream: S) -> Result<TlsStream<S>, Error>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            self.inner.connect(host, stream).await.map_err(Error::tls)
        }
    }
}

pub use engine::{TlsConnector, TlsStream};

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}
