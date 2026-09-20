//! The TLS engine selected by the `rustls` or `native-tls` feature.
//! `rustls` takes precedence when both are enabled.
//!
//! Both engines expose the same two operations: build a connector from the
//! extra roots once, and wrap an established byte stream in TLS. Each
//! connector is really a pair — one configuration per [`Protocols`] value —
//! built from the same verifier and roots, because the ALPN list has to be
//! fixed before the handshake starts.

use super::connect::Protocols;

#[cfg(tls_rustls)]
mod engine {
    use std::sync::Arc;

    use futures_io::{AsyncRead, AsyncWrite};
    use rustls::{ClientConfig, crypto::ring, pki_types::ServerName};
    use rustls_pki_types::CertificateDer;
    #[cfg(not(android_verifier))]
    use rustls_platform_verifier::Verifier;

    use super::Protocols;
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

    /// The system anchors read from disk plus `extra_roots`, verified by webpki;
    /// see the `android` module for why the platform verifier is not used.
    #[cfg(android_verifier)]
    fn verifier(
        extra_roots: &[CertificateDer<'static>],
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, Error> {
        let mut store = super::super::android::system_roots()?;
        for root in extra_roots {
            store.add(root.clone()).map_err(Error::tls)?;
        }
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider)
                .build()
                .map_err(Error::tls)?;
        Ok(verifier)
    }

    /// The ALPN list for `protocols`: h2 only exists with the `http2` feature.
    fn alpn_protocols(protocols: Protocols) -> Vec<Vec<u8>> {
        match protocols {
            Protocols::Http1 => vec![b"http/1.1".to_vec()],
            #[cfg(feature = "http2")]
            Protocols::Http2OrHttp1 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            #[cfg(not(feature = "http2"))]
            Protocols::Http2OrHttp1 => vec![b"http/1.1".to_vec()],
        }
    }

    /// rustls with certificate verification delegated to the operating system.
    #[derive(Clone)]
    pub struct TlsConnector {
        /// The ALPN-less base configuration; QUIC clones it and sets `h3`.
        #[cfg_attr(not(http3), allow(dead_code))]
        base: Arc<ClientConfig>,
        http1: futures_rustls::TlsConnector,
        http2_or_http1: futures_rustls::TlsConnector,
    }

    impl TlsConnector {
        pub fn new(extra_roots: &[CertificateDer<'static>]) -> Result<Self, Error> {
            let provider = Arc::new(ring::default_provider());
            let verifier = verifier(extra_roots, Arc::clone(&provider))?;
            let base = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(Error::tls)?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            let mut http1 = base.clone();
            http1.alpn_protocols = alpn_protocols(Protocols::Http1);
            let mut http2_or_http1 = base.clone();
            http2_or_http1.alpn_protocols = alpn_protocols(Protocols::Http2OrHttp1);
            Ok(Self {
                base: Arc::new(base),
                http1: futures_rustls::TlsConnector::from(Arc::new(http1)),
                http2_or_http1: futures_rustls::TlsConnector::from(Arc::new(http2_or_http1)),
            })
        }

        /// The shared client configuration; `transport::quic` clones it with
        /// ALPN `h3` for QUIC connections.
        #[cfg(http3)]
        #[allow(dead_code)] // the h3 dial path (#69) reads it
        pub const fn client_config(&self) -> &Arc<ClientConfig> {
            &self.base
        }

        pub async fn connect<S>(
            &self,
            host: &str,
            stream: S,
            protocols: Protocols,
        ) -> Result<TlsStream<S>, Error>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            let server_name = ServerName::try_from(host.to_owned()).map_err(Error::tls)?;
            let connector = match protocols {
                Protocols::Http1 => &self.http1,
                Protocols::Http2OrHttp1 => &self.http2_or_http1,
            };
            connector
                .connect(server_name, stream)
                .await
                .map_err(Error::tls)
        }
    }

    /// The protocol `stream`'s TLS session negotiated through ALPN, if any.
    ///
    /// Infallible for rustls — the signature matches the native-tls engine.
    #[allow(clippy::unnecessary_wraps)] // the native-tls engine can fail here
    pub fn negotiated_alpn<S>(stream: &TlsStream<S>) -> Result<Option<Vec<u8>>, Error> {
        let (_, connection) = stream.get_ref();
        Ok(connection.alpn_protocol().map(<[u8]>::to_vec))
    }
}

#[cfg(tls_native)]
mod engine {
    use futures_io::{AsyncRead, AsyncWrite};
    use rustls_pki_types::CertificateDer;

    use super::{
        super::native_tls_stream::{self, TlsConnector as Connector},
        Protocols,
    };
    use crate::Error;

    pub type TlsStream<S> = native_tls_stream::TlsStream<S>;

    const ALPN_HTTP1: &[&str] = &["http/1.1"];
    #[cfg(feature = "http2")]
    const ALPN_HTTP2_OR_HTTP1: &[&str] = &["h2", "http/1.1"];
    #[cfg(not(feature = "http2"))]
    const ALPN_HTTP2_OR_HTTP1: &[&str] = ALPN_HTTP1;

    /// One connector per ALPN list, over the same extra roots.
    fn connector(
        extra_roots: &[CertificateDer<'static>],
        alpns: &[&str],
    ) -> Result<Connector, Error> {
        let mut builder = native_tls::TlsConnector::builder();
        for root in extra_roots {
            let certificate = native_tls::Certificate::from_der(root).map_err(Error::tls)?;
            builder.add_root_certificate(certificate);
        }
        builder.request_alpns(alpns);
        Ok(Connector::new(builder.build().map_err(Error::tls)?))
    }

    /// The platform's native TLS library through `native-tls`.
    #[derive(Clone)]
    pub struct TlsConnector {
        http1: Connector,
        http2_or_http1: Connector,
    }

    impl TlsConnector {
        pub fn new(extra_roots: &[CertificateDer<'static>]) -> Result<Self, Error> {
            Ok(Self {
                http1: connector(extra_roots, ALPN_HTTP1)?,
                http2_or_http1: connector(extra_roots, ALPN_HTTP2_OR_HTTP1)?,
            })
        }

        pub async fn connect<S>(
            &self,
            host: &str,
            stream: S,
            protocols: Protocols,
        ) -> Result<TlsStream<S>, Error>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            let connector = match protocols {
                Protocols::Http1 => &self.http1,
                Protocols::Http2OrHttp1 => &self.http2_or_http1,
            };
            connector.connect(host, stream).await.map_err(Error::tls)
        }
    }

    /// The protocol `stream`'s TLS session negotiated through ALPN, if any.
    pub fn negotiated_alpn<S>(stream: &TlsStream<S>) -> Result<Option<Vec<u8>>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        stream.negotiated_alpn().map_err(Error::tls)
    }
}

pub use engine::{TlsConnector, TlsStream, negotiated_alpn};

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}
