//! The TLS engine selected by the `rustls` or `native-tls` feature.
//! `rustls` takes precedence when both are enabled.
//!
//! Both engines expose the same two operations: build a connector from the
//! extra roots once, and wrap an established byte stream in TLS. Each
//! connector is really a pair — one configuration per [`Protocols`] value —
//! built from the same verifier and roots, because the ALPN list has to be
//! fixed before the handshake starts.

use super::route::Protocols;

#[cfg(tls_rustls)]
mod engine {
    #[cfg(connector)]
    use std::io;
    use std::sync::Arc;

    #[cfg(onecrl)]
    use arc_swap::ArcSwap;
    #[cfg(connector)]
    use futures_io::{AsyncRead, AsyncWrite};
    #[cfg(connector)]
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, crypto::ring};
    use rustls_pki_types::CertificateDer;
    #[cfg(not(any(android_verifier, wasi_verifier)))]
    use rustls_platform_verifier::Verifier;

    #[cfg(onecrl)]
    use super::super::onecrl::Additions;
    use super::Protocols;
    #[cfg(any(connector, android_verifier))]
    use crate::Cause;
    use crate::Error;
    #[cfg(connector)]
    use crate::{ConnectFailure, Hop, TlsError, TlsFailure};

    #[cfg(connector)]
    pub type TlsStream<S> = futures_rustls::client::TlsStream<S>;

    /// The platform verifier, extended with `extra_roots`.
    #[cfg(not(any(android_verifier, wasi_verifier)))]
    fn verifier(
        extra_roots: &[CertificateDer<'static>],
        provider: Arc<rustls::crypto::CryptoProvider>,
        #[cfg(onecrl)] additions: Option<Arc<ArcSwap<Additions>>>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, Error> {
        let verifier = if extra_roots.is_empty() {
            Verifier::new(provider)
        } else {
            Verifier::new_with_extra_roots(extra_roots.iter().cloned(), provider)
        }
        .map_err(Error::trust_store)?;
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(verifier);
        #[cfg(onecrl)]
        let verifier = onecrl_wrap(verifier, additions);
        Ok(verifier)
    }

    /// The system anchors read from disk plus `extra_roots`, verified by webpki;
    /// see the `android` module for why the platform verifier is not used.
    #[cfg(android_verifier)]
    fn verifier(
        extra_roots: &[CertificateDer<'static>],
        provider: Arc<rustls::crypto::CryptoProvider>,
        #[cfg(onecrl)] additions: Option<Arc<ArcSwap<Additions>>>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, Error> {
        let mut store = super::super::android::system_roots()?;
        for root in extra_roots {
            store.add(root.clone()).map_err(Error::trust_store)?;
        }
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider)
                .build()
                .map_err(|error| Error::trust_store(Cause::Detail(error.to_string())))?;
        #[cfg(onecrl)]
        let verifier = onecrl_wrap(verifier, additions);
        Ok(verifier)
    }

    /// Mozilla's roots, compiled in by `webpki-roots`, plus `extra_roots`,
    /// verified by webpki: a WASI host has no platform trust store.
    #[cfg(wasi_verifier)]
    fn verifier(
        extra_roots: &[CertificateDer<'static>],
        provider: Arc<rustls::crypto::CryptoProvider>,
        #[cfg(onecrl)] additions: Option<Arc<ArcSwap<Additions>>>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, Error> {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for root in extra_roots {
            store.add(root.clone()).map_err(Error::trust_store)?;
        }
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider)
                .build()
                .map_err(|error| Error::trust_store(Cause::Detail(error.to_string())))?;
        #[cfg(onecrl)]
        let verifier = onecrl_wrap(verifier, additions);
        Ok(verifier)
    }

    /// Wrap `verifier` in the OneCRL baseline where the target carries it;
    /// `additions` is the refresher's shared table when the transport opted
    /// in.
    #[cfg(onecrl)]
    fn onecrl_wrap(
        verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
        additions: Option<Arc<ArcSwap<Additions>>>,
    ) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
        Arc::new(super::super::onecrl::OneCrlVerifier::new(
            verifier, additions,
        ))
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
        #[cfg(http3)]
        base: Arc<ClientConfig>,
        /// The `http/1.1` configuration, which the native backend hands to
        /// `http-kit-tls` as is.
        #[cfg(native_backend)]
        http1_config: Arc<ClientConfig>,
        /// The verifier every configuration above runs, which the native
        /// backend's HTTP/3 handshakes call too.
        #[cfg(native_h3)]
        verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
        #[cfg(connector)]
        http1: futures_rustls::TlsConnector,
        #[cfg(connector)]
        http2_or_http1: futures_rustls::TlsConnector,
    }

    /// Wraps the verifier a connector would run, so a test can observe or
    /// decide what every TLS and QUIC handshake of a transport is shown.
    #[cfg(test)]
    pub type VerifierWrap = Box<
        dyn FnOnce(
            Arc<dyn rustls::client::danger::ServerCertVerifier>,
        ) -> Arc<dyn rustls::client::danger::ServerCertVerifier>,
    >;

    impl TlsConnector {
        pub fn new(
            extra_roots: &[CertificateDer<'static>],
            #[cfg(onecrl)] additions: Option<Arc<ArcSwap<Additions>>>,
            #[cfg(test)] wrap: Option<VerifierWrap>,
        ) -> Result<Self, Error> {
            let provider = Arc::new(ring::default_provider());
            let verifier = verifier(
                extra_roots,
                Arc::clone(&provider),
                #[cfg(onecrl)]
                additions,
            )?;
            #[cfg(test)]
            let verifier = match wrap {
                Some(wrap) => wrap(verifier),
                None => verifier,
            };
            #[cfg(native_h3)]
            let shared = Arc::clone(&verifier);
            let base = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(Error::tls_config)?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            let with_alpn = |protocols| {
                let mut config = base.clone();
                config.alpn_protocols = alpn_protocols(protocols);
                Arc::new(config)
            };
            let http1 = with_alpn(Protocols::Http1);
            Ok(Self {
                #[cfg(connector)]
                http2_or_http1: futures_rustls::TlsConnector::from(with_alpn(
                    Protocols::Http2OrHttp1,
                )),
                #[cfg(http3)]
                base: Arc::new(base),
                #[cfg(native_backend)]
                http1_config: Arc::clone(&http1),
                #[cfg(native_h3)]
                verifier: shared,
                #[cfg(connector)]
                http1: futures_rustls::TlsConnector::from(http1),
            })
        }

        /// The server certificate verifier: the platform verifier with the
        /// transport's extra roots, wrapped in OneCRL where it applies.
        #[cfg(native_h3)]
        pub fn verifier(&self) -> &Arc<dyn rustls::client::danger::ServerCertVerifier> {
            &self.verifier
        }

        /// The configuration offering `http/1.1` alone, with the platform
        /// verifier (and OneCRL, where it applies) — what the native
        /// backend's `http-kit-tls` handshakes run with.
        #[cfg(native_backend)]
        pub const fn http1_config(&self) -> &Arc<ClientConfig> {
            &self.http1_config
        }

        /// The shared client configuration; `transport::quic` clones it with
        /// ALPN `h3` for QUIC connections.
        #[cfg(http3)]
        pub const fn client_config(&self) -> &Arc<ClientConfig> {
            &self.base
        }

        /// The TLS handshake with `host`:`port`, the `hop` of the route, over
        /// `stream`.
        ///
        /// # Errors
        ///
        /// `host` is no server name, or the handshake failed.
        #[cfg(connector)]
        pub async fn connect<S>(
            &self,
            hop: Hop,
            host: &str,
            port: u16,
            stream: S,
            protocols: Protocols,
        ) -> Result<TlsStream<S>, Error>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            let server_name = ServerName::try_from(host.to_owned()).map_err(|error| {
                Error::InvalidUri(format!("{host}: not a TLS server name: {error}"))
            })?;
            let connector = match protocols {
                Protocols::Http1 => &self.http1,
                Protocols::Http2OrHttp1 => &self.http2_or_http1,
            };
            connector
                .connect(server_name, stream)
                .await
                .map_err(|error| {
                    Error::connect(hop, host, port, ConnectFailure::Tls(failure(error)))
                })
        }
    }

    /// How a handshake failed through `futures-rustls`.
    ///
    /// rustls's `io` adapters report a TLS failure as an
    /// [`io::ErrorKind::InvalidData`] error whose payload is the
    /// [`rustls::Error`] (the contract of `rustls::Connection`'s `io::Read`
    /// and `io::Write`, which futures-rustls forwards), so the typed error
    /// comes back out of the `io::Error` once, here. A transport failure or a
    /// peer closing mid-handshake is no `rustls::Error`: it stays the
    /// `io::Error`.
    #[cfg(connector)]
    fn failure(error: io::Error) -> TlsError {
        match error.downcast::<rustls::Error>() {
            Ok(error) => TlsError::new(TlsFailure::of_rustls(&error), Cause::Rustls(error)),
            Err(error) => TlsError::new(TlsFailure::Protocol, Cause::from(error)),
        }
    }

    /// The protocol `stream`'s TLS session negotiated through ALPN, if any.
    ///
    /// Infallible for rustls — the signature matches the native-tls engine.
    #[cfg(connector)]
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
    use crate::{Cause, ConnectFailure, Error, ExchangeFailure, Hop, TlsError, TlsFailure};

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
            let certificate =
                native_tls::Certificate::from_der(root).map_err(Error::trust_store)?;
            builder.add_root_certificate(certificate);
        }
        builder.request_alpns(alpns);
        Ok(Connector::new(builder.build().map_err(Error::tls_config)?))
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

        /// The TLS handshake with `host`:`port`, the `hop` of the route, over
        /// `stream`.
        ///
        /// # Errors
        ///
        /// The handshake failed. `native-tls` reports no classification, so
        /// the failure is [`TlsFailure::Unclassified`].
        pub async fn connect<S>(
            &self,
            hop: Hop,
            host: &str,
            port: u16,
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
            connector.connect(host, stream).await.map_err(|error| {
                Error::connect(
                    hop,
                    host,
                    port,
                    ConnectFailure::Tls(TlsError::new(
                        TlsFailure::Unclassified,
                        Cause::NativeTls(error),
                    )),
                )
            })
        }
    }

    /// The protocol `stream`'s TLS session negotiated through ALPN, if any.
    pub fn negotiated_alpn<S>(stream: &TlsStream<S>) -> Result<Option<Vec<u8>>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        stream
            .negotiated_alpn()
            .map_err(|error| Error::exchange(ExchangeFailure::Tls, Cause::NativeTls(error)))
    }
}

pub use engine::TlsConnector;
#[cfg(all(test, tls_rustls))]
pub use engine::VerifierWrap;
#[cfg(connector)]
pub use engine::{TlsStream, negotiated_alpn};

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}
