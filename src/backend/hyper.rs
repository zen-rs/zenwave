use async_io::block_on;
use async_net::TcpStream;
use core::future::Future;
use executor_core::{AnyExecutor, Executor};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::TryStreamExt;
use http::StatusCode;
use http_body_util::BodyDataStream;
use http_kit::{Endpoint, HttpError, Method, Request, Response};
use hyper::http;
use std::{
    mem::replace,
    pin::Pin,
    task::{Context, Poll},
    thread,
};

use crate::Client;

/// Hyper-based HTTP client backend powered by `async-io`/`async-net`.
#[derive(Debug, Default)]
pub struct HyperBackend {
    executor: Option<AnyExecutor>,
}

impl HyperBackend {
    /// Create a new `HyperBackend`.
    #[must_use]
    pub const fn new() -> Self {
        Self { executor: None }
    }

    /// Create a `HyperBackend` that uses the provided executor for background tasks.
    #[must_use]
    pub fn with_executor(executor: impl Executor + 'static) -> Self {
        Self {
            executor: Some(AnyExecutor::new(executor)),
        }
    }

    fn spawn_background(&self, fut: impl Future<Output = ()> + Send + 'static) {
        if let Some(executor) = &self.executor {
            executor.spawn(fut).detach();
        } else {
            thread::spawn(move || {
                block_on(fut);
            });
        }
    }
}

#[derive(Debug)]
pub enum HyperError {
    Connection(hyper::Error),
    Io(std::io::Error),
    TlsNotAvailable,
    InvalidUri(String),
    Remote {
        status: StatusCode,
        body: Option<String>,
        raw_response: Response,
    },
}

impl core::fmt::Display for HyperError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "connection error: {err}"),
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::TlsNotAvailable => write!(f, "TLS requested but no TLS feature enabled"),
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
    fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Remote { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl Endpoint for HyperBackend {
    type Error = HyperError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(http_kit::Body::empty())
            .unwrap();
        let mut request: http::Request<http_kit::Body> = replace(request, dummy_request);

        // Ensure Host header is present (required by hyper 1.0 / HTTP 1.1)
        if request.headers().get(http::header::HOST).is_none() {
            if let Some(authority) = request.uri().authority() {
                if let Ok(value) = http::header::HeaderValue::from_str(authority.as_str()) {
                    request.headers_mut().insert(http::header::HOST, value);
                }
            }
        }

        let stream = connect(&request).await?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(stream)
            .await
            .map_err(HyperError::Connection)?;

        // Drive the connection in the background.
        self.spawn_background(async move {
            if let Err(err) = connection.await {
                eprintln!("hyper connection error: {err}");
            }
        });

        let response = sender
            .send_request(request)
            .await
            .map_err(HyperError::Connection)?;

        let mut response = response.map(|body| {
            let stream = BodyDataStream::new(body);
            let stream = stream.map_err(|error| {
                http_kit::BodyError::Other(Box::new(error)) // TODO: improve error conversion
            });
            http_kit::Body::from_stream(stream)
        });

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
                raw_response: response,
            });
        }

        Ok(response)
    }
}

impl Client for HyperBackend {}

async fn connect(request: &http::Request<http_kit::Body>) -> Result<MaybeTlsStream, HyperError> {
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| HyperError::InvalidUri(uri.to_string()))?
        .to_string();
    let scheme = uri.scheme_str().unwrap_or("http");
    let use_tls = match scheme {
        "https" => true,
        "http" => false,
        other => return Err(HyperError::InvalidUri(other.to_string())),
    };
    let port = uri.port_u16().unwrap_or(if use_tls { 443 } else { 80 });

    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(HyperError::Io)?;
    stream.set_nodelay(true).map_err(HyperError::Io)?;

    if use_tls {
        // TLS selection logic:
        // 1. When both native-tls and rustls are enabled (default-backend):
        //    - On Apple platforms: use native-tls
        //    - On other platforms: use rustls with system certificates
        // 2. When only native-tls is enabled: use native-tls
        // 3. When only rustls is enabled: use rustls with system certificates

        // Case: Both TLS implementations available, Apple platform -> use native-tls
        #[cfg(all(feature = "native-tls", feature = "rustls", target_vendor = "apple"))]
        {
            let connector = async_native_tls::TlsConnector::new();
            let tls = connector
                .connect(host.as_str(), stream)
                .await
                .map_err(|err| HyperError::Io(std::io::Error::other(err)))?;
            return Ok(MaybeTlsStream::Native(tls));
        }

        // Case: Both TLS implementations available, non-Apple platform -> use rustls
        #[cfg(all(
            feature = "native-tls",
            feature = "rustls",
            not(target_vendor = "apple")
        ))]
        {
            return connect_rustls(host, stream).await;
        }

        // Case: Only native-tls enabled
        #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
        {
            let connector = async_native_tls::TlsConnector::new();
            let tls = connector
                .connect(host.as_str(), stream)
                .await
                .map_err(|err| HyperError::Io(std::io::Error::other(err)))?;
            return Ok(MaybeTlsStream::Native(tls));
        }

        // Case: Only rustls enabled
        #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
        {
            return connect_rustls(host, stream).await;
        }

        #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
        {
            return Err(HyperError::TlsNotAvailable);
        }
    }

    Ok(MaybeTlsStream::Plain(stream))
}

/// Connect using rustls with system certificates.
#[cfg(feature = "rustls")]
#[allow(dead_code)] // Used on non-Apple platforms; unused on Apple when both TLS features enabled
async fn connect_rustls(host: String, stream: TcpStream) -> Result<MaybeTlsStream, HyperError> {
    use std::sync::Arc;

    use futures_rustls::{
        TlsConnector,
        client::TlsStream as RustlsStream,
        rustls::{self, pki_types::ServerName},
    };

    // Load system certificates
    let mut root_store = rustls::RootCertStore::empty();

    // Load system certificates (rustls-native-certs returns CertificateResult with certs and errors)
    let cert_result = rustls_native_certs::load_native_certs();
    for cert in cert_result.certs {
        // Ignore invalid certificates, just skip them
        let _ = root_store.add(cert);
    }

    // If no system certs were loaded, fall back to webpki roots
    if root_store.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.clone())
        .map_err(|err| HyperError::Io(std::io::Error::other(err)))?;

    let stream: RustlsStream<TcpStream> = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| HyperError::Io(std::io::Error::other(err)))?;
    Ok(MaybeTlsStream::Rustls(Box::new(stream)))
}

enum MaybeTlsStream {
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    Native(async_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls")]
    #[allow(dead_code)]
    // Used on non-Apple platforms; unused on Apple when both TLS features enabled
    Rustls(Box<futures_rustls::client::TlsStream<TcpStream>>),
}

impl Unpin for MaybeTlsStream {}

impl hyper::rt::Read for MaybeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let slice = unsafe { buf.as_mut() };
        let bytes = unsafe { &mut *(std::ptr::from_mut(slice) as *mut [u8]) };

        let result = match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, bytes),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_read(cx, bytes),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_read(cx, bytes),
        };

        match result {
            Poll::Ready(Ok(n)) => {
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::rt::Write for MaybeTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_close(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(feature = "native-tls")]
            Self::Native(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(feature = "rustls")]
            Self::Rustls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }
}
