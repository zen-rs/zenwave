//! The byte stream a connection ends up on, and its adapter for hyper.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use async_net::TcpStream;
use futures_io::{AsyncRead, AsyncWrite};

use super::tls::{self, TlsStream};

/// A connected stream: plain TCP, TLS over TCP, or TLS to the target inside
/// TLS to an HTTPS proxy.
pub enum Stream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    TlsOverTls(Box<TlsStream<TlsStream<TcpStream>>>),
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(_) => f.write_str("Stream::Tcp"),
            Self::Tls(_) => f.write_str("Stream::Tls"),
            Self::TlsOverTls(_) => f.write_str("Stream::TlsOverTls"),
        }
    }
}

impl Stream {
    /// The ALPN protocol negotiated on the innermost TLS layer, or `None` for
    /// plaintext connections and peers that picked no protocol.
    ///
    /// # Errors
    ///
    /// Returns the TLS engine's error when it cannot report the negotiated
    /// protocol (native-tls only; rustls is infallible).
    pub fn negotiated_alpn(&self) -> Result<Option<Vec<u8>>, crate::Error> {
        match self {
            Self::Tcp(_) => Ok(None),
            Self::Tls(stream) => tls::negotiated_alpn(stream),
            Self::TlsOverTls(stream) => tls::negotiated_alpn(stream),
        }
    }
}

impl Unpin for Stream {}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_close(cx),
            Self::Tls(stream) => Pin::new(stream).poll_close(cx),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_close(cx),
        }
    }
}
