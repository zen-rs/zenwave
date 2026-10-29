//! The byte stream a connection ends up on, and its adapter for hyper.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use async_net::TcpStream;
#[cfg(unix_socket)]
use async_net::unix::UnixStream;
use futures_io::{AsyncRead, AsyncWrite};

use super::tls::{self, TlsStream};

/// A connected stream: plain TCP or a unix domain socket, TLS over either,
/// or TLS to the target inside TLS to an HTTPS proxy.
pub enum Stream {
    Tcp(TcpStream),
    /// Plaintext on a unix domain socket.
    #[cfg(unix_socket)]
    Unix(UnixStream),
    Tls(Box<TlsStream<TcpStream>>),
    /// TLS on a unix domain socket.
    #[cfg(unix_socket)]
    TlsOverUnix(Box<TlsStream<UnixStream>>),
    TlsOverTls(Box<TlsStream<TlsStream<TcpStream>>>),
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(_) => f.write_str("Stream::Tcp"),
            #[cfg(unix_socket)]
            Self::Unix(_) => f.write_str("Stream::Unix"),
            Self::Tls(_) => f.write_str("Stream::Tls"),
            #[cfg(unix_socket)]
            Self::TlsOverUnix(_) => f.write_str("Stream::TlsOverUnix"),
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
            #[cfg(unix_socket)]
            Self::Unix(_) => Ok(None),
            Self::Tls(stream) => tls::negotiated_alpn(stream),
            #[cfg(unix_socket)]
            Self::TlsOverUnix(stream) => tls::negotiated_alpn(stream),
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
            #[cfg(unix_socket)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix_socket)]
            Self::TlsOverUnix(stream) => Pin::new(stream).poll_read(cx, buf),
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
            #[cfg(unix_socket)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix_socket)]
            Self::TlsOverUnix(stream) => Pin::new(stream).poll_write(cx, buf),
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
            #[cfg(unix_socket)]
            Self::Unix(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(unix_socket)]
            Self::TlsOverUnix(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix_socket)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix_socket)]
            Self::TlsOverUnix(stream) => Pin::new(stream).poll_flush(cx),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(unix_socket)]
            Self::Unix(stream) => Pin::new(stream).poll_close(cx),
            Self::Tls(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(unix_socket)]
            Self::TlsOverUnix(stream) => Pin::new(stream).poll_close(cx),
            Self::TlsOverTls(stream) => Pin::new(stream).poll_close(cx),
        }
    }
}
