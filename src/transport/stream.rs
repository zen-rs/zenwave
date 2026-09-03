//! The byte stream a connection ends up on, and its adapter for hyper.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use async_net::TcpStream;
use futures_io::{AsyncRead, AsyncWrite};

use super::tls::TlsStream;

/// A connected stream: plain TCP, or TLS over TCP.
pub enum Stream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(_) => f.write_str("Stream::Tcp"),
            Self::Tls(_) => f.write_str("Stream::Tls"),
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
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_close(cx),
            Self::Tls(stream) => Pin::new(stream).poll_close(cx),
        }
    }
}

/// Adapts a `futures-io` stream to hyper's I/O traits.
#[cfg(feature = "hyper-backend")]
#[derive(Debug)]
pub struct HyperIo<S>(pub S);

#[cfg(feature = "hyper-backend")]
impl<S: AsyncRead + Unpin> hyper::rt::Read for HyperIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: the cursor hands out its uninitialised tail; `poll_read` only
        // writes into it and `advance` is called with the count it reported.
        let slice = unsafe { buf.as_mut() };
        let bytes = unsafe { &mut *(std::ptr::from_mut(slice) as *mut [u8]) };
        match Pin::new(&mut self.0).poll_read(cx, bytes) {
            Poll::Ready(Ok(n)) => {
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "hyper-backend")]
impl<S: AsyncWrite + Unpin> hyper::rt::Write for HyperIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }
}
