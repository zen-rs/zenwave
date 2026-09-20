//! Adapts `futures-io` streams to hyper's I/O traits.
//!
//! Kept deliberately free of `crate::` imports so integration tests can
//! include it directly (`#[path]` in `tests/common`) when they drive a hyper
//! server over `futures-io` streams.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures_io::{AsyncRead, AsyncWrite};

/// Adapts a `futures-io` stream to hyper's I/O traits.
#[derive(Debug)]
pub struct HyperIo<S>(pub S);

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
