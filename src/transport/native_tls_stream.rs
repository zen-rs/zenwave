//! `native-tls` driven on a `futures-io` stream.
//!
//! `async-native-tls` wraps `native_tls::TlsStream` privately and exposes no
//! accessor for the negotiated ALPN protocol, which HTTP/2 negotiation needs,
//! so the adapter lives in-tree. The technique is the same one that crate
//! uses: `native-tls` drives a blocking-looking [`StdAdapter`] whose `Read` /
//! `Write` operations poll the async stream under a stashed task context and
//! report `WouldBlock` when the poll pends.

use std::{
    fmt,
    io::{self, Read, Write},
    pin::Pin,
    ptr::null_mut,
    task::{Context, Poll},
};

use futures_io::{AsyncRead, AsyncWrite};
use native_tls::{Error, HandshakeError, MidHandshakeTlsStream};

/// A blocking facade over an async stream for `native-tls` to drive.
///
/// `context` carries the task context of the in-flight poll; it is set before
/// every operation that can reach the inner stream and cleared on the way out.
#[derive(Debug)]
pub struct StdAdapter<S> {
    inner: S,
    context: *mut (),
}

// The context pointer is only dereferenced synchronously inside `with_context`
// while a poll holds `&mut self`; it is never shared or sent itself.
unsafe impl<S: Send> Send for StdAdapter<S> {}
unsafe impl<S: Sync> Sync for StdAdapter<S> {}

impl<S: Unpin> StdAdapter<S> {
    fn with_context<R>(&mut self, f: impl FnOnce(&mut Context<'_>, Pin<&mut S>) -> R) -> R {
        assert!(!self.context.is_null());
        // SAFETY: `context` is set to the poll's `Context` by the `TlsStream`
        // or handshake future that owns this adapter, and is only dereferenced
        // while that poll is running.
        let context = unsafe { &mut *self.context.cast::<Context<'_>>() };
        f(context, Pin::new(&mut self.inner))
    }
}

impl<S: AsyncRead + Unpin> Read for StdAdapter<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.with_context(|cx, stream| stream.poll_read(cx, buf)) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S: AsyncWrite + Unpin> Write for StdAdapter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.with_context(|cx, stream| stream.poll_write(cx, buf)) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.with_context(|cx, stream| stream.poll_flush(cx)) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

/// A `native_tls::TlsConnector` for async streams.
#[derive(Clone)]
pub struct TlsConnector(native_tls::TlsConnector);

impl TlsConnector {
    /// Wrap a configured `native-tls` connector.
    pub const fn new(inner: native_tls::TlsConnector) -> Self {
        Self(inner)
    }

    /// Start TLS on `stream`, completing the handshake across polls.
    ///
    /// # Errors
    ///
    /// Returns the `native-tls` error when the handshake fails.
    pub async fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Handshake {
            state: HandshakeState::Start {
                connector: self.0.clone(),
                domain: domain.to_owned(),
                stream: Some(stream),
            },
        }
        .await
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}

/// The TLS session produced by [`TlsConnector::connect`].
#[derive(Debug)]
pub struct TlsStream<S>(native_tls::TlsStream<StdAdapter<S>>);

impl<S> TlsStream<S>
where
    StdAdapter<S>: Read + Write,
{
    /// Run `f` on the blocking stream with `cx` stashed for [`StdAdapter`].
    fn with_context<R>(
        &mut self,
        cx: &mut Context<'_>,
        f: impl FnOnce(&mut native_tls::TlsStream<StdAdapter<S>>) -> R,
    ) -> R {
        self.0.get_mut().context = std::ptr::from_mut(cx).cast::<()>();
        let guard = ContextGuard(self);
        f(&mut (guard.0).0)
    }

    /// The ALPN protocol the peer picked, when it picked one.
    ///
    /// # Errors
    ///
    /// Returns the `native-tls` error when the platform TLS layer cannot
    /// report the negotiated protocol.
    pub fn negotiated_alpn(&self) -> Result<Option<Vec<u8>>, Error> {
        self.0.negotiated_alpn()
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(cx, |stream| ready(stream.read(buf)))
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(cx, |stream| ready(stream.write(buf)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context(cx, |stream| ready(stream.flush()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context(cx, |stream| ready(stream.shutdown()))
    }
}

/// Clears the stashed task context when the operation ends — even on panic —
/// so a stale pointer never survives the poll that set it.
struct ContextGuard<'a, S>(&'a mut TlsStream<S>);

impl<S> Drop for ContextGuard<'_, S> {
    fn drop(&mut self) {
        self.0.0.get_mut().context = null_mut();
    }
}

/// The future behind [`TlsConnector::connect`].
struct Handshake<S: Unpin> {
    state: HandshakeState<S>,
}

enum HandshakeState<S: Unpin> {
    Start {
        connector: native_tls::TlsConnector,
        domain: String,
        stream: Option<S>,
    },
    Mid(MidHandshakeTlsStream<StdAdapter<S>>),
    Done,
}

impl<S> std::future::Future for Handshake<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<TlsStream<S>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.state {
            HandshakeState::Start {
                connector,
                domain,
                stream,
            } => {
                let adapter = StdAdapter {
                    inner: stream.take().expect("future polled after completion"),
                    context: std::ptr::from_mut(cx).cast::<()>(),
                };
                match connector.connect(domain, adapter) {
                    Ok(mut stream) => {
                        stream.get_mut().context = null_mut();
                        Poll::Ready(Ok(TlsStream(stream)))
                    }
                    Err(HandshakeError::Failure(error)) => Poll::Ready(Err(error)),
                    Err(HandshakeError::WouldBlock(mut mid)) => {
                        mid.get_mut().context = null_mut();
                        self.state = HandshakeState::Mid(mid);
                        Poll::Pending
                    }
                }
            }
            HandshakeState::Mid(_) => {
                let HandshakeState::Mid(mut mid) =
                    std::mem::replace(&mut self.state, HandshakeState::Done)
                else {
                    unreachable!()
                };
                mid.get_mut().context = std::ptr::from_mut(cx).cast::<()>();
                match mid.handshake() {
                    Ok(mut stream) => {
                        stream.get_mut().context = null_mut();
                        Poll::Ready(Ok(TlsStream(stream)))
                    }
                    Err(HandshakeError::Failure(error)) => Poll::Ready(Err(error)),
                    Err(HandshakeError::WouldBlock(mut mid)) => {
                        mid.get_mut().context = null_mut();
                        self.state = HandshakeState::Mid(mid);
                        Poll::Pending
                    }
                }
            }
            HandshakeState::Done => panic!("future polled after completion"),
        }
    }
}

/// `WouldBlock` becomes `Pending`; anything else resolves the poll.
fn ready<T>(result: io::Result<T>) -> Poll<io::Result<T>> {
    match result {
        Ok(value) => Poll::Ready(Ok(value)),
        Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(error) => Poll::Ready(Err(error)),
    }
}
