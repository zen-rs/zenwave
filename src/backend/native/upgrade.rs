//! Handing the stream a `101 Switching Protocols` switched to the caller.
//!
//! The switched stream belongs to the connection's thread: the thread whose
//! runtime runs the backend's pool, where an `http-kit-io` socket is `!Send`
//! (compio's are). So the stream itself never travels: the `101` response
//! carries an [`Upgrade`] token, `Send + Sync` as `http::Extensions` demands,
//! and [`Upgrade::switched`], awaited on that same thread, asks the
//! connection's driver for the stream and receives it there.
//!
//! A thread-per-core caller builds its backend with
//! [`NativeBackend::on_current_thread`](super::NativeBackend::on_current_thread),
//! so its pool, its connections and its switched streams all live on the
//! caller's own thread, beside whatever else that thread runs (the
//! downstream half of a proxied upgrade, for one).

use std::{
    fmt, io,
    marker::PhantomData,
    mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    thread::{self, ThreadId},
};

use futures_channel::oneshot;
use futures_io::{AsyncRead, AsyncWrite};
use http_kit::{Response, utils::Bytes};
#[cfg(any(target_os = "linux", target_os = "android"))]
use http_kit_io::splice::SpliceDuplex;
use http_kit_io::{Read, SpliceRead, SpliceWrite, Write, poll::CopyingPoll};

use super::connect::Rejoined;
use crate::{Cause, Error, ExchangeFailure};

/// Where a claim's stream is sent: made by the claiming future, on the
/// connection's thread, and answered by the driver on that same thread.
struct Reply(oneshot::Sender<Switched>);

// SAFETY: a `Reply` is created by `Upgrade::switched` only after it checked
// that it runs on the connection's thread, and is received by the
// connection's driver, which runs on that thread too; the `Switched` it
// carries is created by the driver and lands in a receiver owned by a
// `Switching` future, which is `!Send` and so stays on that thread. A
// `Reply` dropped elsewhere (its channel's buffer outliving both ends) holds
// a sender that never sent, so no `Switched` is ever touched off its thread.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the field is touched only on the connection's thread, as argued above"
)]
unsafe impl Send for Reply {}

/// The token a `101` response carries in its extensions: the right to the
/// stream the response switched.
///
/// Take it with [`Upgrade::on`], then await [`Upgrade::switched`] on the
/// thread that runs the backend's pool. A token never claimed lets the
/// connection close once every clone is dropped.
#[derive(Clone)]
pub struct Upgrade {
    owner: ThreadId,
    claim: Arc<Mutex<Option<oneshot::Sender<Reply>>>>,
}

impl fmt::Debug for Upgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upgrade")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

/// The driver's half of a connection's [`Upgrade`]: where a claim arrives.
pub(super) struct Claims(oneshot::Receiver<Reply>);

/// A connection's upgrade token and the driver's half of it, made on the
/// connection's thread.
pub(super) fn channel() -> (Upgrade, Claims) {
    let (claim, claims) = oneshot::channel();
    let upgrade = Upgrade {
        owner: thread::current().id(),
        claim: Arc::new(Mutex::new(Some(claim))),
    };
    (upgrade, Claims(claims))
}

impl Claims {
    /// Hands `switched` to the claim, once one arrives; with every token
    /// dropped unclaimed, the stream is dropped here, on its thread.
    pub(super) async fn hand_over(self, switched: Switched) {
        if let Ok(Reply(reply)) = self.0.await
            && reply.send(switched).is_err()
        {
            tracing::debug!("the switched stream's claim was dropped before it arrived");
        }
    }
}

impl Upgrade {
    /// Takes the token out of a response that switched protocols: a `101`,
    /// or a `2xx` answering `CONNECT`. `None` for any other response.
    #[must_use]
    pub fn on(response: &mut Response) -> Option<Self> {
        response.extensions_mut().remove::<Self>()
    }

    /// The switched stream, once the connection's driver has handed it over.
    ///
    /// # Errors
    ///
    /// The connection ended before it switched: its pool stopped, or the
    /// server broke the exchange after its `101` head.
    ///
    /// # Panics
    ///
    /// Called on any thread but the one running the backend's pool — the
    /// thread [`NativeBackend::on_current_thread`] was called on — since the
    /// stream cannot leave that thread; or called a second time across the
    /// token's clones, since a connection switches once.
    ///
    /// [`NativeBackend::on_current_thread`]: super::NativeBackend::on_current_thread
    pub fn switched(self) -> impl Future<Output = Result<Switched, Error>> {
        assert_eq!(
            thread::current().id(),
            self.owner,
            "a switched stream is claimed on the thread running its backend's pool \
             (the one `NativeBackend::on_current_thread` was called on); \
             a backend on a driver thread cannot hand one over"
        );
        let claim = self
            .claim
            .lock()
            .expect("the claim slot holds no invariant a panic breaks")
            .take()
            .expect("a connection switches once: its stream is claimed once");
        let (reply, received) = oneshot::channel();
        // A driver that already ended hands the reply back; its sender then
        // drops here, never having sent.
        drop(claim.send(Reply(reply)));
        Switching {
            received,
            _thread: PhantomData,
        }
    }
}

/// The claim's wait for its stream. `!Send`: the stream arrives on the
/// connection's thread and must stay there.
struct Switching {
    received: oneshot::Receiver<Switched>,
    _thread: PhantomData<*const ()>,
}

impl Future for Switching {
    type Output = Result<Switched, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let received = ready!(Pin::new(&mut self.received).poll(cx));
        Poll::Ready(received.map_err(|_| {
            Error::exchange(
                ExchangeFailure::Terminated,
                Cause::Io(Arc::new(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the connection ended before handing over its switched stream",
                ))),
            )
        }))
    }
}

/// Object-safe pairing of the two stream traits, so one box holds both.
trait Stream: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> Stream for T {}

/// A switched connection's concrete halves, erased for [`Switched`] to hold:
/// polled as one `futures_io` stream, or, on Linux, handed to a forwarder as
/// the two splice steps.
trait Halves {
    /// The poll-style stream over the halves.
    fn into_poll(self: Box<Self>) -> Pin<Box<dyn Stream>>;

    /// Whether both halves can splice.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool;

    /// The halves as one end of a tunnel, `replay` being what to forward
    /// first.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn into_splice(self: Box<Self>, replay: Bytes) -> SpliceDuplex;
}

impl<R, W> Halves for Rejoined<R, W>
where
    R: Read + SpliceRead + 'static,
    W: Write + SpliceWrite + 'static,
{
    fn into_poll(self: Box<Self>) -> Pin<Box<dyn Stream>> {
        Box::pin(CopyingPoll::new(*self))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        SpliceRead::can_splice(&self.read) && SpliceWrite::can_splice(&self.write)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn into_splice(self: Box<Self>, replay: Bytes) -> SpliceDuplex {
        SpliceDuplex::new(replay, self.read, self.write)
    }
}

/// Where a [`Switched`]'s connection is: still two halves, or already read
/// or written through a poll-style view that buffers.
enum State {
    Halves(Box<dyn Halves>),
    Poll(Pin<Box<dyn Stream>>),
    /// Transient while the state is being replaced; seen only after a panic.
    Poisoned,
}

/// The stream a `101` switched: the connection's halves rejoined, first
/// yielding the bytes the server sent right after its response head.
///
/// It is the same type whatever route the connection took (plain TCP, TLS,
/// a proxy's tunnel, a unix socket), and bound to the thread its connection
/// ran on. Read and write it through `futures_io`'s traits, or, on Linux and
/// Android, forward it with [`into_splice`](Self::into_splice) without the
/// bytes entering user space.
pub struct Switched {
    /// Read off the socket with the response head, not yet handed out.
    replay: Bytes,
    io: State,
}

impl Switched {
    pub(super) fn new<R, W>(replay: Bytes, halves: Rejoined<R, W>) -> Self
    where
        R: Read + SpliceRead + 'static,
        W: Write + SpliceWrite + 'static,
    {
        Self {
            replay,
            io: State::Halves(Box::new(halves)),
        }
    }

    /// Whether [`into_splice`](Self::into_splice) would succeed: neither
    /// half has been read or written through the `futures_io` traits yet, and
    /// both can move bytes through a pipe (a plain socket, or a kernel TLS
    /// one; a TLS session in user space cannot).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[must_use]
    pub fn can_splice(&self) -> bool {
        matches!(&self.io, State::Halves(halves) if halves.can_splice())
    }

    /// This connection as one end of a tunnel, for
    /// [`SpliceDuplex::join`] to forward against another: the bytes the
    /// server sent after its `101` head are replayed first, then both
    /// directions go through the kernel.
    ///
    /// # Errors
    ///
    /// Gives the stream back when it cannot splice: a half is a TLS session
    /// in user space, or the stream was already read or written, which
    /// moved bytes into the buffers of its `futures_io` view.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn into_splice(self) -> Result<SpliceDuplex, Self> {
        if !self.can_splice() {
            return Err(self);
        }
        let Self { replay, io } = self;
        let State::Halves(halves) = io else {
            unreachable!("can_splice holds only for halves");
        };
        Ok(halves.into_splice(replay))
    }

    /// The `futures_io` view of the connection, made on first use.
    fn stream(&mut self) -> Pin<&mut dyn Stream> {
        if matches!(self.io, State::Halves(_)) {
            let State::Halves(halves) = mem::replace(&mut self.io, State::Poisoned) else {
                unreachable!("matched halves above");
            };
            self.io = State::Poll(halves.into_poll());
        }
        match &mut self.io {
            State::Poll(stream) => stream.as_mut(),
            State::Halves(_) => unreachable!("converted above"),
            State::Poisoned => panic!("a switched stream used after a panic"),
        }
    }
}

impl fmt::Debug for Switched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Switched")
            .field("replay", &self.replay.len())
            .finish_non_exhaustive()
    }
}

impl AsyncRead for Switched {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.replay.is_empty() {
            let len = self.replay.len().min(buf.len());
            buf[..len].copy_from_slice(&self.replay.split_to(len));
            return Poll::Ready(Ok(len));
        }
        self.stream().poll_read(cx, buf)
    }
}

impl AsyncWrite for Switched {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream().poll_close(cx)
    }
}
