//! QUIC transport on async-io: the `quinn::Runtime` implementation and the
//! TLS configuration h3 connections are dialed with.
//!
//! quinn's bundled runtimes are not used: `runtime-smol` spawns on smol's
//! global executor and `runtime-tokio` needs tokio. Timers run on
//! `async_io::Timer`, the UDP socket is driven by `async_io::Async`, and the
//! futures quinn needs driven in the background are scheduled through a
//! [`Spawn`] supplied by the caller, so the backend keeps owning how its
//! connection drivers run.

use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use async_io::Async;
use quinn::udp::{RecvMeta, Transmit, UdpSocketState};

use super::Spawn;
use crate::Error;

/// `quinn::Runtime` over async-io: `async_io::Timer` for timers, an
/// `Async<UdpSocket>` wrapper for datagrams, `spawn` for tasks.
pub struct AsyncIoRuntime {
    pub spawn: Spawn,
}

impl fmt::Debug for AsyncIoRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncIoRuntime").finish_non_exhaustive()
    }
}

impl quinn::Runtime for AsyncIoRuntime {
    fn new_timer(&self, t: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        Box::pin(Timer(async_io::Timer::at(t)))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        (self.spawn)(future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        Ok(Arc::new(UdpSocket::new(socket)?))
    }
}

/// `async_io::Timer` adapted to `quinn::AsyncTimer`.
#[derive(Debug)]
struct Timer(async_io::Timer);

impl quinn::AsyncTimer for Timer {
    fn reset(mut self: Pin<&mut Self>, t: std::time::Instant) {
        self.0.set_at(t);
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.0).poll(cx).map(|_| ())
    }
}

/// A `std` UDP socket driven by async-io, adapted to `quinn::AsyncUdpSocket`
/// the way quinn's own smol/async-std runtimes do it.
#[derive(Debug)]
struct UdpSocket {
    io: Async<std::net::UdpSocket>,
    inner: UdpSocketState,
}

impl UdpSocket {
    fn new(socket: std::net::UdpSocket) -> io::Result<Self> {
        Ok(Self {
            inner: UdpSocketState::new((&socket).into())?,
            io: Async::new_nonblocking(socket)?,
        })
    }
}

impl quinn::AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(UdpPollHelper {
            make_fut: move || {
                let socket = self.clone();
                Box::pin(async move { socket.io.writable().await })
            },
            fut: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.send((&self.io).into(), transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_readable(cx))?;
            if let Ok(result) = self.inner.recv((&self.io).into(), bufs, meta) {
                return Poll::Ready(Ok(result));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.as_ref().local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

type PollerFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

/// Turns a constructor of single-use writable futures into a `quinn::UdpPoller`
/// usable indefinitely: the current future is kept until it resolves, then a
/// fresh one is created on the next call. (quinn's own `UdpPollHelper` is only
/// compiled when one of its bundled runtimes is enabled.)
struct UdpPollHelper<MakeFut>
where
    MakeFut: Fn() -> PollerFuture + Send + Sync + Unpin + 'static,
{
    make_fut: MakeFut,
    fut: Option<PollerFuture>,
}

impl<MakeFut> quinn::UdpPoller for UdpPollHelper<MakeFut>
where
    MakeFut: Fn() -> PollerFuture + Send + Sync + Unpin + 'static,
{
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fut.is_none() {
            this.fut = Some((this.make_fut)());
        }
        let result = this
            .fut
            .as_mut()
            .expect("poller future is set")
            .as_mut()
            .poll(cx);
        if result.is_ready() {
            // Polling a resolved future is an error, so a fresh one is made on
            // the next call.
            this.fut = None;
        }
        result
    }
}

impl<MakeFut> fmt::Debug for UdpPollHelper<MakeFut>
where
    MakeFut: Fn() -> PollerFuture + Send + Sync + Unpin + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPollHelper").finish_non_exhaustive()
    }
}

/// A client QUIC endpoint: one dual-stack UDP socket driven by the async-io
/// runtime. `Transport` keeps it in a `OnceCell` so every h3 connection
/// through the transport shares it.
pub fn endpoint(spawn: Spawn) -> Result<quinn::Endpoint, Error> {
    // `IPV6_V6ONLY` defaults differ per platform — on Windows and the BSDs a
    // v6 wildcard socket would not reach IPv4 remotes — so it is set
    // explicitly and one socket serves both address families.
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|error| Error::Transport(Box::new(error)))?;
    socket
        .set_only_v6(false)
        .map_err(|error| Error::Transport(Box::new(error)))?;
    socket
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())
        .map_err(|error| Error::Transport(Box::new(error)))?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket.into(),
        Arc::new(AsyncIoRuntime { spawn }),
    )
    .map_err(|error| Error::Transport(Box::new(error)))
}

/// QUIC client TLS derived from the transport's shared rustls configuration:
/// the same verifier and extra roots, with ALPN fixed to `h3`.
pub fn client_config(base: &rustls::ClientConfig) -> Result<quinn::ClientConfig, Error> {
    let mut config = base.clone();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(config)
        .map_err(|error| Error::Transport(Box::new(error)))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}
