//! A hickory `RuntimeProvider` on async-io/async-net: timers through
//! `async_io::Timer`, UDP through `async_net::UdpSocket`, TCP through
//! `async_net::TcpStream`, and background tasks through the caller's
//! [`Spawn`] closure.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    thread,
    time::Duration,
};

use async_io::{Async, Timer};
use async_net::{TcpStream, UdpSocket};
use async_trait::async_trait;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::{FutureExt, future::Either, future::select, pin_mut};
use hickory_resolver::net::runtime::{
    DnsTcpStream, DnsUdpSocket, RuntimeProvider, Spawn as HickorySpawn, Time,
};

use super::Spawn;

/// Runs hickory's resolver on async-io/async-net.
///
/// Cheap to clone: the provider is only a spawn closure.
#[derive(Clone)]
pub(super) struct AsyncIoRuntimeProvider {
    spawn: Spawn,
}

impl AsyncIoRuntimeProvider {
    /// A provider that runs every background task on a dedicated thread —
    /// the same fallback `HyperBackend` uses when no executor is supplied.
    pub(super) fn thread_per_task() -> Self {
        Self {
            spawn: Arc::new(|future| {
                thread::spawn(move || {
                    async_io::block_on(future);
                });
            }),
        }
    }
}

impl RuntimeProvider for AsyncIoRuntimeProvider {
    type Handle = AsyncIoHandle;
    type Timer = AsyncIoTime;
    type Udp = AsyncIoUdpSocket;
    type Tcp = AsyncIoTcpStream;

    fn create_handle(&self) -> Self::Handle {
        AsyncIoHandle(self.spawn.clone())
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        Box::pin(async move {
            let connect = async move {
                let stream = match bind_addr {
                    Some(bind_addr) => connect_bound(server_addr, bind_addr).await?,
                    None => TcpStream::connect(server_addr).await?,
                };
                stream.set_nodelay(true)?;
                Ok(AsyncIoTcpStream(stream))
            };
            match wait_for {
                Some(timeout) => AsyncIoTime::timeout(timeout, connect).await?,
                None => connect.await,
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        Box::pin(async move {
            let socket = UdpSocket::bind(local_addr).await?;
            Ok(AsyncIoUdpSocket(socket.into()))
        })
    }
}

/// Connect with the local address pinned. `async_net::TcpStream` cannot bind
/// before connecting, so the socket is built and driven here instead.
async fn connect_bound(server_addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<TcpStream> {
    let domain = if server_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    socket.bind(&bind_addr.into())?;
    match socket.connect(&server_addr.into()) {
        // In progress is the expected outcome on a nonblocking socket.
        Err(error) if in_progress(&error) => {}
        result => result?,
    }
    let stream = Async::new_nonblocking(std::net::TcpStream::from(socket))?;
    stream.writable().await?;
    if let Some(error) = stream.get_ref().take_error()? {
        return Err(error);
    }
    Ok(stream.into())
}

/// Whether a failed nonblocking `connect` is an in-progress attempt rather
/// than an error: `EINPROGRESS` on unix, `WSAEWOULDBLOCK` elsewhere.
#[cfg(unix)]
fn in_progress(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EINPROGRESS)
}

#[cfg(not(unix))]
fn in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

/// The hickory `Handle`: hands background tasks to the spawn closure.
#[derive(Clone)]
pub(super) struct AsyncIoHandle(Spawn);

impl HickorySpawn for AsyncIoHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        (self.0)(Box::pin(future));
    }
}

/// `async_io::Timer` as hickory's `Time`.
#[derive(Clone, Copy, Debug)]
pub(super) struct AsyncIoTime;

#[async_trait]
impl Time for AsyncIoTime {
    async fn delay_for(duration: Duration) {
        Timer::after(duration).await;
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, io::Error> {
        let timer = Timer::after(duration);
        pin_mut!(future);
        pin_mut!(timer);
        match select(future.fuse(), timer.fuse()).await {
            Either::Left((output, _)) => Ok(output),
            Either::Right(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "operation timed out",
            )),
        }
    }
}

/// `async_net::UdpSocket` adapted to hickory's `DnsUdpSocket`. The inner
/// `Async` is kept for poll access, which the async wrappers don't expose.
pub(super) struct AsyncIoUdpSocket(Arc<Async<std::net::UdpSocket>>);

#[async_trait]
impl DnsUdpSocket for AsyncIoUdpSocket {
    type Time = AsyncIoTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        loop {
            match self.0.get_ref().recv_from(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    match self.0.poll_readable(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.0.get_ref().send_to(buf, target) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    match self.0.poll_writable(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                result => return Poll::Ready(result),
            }
        }
    }
}

/// `async_net::TcpStream` adapted to hickory's `DnsTcpStream`.
pub(super) struct AsyncIoTcpStream(TcpStream);

impl AsyncRead for AsyncIoTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for AsyncIoTcpStream {
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

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl DnsTcpStream for AsyncIoTcpStream {
    type Time = AsyncIoTime;
}
