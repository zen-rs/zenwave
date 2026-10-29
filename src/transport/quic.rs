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
    time::Duration,
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

/// How long a QUIC connection may sit without packets before the endpoint
/// closes it — the dead-peer detector. This is quinn's default, restated
/// explicitly so [`QUIC_KEEP_ALIVE_INTERVAL`] can be justified against it.
const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often an otherwise-quiet QUIC connection sends a keep-alive packet.
/// RFC 9000 §10.1.2 lets an endpoint defer the idle timeout by sending
/// ack-eliciting packets, and since a lost one is not retransmitted the
/// interval must leave room for more than one within the timeout: a third
/// of [`QUIC_MAX_IDLE_TIMEOUT`] survives two lost keep-alives. Without it a
/// request whose response takes longer than the idle timeout to start dies
/// mid-wait even though nothing is wrong with the connection (#93).
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// QUIC client TLS derived from the transport's shared rustls configuration:
/// the same verifier and extra roots, with ALPN fixed to `h3`.
pub fn client_config(base: &rustls::ClientConfig) -> Result<quinn::ClientConfig, Error> {
    client_config_with_timeouts(base, QUIC_MAX_IDLE_TIMEOUT, Some(QUIC_KEEP_ALIVE_INTERVAL))
}

/// `client_config` with the idle and keep-alive durations passed in — the
/// tests shrink them so the wait stays short, and `None` keep-alive is the
/// negative control.
fn client_config_with_timeouts(
    base: &rustls::ClientConfig,
    max_idle_timeout: Duration,
    keep_alive_interval: Option<Duration>,
) -> Result<quinn::ClientConfig, Error> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            max_idle_timeout
                .try_into()
                .map_err(|error| Error::Transport(Box::new(error)))?,
        ))
        .keep_alive_interval(keep_alive_interval);
    let mut config = base.clone();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(config)
        .map_err(|error| Error::Transport(Box::new(error)))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::TryStreamExt;

    use super::{QUIC_KEEP_ALIVE_INTERVAL, QUIC_MAX_IDLE_TIMEOUT, client_config_with_timeouts};
    use crate::{
        Transport,
        backend::{
            h3::H3Connection,
            test_support::{H3Server, TestCa, block_on_test, thread_spawn},
        },
    };

    /// The idle timeout the tests run against — short enough that `/delayed`'s
    /// 2 s response crosses it, keeping the suite fast.
    const IDLE: Duration = Duration::from_secs(1);
    /// Well inside `IDLE`: three keep-alives land before it fires.
    const KEEP_ALIVE: Duration = Duration::from_millis(300);

    fn request(uri: String) -> http::Request<http_kit::Body> {
        http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(http_kit::Body::empty())
            .expect("request builds")
    }

    async fn body_bytes(body: http_kit::Body) -> Vec<u8> {
        body.try_collect::<Vec<Bytes>>()
            .await
            .expect("body is valid")
            .concat()
    }

    /// A client h3 connection to `server` with the test idle timeout and the
    /// given keep-alive. The returned `Transport` owns the shared QUIC
    /// endpoint and must outlive the connection.
    async fn connect(server: &H3Server, keep_alive: Option<Duration>) -> (Transport, H3Connection) {
        let transport = server.transport();
        let spawn = thread_spawn();
        let endpoint = transport
            .quic_endpoint(spawn.clone())
            .expect("client endpoint binds");
        let config = client_config_with_timeouts(transport.tls().client_config(), IDLE, keep_alive)
            .expect("QUIC client config");
        let connection =
            H3Connection::connect(endpoint, config, server.addr(), "localhost", &spawn)
                .await
                .expect("h3 connection is established");
        (transport, connection)
    }

    /// The production constants must keep the keep-alive interval well inside
    /// the idle timeout (RFC 9000 §10.1.2) — the property the fix rests on.
    #[test]
    fn keep_alive_interval_sits_well_inside_the_idle_timeout() {
        assert!(QUIC_KEEP_ALIVE_INTERVAL * 2 < QUIC_MAX_IDLE_TIMEOUT);
    }

    /// `/delayed` answers 2 s after the request — beyond the client's 1 s
    /// idle timeout — so the response only arrives because keep-alive
    /// packets defer the timeout (RFC 9000 §10.1.2). This is the #93
    /// reproducer: before the fix every such request died at the timeout.
    #[test]
    fn keep_alive_holds_the_connection_past_the_idle_timeout() {
        let server = H3Server::start(&TestCa::new());
        block_on_test(async {
            let (_transport, mut connection) = connect(&server, Some(KEEP_ALIVE)).await;
            let response = connection
                .request(request(server.uri("/delayed")))
                .await
                .expect("the request survives the server's delay");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(
                body_bytes(response.into_body()).await,
                b"delayed hello over h3"
            );
        });
    }

    /// Negative control of the same setup: with keep-alive disabled the idle
    /// timeout fires mid-request and the request dies — the failure #93
    /// reports.
    #[test]
    fn without_keep_alive_the_idle_timeout_kills_the_request() {
        let server = H3Server::start(&TestCa::new());
        block_on_test(async {
            let (_transport, mut connection) = connect(&server, None).await;
            let error = connection
                .request(request(server.uri("/delayed")))
                .await
                .expect_err("the request must die with the idle timeout");
            assert!(
                error
                    .to_string()
                    .to_lowercase()
                    .replace(' ', "")
                    .contains("timeout"),
                "the failure must be the QUIC idle timeout, got: {error}"
            );
        });
    }
}
