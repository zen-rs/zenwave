//! Compile- and link-checked WASI native backend tests (`native-backend`, plus
//! `native-http3`).
//!
//! Verifies that `NativeBackend::on_current_thread` builds and links on
//! `wasm32-wasip2` and `wasm32-wasip3` over a host's `Dial`, `Datagram`,
//! `Resolve` (and `ResolveHttps` with `native-http3`) and `Timer`, with TLS
//! verified against compiled-in `webpki-roots`.
#![cfg(all(target_os = "wasi", feature = "native-backend"))]
#![expect(
    dead_code,
    reason = "some functions verify trait bounds at compile time without an OS reactor"
)]

use std::{
    any::Any,
    borrow::Borrow,
    fs::File,
    future::{Future, ready},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use executor_core::{LocalExecutor, Task};
use futures_channel::oneshot;
use futures_executor::{LocalPool, LocalSpawner};
use futures_util::{Stream, stream, task::LocalSpawnExt as _};
use http_kit_io::{
    Answer, BufResult, Datagram, DatagramSocket, Dial, IoBuf, IoBufMut, IoVectoredBuf, NoBuf, Read,
    ReadAhead, ReadOwned, Received, RecvMeta, Resolve, SendFile, SpliceRead, SpliceWrite, Split,
    TcpOptions, Timer, Write,
};
use zenwave::{Client, Proxy, Transport, backend::NativeBackend};

/// The connection and datagram socket type of a host that never opens one:
/// `Host::connect` and `Host::bind_udp` fail, and a value of this type reports
/// a closed socket.
#[derive(Debug)]
struct Closed;

fn closed() -> io::Error {
    io::ErrorKind::NotConnected.into()
}

impl Read for Closed {
    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        ready(BufResult(Err(closed()), buf))
    }
}

impl ReadOwned for Closed {
    type Buf = NoBuf;

    fn read_owned(&mut self) -> impl Future<Output = io::Result<Received<NoBuf>>> {
        ready(Ok(Received::End))
    }
}

impl ReadAhead for Closed {
    fn stop_read_ahead(&mut self) -> impl Future<Output = Vec<u8>> {
        ready(Vec::new())
    }
}

impl Write for Closed {
    fn write<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        ready(BufResult(Err(closed()), buf))
    }

    fn write_vectored<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<usize, B>> {
        ready(BufResult(Err(closed()), buf))
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        ready(Err(closed()))
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        ready(Err(closed()))
    }
}

impl SendFile for Closed {
    fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        _offset: u64,
        _len: usize,
    ) -> impl Future<Output = BufResult<usize, F>> {
        ready(BufResult(Err(closed()), file))
    }
}

impl SpliceRead for Closed {}

impl SpliceWrite for Closed {}

impl Split for Closed {
    type ReadHalf = Self;
    type WriteHalf = Self;

    fn split(self) -> (Self, Self) {
        (Self, Self)
    }
}

impl TcpOptions for Closed {
    fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        Err(closed())
    }

    fn nodelay(&self) -> io::Result<bool> {
        Err(closed())
    }
}

impl DatagramSocket for Closed {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(closed())
    }

    fn max_send_segments(&self) -> usize {
        1
    }

    fn send_from<B: IoBuf>(
        &self,
        buf: B,
        _target: SocketAddr,
        _source: Option<IpAddr>,
    ) -> impl Future<Output = BufResult<usize, B>> {
        ready(BufResult(Err(closed()), buf))
    }

    fn send_segments_from<B: IoBuf>(
        &self,
        buf: B,
        _segment_size: NonZeroU16,
        _target: SocketAddr,
        _source: Option<IpAddr>,
    ) -> impl Future<Output = BufResult<usize, B>> {
        ready(BufResult(Err(closed()), buf))
    }

    fn recv_from<B: IoBufMut>(&self, buf: B) -> impl Future<Output = BufResult<RecvMeta, B>> {
        ready(BufResult(Err(closed()), buf))
    }
}

/// What a WASI host hands the backend: TCP and UDP sockets, a resolver (with
/// HTTPS records when `native-http3` is enabled) and a clock.
#[derive(Debug, Clone, Copy)]
struct Host;

impl Dial for Host {
    type Connection = Closed;

    fn connect(&self, _addr: SocketAddr) -> impl Future<Output = io::Result<Closed>> {
        ready(Err(io::ErrorKind::Unsupported.into()))
    }
}

impl Datagram for Host {
    type UdpSocket = Closed;

    fn bind_udp(&self, _addr: SocketAddr) -> impl Future<Output = io::Result<Closed>> {
        ready(Err(io::ErrorKind::Unsupported.into()))
    }
}

impl Resolve for Host {
    fn lookup(&self, _host: &str) -> impl Stream<Item = Answer> {
        stream::once(ready(Answer::Ranked(Ok(vec![IpAddr::V4(
            Ipv4Addr::LOCALHOST,
        )]))))
    }
}

#[cfg(feature = "native-http3")]
impl zenwave::dns::ResolveHttps for Host {
    fn https_record(
        &self,
        _host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Option<zenwave::dns::HttpsRecord>, zenwave::ResolveError>>
    {
        ready(Ok(Some(zenwave::dns::HttpsRecord {
            alpn: vec!["h3".to_owned()],
            port: Some(port),
            ttl: std::time::Duration::from_secs(60),
        })))
    }
}

impl Timer for Host {
    fn sleep_until(&self, _deadline: Instant) -> impl Future<Output = ()> {
        ready(())
    }
}

/// Single-threaded test executor wrapping `futures_executor::LocalSpawner`.
struct Spawner(LocalSpawner);

struct Spawned<T>(oneshot::Receiver<T>);

impl<T> Future for Spawned<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.expect("spawned task canceled"))
    }
}

impl<T> Task<T> for Spawned<T> {
    fn poll_result(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<T, Box<dyn Any + Send>>> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.map_err(|error| Box::new(error) as Box<dyn Any + Send>))
    }
}

impl LocalExecutor for Spawner {
    type Task<T: 'static> = Spawned<T>;

    fn spawn_local<Fut>(&self, fut: Fut) -> Spawned<Fut::Output>
    where
        Fut: Future + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        self.0
            .spawn_local(async move {
                let _ = sender.send(fut.await);
            })
            .expect("the local pool is still running");
        Spawned(receiver)
    }
}

/// The backend over the host, on the host's executor: it is a `Client`.
fn backend<E: LocalExecutor>(executor: &E) -> impl Client {
    let transport = Transport::builder().build().expect("the transport builds");
    NativeBackend::on_current_thread(transport, Host, Host, executor)
}

#[test]
fn native_backend_wires_host_capabilities() {
    let mut pool = LocalPool::new();
    let spawner = Spawner(pool.spawner());
    let Ok(transport) = Transport::builder().proxy(Proxy::none()).build() else {
        // Without `rustls-ring` no default CryptoProvider is installed; the
        // branch below is still monomorphized and linked by `wasm-ld`.
        return;
    };
    let mut client = NativeBackend::on_current_thread(transport, Host, Host, &spawner);
    let result =
        pool.run_until(async { client.get("https://example.com/").expect("valid URI").await });
    assert!(result.is_err());
}
