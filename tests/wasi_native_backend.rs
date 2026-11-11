//! Compile-only: the native backend builds on `wasm32-wasip2` over a host's
//! own `Dial`, `Resolve` and `Timer`, with TLS verified against the compiled-in
//! `webpki-roots`. A WASI host has no OS reactor, so nothing here runs; the
//! test is that the bounds are satisfiable there and that `NativeBackend`
//! takes them.
#![cfg(all(target_os = "wasi", feature = "native-backend"))]
#![expect(
    dead_code,
    reason = "compile-only: the host and its backend are type-checked, never run"
)]

use std::{
    borrow::Borrow,
    fs::File,
    future::{Future, ready},
    io,
    net::SocketAddr,
    time::Instant,
};

use executor_core::LocalExecutor;
use futures_util::{Stream, stream};
use http_kit_io::{
    Answer, BufResult, Dial, IoBuf, IoBufMut, IoVectoredBuf, NoBuf, Read, ReadAhead, ReadOwned,
    Received, Resolve, SendFile, SpliceRead, SpliceWrite, Split, TcpOptions, Timer, Write,
};
use zenwave::{Client, Transport, backend::NativeBackend};

/// The connection type of a host that never opens one: `Host::connect` always
/// fails, and a value of this type reports a closed socket.
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

/// What a WASI host hands the backend: sockets, a resolver and a clock.
#[derive(Debug, Clone, Copy)]
struct Host;

impl Dial for Host {
    type Connection = Closed;

    fn connect(&self, _addr: SocketAddr) -> impl Future<Output = io::Result<Closed>> {
        ready(Err(io::ErrorKind::Unsupported.into()))
    }
}

impl Resolve for Host {
    fn lookup(&self, _host: &str) -> impl Stream<Item = Answer> {
        stream::once(ready(Answer::Ranked(Err(io::ErrorKind::NotFound.into()))))
    }
}

impl Timer for Host {
    fn sleep_until(&self, _deadline: Instant) -> impl Future<Output = ()> {
        ready(())
    }
}

/// The backend over the host, on the host's executor: it is a `Client`.
fn backend<E: LocalExecutor>(executor: &E) -> impl Client {
    let transport = Transport::builder().build().expect("the transport builds");
    NativeBackend::on_current_thread(transport, Host, Host, executor)
}
