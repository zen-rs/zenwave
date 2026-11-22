//! Embedded `no_std + alloc` HTTP/1.1 client backend.
//!
//! Runs over `embedded-io-async` and `embedded-nal-async` (such as
//! `embassy-net` on ESP32-C6 `riscv32imac-unknown-none-elf`), driven by
//! sans-IO [`http_kit_h1::proto`] and, with `embedded-tls`, unbuffered `rustls`.
//!
//! Hardware network stacks (`embassy_net::Stack`, `TcpClient`, `DnsSocket`)
//! borrow peripheral buffers and are `!Send`. [`EmbeddedBackend::channel`]
//! splits the client into two halves, matching [`NativeBackend`](super::NativeBackend)'s
//! actor design:
//! - [`EmbeddedBackend`] is a cheap `Clone + Send + Sync` [`Client`] handle
//!   that composes with `zenwave` middleware (`FollowRedirect`, `BearerAuth`,
//!   `BasicAuth`, `ErrorForStatus`, `Timeout`, `Retry`).
//! - [`EmbeddedRunner`] owns the command receiver and runs on the executor task
//!   that holds `&TcpConnect` and `&Dns`, streaming request and response body
//!   frames across bounded channels so large payloads never buffer whole in
//!   MCU SRAM.

#![allow(clippy::future_not_send)]

#[cfg(embedded_tls)]
use alloc::sync::Arc;
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};
use embedded_nal_async::{AddrType, Dns, TcpConnect};
use futures_channel::oneshot;
use futures_util::{
    StreamExt,
    future::{Either, select},
    pin_mut,
};
use http::{HeaderValue, Method, header, uri::Scheme};
use http_kit::{Body, BodyError, BodyFrame, Endpoint, ReceiveError, Request, Response};
use http_kit_h1::{
    Limits, ParseError, RequestTarget,
    proto::{
        BodyDecoder, BodyKind, Decoded, ResponseHead, encode_request_head, parse_response_head,
    },
};

use super::shared::{parse_authority, received, take_request};
use crate::{
    Attempt, Cause, Client, ConfigError, ConnectFailure, ConnectPhase, Error, ExchangeFailure, Hop,
    ResolveError, TcpFailure, TimedOut, Timeouts, Transport,
    clock::{Clock, Clocked},
};
#[cfg(embedded_tls)]
use crate::{TlsError, TlsFailure};

/// Bounded channel capacity for streaming response body frames from the network
/// task to the caller's [`Body`], applying TCP backpressure on 512 KiB SRAM MCUs.
const BODY_CHANNEL_CAPACITY: usize = 2;

/// Scratch read chunk size when pulling bytes from an `embedded-io-async` socket
/// (fits standard 1500-byte Wi-Fi / Ethernet MTUs without inflating task stacks).
const SOCKET_READ_CHUNK: usize = 2048;

/// Initial capacity for the reusable request-head encoding buffer.
const HEAD_INITIAL_CAP: usize = 512;

/// Initial TLS record scratch buffer capacity (grows dynamically on demand when
/// `rustls` reports [`InsufficientSizeError`](rustls::unbuffered::InsufficientSizeError)).
#[cfg(embedded_tls)]
const TLS_INITIAL_BUF: usize = 4096;

/// TLS record header size (`ContentType` + `ProtocolVersion` + 16-bit length, RFC 8446 §5.1).
#[cfg(embedded_tls)]
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Maximum wire length of one encrypted TLS 1.3 record (`5 + 16384 + 256`, RFC 8446 §5.2).
#[cfg(embedded_tls)]
const TLS_MAX_RECORD_WIRE: usize = TLS_RECORD_HEADER_LEN + 16_384 + 256;

/// Monotonic timer source for [`EmbeddedRunner::run_with_timer`] and [`TimerClock`].
pub trait EmbeddedTimer {
    /// Future returned by [`after`](Self::after).
    type After: Future<Output = ()>;

    /// Completes once `duration` has elapsed.
    fn after(&self, duration: Duration) -> Self::After;
}

impl<T: EmbeddedTimer + ?Sized> EmbeddedTimer for &T {
    type After = T::After;

    fn after(&self, duration: Duration) -> Self::After {
        (**self).after(duration)
    }
}

/// Adapts a `Send + Sync` [`EmbeddedTimer`] into a [`Clock`] for
/// [`Timeout`](crate::Timeout) and [`Retry`](crate::retry::Retry) middleware.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerClock<T>(pub T);

impl<T> Clock for TimerClock<T>
where
    T: EmbeddedTimer + Clone + Send + Sync + 'static,
    T::After: Send + 'static,
{
    type Sleep = T::After;

    fn sleep(&self, duration: Duration) -> Self::Sleep {
        self.0.after(duration)
    }
}

struct RequestCommand {
    request: http::Request<Body>,
    timeouts: Timeouts,
    reply: oneshot::Sender<Result<Response, Error>>,
}

/// Embedded `no_std + alloc` HTTP/1.1 client handle.
///
/// Construct with [`EmbeddedBackend::channel`] and drive the returned
/// [`EmbeddedRunner`] on the task that owns the device's network stack.
#[derive(Clone)]
pub struct EmbeddedBackend {
    transport: Transport,
    sender: async_channel::Sender<RequestCommand>,
}

impl fmt::Debug for EmbeddedBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedBackend")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl EmbeddedBackend {
    /// Create a connected `(EmbeddedBackend, EmbeddedRunner)` pair over `transport`.
    #[must_use]
    pub fn channel(transport: Transport) -> (Self, EmbeddedRunner) {
        let (sender, receiver) = async_channel::unbounded();
        let runner = EmbeddedRunner {
            transport: transport.clone(),
            limits: Limits::default(),
            receiver,
            buffers: RunnerBuffers::new(),
        };
        (Self { transport, sender }, runner)
    }

    /// Attach a `Send + Sync` [`EmbeddedTimer`] so [`Client::timeout`] and
    /// [`Client::retry`] derive their [`Clock`] directly from this client.
    #[must_use]
    pub const fn with_clock<T>(self, timer: T) -> ClockedEmbeddedBackend<T> {
        ClockedEmbeddedBackend {
            inner: self,
            clock: TimerClock(timer),
        }
    }
}

impl Endpoint for EmbeddedBackend {
    type Error = Error;

    async fn respond(&mut self, slot: &mut Request) -> Result<Response, Self::Error> {
        let timeouts = slot
            .extensions()
            .get::<Timeouts>()
            .copied()
            .unwrap_or_default()
            .or(self.transport.timeouts());
        let request = take_request(slot);
        let (reply, rx) = oneshot::channel();
        self.sender
            .send(RequestCommand {
                request,
                timeouts,
                reply,
            })
            .await
            .map_err(|_| Error::Stopped)?;
        let response = rx.await.map_err(|_| Error::Stopped)??;
        received(&response);
        Ok(response)
    }
}

http_kit::impl_send_endpoint!(EmbeddedBackend);

impl Client for EmbeddedBackend {}

/// An [`EmbeddedBackend`] paired with a [`TimerClock`] implementing [`Clocked`].
#[derive(Debug, Clone)]
pub struct ClockedEmbeddedBackend<T> {
    inner: EmbeddedBackend,
    clock: TimerClock<T>,
}

impl<T> Endpoint for ClockedEmbeddedBackend<T>
where
    T: EmbeddedTimer + Clone + Send + Sync + 'static,
    T::After: Send + 'static,
{
    type Error = Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.inner.respond(request).await
    }
}

impl<T> http_kit::SendEndpoint for ClockedEmbeddedBackend<T>
where
    T: EmbeddedTimer + Clone + Send + Sync + 'static,
    T::After: Send + 'static,
{
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
        self.respond(request)
    }
}

impl<T> Client for ClockedEmbeddedBackend<T>
where
    T: EmbeddedTimer + Clone + Send + Sync + 'static,
    T::After: Send + 'static,
{
}

impl<T> Clocked for ClockedEmbeddedBackend<T>
where
    T: EmbeddedTimer + Clone + Send + Sync + 'static,
    T::After: Send + 'static,
{
    type Clock = TimerClock<T>;

    fn clock(&self) -> Self::Clock {
        self.clock.clone()
    }
}

/// Reusable scratch buffers owned by [`EmbeddedRunner`] across sequential exchanges
/// so steady-state requests avoid repeated 2–16 KiB heap allocations on MCU allocators.
struct RunnerBuffers {
    head_buf: BytesMut,
    app_rx: BytesMut,
    #[cfg(embedded_tls)]
    rx_tls: Vec<u8>,
    #[cfg(embedded_tls)]
    tx_tls: Vec<u8>,
}

impl RunnerBuffers {
    fn new() -> Self {
        Self {
            head_buf: BytesMut::with_capacity(HEAD_INITIAL_CAP),
            app_rx: BytesMut::with_capacity(SOCKET_READ_CHUNK),
            #[cfg(embedded_tls)]
            rx_tls: vec![0u8; TLS_INITIAL_BUF],
            #[cfg(embedded_tls)]
            tx_tls: vec![0u8; TLS_INITIAL_BUF],
        }
    }

    fn reset(&mut self) {
        self.head_buf.clear();
        if self.head_buf.capacity() > HEAD_INITIAL_CAP * 2 {
            self.head_buf = BytesMut::with_capacity(HEAD_INITIAL_CAP);
        }
        self.app_rx.clear();
        if self.app_rx.capacity() > SOCKET_READ_CHUNK * 2 {
            self.app_rx = BytesMut::with_capacity(SOCKET_READ_CHUNK);
        }
        #[cfg(embedded_tls)]
        {
            reset_tls_vec(&mut self.rx_tls);
            reset_tls_vec(&mut self.tx_tls);
        }
    }
}

#[cfg(embedded_tls)]
fn reset_tls_vec(buf: &mut Vec<u8>) {
    if buf.capacity() > TLS_INITIAL_BUF * 2 {
        *buf = vec![0u8; TLS_INITIAL_BUF];
    } else if buf.len() != TLS_INITIAL_BUF {
        buf.resize(TLS_INITIAL_BUF, 0);
    }
}

/// Network driver task paired with an [`EmbeddedBackend`].
///
/// Its `run` futures intentionally borrow `!Send` embedded peripheral stacks
/// (`embassy-net` sockets and DNS handles) on the local executor task.
pub struct EmbeddedRunner {
    transport: Transport,
    limits: Limits,
    receiver: async_channel::Receiver<RequestCommand>,
    buffers: RunnerBuffers,
}

impl fmt::Debug for EmbeddedRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedRunner")
            .field("transport", &self.transport)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

struct NoTimer;

impl EmbeddedRunner {
    /// Override the HTTP/1.1 header and trailer framing [`Limits`] enforced by
    /// the runner (defaults to [`Limits::default`]).
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Drive requests over `tcp` and `dns` until every [`EmbeddedBackend`]
    /// handle is dropped.
    ///
    /// Per-request or transport [`Timeouts`] require a timer source; use
    /// [`run_with_timer`](Self::run_with_timer) when timeouts are configured.
    #[allow(clippy::future_not_send)]
    pub async fn run<C, D>(mut self, tcp: &C, dns: &D)
    where
        C: TcpConnect,
        D: Dns,
    {
        while let Ok(cmd) = self.receiver.recv().await {
            if cmd.reply.is_canceled() {
                continue;
            }
            if has_any_timeout(&cmd.timeouts) {
                let _ = cmd.reply.send(Err(Error::Config(ConfigError::Unsupported {
                    what: "per-request timeouts without EmbeddedRunner::run_with_timer",
                })));
                continue;
            }
            exchange_one(
                &self.transport,
                &self.limits,
                &mut self.buffers,
                tcp,
                dns,
                None::<&NoTimer>,
                cmd,
            )
            .await;
            self.buffers.reset();
        }
    }

    /// Drive requests over `tcp`, `dns` and `timer`, enforcing connect,
    /// response-head and body-idle deadlines until every [`EmbeddedBackend`]
    /// handle is dropped.
    #[allow(clippy::future_not_send)]
    pub async fn run_with_timer<C, D, T>(mut self, tcp: &C, dns: &D, timer: &T)
    where
        C: TcpConnect,
        D: Dns,
        T: EmbeddedTimer,
    {
        while let Ok(cmd) = self.receiver.recv().await {
            if cmd.reply.is_canceled() {
                continue;
            }
            exchange_one(
                &self.transport,
                &self.limits,
                &mut self.buffers,
                tcp,
                dns,
                Some(timer),
                cmd,
            )
            .await;
            self.buffers.reset();
        }
    }
}

impl EmbeddedTimer for NoTimer {
    type After = core::future::Pending<()>;

    fn after(&self, _duration: Duration) -> Self::After {
        core::future::pending()
    }
}

const fn has_any_timeout(timeouts: &Timeouts) -> bool {
    matches!(timeouts.connect, Some(d) if !matches!(d, Duration::MAX))
        || matches!(timeouts.exchange.response_head, Some(d) if !matches!(d, Duration::MAX))
        || matches!(timeouts.exchange.body_idle, Some(d) if !matches!(d, Duration::MAX))
}

const fn active_deadline(bound: Option<Duration>) -> Option<Duration> {
    match bound {
        Some(Duration::MAX) | None => None,
        Some(d) => Some(d),
    }
}

#[allow(clippy::future_not_send)]
async fn timed<F, Output, T>(
    timer: Option<&T>,
    bound: Option<Duration>,
    on_timeout: impl FnOnce() -> Error,
    fut: F,
) -> Result<Output, Error>
where
    F: Future<Output = Result<Output, Error>>,
    T: EmbeddedTimer,
{
    let Some(duration) = active_deadline(bound) else {
        return fut.await;
    };
    let Some(timer) = timer else {
        return fut.await;
    };
    let sleep = timer.after(duration);
    pin_mut!(fut);
    pin_mut!(sleep);
    match select(fut, sleep).await {
        Either::Left((out, _)) => out,
        Either::Right(((), _)) => Err(on_timeout()),
    }
}

trait StreamIo {
    async fn read_into(&mut self, dst: &mut BytesMut) -> Result<usize, Error>;
    async fn write_bytes(&mut self, buf: &[u8]) -> Result<(), Error>;
    async fn flush_bytes(&mut self) -> Result<(), Error>;
    async fn shutdown(&mut self);
}

struct PlainStream<S>(S);

impl<S: AsyncRead + AsyncWrite> StreamIo for PlainStream<S> {
    #[allow(clippy::future_not_send)]
    async fn read_into(&mut self, dst: &mut BytesMut) -> Result<usize, Error> {
        let old_len = dst.len();
        dst.resize(old_len + SOCKET_READ_CHUNK, 0);
        match self.0.read(&mut dst[old_len..]).await {
            Ok(n) => {
                dst.truncate(old_len + n);
                Ok(n)
            }
            Err(err) => {
                dst.truncate(old_len);
                Err(Error::exchange(
                    ExchangeFailure::Io,
                    Cause::Detail(format!("{err:?}")),
                ))
            }
        }
    }

    #[allow(clippy::future_not_send)]
    async fn write_bytes(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.0
            .write_all(buf)
            .await
            .map_err(|err| Error::exchange(ExchangeFailure::Io, Cause::Detail(format!("{err:?}"))))
    }

    #[allow(clippy::future_not_send)]
    async fn flush_bytes(&mut self) -> Result<(), Error> {
        self.0
            .flush()
            .await
            .map_err(|err| Error::exchange(ExchangeFailure::Io, Cause::Detail(format!("{err:?}"))))
    }

    #[allow(clippy::future_not_send)]
    async fn shutdown(&mut self) {
        let _ = self.0.flush().await;
    }
}

#[cfg(embedded_tls)]
fn encode_tls_record<D>(
    mut enc: rustls::unbuffered::EncodeTlsData<'_, D>,
    tx_tls: &mut Vec<u8>,
    tx_filled: &mut usize,
) {
    loop {
        match enc.encode(&mut tx_tls[*tx_filled..]) {
            Ok(written) => {
                *tx_filled += written;
                return;
            }
            Err(rustls::unbuffered::EncodeError::InsufficientSize(need)) => {
                tx_tls.resize(*tx_filled + need.required_size, 0);
            }
            Err(rustls::unbuffered::EncodeError::AlreadyEncoded) => return,
        }
    }
}

/// Grows `rx_tls` using the 5-byte TLS record header's declared length when
/// available so a single certificate record does not double past what it needs.
#[cfg(embedded_tls)]
fn grow_tls_rx(rx_tls: &mut Vec<u8>, rx_filled: usize) {
    let min_next = rx_tls.len().saturating_add(SOCKET_READ_CHUNK);
    let target = if rx_filled >= TLS_RECORD_HEADER_LEN {
        let payload_len = usize::from(u16::from_be_bytes([rx_tls[3], rx_tls[4]]));
        let record_wire = TLS_RECORD_HEADER_LEN
            .saturating_add(payload_len)
            .min(TLS_MAX_RECORD_WIRE);
        record_wire.max(min_next)
    } else {
        min_next
    };
    rx_tls.resize(target, 0);
}

#[cfg(embedded_tls)]
struct UnbufferedTlsStream<S> {
    socket: S,
    conn: rustls::client::UnbufferedClientConnection,
    rx_tls: Vec<u8>,
    rx_filled: usize,
    tx_tls: Vec<u8>,
    tx_filled: usize,
    peer_closed: bool,
}

#[cfg(embedded_tls)]
impl<S: AsyncRead + AsyncWrite> UnbufferedTlsStream<S> {
    #[allow(clippy::future_not_send)]
    async fn connect(
        config: Arc<rustls::ClientConfig>,
        host: &str,
        port: u16,
        socket: S,
        rx_slot: &mut Vec<u8>,
        tx_slot: &mut Vec<u8>,
        app_rx: &mut BytesMut,
    ) -> Result<Self, Error> {
        let server_name =
            rustls_pki_types::ServerName::try_from(host.to_owned()).map_err(|err| {
                Error::connect(
                    Hop::Origin,
                    host.to_owned(),
                    port,
                    ConnectFailure::Tls(TlsError::new(
                        TlsFailure::Certificate,
                        Cause::Detail(err.to_string()),
                    )),
                )
            })?;
        let conn = rustls::client::UnbufferedClientConnection::new(config, server_name).map_err(
            |err| {
                Error::connect(
                    Hop::Origin,
                    host.to_owned(),
                    port,
                    ConnectFailure::Tls(TlsError::new(
                        TlsFailure::of_rustls(&err),
                        Cause::Rustls(err),
                    )),
                )
            },
        )?;
        let mut rx_tls = core::mem::take(rx_slot);
        let mut tx_tls = core::mem::take(tx_slot);
        if rx_tls.len() < TLS_INITIAL_BUF {
            rx_tls.resize(TLS_INITIAL_BUF, 0);
        }
        if tx_tls.len() < TLS_INITIAL_BUF {
            tx_tls.resize(TLS_INITIAL_BUF, 0);
        }
        let mut tls = Self {
            socket,
            conn,
            rx_tls,
            rx_filled: 0,
            tx_tls,
            tx_filled: 0,
            peer_closed: false,
        };
        if let Err(err) = tls.handshake(host, port, app_rx).await {
            let (rx_b, tx_b) = tls.into_buffers();
            *rx_slot = rx_b;
            *tx_slot = tx_b;
            return Err(err);
        }
        Ok(tls)
    }

    fn into_buffers(self) -> (Vec<u8>, Vec<u8>) {
        (self.rx_tls, self.tx_tls)
    }

    fn discard_rx(&mut self, discard: usize) {
        if discard == 0 {
            return;
        }
        if discard >= self.rx_filled {
            self.rx_filled = 0;
        } else {
            self.rx_tls.copy_within(discard..self.rx_filled, 0);
            self.rx_filled -= discard;
        }
    }

    #[allow(clippy::future_not_send)]
    async fn flush_tx_handshake(&mut self, host: &str, port: u16) -> Result<(), Error> {
        if self.tx_filled > 0 {
            self.socket
                .write_all(&self.tx_tls[..self.tx_filled])
                .await
                .map_err(|err| {
                    Error::connect(
                        Hop::Origin,
                        host.to_owned(),
                        port,
                        ConnectFailure::Tls(TlsError::new(
                            TlsFailure::Protocol,
                            Cause::Detail(format!("{err:?}")),
                        )),
                    )
                })?;
            self.socket.flush().await.map_err(|err| {
                Error::connect(
                    Hop::Origin,
                    host.to_owned(),
                    port,
                    ConnectFailure::Tls(TlsError::new(
                        TlsFailure::Protocol,
                        Cause::Detail(format!("{err:?}")),
                    )),
                )
            })?;
            self.tx_filled = 0;
        }
        Ok(())
    }

    #[allow(clippy::future_not_send)]
    async fn read_rx_ciphertext_handshake(&mut self, host: &str, port: u16) -> Result<(), Error> {
        if self.rx_filled == self.rx_tls.len() {
            grow_tls_rx(&mut self.rx_tls, self.rx_filled);
        }
        let n = self
            .socket
            .read(&mut self.rx_tls[self.rx_filled..])
            .await
            .map_err(|err| {
                Error::connect(
                    Hop::Origin,
                    host.to_owned(),
                    port,
                    ConnectFailure::Tls(TlsError::new(
                        TlsFailure::Protocol,
                        Cause::Detail(format!("{err:?}")),
                    )),
                )
            })?;
        if n == 0 {
            return Err(Error::connect(
                Hop::Origin,
                host.to_owned(),
                port,
                ConnectFailure::Tls(TlsError::new(
                    TlsFailure::Protocol,
                    Cause::Detail("peer closed TCP stream during TLS handshake".to_owned()),
                )),
            ));
        }
        self.rx_filled += n;
        Ok(())
    }

    #[allow(clippy::future_not_send)]
    async fn handshake(
        &mut self,
        host: &str,
        port: u16,
        app_rx: &mut BytesMut,
    ) -> Result<(), Error> {
        use rustls::unbuffered::{ConnectionState, UnbufferedStatus};

        loop {
            let UnbufferedStatus { mut discard, state } = self
                .conn
                .process_tls_records(&mut self.rx_tls[..self.rx_filled]);

            let state = match state {
                Ok(state) => state,
                Err(err) => {
                    self.discard_rx(discard);
                    // Best-effort transmit any queued fatal alert before returning the TLS error.
                    self.drain_pending_alert_records();
                    let _ = self.flush_tx_handshake(host, port).await;
                    return Err(Error::connect(
                        Hop::Origin,
                        host.to_owned(),
                        port,
                        ConnectFailure::Tls(TlsError::new(
                            TlsFailure::of_rustls(&err),
                            Cause::Rustls(err),
                        )),
                    ));
                }
            };

            match state {
                ConnectionState::EncodeTlsData(enc) => {
                    encode_tls_record(enc, &mut self.tx_tls, &mut self.tx_filled);
                    self.discard_rx(discard);
                }
                ConnectionState::TransmitTlsData(tx) => {
                    tx.done();
                    self.discard_rx(discard);
                    self.flush_tx_handshake(host, port).await?;
                }
                ConnectionState::BlockedHandshake => {
                    self.discard_rx(discard);
                    self.flush_tx_handshake(host, port).await?;
                    self.read_rx_ciphertext_handshake(host, port).await?;
                }
                ConnectionState::ReadTraffic(mut traffic) => {
                    while let Some(rec) = traffic.next_record() {
                        let rec = rec.map_err(|err| {
                            Error::connect(
                                Hop::Origin,
                                host.to_owned(),
                                port,
                                ConnectFailure::Tls(TlsError::new(
                                    TlsFailure::of_rustls(&err),
                                    Cause::Rustls(err),
                                )),
                            )
                        })?;
                        discard += rec.discard;
                        app_rx.extend_from_slice(rec.payload);
                    }
                    self.discard_rx(discard);
                    return Ok(());
                }
                ConnectionState::WriteTraffic(_) => {
                    self.discard_rx(discard);
                    return Ok(());
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    self.discard_rx(discard);
                    self.peer_closed = true;
                    return Ok(());
                }
                _ => {
                    self.discard_rx(discard);
                }
            }
        }
    }

    fn drain_pending_alert_records(&mut self) {
        while let rustls::unbuffered::UnbufferedStatus {
            discard,
            state: Ok(rustls::unbuffered::ConnectionState::EncodeTlsData(enc)),
        } = self
            .conn
            .process_tls_records(&mut self.rx_tls[..self.rx_filled])
        {
            encode_tls_record(enc, &mut self.tx_tls, &mut self.tx_filled);
            self.discard_rx(discard);
        }
    }

    #[allow(clippy::future_not_send)]
    async fn flush_tx_exchange(&mut self) -> Result<(), Error> {
        if self.tx_filled > 0 {
            self.socket
                .write_all(&self.tx_tls[..self.tx_filled])
                .await
                .map_err(|err| {
                    Error::exchange(ExchangeFailure::Io, Cause::Detail(format!("{err:?}")))
                })?;
            self.tx_filled = 0;
        }
        Ok(())
    }
}

#[cfg(embedded_tls)]
impl<S: AsyncRead + AsyncWrite> StreamIo for UnbufferedTlsStream<S> {
    #[allow(clippy::future_not_send)]
    async fn read_into(&mut self, dst: &mut BytesMut) -> Result<usize, Error> {
        use rustls::unbuffered::{ConnectionState, UnbufferedStatus};

        if self.peer_closed {
            return Ok(0);
        }

        loop {
            let UnbufferedStatus { mut discard, state } = self
                .conn
                .process_tls_records(&mut self.rx_tls[..self.rx_filled]);
            let state =
                state.map_err(|err| Error::exchange(ExchangeFailure::Tls, Cause::Rustls(err)))?;
            match state {
                ConnectionState::ReadTraffic(mut traffic) => {
                    let mut produced = 0usize;
                    while let Some(rec) = traffic.next_record() {
                        let rec = rec.map_err(|err| {
                            Error::exchange(ExchangeFailure::Tls, Cause::Rustls(err))
                        })?;
                        discard += rec.discard;
                        dst.extend_from_slice(rec.payload);
                        produced += rec.payload.len();
                    }
                    self.discard_rx(discard);
                    if produced > 0 {
                        return Ok(produced);
                    }
                }
                ConnectionState::EncodeTlsData(enc) => {
                    encode_tls_record(enc, &mut self.tx_tls, &mut self.tx_filled);
                    self.discard_rx(discard);
                }
                ConnectionState::TransmitTlsData(tx) => {
                    tx.done();
                    self.discard_rx(discard);
                    self.flush_tx_exchange().await?;
                    self.socket.flush().await.map_err(|err| {
                        Error::exchange(ExchangeFailure::Io, Cause::Detail(format!("{err:?}")))
                    })?;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    self.discard_rx(discard);
                    self.peer_closed = true;
                    return Ok(0);
                }
                ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => {
                    self.discard_rx(discard);
                    self.flush_tx_exchange().await?;
                    if self.rx_filled == self.rx_tls.len() {
                        grow_tls_rx(&mut self.rx_tls, self.rx_filled);
                    }
                    let n = self
                        .socket
                        .read(&mut self.rx_tls[self.rx_filled..])
                        .await
                        .map_err(|err| {
                            Error::exchange(ExchangeFailure::Io, Cause::Detail(format!("{err:?}")))
                        })?;
                    if n == 0 {
                        self.peer_closed = true;
                        return Ok(0);
                    }
                    self.rx_filled += n;
                }
                _ => {
                    self.discard_rx(discard);
                }
            }
        }
    }

    #[allow(clippy::future_not_send)]
    async fn write_bytes(&mut self, mut buf: &[u8]) -> Result<(), Error> {
        use rustls::unbuffered::{ConnectionState, EncryptError, UnbufferedStatus};

        while !buf.is_empty() {
            let UnbufferedStatus { mut discard, state } = self
                .conn
                .process_tls_records(&mut self.rx_tls[..self.rx_filled]);
            let state =
                state.map_err(|err| Error::exchange(ExchangeFailure::Tls, Cause::Rustls(err)))?;
            match state {
                ConnectionState::WriteTraffic(mut wt) => {
                    // Encrypt in slices up to the RFC 8446 §5.1 16 KiB TLS plaintext record limit.
                    let slice = &buf[..buf.len().min(16_384)];
                    loop {
                        match wt.encrypt(slice, &mut self.tx_tls[self.tx_filled..]) {
                            Ok(written) => {
                                self.tx_filled += written;
                                break;
                            }
                            Err(EncryptError::InsufficientSize(need)) => {
                                self.tx_tls.resize(self.tx_filled + need.required_size, 0);
                            }
                            Err(EncryptError::EncryptExhausted) => {
                                self.discard_rx(discard);
                                return Err(Error::exchange(
                                    ExchangeFailure::Tls,
                                    Cause::Detail("TLS cipher keystream exhausted".to_owned()),
                                ));
                            }
                        }
                    }
                    buf = &buf[slice.len()..];
                    self.discard_rx(discard);
                    self.flush_tx_exchange().await?;
                }
                ConnectionState::EncodeTlsData(enc) => {
                    encode_tls_record(enc, &mut self.tx_tls, &mut self.tx_filled);
                    self.discard_rx(discard);
                }
                ConnectionState::TransmitTlsData(tx) => {
                    tx.done();
                    self.discard_rx(discard);
                    self.flush_tx_exchange().await?;
                }
                ConnectionState::ReadTraffic(mut traffic) => {
                    // Drain any post-handshake records (e.g. NewSessionTicket) before encrypting.
                    while let Some(rec) = traffic.next_record() {
                        let rec = rec.map_err(|err| {
                            Error::exchange(ExchangeFailure::Tls, Cause::Rustls(err))
                        })?;
                        discard += rec.discard;
                    }
                    self.discard_rx(discard);
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    self.discard_rx(discard);
                    return Err(Error::exchange(
                        ExchangeFailure::Terminated,
                        Cause::Detail("TLS peer closed before request write finished".to_owned()),
                    ));
                }
                _ => {
                    self.discard_rx(discard);
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::future_not_send)]
    async fn flush_bytes(&mut self) -> Result<(), Error> {
        self.flush_tx_exchange().await?;
        self.socket
            .flush()
            .await
            .map_err(|err| Error::exchange(ExchangeFailure::Io, Cause::Detail(format!("{err:?}"))))
    }

    #[allow(clippy::future_not_send)]
    async fn shutdown(&mut self) {
        use rustls::unbuffered::{ConnectionState, EncryptError, UnbufferedStatus};

        if let UnbufferedStatus {
            discard,
            state: Ok(ConnectionState::WriteTraffic(mut wt)),
        } = self
            .conn
            .process_tls_records(&mut self.rx_tls[..self.rx_filled])
        {
            loop {
                match wt.queue_close_notify(&mut self.tx_tls[self.tx_filled..]) {
                    Ok(written) => {
                        self.tx_filled += written;
                        break;
                    }
                    Err(EncryptError::InsufficientSize(need)) => {
                        self.tx_tls.resize(self.tx_filled + need.required_size, 0);
                    }
                    Err(EncryptError::EncryptExhausted) => break,
                }
            }
            self.discard_rx(discard);
            let _ = self.flush_tx_exchange().await;
        }
        let _ = self.socket.flush().await;
    }
}

#[allow(clippy::future_not_send)]
async fn exchange_one<C, D, T>(
    transport: &Transport,
    limits: &Limits,
    buffers: &mut RunnerBuffers,
    tcp: &C,
    dns: &D,
    timer: Option<&T>,
    cmd: RequestCommand,
) where
    C: TcpConnect,
    D: Dns,
    T: EmbeddedTimer,
{
    let RequestCommand {
        mut request,
        timeouts,
        reply,
    } = cmd;

    let (scheme, host, port) = match parse_authority(request.uri()) {
        Ok(parts) => parts,
        Err(err) => {
            let _ = reply.send(Err(err));
            return;
        }
    };

    if request.headers().get(header::HOST).is_none() {
        let host_header =
            if (scheme == Scheme::HTTP && port == 80) || (scheme == Scheme::HTTPS && port == 443) {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
        if let Ok(val) = HeaderValue::from_str(&host_header) {
            request.headers_mut().insert(header::HOST, val);
        }
    }
    if request.headers().get(header::CONNECTION).is_none() {
        request
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }

    if scheme == Scheme::HTTPS {
        exchange_https(
            transport, limits, buffers, tcp, dns, timer, &host, port, request, &timeouts, reply,
        )
        .await;
        return;
    }

    #[cfg(not(embedded_tls))]
    let _ = transport;

    exchange_http(
        limits, buffers, tcp, dns, timer, &host, port, request, &timeouts, reply,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(embedded_tls), allow(clippy::unused_async))]
async fn exchange_https<C, D, T>(
    transport: &Transport,
    limits: &Limits,
    buffers: &mut RunnerBuffers,
    tcp: &C,
    dns: &D,
    timer: Option<&T>,
    host: &str,
    port: u16,
    request: http::Request<Body>,
    timeouts: &Timeouts,
    reply: oneshot::Sender<Result<Response, Error>>,
) where
    C: TcpConnect,
    D: Dns,
    T: EmbeddedTimer,
{
    #[cfg(not(embedded_tls))]
    {
        let _ = (
            transport, limits, buffers, tcp, dns, timer, host, port, request, timeouts,
        );
        let _ = reply.send(Err(Error::Config(ConfigError::Unsupported {
            what: "HTTPS without the `embedded-tls` feature",
        })));
    }
    #[cfg(embedded_tls)]
    {
        let Some(tls_config) = transport.embedded_tls().cloned() else {
            let _ = reply.send(Err(Error::tls_config(Cause::Detail(
                "HTTPS on EmbeddedBackend requires TransportBuilder::embedded_tls_provider or embedded_tls_config".to_owned(),
            ))));
            return;
        };
        let phase = core::cell::Cell::new(ConnectPhase::Resolve);
        buffers.app_rx.clear();
        let RunnerBuffers {
            app_rx,
            rx_tls,
            tx_tls,
            ..
        } = buffers;
        let dial = timed(
            timer,
            timeouts.connect,
            || {
                Error::Timeout(TimedOut::Connect {
                    during: phase.get(),
                })
            },
            async {
                let ip = resolve_host(dns, host, port).await?;
                phase.set(ConnectPhase::Tcp);
                let remote = SocketAddr::new(ip, port);
                let sock = tcp.connect(remote).await.map_err(|err| {
                    Error::connect(
                        Hop::Origin,
                        host.to_owned(),
                        port,
                        ConnectFailure::Tcp(TcpFailure::new(vec![make_attempt(
                            remote,
                            format!("{err:?}"),
                        )])),
                    )
                })?;
                phase.set(ConnectPhase::Tls);
                UnbufferedTlsStream::connect(tls_config, host, port, sock, rx_tls, tx_tls, app_rx)
                    .await
            },
        )
        .await;

        match dial {
            Ok(mut tls_stream) => {
                drive_http_exchange(
                    &mut tls_stream,
                    &mut buffers.app_rx,
                    &mut buffers.head_buf,
                    limits,
                    timer,
                    timeouts,
                    request,
                    reply,
                )
                .await;
                tls_stream.shutdown().await;
                let (rx_b, tx_b) = tls_stream.into_buffers();
                buffers.rx_tls = rx_b;
                buffers.tx_tls = tx_b;
            }
            Err(err) => {
                let _ = reply.send(Err(err));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn exchange_http<C, D, T>(
    limits: &Limits,
    buffers: &mut RunnerBuffers,
    tcp: &C,
    dns: &D,
    timer: Option<&T>,
    host: &str,
    port: u16,
    request: http::Request<Body>,
    timeouts: &Timeouts,
    reply: oneshot::Sender<Result<Response, Error>>,
) where
    C: TcpConnect,
    D: Dns,
    T: EmbeddedTimer,
{
    let phase = core::cell::Cell::new(ConnectPhase::Resolve);
    let dial = timed(
        timer,
        timeouts.connect,
        || {
            Error::Timeout(TimedOut::Connect {
                during: phase.get(),
            })
        },
        async {
            let ip = resolve_host(dns, host, port).await?;
            phase.set(ConnectPhase::Tcp);
            let remote = SocketAddr::new(ip, port);
            let sock = tcp.connect(remote).await.map_err(|err| {
                Error::connect(
                    Hop::Origin,
                    host.to_owned(),
                    port,
                    ConnectFailure::Tcp(TcpFailure::new(vec![make_attempt(
                        remote,
                        format!("{err:?}"),
                    )])),
                )
            })?;
            Ok(PlainStream(sock))
        },
    )
    .await;

    match dial {
        Ok(mut plain_stream) => {
            buffers.app_rx.clear();
            drive_http_exchange(
                &mut plain_stream,
                &mut buffers.app_rx,
                &mut buffers.head_buf,
                limits,
                timer,
                timeouts,
                request,
                reply,
            )
            .await;
            plain_stream.shutdown().await;
        }
        Err(err) => {
            let _ = reply.send(Err(err));
        }
    }
}

#[allow(clippy::future_not_send)]
async fn resolve_host<D: Dns>(dns: &D, host: &str, port: u16) -> Result<IpAddr, Error> {
    let clean = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return Ok(ip);
    }
    dns.get_host_by_name(clean, AddrType::Either)
        .await
        .map_err(|err| {
            Error::connect(
                Hop::Origin,
                host.to_owned(),
                port,
                ConnectFailure::Resolve(ResolveError::Lookup(Cause::Detail(format!("{err:?}")))),
            )
        })
}

#[allow(clippy::missing_const_for_fn)]
fn make_attempt(remote: SocketAddr, detail: String) -> Attempt {
    #[cfg(has_std)]
    {
        Attempt::new(Some(remote), std::io::Error::other(detail))
    }
    #[cfg(not(has_std))]
    {
        Attempt::new(Some(remote), detail)
    }
}

enum EagerBody {
    Complete(Bytes),
    Streaming(Vec<Result<BodyFrame, BodyError>>),
}

/// Drains whatever body frames are already buffered alongside the response head.
/// When the entire body arrived in that first read (and carried no trailers), returns
/// [`EagerBody::Complete`] so [`drive_http_exchange`] hands back an in-memory [`Body`]
/// without allocating a bounded `async_channel`.
fn decode_buffered_body(
    decoder: &mut BodyDecoder,
    rx_buf: &mut BytesMut,
    limits: &Limits,
) -> EagerBody {
    let mut data_chunks: Vec<Bytes> = Vec::new();
    loop {
        match decoder.decode(rx_buf, limits) {
            Ok(Some(Decoded::Data(bytes))) => {
                if !bytes.is_empty() {
                    data_chunks.push(bytes);
                }
            }
            Ok(Some(Decoded::End)) => {
                let merged = match data_chunks.len() {
                    0 => Bytes::new(),
                    1 => data_chunks.pop().expect("single chunk"),
                    _ => {
                        let total: usize = data_chunks.iter().map(Bytes::len).sum();
                        let mut out = BytesMut::with_capacity(total);
                        for chunk in data_chunks {
                            out.extend_from_slice(&chunk);
                        }
                        out.freeze()
                    }
                };
                return EagerBody::Complete(merged);
            }
            Ok(Some(Decoded::Trailers(trailers))) => {
                let mut frames: Vec<Result<BodyFrame, BodyError>> = data_chunks
                    .into_iter()
                    .map(|b| Ok(BodyFrame::Data(b)))
                    .collect();
                frames.push(Ok(BodyFrame::Trailers(trailers)));
                return EagerBody::Streaming(frames);
            }
            Ok(None) => {
                let frames = data_chunks
                    .into_iter()
                    .map(|b| Ok(BodyFrame::Data(b)))
                    .collect();
                return EagerBody::Streaming(frames);
            }
            Err(err) => {
                let mut frames: Vec<Result<BodyFrame, BodyError>> = data_chunks
                    .into_iter()
                    .map(|b| Ok(BodyFrame::Data(b)))
                    .collect();
                frames.push(Err(BodyError::from(http_kit_h1::Error::Parse(err))));
                return EagerBody::Streaming(frames);
            }
        }
    }
}

fn build_response(parts: http::response::Parts, body: Body) -> Response {
    let mut resp = Response::new(body);
    *resp.status_mut() = parts.status;
    *resp.version_mut() = parts.version;
    *resp.headers_mut() = parts.headers;
    *resp.extensions_mut() = parts.extensions;
    resp
}

#[allow(clippy::too_many_arguments, clippy::future_not_send)]
async fn drive_http_exchange<S, T>(
    stream: &mut S,
    rx_buf: &mut BytesMut,
    head_buf: &mut BytesMut,
    limits: &Limits,
    timer: Option<&T>,
    timeouts: &Timeouts,
    request: http::Request<Body>,
    reply: oneshot::Sender<Result<Response, Error>>,
) where
    S: StreamIo,
    T: EmbeddedTimer,
{
    let request_method = request.method().clone();
    if let Err(err) = write_request(stream, head_buf, request).await {
        let _ = reply.send(Err(err));
        return;
    }

    let head = match timed(
        timer,
        timeouts.exchange.response_head,
        || Error::Timeout(TimedOut::ResponseHead),
        read_final_response_head(stream, rx_buf, &request_method, limits),
    )
    .await
    {
        Ok(head) => head,
        Err(err) => {
            let _ = reply.send(Err(err));
            return;
        }
    };

    if matches!(head.body, BodyKind::Empty) {
        let _ = reply.send(Ok(build_response(head.parts, Body::empty())));
        return;
    }

    let mut decoder = BodyDecoder::new(head.body);
    let initial_frames = match decode_buffered_body(&mut decoder, rx_buf, limits) {
        EagerBody::Complete(bytes) => {
            let body = if bytes.is_empty() {
                Body::empty()
            } else {
                Body::from_bytes(bytes)
            };
            let _ = reply.send(Ok(build_response(head.parts, body)));
            return;
        }
        EagerBody::Streaming(frames) => frames,
    };

    let (body_tx, body_rx) =
        async_channel::bounded::<Result<BodyFrame, BodyError>>(BODY_CHANNEL_CAPACITY);
    let resp = build_response(head.parts, Body::from_frames(body_rx));

    if reply.send(Ok(resp)).is_err() {
        return;
    }

    for frame in initial_frames {
        let is_err = frame.is_err();
        if body_tx.send(frame).await.is_err() || is_err {
            return;
        }
    }

    stream_response_body(
        stream,
        rx_buf,
        decoder,
        limits,
        timer,
        timeouts.exchange.body_idle,
        body_tx,
    )
    .await;
}

#[allow(clippy::future_not_send)]
async fn write_request<S: StreamIo>(
    stream: &mut S,
    head_buf: &mut BytesMut,
    request: http::Request<Body>,
) -> Result<(), Error> {
    let (parts, mut body) = request.into_parts();
    let known_len = if body.is_empty() == Some(true) {
        Some(0)
    } else {
        body.len().and_then(|len| u64::try_from(len).ok())
    };

    head_buf.clear();
    let mut plan = encode_request_head(&parts, RequestTarget::Origin, known_len, head_buf)
        .map_err(map_h1_encode_error)?;
    stream.write_bytes(head_buf).await?;

    if !plan.encoder.sends_body() {
        return stream.flush_bytes().await;
    }

    let mut wire_chunks = Vec::with_capacity(3);
    while let Some(frame_res) = body.next().await {
        let frame = frame_res.map_err(|err| {
            Error::exchange(ExchangeFailure::RequestBody, Cause::Detail(err.to_string()))
        })?;
        match frame {
            BodyFrame::Data(data) => {
                if !data.is_empty() {
                    wire_chunks.clear();
                    plan.encoder
                        .data(data, &mut wire_chunks)
                        .map_err(map_h1_encode_error)?;
                    for chunk in &wire_chunks {
                        stream.write_bytes(chunk).await?;
                    }
                }
            }
            BodyFrame::Trailers(trailers) => {
                let tail = plan
                    .encoder
                    .trailers(&trailers)
                    .map_err(map_h1_encode_error)?;
                stream.write_bytes(&tail).await?;
                return stream.flush_bytes().await;
            }
            _ => {}
        }
    }

    if let Some(tail) = plan.encoder.finish().map_err(map_h1_encode_error)? {
        stream.write_bytes(&tail).await?;
    }
    stream.flush_bytes().await
}

#[allow(clippy::future_not_send)]
async fn read_final_response_head<S: StreamIo>(
    stream: &mut S,
    rx_buf: &mut BytesMut,
    request_method: &Method,
    limits: &Limits,
) -> Result<ResponseHead, Error> {
    let mut received_any = !rx_buf.is_empty();
    loop {
        match parse_response_head(rx_buf, limits, request_method) {
            Ok(Some(head)) => {
                if head.is_interim() {
                    continue;
                }
                return Ok(head);
            }
            Ok(None) => {
                let n = stream.read_into(rx_buf).await?;
                if n == 0 {
                    let failure = if received_any {
                        ExchangeFailure::Incomplete
                    } else {
                        ExchangeFailure::Terminated
                    };
                    return Err(Error::exchange(
                        failure,
                        Cause::H1(http_kit_h1::Error::ConnectionClosed),
                    ));
                }
                received_any = true;
            }
            Err(err) => return Err(map_parse_error(err)),
        }
    }
}

#[allow(clippy::future_not_send)]
async fn stream_response_body<S, T>(
    stream: &mut S,
    rx_buf: &mut BytesMut,
    mut decoder: BodyDecoder,
    limits: &Limits,
    timer: Option<&T>,
    body_idle: Option<Duration>,
    body_tx: async_channel::Sender<Result<BodyFrame, BodyError>>,
) where
    S: StreamIo,
    T: EmbeddedTimer,
{
    loop {
        match decoder.decode(rx_buf, limits) {
            Ok(Some(Decoded::Data(bytes))) => {
                if body_tx.send(Ok(BodyFrame::Data(bytes))).await.is_err() {
                    return;
                }
            }
            Ok(Some(Decoded::Trailers(trailers))) => {
                let _ = body_tx.send(Ok(BodyFrame::Trailers(trailers))).await;
            }
            Ok(Some(Decoded::End)) => return,
            Ok(None) => {
                let read_res = timed(
                    timer,
                    body_idle,
                    || Error::Timeout(TimedOut::BodyIdle),
                    stream.read_into(rx_buf),
                )
                .await;
                match read_res {
                    Ok(0) => loop {
                        match decoder.decode_eof(rx_buf, limits) {
                            Ok(Decoded::Data(bytes)) => {
                                if body_tx.send(Ok(BodyFrame::Data(bytes))).await.is_err() {
                                    return;
                                }
                            }
                            Ok(Decoded::Trailers(trailers)) => {
                                let _ = body_tx.send(Ok(BodyFrame::Trailers(trailers))).await;
                            }
                            Ok(Decoded::End) => return,
                            Err(err) => {
                                let _ = body_tx
                                    .send(Err(BodyError::from(http_kit_h1::Error::Parse(err))))
                                    .await;
                                return;
                            }
                        }
                    },
                    Ok(_) => {}
                    Err(Error::Timeout(TimedOut::BodyIdle)) => {
                        let _ = body_tx
                            .send(Err(BodyError::Receive(ReceiveError::Stalled)))
                            .await;
                        return;
                    }
                    Err(err) => {
                        let _ = body_tx.send(Err(BodyError::Other(Box::new(err)))).await;
                        return;
                    }
                }
            }
            Err(err) => {
                let _ = body_tx
                    .send(Err(BodyError::from(http_kit_h1::Error::Parse(err))))
                    .await;
                return;
            }
        }
    }
}

fn map_h1_encode_error(err: http_kit_h1::Error) -> Error {
    let failure = match &err {
        http_kit_h1::Error::ContentLengthMismatch { declared } => {
            ExchangeFailure::RequestBodyLength {
                declared: *declared,
            }
        }
        _ => ExchangeFailure::InvalidRequest,
    };
    Error::exchange(failure, Cause::H1(err))
}

fn map_parse_error(err: ParseError) -> Error {
    let failure = match &err {
        ParseError::HeadTooLarge { limit } => ExchangeFailure::HeadTooLarge { limit: *limit },
        ParseError::TooManyHeaders { limit } => ExchangeFailure::TooManyFields { limit: *limit },
        ParseError::UnsupportedTransferCoding => ExchangeFailure::TransferCoding,
        ParseError::Incomplete => ExchangeFailure::Incomplete,
        _ => ExchangeFailure::Protocol,
    };
    Error::exchange(failure, Cause::H1(http_kit_h1::Error::Parse(err)))
}

#[cfg(test)]
mod tests {
    use core::{
        cell::RefCell,
        future::{Ready, ready},
        net::Ipv4Addr,
    };

    use futures_executor::block_on;
    use futures_util::future::join;
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::ResponseExt as _;

    #[derive(Debug, Clone, Copy)]
    struct MockIoError;

    impl fmt::Display for MockIoError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("mock embedded I/O error")
        }
    }

    impl core::error::Error for MockIoError {}

    impl embedded_io_async::Error for MockIoError {
        fn kind(&self) -> embedded_io_async::ErrorKind {
            embedded_io_async::ErrorKind::Other
        }
    }

    type ChunkList = Vec<Vec<u8>>;

    /// `!Send` mock embedded stack (via `RefCell`) mirroring `embassy_net::Stack` on ESP32-C6.
    struct MockEmbeddedStack {
        exchanges: RefCell<Vec<ChunkList>>,
        recorded_requests: RefCell<Vec<Vec<u8>>>,
    }

    impl MockEmbeddedStack {
        fn with_responses(responses: impl IntoIterator<Item = ChunkList>) -> Self {
            Self {
                exchanges: RefCell::new(responses.into_iter().collect()),
                recorded_requests: RefCell::new(Vec::new()),
            }
        }
    }

    struct MockSocket<'a> {
        stack: &'a MockEmbeddedStack,
        tx: Vec<u8>,
        rx_chunks: ChunkList,
        chunk_idx: usize,
        chunk_off: usize,
    }

    impl Drop for MockSocket<'_> {
        fn drop(&mut self) {
            self.stack
                .recorded_requests
                .borrow_mut()
                .push(core::mem::take(&mut self.tx));
        }
    }

    impl embedded_io_async::ErrorType for MockSocket<'_> {
        type Error = MockIoError;
    }

    impl AsyncRead for MockSocket<'_> {
        fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>> {
            while self.chunk_idx < self.rx_chunks.len() {
                let chunk = &self.rx_chunks[self.chunk_idx];
                if self.chunk_off < chunk.len() {
                    let take = (chunk.len() - self.chunk_off).min(buf.len());
                    buf[..take].copy_from_slice(&chunk[self.chunk_off..self.chunk_off + take]);
                    self.chunk_off += take;
                    return ready(Ok(take));
                }
                self.chunk_idx += 1;
                self.chunk_off = 0;
            }
            ready(Ok(0))
        }
    }

    impl AsyncWrite for MockSocket<'_> {
        fn write(&mut self, buf: &[u8]) -> impl Future<Output = Result<usize, Self::Error>> {
            self.tx.extend_from_slice(buf);
            ready(Ok(buf.len()))
        }

        fn flush(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
            ready(Ok(()))
        }
    }

    impl TcpConnect for MockEmbeddedStack {
        type Error = MockIoError;
        type Connection<'a> = MockSocket<'a>;

        fn connect(
            &self,
            _remote: SocketAddr,
        ) -> impl Future<Output = Result<Self::Connection<'_>, Self::Error>> {
            let rx_chunks = self.exchanges.borrow_mut().remove(0);
            ready(Ok(MockSocket {
                stack: self,
                tx: Vec::new(),
                rx_chunks,
                chunk_idx: 0,
                chunk_off: 0,
            }))
        }
    }

    impl Dns for MockEmbeddedStack {
        type Error = MockIoError;

        fn get_host_by_name(
            &self,
            _host: &str,
            _addr_type: AddrType,
        ) -> impl Future<Output = Result<IpAddr, Self::Error>> {
            ready(Ok(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))))
        }

        fn get_host_by_address(
            &self,
            _addr: IpAddr,
            _result: &mut [u8],
        ) -> impl Future<Output = Result<usize, Self::Error>> {
            ready(Err(MockIoError))
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Telemetry {
        chip: String,
        greeting: String,
    }

    #[test]
    fn embedded_backend_streams_chunked_cjk_json_and_follows_redirects() {
        let cjk = "无线遥测正常。テレメトリ正常。원격 측정 정상.";
        let response_json = serde_json::to_vec(&Telemetry {
            chip: "esp32c6".to_owned(),
            greeting: cjk.to_owned(),
        })
        .unwrap();

        let redirect_raw = b"HTTP/1.1 302 Found\r\nLocation: http://esp-emu.local:8080/v1/telemetry\r\nContent-Length: 0\r\n\r\n".to_vec();
        let split = response_json.len() / 2;
        let first_part = &response_json[..split];
        let second_part = &response_json[split..];
        let final_head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let chunk_1 = [
            format!("{:x}\r\n", first_part.len()).as_bytes(),
            first_part,
            b"\r\n",
        ]
        .concat();
        let chunk_2 = [
            format!("{:x}\r\n", second_part.len()).as_bytes(),
            second_part,
            b"\r\n0\r\n\r\n",
        ]
        .concat();

        let stack = MockEmbeddedStack::with_responses([
            vec![redirect_raw],
            vec![final_head, chunk_1, chunk_2],
        ]);

        let (backend, runner) = EmbeddedBackend::channel(Transport::system());
        let mut client = backend
            .follow_redirect()
            .bearer_auth("esp32c6-session-token")
            .error_for_status();

        block_on(async {
            let client_task = async {
                assert!(client.post("http://esp-emu.local:8080/ invalid").is_err());
                let out: Telemetry = client
                    .post("http://esp-emu.local:8080/entry")
                    .unwrap()
                    .json_body(&Telemetry {
                        chip: "esp32c6".to_owned(),
                        greeting: cjk.to_owned(),
                    })
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(out.chip, "esp32c6");
                assert_eq!(out.greeting, cjk);
                drop(client);
            };
            join(runner.run(&stack, &stack), client_task).await;
        });

        let requests = stack.recorded_requests.borrow();
        assert_eq!(requests.len(), 2);
        let first_req = core::str::from_utf8(&requests[0]).unwrap();
        assert!(first_req.starts_with("POST /entry HTTP/1.1\r\n"));
        assert!(first_req.contains("authorization: Bearer esp32c6-session-token\r\n"));
        let second_req = core::str::from_utf8(&requests[1]).unwrap();
        assert!(second_req.starts_with("GET /v1/telemetry HTTP/1.1\r\n"));
    }

    #[test]
    fn embedded_runner_enforces_response_head_timeout_when_timer_fires() {
        struct ImmediateTimer;
        impl EmbeddedTimer for ImmediateTimer {
            type After = Ready<()>;
            fn after(&self, _duration: Duration) -> Self::After {
                ready(())
            }
        }

        struct PendingSocket;
        impl embedded_io_async::ErrorType for PendingSocket {
            type Error = MockIoError;
        }
        impl AsyncRead for PendingSocket {
            fn read(
                &mut self,
                _buf: &mut [u8],
            ) -> impl Future<Output = Result<usize, Self::Error>> {
                core::future::pending()
            }
        }
        impl AsyncWrite for PendingSocket {
            fn write(&mut self, buf: &[u8]) -> impl Future<Output = Result<usize, Self::Error>> {
                ready(Ok(buf.len()))
            }
            fn flush(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
                ready(Ok(()))
            }
        }

        struct StallStack;
        impl TcpConnect for StallStack {
            type Error = MockIoError;
            type Connection<'a> = PendingSocket;
            fn connect(
                &self,
                _remote: SocketAddr,
            ) -> impl Future<Output = Result<Self::Connection<'_>, Self::Error>> {
                ready(Ok(PendingSocket))
            }
        }
        impl Dns for StallStack {
            type Error = MockIoError;
            fn get_host_by_name(
                &self,
                _host: &str,
                _addr_type: AddrType,
            ) -> impl Future<Output = Result<IpAddr, Self::Error>> {
                ready(Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            }
            fn get_host_by_address(
                &self,
                _addr: IpAddr,
                _result: &mut [u8],
            ) -> impl Future<Output = Result<usize, Self::Error>> {
                ready(Err(MockIoError))
            }
        }

        let transport = Transport::builder()
            .response_head_timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let (mut client, runner) = EmbeddedBackend::channel(transport);
        let stack = StallStack;
        let timer = ImmediateTimer;

        block_on(async {
            let check = async {
                let err = client
                    .get("http://127.0.0.1:8080/stall")
                    .unwrap()
                    .await
                    .unwrap_err();
                assert!(matches!(err, Error::Timeout(TimedOut::ResponseHead)));
                drop(client);
            };
            join(runner.run_with_timer(&stack, &stack, &timer), check).await;
        });
    }

    #[cfg(embedded_tls)]
    async fn serve_one_unbuffered_https(
        server_cfg: Arc<rustls::ServerConfig>,
        c2s_rx: async_channel::Receiver<Vec<u8>>,
        s2c_tx: async_channel::Sender<Vec<u8>>,
    ) {
        use rustls::{server::UnbufferedServerConnection, unbuffered::ConnectionState};

        let mut srv = UnbufferedServerConnection::new(server_cfg).unwrap();
        let mut rx_buf = Vec::new();
        let mut app_req = Vec::new();
        loop {
            let status = srv.process_tls_records(&mut rx_buf);
            let mut discard = status.discard;
            match status.state.unwrap() {
                ConnectionState::EncodeTlsData(mut enc) => {
                    let mut out = vec![0u8; 4096];
                    let n = match enc.encode(&mut out) {
                        Ok(n) => n,
                        Err(rustls::unbuffered::EncodeError::InsufficientSize(need)) => {
                            out.resize(need.required_size, 0);
                            enc.encode(&mut out).unwrap()
                        }
                        Err(err) => panic!("server encode: {err}"),
                    };
                    out.truncate(n);
                    let _ = s2c_tx.send(out).await;
                    rx_buf.drain(..discard);
                }
                ConnectionState::TransmitTlsData(tx) => {
                    tx.done();
                    rx_buf.drain(..discard);
                }
                ConnectionState::BlockedHandshake => {
                    rx_buf.drain(..discard);
                    let chunk = c2s_rx.recv().await.expect("client handshake bytes");
                    rx_buf.extend_from_slice(&chunk);
                }
                ConnectionState::ReadTraffic(mut rt) => {
                    while let Some(rec) = rt.next_record() {
                        let rec = rec.unwrap();
                        discard += rec.discard;
                        app_req.extend_from_slice(rec.payload);
                    }
                    rx_buf.drain(..discard);
                }
                ConnectionState::WriteTraffic(mut wt) => {
                    rx_buf.drain(..discard);
                    if app_req.windows(4).any(|w| w == b"\r\n\r\n") {
                        let body = "加密通道正常。暗号化通信は正常です。암호화 채널 정상.";
                        let raw = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        let mut out = vec![0u8; raw.len() + 256];
                        let n = wt.encrypt(raw.as_bytes(), &mut out).unwrap();
                        out.truncate(n);
                        let _ = s2c_tx.send(out).await;
                        let mut close_buf = vec![0u8; 128];
                        let cn = wt.queue_close_notify(&mut close_buf).unwrap();
                        close_buf.truncate(cn);
                        let _ = s2c_tx.send(close_buf).await;
                        break;
                    }
                    let Ok(chunk) = c2s_rx.recv().await else {
                        break;
                    };
                    rx_buf.extend_from_slice(&chunk);
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => break,
                _ => {
                    rx_buf.drain(..discard);
                }
            }
        }
    }

    #[cfg(embedded_tls)]
    #[derive(Debug)]
    struct FixedTimeProvider(rustls_pki_types::UnixTime);

    #[cfg(embedded_tls)]
    impl rustls::time_provider::TimeProvider for FixedTimeProvider {
        fn current_time(&self) -> Option<rustls_pki_types::UnixTime> {
            Some(self.0)
        }
    }

    #[cfg(embedded_tls)]
    struct DuplexSocket {
        rx: async_channel::Receiver<Vec<u8>>,
        tx: async_channel::Sender<Vec<u8>>,
        pending: Vec<u8>,
        offset: usize,
    }

    #[cfg(embedded_tls)]
    impl embedded_io_async::ErrorType for DuplexSocket {
        type Error = MockIoError;
    }

    #[cfg(embedded_tls)]
    impl AsyncRead for DuplexSocket {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            while self.offset >= self.pending.len() {
                let Ok(next) = self.rx.recv().await else {
                    return Ok(0);
                };
                self.pending = next;
                self.offset = 0;
            }
            let n = (self.pending.len() - self.offset).min(buf.len());
            buf[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
            self.offset += n;
            Ok(n)
        }
    }

    #[cfg(embedded_tls)]
    impl AsyncWrite for DuplexSocket {
        fn write(&mut self, buf: &[u8]) -> impl Future<Output = Result<usize, Self::Error>> {
            let _ = self.tx.send_blocking(buf.to_vec());
            ready(Ok(buf.len()))
        }
        fn flush(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
            ready(Ok(()))
        }
    }

    #[cfg(embedded_tls)]
    struct DuplexStack {
        slot: RefCell<Option<DuplexSocket>>,
    }

    #[cfg(embedded_tls)]
    impl TcpConnect for DuplexStack {
        type Error = MockIoError;
        type Connection<'a> = DuplexSocket;
        fn connect(
            &self,
            _remote: SocketAddr,
        ) -> impl Future<Output = Result<Self::Connection<'_>, Self::Error>> {
            ready(Ok(self.slot.borrow_mut().take().expect("one TLS dial")))
        }
    }

    #[cfg(embedded_tls)]
    impl Dns for DuplexStack {
        type Error = MockIoError;
        fn get_host_by_name(
            &self,
            _host: &str,
            _addr_type: AddrType,
        ) -> impl Future<Output = Result<IpAddr, Self::Error>> {
            ready(Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)))
        }
        fn get_host_by_address(
            &self,
            _addr: IpAddr,
            _result: &mut [u8],
        ) -> impl Future<Output = Result<usize, Self::Error>> {
            ready(Err(MockIoError))
        }
    }

    #[cfg(embedded_tls)]
    #[test]
    fn embedded_tls_unbuffered_handshake_and_https_round_trip() {
        let certified = rcgen::generate_simple_self_signed(vec!["esp32c6.local".to_owned()])
            .expect("generate self-signed cert");
        let cert_pem = certified.cert.pem();
        let cert_der = rustls_pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );

        let now = rustls_pki_types::UnixTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let time_provider: Arc<dyn rustls::time_provider::TimeProvider> =
            Arc::new(FixedTimeProvider(now));

        let server_cfg = Arc::new(
            rustls::ServerConfig::builder_with_details(
                Arc::clone(&provider),
                Arc::clone(&time_provider),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap(),
        );

        let transport = Transport::builder()
            .extra_root_certificates_pem(cert_pem.as_bytes())
            .unwrap()
            .embedded_tls_provider(provider, time_provider)
            .build()
            .unwrap();

        let (c2s_tx, c2s_rx) = async_channel::unbounded::<Vec<u8>>();
        let (s2c_tx, s2c_rx) = async_channel::unbounded::<Vec<u8>>();
        let stack = DuplexStack {
            slot: RefCell::new(Some(DuplexSocket {
                rx: s2c_rx,
                tx: c2s_tx,
                pending: Vec::new(),
                offset: 0,
            })),
        };

        let server_task = serve_one_unbuffered_https(server_cfg, c2s_rx, s2c_tx);
        let (mut client, runner) = EmbeddedBackend::channel(transport);
        block_on(async {
            let client_task = async {
                let resp = client
                    .get("https://esp32c6.local/secure")
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(resp.status(), http::StatusCode::OK);
                let text = resp.into_string().await.unwrap();
                assert_eq!(
                    text.as_str(),
                    "加密通道正常。暗号化通信は正常です。암호화 채널 정상."
                );
                drop(client);
            };
            let ((), ((), ())) =
                join(runner.run(&stack, &stack), join(server_task, client_task)).await;
        });
    }
}
