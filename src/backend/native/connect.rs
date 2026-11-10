//! Opening an HTTP/1.1 connection on `http-kit-io` sockets, through the
//! transport's proxy rules: the [`route`] the async-net connector follows,
//! with every leg on owned-buffer streams and TLS through `http-kit-tls`,
//! the origin's session inside the proxy's when the proxy is HTTPS.

use std::{
    future::{Future, pending},
    io,
    net::SocketAddr,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use futures_channel::oneshot;
use futures_util::{
    FutureExt,
    future::{Either, LocalBoxFuture, select},
};
use http::{HeaderValue, Method, header, uri::Scheme};
use http_kit::{Body, Request};
use http_kit_h1::{
    ClientConfig, ClientOutcome, RequestTarget, SendRequest, handshake, handshake_stream,
};
use http_kit_io::{
    BufResult, IntoInner, Io, IoBuf, IoBufMut, Read, SendFile, Split, TcpOptions, Timer, Write,
    poll::CopyingPoll,
};
use http_kit_tls::{TlsConnector, Transport as TlsTransport, rustls::pki_types::ServerName};
use tracing::debug;

use super::upgrade::{self, Switched, Upgrade};
use crate::{
    Error, Transport,
    error::ProxyErrorKind,
    transport::{
        happy_eyeballs::{self, Dialer},
        route::{Origin, Protocols, Route, Target, Via, route},
        socks5::{self, Handshake},
    },
};

/// An `http-kit-io` implementation whose stream sockets `http-kit-tls` can
/// run over: every implementation `http-kit-io` ships is one.
#[cfg(unix)]
pub trait NativeIo: Io<TcpStream: TlsTransport, UnixStream: TlsTransport> {}

#[cfg(unix)]
impl<I: Io<TcpStream: TlsTransport, UnixStream: TlsTransport>> NativeIo for I {}

/// An `http-kit-io` implementation whose stream sockets `http-kit-tls` can
/// run over: every implementation `http-kit-io` ships is one.
#[cfg(not(unix))]
pub trait NativeIo: Io<TcpStream: TlsTransport> {}

#[cfg(not(unix))]
impl<I: Io<TcpStream: TlsTransport>> NativeIo for I {}

/// A fresh HTTP/1.1 connection: its handle, how requests on it are shaped,
/// and the future that drives its socket.
pub struct Dialed {
    pub send: H1Send,
    pub via: Via,
    pub driver: LocalBoxFuture<'static, ()>,
}

/// An HTTP/1.1 connection's request handle, with the token to the stream a
/// request on it may switch the connection to.
#[derive(Debug)]
pub struct H1Send {
    pub requests: SendRequest,
    pub upgrade: Upgrade,
    /// Set once a read on the connection outlasted the read timeout, which
    /// closed it: what failed under a request then was the timeout.
    pub stalled: Stalled,
}

impl H1Send {
    /// Whether the connection stopped taking requests.
    pub fn is_closed(&self) -> bool {
        self.requests.is_closed()
    }
}

/// The mark a connection's read half sets when a read outlasted the read
/// timeout. It is read on the request's thread, after the connection's
/// channels closed.
#[derive(Clone, Debug, Default)]
pub struct Stalled(Arc<AtomicBool>);

impl Stalled {
    fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether the connection closed because a read timed out.
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Connects to `origin` the way the transport's rules say — its unix domain
/// socket when it has one, else TCP through whatever proxy the rules pick —
/// and runs the HTTP/1.1 handshake over the result, within the transport's
/// connect timeout.
///
/// # Errors
///
/// Every leg's failure; [`Error::Timeout`] when the connect timeout passed
/// first.
pub async fn dial<I: NativeIo>(
    io: &I,
    transport: &Transport,
    tls: &TlsConnector,
    origin: &Origin,
) -> Result<Dialed, Error> {
    let Some(deadline) = transport
        .connect_timeout()
        .and_then(|timeout| Instant::now().checked_add(timeout))
    else {
        return dial_route(io, transport, tls, origin).await;
    };
    // Dropping the dial at the deadline closes whatever sockets it opened.
    match select(
        pin!(dial_route(io, transport, tls, origin)),
        pin!(io.sleep_until(deadline)),
    )
    .await
    {
        Either::Left((dialed, _)) => dialed,
        Either::Right(((), _)) => {
            debug!(host = %origin.host, "connect timeout passed before the dial finished");
            Err(Error::Timeout)
        }
    }
}

/// [`dial`], unbounded.
async fn dial_route<I: NativeIo>(
    io: &I,
    transport: &Transport,
    tls: &TlsConnector,
    origin: &Origin,
) -> Result<Dialed, Error> {
    let secure = origin.scheme == Scheme::HTTPS;
    let last = LastLeg {
        io,
        tls,
        read_timeout: transport.read_timeout(),
    };

    #[cfg(unix_socket)]
    if let Some(path) = transport.unix_socket() {
        let unix = io.connect_unix(path).await.map_err(|error| {
            Error::Transport(Box::new(io::Error::new(
                error.kind(),
                format!("unix domain socket {}: {error}", path.display()),
            )))
        })?;
        return last.finish(&origin.host, secure, unix, Via::Direct).await;
    }

    let target = Target {
        host: &origin.host,
        port: origin.port,
        tls: secure,
        tunnel_plaintext: false,
        protocols: Protocols::Http1,
    };
    match route(transport.proxy(), target)? {
        Route::Direct => {
            let tcp = tcp(io, &origin.host, origin.port).await?;
            last.finish(&origin.host, secure, tcp, Via::Direct).await
        }
        Route::Forward {
            proxy,
            authorization,
        } => {
            let tcp = tcp(io, &proxy.host, proxy.port).await?;
            last.finish(
                &proxy.host,
                proxy.tls,
                tcp,
                Via::HttpProxy { authorization },
            )
            .await
        }
        Route::Tunnel {
            proxy,
            authority,
            authorization,
        } => {
            let tcp = tcp(io, &proxy.host, proxy.port).await?;
            if proxy.tls {
                // The proxy's session carries the tunnel, and the origin's
                // runs inside it.
                let secured = tls
                    .connect(server_name(&proxy.host)?, tcp, io)
                    .await
                    .map_err(Error::tls)?;
                let tunneled = tunnel(io, secured, &authority, authorization).await?;
                last.finish(&origin.host, secure, tunneled, Via::Direct)
                    .await
            } else {
                let tunneled = tunnel(io, tcp, &authority, authorization).await?;
                last.finish(&origin.host, secure, tunneled, Via::Direct)
                    .await
            }
        }
        Route::Socks5 {
            host,
            port,
            credentials,
            resolve_remotely,
        } => {
            let tcp = tcp(io, &host, port).await?;
            let OwnedBytes(tcp) = socks5::connect(
                OwnedBytes(tcp),
                &origin.host,
                origin.port,
                credentials
                    .as_ref()
                    .map(|(user, password)| (user.as_str(), password.as_str())),
                resolve_remotely,
            )
            .await?;
            last.finish(&origin.host, secure, tcp, Via::Direct).await
        }
    }
}

/// What the last leg of every route needs: TLS to the host that leg
/// reaches, and the read timeout the connection's reads run under.
struct LastLeg<'a, I> {
    io: &'a I,
    tls: &'a TlsConnector,
    read_timeout: Option<Duration>,
}

impl<I: Io> LastLeg<'_, I> {
    /// Wraps `stream` in TLS for `host` when `secure`, then starts
    /// HTTP/1.1 on it.
    async fn finish<S: TlsTransport>(
        &self,
        host: &str,
        secure: bool,
        stream: S,
        via: Via,
    ) -> Result<Dialed, Error> {
        let config = ClientConfig {
            request_target: match via {
                Via::Direct => RequestTarget::Origin,
                Via::HttpProxy { .. } => RequestTarget::Absolute,
            },
            ..ClientConfig::default()
        };
        let io = self.io.clone();
        if !secure {
            return Ok(start(stream, io, config, via, self.read_timeout));
        }
        let stream = self
            .tls
            .connect(server_name(host)?, stream, self.io)
            .await
            .map_err(Error::tls)?;
        Ok(start(stream, io, config, via, self.read_timeout))
    }
}

/// `host` as the name a TLS handshake sends and verifies.
fn server_name(host: &str) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(host.to_owned()).map_err(Error::tls)
}

/// Runs the HTTP/1.1 client over `stream`, each of its reads bounded by
/// `read_timeout`; the driver logs how it ended, and when a request
/// switched the connection, holds the switched stream on this thread until
/// the request's [`Upgrade`] claims it.
///
/// A read that outlasts the timeout stops the driver, which drops the
/// connection with the read still in flight. The switched stream is handed
/// over without the bound: its idle time belongs to its owner.
fn start<S, T>(
    stream: S,
    timer: T,
    config: ClientConfig,
    via: Via,
    read_timeout: Option<Duration>,
) -> Dialed
where
    S: Split + 'static,
    S::ReadHalf: Read + 'static,
    S::WriteHalf: Write + SendFile + 'static,
    T: Timer + Clone + 'static,
{
    let (read, write) = stream.split();
    let stalled = Stalled::default();
    let (stall, stalls) = oneshot::channel();
    let read = TimedRead {
        inner: read,
        timer: timer.clone(),
        timeout: read_timeout,
        stall: Some(stall),
        stalled: stalled.clone(),
    };
    let (requests, connection) = handshake(read, write, timer, config);
    let (upgrade, claims) = upgrade::channel();
    let driver = async move {
        // Canceled only once the read half is gone, with the connection.
        let stalled = async {
            if stalls.await.is_err() {
                pending::<()>().await;
            }
        };
        let ended = match select(pin!(connection.run()), pin!(stalled)).await {
            Either::Left((ended, _)) => ended,
            Either::Right(((), _)) => {
                debug!("HTTP/1.1 connection closed: a read outlasted the read timeout");
                return;
            }
        };
        match ended {
            Ok(ClientOutcome::Closed) => {}
            Ok(ClientOutcome::Upgraded(upgraded)) => {
                let rejoined = Rejoined {
                    read: upgraded.read.inner,
                    write: upgraded.write,
                };
                let switched = Switched::new(upgraded.read_buf, CopyingPoll::new(rejoined));
                claims.hand_over(switched).await;
            }
            Err(error) => debug!(%error, "HTTP/1.1 connection ended with an error"),
        }
    }
    .boxed_local();
    Dialed {
        send: H1Send {
            requests,
            upgrade,
            stalled,
        },
        via,
        driver,
    }
}

/// A connection's read half whose every read waits at most `timeout` for
/// the server.
///
/// An owned-buffer read cannot be abandoned and still hand its buffer back,
/// so a read that runs out never returns: it marks the connection
/// [`Stalled`], signals the driver through `stall`, and stays pending until
/// the driver drops the connection.
struct TimedRead<R, T> {
    inner: R,
    timer: T,
    timeout: Option<Duration>,
    stall: Option<oneshot::Sender<()>>,
    stalled: Stalled,
}

impl<R: Read, T: Timer> Read for TimedRead<R, T> {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        let Some(deadline) = self
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout))
        else {
            return self.inner.read(buf).await;
        };
        match select(
            pin!(self.inner.read(buf)),
            pin!(self.timer.sleep_until(deadline)),
        )
        .await
        {
            Either::Left((read, _)) => read,
            Either::Right(((), _)) => {
                self.stalled.mark();
                if let Some(stall) = self.stall.take() {
                    stall.send(()).ok();
                }
                pending().await
            }
        }
    }
}

/// Asks the HTTP proxy on `stream` for a `CONNECT` tunnel to `authority` and
/// hands back the socket's halves once the proxy relays bytes.
async fn tunnel<I, S>(
    io: &I,
    stream: S,
    authority: &str,
    authorization: Option<HeaderValue>,
) -> Result<Rejoined<S::ReadHalf, S::WriteHalf>, Error>
where
    I: Io,
    S: Split + 'static,
    S::WriteHalf: SendFile,
{
    let (send, connection) = handshake_stream(stream, io.clone(), ClientConfig::default());
    let mut request = Request::new(Body::empty());
    *request.method_mut() = Method::CONNECT;
    *request.uri_mut() = authority
        .parse()
        .map_err(|error| Error::InvalidUri(format!("{authority}: {error}")))?;
    let host = HeaderValue::from_str(authority)
        .map_err(|error| Error::InvalidRequest(error.to_string()))?;
    request.headers_mut().insert(header::HOST, host);
    if let Some(authorization) = authorization {
        request
            .headers_mut()
            .insert(header::PROXY_AUTHORIZATION, authorization);
    }
    // The handle goes with the exchange, so a refused tunnel lets the
    // connection close instead of waiting for another request; only the
    // status leaves it, so a refusal's body is dropped while the connection
    // still pumps it.
    let exchange = async move { send.send(request).await.map(|response| response.status()) };
    let (outcome, status) = futures_util::join!(connection.run(), exchange);
    let status = status.map_err(|error| match error {
        http_kit_h1::Error::ConnectionClosed => {
            ProxyErrorKind::TunnelProtocol("proxy closed the connection before answering CONNECT")
                .into()
        }
        error => Error::Transport(Box::new(error)),
    })?;
    if !status.is_success() {
        return Err(ProxyErrorKind::TunnelRejected(status).into());
    }
    match outcome.map_err(|error| Error::Transport(Box::new(error)))? {
        ClientOutcome::Upgraded(upgraded) => {
            if !upgraded.read_buf.is_empty() {
                return Err(ProxyErrorKind::TunnelProtocol(
                    "proxy sent bytes into the tunnel before the client spoke",
                )
                .into());
            }
            Ok(Rejoined {
                read: upgraded.read,
                write: upgraded.write,
            })
        }
        ClientOutcome::Closed => Err(ProxyErrorKind::TunnelProtocol(
            "proxy answered CONNECT without switching to the tunnel",
        )
        .into()),
    }
}

/// A connection's halves after an HTTP/1.1 switch, as one stream again.
pub struct Rejoined<R, W> {
    read: R,
    write: W,
}

impl<R: Read + 'static, W: Write + 'static> Split for Rejoined<R, W> {
    type ReadHalf = R;
    type WriteHalf = W;

    fn split(self) -> (R, W) {
        (self.read, self.write)
    }
}

/// TCP to `host`:`port`, raced over its addresses (RFC 8305).
async fn tcp<I: Io>(io: &I, host: &str, port: u16) -> Result<I::TcpStream, Error> {
    happy_eyeballs::connect(&IoDialer(io), host, port)
        .await
        .map_err(|error| Error::Transport(Box::new(error)))
}

/// Happy eyeballs over an `http-kit-io` implementation. Every connection
/// it opens has `TCP_NODELAY` on, as the async-net dialer's do: a request
/// head or a TLS record goes out at once instead of waiting on Nagle.
struct IoDialer<'a, I>(&'a I);

impl<I: Io> Dialer for IoDialer<'_, I> {
    type Stream = I::TcpStream;

    async fn dial(&self, addr: SocketAddr) -> io::Result<I::TcpStream> {
        let stream = self.0.connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        self.0.sleep_until(deadline)
    }
}

/// The SOCKS5 handshake over an owned-buffer stream.
struct OwnedBytes<S>(S);

impl<S: Read + Write> Handshake for OwnedBytes<S> {
    async fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.0.write_all(bytes).await.0
    }

    async fn recv(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            let filled = bytes.len();
            let BufResult(read, slice) = self.0.read(bytes.slice(filled..len)).await;
            bytes = slice.into_inner();
            match read {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(bytes)
    }
}
