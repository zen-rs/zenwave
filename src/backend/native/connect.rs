//! Opening an HTTP/1.1 connection on `http-kit-io` sockets, through the
//! transport's proxy rules: the [`route`] the async-net connector follows,
//! with every leg on owned-buffer streams and TLS through `http-kit-tls`,
//! the origin's session inside the proxy's when the proxy is HTTPS.

use std::{cell::Cell, future::Future, io, net::SocketAddr, pin::pin, sync::Arc, time::Instant};

use futures_util::{
    FutureExt,
    future::{Either, LocalBoxFuture, select},
};
use http::{HeaderValue, Method, header, uri::Scheme};
use http_kit::{Body, Request};
use http_kit_h1::{ClientConfig, ClientOutcome, RequestTarget, SendRequest, handshake_stream};
use http_kit_io::{
    BufResult, Dial, IntoInner, IoBuf, Read, ReadOwned, Resolve, SendFile, SpliceRead, SpliceWrite,
    Split, TcpOptions, Timer, Write,
};
use http_kit_tls::{
    HandshakeError, TlsConnector, Transport as TlsTransport, rustls::pki_types::ServerName,
};
use tracing::debug;

use super::upgrade::{self, Switched, Upgrade};
#[cfg(all(feature = "native-kernel-tls", target_os = "linux"))]
use crate::ConfigError;
use crate::{
    Cause, ConnectFailure, ConnectPhase, Error, Hop, TimedOut, TlsError, TlsFailure, Transport,
    TunnelError,
    transport::{
        happy_eyeballs::{self, Dialer},
        route::{Origin, Protocols, Route, Target, Via, route},
        socks5::{self, Handshake},
    },
};

/// What the native backend asks of an `http-kit-io` implementation.
///
/// It dials TCP (and, where the platform has them, Unix-domain) connections
/// that `http-kit-tls` can run over, keeps time, and, under `native-http3`,
/// binds datagram sockets.
///
/// It is zenwave's name for that set of capabilities and nothing more:
/// every type that offers them is one.
pub trait NativeIo:
    Dial<Connection: TlsTransport> + Timer + Clone + 'static + UnixDial + QuicBind
{
}

impl<I: Dial<Connection: TlsTransport> + Timer + Clone + 'static + UnixDial + QuicBind> NativeIo
    for I
{
}

/// What the native backend asks of a resolver: [`Resolve`] for the addresses
/// it dials and, with `native-http3`, [`ResolveHttps`](crate::dns::ResolveHttps)
/// for HTTP/3 discovery.
///
/// Like [`NativeIo`], zenwave's name for that set and nothing more.
#[cfg(native_h3)]
pub trait NativeResolve: crate::dns::ResolveHttps + 'static {}

#[cfg(native_h3)]
impl<R: crate::dns::ResolveHttps + 'static> NativeResolve for R {}

/// What the native backend asks of a resolver: [`Resolve`] for the addresses
/// it dials and, with `native-http3`, `ResolveHttps` for HTTP/3 discovery.
///
/// Like [`NativeIo`], zenwave's name for that set and nothing more.
#[cfg(not(native_h3))]
pub trait NativeResolve: Resolve + 'static {}

#[cfg(not(native_h3))]
impl<R: Resolve + 'static> NativeResolve for R {}

/// [`http_kit_io::DialUnix`] where the platform has Unix-domain sockets, and
/// no requirement elsewhere.
#[cfg(unix)]
pub trait UnixDial: http_kit_io::DialUnix<UnixConnection: TlsTransport> {}

#[cfg(unix)]
impl<I: http_kit_io::DialUnix<UnixConnection: TlsTransport>> UnixDial for I {}

/// [`http_kit_io::DialUnix`] where the platform has Unix-domain sockets, and
/// no requirement elsewhere.
#[cfg(not(unix))]
pub trait UnixDial {}

#[cfg(not(unix))]
impl<I> UnixDial for I {}

/// [`http_kit_io::Datagram`] with `native-http3`, which dials QUIC over UDP,
/// and no requirement without it.
#[cfg(native_h3)]
pub trait QuicBind: http_kit_io::Datagram {}

#[cfg(native_h3)]
impl<I: http_kit_io::Datagram> QuicBind for I {}

/// [`http_kit_io::Datagram`] with `native-http3`, which dials QUIC over UDP,
/// and no requirement without it.
#[cfg(not(native_h3))]
pub trait QuicBind {}

#[cfg(not(native_h3))]
impl<I> QuicBind for I {}

/// A fresh HTTP/1.1 connection: its handle, how requests on it are shaped,
/// and the future that drives its socket.
pub struct Dialed {
    pub send: H1Send,
    pub via: Via,
    pub driver: LocalBoxFuture<'static, ()>,
    /// Where the origin's TLS records are encrypted, for a TLS connection.
    #[cfg(all(
        test,
        target_os = "linux",
        feature = "native-kernel-tls",
        native_driver
    ))]
    pub tls_mode: Option<http_kit_tls::Mode>,
}

/// The TLS connector for `config`. With `native-kernel-tls` on Linux the
/// kernel is probed here, once for the connector the pool keeps, and each
/// handshake the kernel can take moves to kernel TLS.
///
/// # Errors
///
/// The kernel probe failed: its loopback sockets could not be opened, or it
/// refused a suite for a reason other than not supporting it.
#[cfg_attr(
    not(all(feature = "native-kernel-tls", target_os = "linux")),
    expect(
        clippy::unnecessary_wraps,
        reason = "only a Linux kernel TLS build can fail to probe"
    )
)]
pub fn connector(config: Arc<http_kit_tls::rustls::ClientConfig>) -> Result<TlsConnector, Error> {
    let connector = TlsConnector::new(config);
    #[cfg(all(feature = "native-kernel-tls", target_os = "linux"))]
    let connector = connector.with_kernel_tls(
        http_kit_tls::KernelTls::probe()
            .map_err(|error| Error::Config(ConfigError::KernelTls(error)))?,
    );
    Ok(connector)
}

/// An HTTP/1.1 connection's request handle, with the token to the stream a
/// request on it may switch the connection to.
#[derive(Debug)]
pub struct H1Send {
    pub requests: SendRequest,
    pub upgrade: Upgrade,
}

impl H1Send {
    /// Whether the connection stopped taking requests.
    pub fn is_closed(&self) -> bool {
        self.requests.is_closed()
    }
}

/// Connects to `origin` the way the transport's rules say — its unix domain
/// socket when it has one, else TCP through whatever proxy the rules pick —
/// and runs the HTTP/1.1 handshake over the result, within the transport's
/// connect timeout.
///
/// # Errors
///
/// Every leg's failure; [`TimedOut::Connect`] when the connect timeout
/// passed first, with the phase the dial was in.
pub async fn dial<I: NativeIo, R: Resolve>(
    io: &I,
    resolver: &R,
    transport: &Transport,
    tls: &TlsConnector,
    origin: &Origin,
) -> Result<Dialed, Error> {
    let phase = Cell::new(ConnectPhase::Resolve);
    let Some(deadline) = transport
        .connect_timeout()
        .and_then(|timeout| Instant::now().checked_add(timeout))
    else {
        return dial_route(io, resolver, transport, tls, origin, &phase).await;
    };
    // Dropping the dial at the deadline closes whatever sockets it opened.
    match select(
        pin!(dial_route(io, resolver, transport, tls, origin, &phase)),
        pin!(io.sleep_until(deadline)),
    )
    .await
    {
        Either::Left((dialed, _)) => dialed,
        Either::Right(((), _)) => {
            let during = phase.get();
            debug!(host = %origin.host, %during, "connect timeout passed before the dial finished");
            Err(Error::Timeout(TimedOut::Connect { during }))
        }
    }
}

/// [`dial`], unbounded. `phase` follows the dial: where it was when a
/// deadline passes.
async fn dial_route<I: NativeIo, R: Resolve>(
    io: &I,
    resolver: &R,
    transport: &Transport,
    tls: &TlsConnector,
    origin: &Origin,
    phase: &Cell<ConnectPhase>,
) -> Result<Dialed, Error> {
    let secure = origin.scheme == Scheme::HTTPS;
    let last = LastLeg { io, tls, phase };

    #[cfg(unix_socket)]
    if let Some(path) = transport.unix_socket() {
        phase.set(ConnectPhase::Tcp);
        let unix = io.connect_unix(path).await.map_err(|error| {
            Error::connect(
                Hop::Origin,
                &origin.host,
                origin.port,
                ConnectFailure::Unix {
                    path: path.to_path_buf(),
                    error,
                },
            )
        })?;
        return last.finish_origin(origin, unix).await;
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
            let tcp = tcp(io, resolver, Hop::Origin, &origin.host, origin.port, phase).await?;
            last.finish_origin(origin, tcp).await
        }
        Route::Forward {
            proxy,
            authorization,
        } => {
            let tcp = tcp(io, resolver, Hop::Proxy, &proxy.host, proxy.port, phase).await?;
            last.finish(
                Hop::Proxy,
                &proxy.host,
                proxy.port,
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
            let tcp = tcp(io, resolver, Hop::Proxy, &proxy.host, proxy.port, phase).await?;
            let via = (proxy.host.as_str(), proxy.port);
            if proxy.tls {
                // The proxy's session carries the tunnel, and the origin's
                // runs inside it.
                phase.set(ConnectPhase::Tls);
                let secured = tls
                    .connect(server_name(via.0)?, tcp, io)
                    .await
                    .map_err(|error| handshake_failure(Hop::Proxy, via.0, via.1, error))?;
                phase.set(ConnectPhase::Proxy);
                let tunneled = tunnel(io, secured, via, &authority, authorization).await?;
                last.finish_origin(origin, tunneled).await
            } else {
                phase.set(ConnectPhase::Proxy);
                let tunneled = tunnel(io, tcp, via, &authority, authorization).await?;
                last.finish_origin(origin, tunneled).await
            }
        }
        Route::Socks5 {
            host,
            port,
            credentials,
            resolve_remotely,
        } => {
            let tcp = tcp(io, resolver, Hop::Proxy, &host, port, phase).await?;
            phase.set(ConnectPhase::Proxy);
            let OwnedBytes(tcp) = socks5::connect(
                OwnedBytes(tcp),
                resolver,
                &origin.host,
                origin.port,
                credentials
                    .as_ref()
                    .map(|(user, password)| (user.as_str(), password.as_str())),
                resolve_remotely,
            )
            .await
            .map_err(|failure| failure.into_error((&host, port), &origin.host, origin.port))?;
            last.finish_origin(origin, tcp).await
        }
    }
}

/// What the last leg of every route needs: TLS to the host that leg
/// reaches.
struct LastLeg<'a, I> {
    io: &'a I,
    tls: &'a TlsConnector,
    phase: &'a Cell<ConnectPhase>,
}

impl<I: Timer + Clone + 'static> LastLeg<'_, I> {
    /// [`finish`](Self::finish) for a `stream` that ends at `origin`.
    async fn finish_origin<S>(&self, origin: &Origin, stream: S) -> Result<Dialed, Error>
    where
        S: TlsTransport + Split<ReadHalf: ReadOwned + SpliceRead, WriteHalf: SpliceWrite>,
    {
        self.finish(
            Hop::Origin,
            &origin.host,
            origin.port,
            origin.scheme == Scheme::HTTPS,
            stream,
            Via::Direct,
        )
        .await
    }

    /// Wraps `stream` in TLS for `host` (the `hop` of the route, at `port`)
    /// when `secure`, then starts HTTP/1.1 on it.
    async fn finish<S>(
        &self,
        hop: Hop,
        host: &str,
        port: u16,
        secure: bool,
        stream: S,
        via: Via,
    ) -> Result<Dialed, Error>
    where
        S: TlsTransport + Split<ReadHalf: ReadOwned + SpliceRead, WriteHalf: SpliceWrite>,
    {
        let mut config = ClientConfig::default();
        config.request_target = match via {
            Via::Direct => RequestTarget::Origin,
            Via::HttpProxy { .. } => RequestTarget::Absolute,
        };
        let io = self.io.clone();
        if !secure {
            return Ok(start(stream, io, config, via));
        }
        self.phase.set(ConnectPhase::Tls);
        let stream = self
            .tls
            .connect(server_name(host)?, stream, self.io)
            .await
            .map_err(|error| handshake_failure(hop, host, port, error))?;
        #[cfg(all(
            test,
            target_os = "linux",
            feature = "native-kernel-tls",
            native_driver
        ))]
        let tls_mode = Some(stream.mode());
        let dialed = start(stream, io, config, via);
        #[cfg(all(
            test,
            target_os = "linux",
            feature = "native-kernel-tls",
            native_driver
        ))]
        let dialed = Dialed { tls_mode, ..dialed };
        Ok(dialed)
    }
}

/// `host` as the name a TLS handshake sends and verifies.
fn server_name(host: &str) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(host.to_owned())
        .map_err(|error| Error::InvalidUri(format!("{host}: {error}")))
}

/// A failed TLS handshake with `host`:`port`, the `hop` of the route, as the
/// error a request reports.
fn handshake_failure(hop: Hop, host: &str, port: u16, error: HandshakeError) -> Error {
    // A kernel that cannot take TLS is the configuration's fault, not the
    // peer's.
    #[cfg(all(feature = "native-kernel-tls", target_os = "linux"))]
    let error = match error {
        HandshakeError::Kernel(error) => return Error::Config(ConfigError::KernelTls(error)),
        other => other,
    };
    let failure = match &error {
        HandshakeError::Tls(error) => TlsFailure::of_rustls(error),
        HandshakeError::TimedOut(_) => {
            return Error::Timeout(TimedOut::Connect {
                during: ConnectPhase::Tls,
            });
        }
        _ => TlsFailure::Protocol,
    };
    Error::connect(
        hop,
        host,
        port,
        ConnectFailure::Tls(TlsError::new(failure, Cause::Handshake(error))),
    )
}

/// Runs the HTTP/1.1 client over `stream`; the driver logs how it ended, and
/// when a request switched the connection, holds the switched stream on this
/// thread until the request's [`Upgrade`] claims it.
fn start<S, T>(stream: S, timer: T, config: ClientConfig, via: Via) -> Dialed
where
    S: Split + 'static,
    S::ReadHalf: ReadOwned + SpliceRead + 'static,
    S::WriteHalf: Write + SendFile + SpliceWrite + 'static,
    T: http_kit_io::Timer + 'static,
{
    let (requests, connection) = handshake_stream(stream, timer, config);
    let (upgrade, claims) = upgrade::channel();
    let driver = async move {
        match connection.run().await {
            Ok(ClientOutcome::Closed) => {}
            Ok(ClientOutcome::Upgraded(upgraded)) => {
                let rejoined = Rejoined {
                    read: upgraded.read,
                    write: upgraded.write,
                };
                let switched = Switched::new(upgraded.read_buf, rejoined);
                claims.hand_over(switched).await;
            }
            Err(error) => debug!(%error, "HTTP/1.1 connection ended with an error"),
        }
    }
    .boxed_local();
    Dialed {
        send: H1Send { requests, upgrade },
        via,
        driver,
        #[cfg(all(
            test,
            target_os = "linux",
            feature = "native-kernel-tls",
            native_driver
        ))]
        tls_mode: None,
    }
}

/// Asks the HTTP proxy on `stream` for a `CONNECT` tunnel to `authority` and
/// hands back the socket's halves once the proxy relays bytes.
async fn tunnel<I, S>(
    io: &I,
    stream: S,
    proxy: (&str, u16),
    authority: &str,
    authorization: Option<HeaderValue>,
) -> Result<Rejoined<S::ReadHalf, S::WriteHalf>, Error>
where
    I: Timer + Clone,
    S: Split + 'static,
    S::ReadHalf: ReadOwned + SpliceRead,
    S::WriteHalf: SendFile + SpliceWrite,
{
    let fail = |error: TunnelError| {
        Error::connect(Hop::Proxy, proxy.0, proxy.1, ConnectFailure::Tunnel(error))
    };
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
        http_kit_h1::Error::ConnectionClosed => fail(TunnelError::Protocol(
            "proxy closed the connection before answering CONNECT",
        )),
        error => fail(TunnelError::Connection(Cause::H1(error))),
    })?;
    if !status.is_success() {
        return Err(fail(TunnelError::Rejected(status)));
    }
    match outcome.map_err(|error| fail(TunnelError::Connection(Cause::H1(error))))? {
        ClientOutcome::Upgraded(upgraded) => {
            if !upgraded.read_buf.is_empty() {
                return Err(fail(TunnelError::Protocol(
                    "proxy sent bytes into the tunnel before the client spoke",
                )));
            }
            Ok(Rejoined {
                read: upgraded.read,
                write: upgraded.write,
            })
        }
        ClientOutcome::Closed => Err(fail(TunnelError::Protocol(
            "proxy answered CONNECT without switching to the tunnel",
        ))),
    }
}

/// A connection's halves after an HTTP/1.1 switch, as one stream again.
pub struct Rejoined<R, W> {
    pub(super) read: R,
    pub(super) write: W,
}

impl<R: Read + 'static, W: Write + 'static> Split for Rejoined<R, W> {
    type ReadHalf = R;
    type WriteHalf = W;

    fn split(self) -> (R, W) {
        (self.read, self.write)
    }
}

/// TCP to `host`:`port`, raced over its addresses (RFC 8305).
async fn tcp<I: Dial + Timer, R: Resolve>(
    io: &I,
    resolver: &R,
    hop: Hop,
    host: &str,
    port: u16,
    phase: &Cell<ConnectPhase>,
) -> Result<I::Connection, Error> {
    phase.set(ConnectPhase::Resolve);
    happy_eyeballs::connect(&IoDialer { io, phase }, resolver, host, port)
        .await
        .map_err(|error| error.into_error(hop, host, port))
}

/// Happy eyeballs over an `http-kit-io` implementation. Every connection
/// it opens has `TCP_NODELAY` on, as the async-net dialer's do: a request
/// head or a TLS record goes out at once instead of waiting on Nagle. The
/// first dial moves `phase` from resolving to connecting.
struct IoDialer<'a, I> {
    io: &'a I,
    phase: &'a Cell<ConnectPhase>,
}

impl<I: Dial + Timer> Dialer for IoDialer<'_, I> {
    type Stream = I::Connection;

    async fn dial(&self, addr: SocketAddr) -> io::Result<I::Connection> {
        self.phase.set(ConnectPhase::Tcp);
        let stream = self.io.connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        self.io.sleep_until(deadline)
    }

    /// The transport's connect timeout bounds the whole dial (`dial`), every
    /// attempt included; nothing else bounds a TCP attempt.
    fn attempt_timeout(&self) -> Option<std::time::Duration> {
        None
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

/// Kernel TLS: a dial over a handshake the kernel can take hands the
/// connection's record layer to it.
#[cfg(all(
    test,
    target_os = "linux",
    feature = "native-kernel-tls",
    native_driver
))]
#[expect(
    clippy::future_not_send,
    reason = "the scenario runs on one runtime thread, as the pool's connections do"
)]
mod tests {
    use std::sync::Arc;

    use futures_util::future::{Either, select};
    use http_kit::Response;
    use http_kit_io::{Listen, Listener};
    use http_kit_tls::{Mode, TlsAcceptor};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use rustls::{
        crypto::ring,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use time::{Duration as TimeDelta, OffsetDateTime};

    use super::*;
    use crate::{Proxy, backend::shared::request_origin, dns::Getaddrinfo};

    /// A greeting in Chinese, Japanese and Korean.
    const GREETING: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

    /// A transport trusting a throwaway CA, and a user-space TLS acceptor
    /// for a `localhost` certificate that CA signed, so the kernel is the
    /// client's alone.
    fn pki() -> (Transport, TlsAcceptor) {
        let now = OffsetDateTime::now_utc();
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "zenwave kernel TLS test CA");
        ca.not_before = now - TimeDelta::days(1);
        ca.not_after = now + TimeDelta::days(30);
        let ca_der = ca.self_signed(&ca_key).expect("self-sign CA").der().clone();
        let issuer = Issuer::new(ca, ca_key);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf params");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.not_before = now - TimeDelta::days(1);
        leaf.not_after = now + TimeDelta::days(30);
        let leaf = leaf.signed_by(&leaf_key, &issuer).expect("sign leaf");
        let mut config =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("default versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
                )
                .expect("server certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .extra_root_certificate_der(ca_der.to_vec())
            .build()
            .expect("transport builds");
        (transport, TlsAcceptor::new(Arc::new(config)))
    }

    /// Echoes the request body, over one TLS connection.
    async fn serve_once<I: NativeIo + Listen<Listener: Listener<Stream: TlsTransport>>>(
        io: I,
        listener: I::Listener,
        tls: TlsAcceptor,
    ) {
        let (stream, _) = listener.accept().await.expect("accept");
        let stream = tls.accept(stream, &io).await.expect("TLS handshake");
        let service = |request: Request| async move {
            let body = request.into_body().into_bytes().await.expect("body reads");
            Response::new(Body::from_bytes(body))
        };
        http_kit_h1::ServerConnection::from_stream(
            stream,
            io,
            http_kit_h1::ServerConfig::default(),
        )
        .serve(&service)
        .await
        .expect("connection serves");
    }

    /// A native-backend dial to an HTTPS origin, through the connector the
    /// pool builds, settles on kernel TLS and carries a request.
    async fn https_runs_over_kernel_tls<
        I: NativeIo + Listen<Listener: Listener<Stream: TlsTransport>>,
    >(
        io: I,
    ) {
        let (transport, acceptor) = pki();
        let listener = io
            .bind_tcp("127.0.0.1:0".parse().expect("loopback"))
            .expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let tls = connector(transport.tls().http1_config().clone()).expect("the kernel probes");
        let origin = request_origin(
            &format!("https://localhost:{port}/")
                .parse()
                .expect("origin URI"),
        )
        .expect("origin");

        let server = serve_once(io.clone(), listener, acceptor);
        let client = async {
            let dialed = dial(&io, &Getaddrinfo, &transport, &tls, &origin)
                .await
                .expect("the dial succeeds");
            assert_eq!(
                dialed.tls_mode,
                Some(Mode::Kernel),
                "the handshake stayed in user space; is the kernel's `tls` module loaded?"
            );
            let mut request = Request::new(Body::from_bytes(GREETING.as_bytes().to_vec()));
            *request.method_mut() = Method::POST;
            *request.uri_mut() = format!("https://localhost:{port}/echo")
                .parse()
                .expect("request URI");
            let Dialed { send, driver, .. } = dialed;
            let exchange = async {
                let response = send.requests.send(request).await.expect("request sends");
                let body = response.into_body().into_bytes().await.expect("body reads");
                assert_eq!(body.as_ref(), GREETING.as_bytes());
                drop(send);
            };
            futures_util::join!(driver, exchange);
        };
        match select(pin!(client), pin!(server)).await {
            Either::Left(((), _)) => {}
            Either::Right(((), _)) => panic!("the server ended before the client"),
        }
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn https_runs_over_kernel_tls_on_compio() {
        compio::runtime::Runtime::new()
            .expect("compio runtime")
            .block_on(https_runs_over_kernel_tls(super::super::Compio::default()));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn https_runs_over_kernel_tls_on_tokio() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(https_runs_over_kernel_tls(super::super::Tokio));
    }

    /// Answers one TLS connection's request with a `101` and, in the same
    /// write, a greeting, then holds the connection open.
    async fn serve_switch<I: NativeIo + Listen<Listener: Listener<Stream: TlsTransport>>>(
        io: I,
        listener: I::Listener,
        tls: TlsAcceptor,
    ) {
        let (stream, _) = listener.accept().await.expect("accept");
        let stream = tls.accept(stream, &io).await.expect("TLS handshake");
        let (mut read, mut write) = stream.split();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let BufResult(filled, chunk) = read.read(Vec::with_capacity(1024)).await;
            assert!(
                filled.expect("the head reads") > 0,
                "the client closed early"
            );
            head.extend_from_slice(&chunk);
        }
        let mut answer =
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n"
                .to_vec();
        answer.extend_from_slice(GREETING.as_bytes());
        write.write_all(answer).await.0.expect("the 101 writes");
        futures_util::future::pending::<()>().await;
    }

    /// The stream a `101` switched over a TLS connection splices when its
    /// records are the kernel's (`kernel`), and is given back by
    /// `into_splice`, still carrying the bytes behind the head, when rustls
    /// holds them in user space.
    async fn switched_over_tls<I: NativeIo + Listen<Listener: Listener<Stream: TlsTransport>>>(
        io: I,
        kernel: bool,
    ) {
        use futures_util::AsyncReadExt as _;

        let (transport, acceptor) = pki();
        let listener = io
            .bind_tcp("127.0.0.1:0".parse().expect("loopback"))
            .expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let tls = if kernel {
            connector(transport.tls().http1_config().clone()).expect("the kernel probes")
        } else {
            TlsConnector::new(transport.tls().http1_config().clone())
        };
        let origin = request_origin(
            &format!("https://localhost:{port}/")
                .parse()
                .expect("origin URI"),
        )
        .expect("origin");

        let server = serve_switch(io.clone(), listener, acceptor);
        let client = async {
            let dialed = dial(&io, &Getaddrinfo, &transport, &tls, &origin)
                .await
                .expect("the dial succeeds");
            let expected = if kernel { Mode::Kernel } else { Mode::User };
            assert_eq!(
                dialed.tls_mode,
                Some(expected),
                "is the kernel's `tls` module loaded?"
            );
            let mut request = Request::new(Body::empty());
            *request.uri_mut() = format!("https://localhost:{port}/echo")
                .parse()
                .expect("request URI");
            request
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            request
                .headers_mut()
                .insert(header::UPGRADE, HeaderValue::from_static("echo"));
            let Dialed { send, driver, .. } = dialed;
            let exchange = async {
                let response = send.requests.send(request).await.expect("request sends");
                assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
                let switched = send
                    .upgrade
                    .clone()
                    .switched()
                    .await
                    .expect("the stream is handed over");
                assert_eq!(switched.can_splice(), kernel);
                match switched.into_splice() {
                    Ok(_end) => assert!(kernel, "a user-space TLS session cannot splice"),
                    Err(mut switched) => {
                        assert!(!kernel, "a kernel TLS socket splices");
                        let mut greeting = vec![0; GREETING.len()];
                        switched
                            .read_exact(&mut greeting)
                            .await
                            .expect("the stream still reads");
                        assert_eq!(greeting, GREETING.as_bytes());
                    }
                }
            };
            futures_util::join!(driver, exchange);
        };
        match select(pin!(client), pin!(server)).await {
            Either::Left(((), _)) => {}
            Either::Right(((), _)) => panic!("the server ended before the client"),
        }
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn a_kernel_tls_switch_splices_on_compio() {
        compio::runtime::Runtime::new()
            .expect("compio runtime")
            .block_on(switched_over_tls(super::super::Compio::default(), true));
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn a_user_space_tls_switch_does_not_splice_on_compio() {
        compio::runtime::Runtime::new()
            .expect("compio runtime")
            .block_on(switched_over_tls(super::super::Compio::default(), false));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn a_kernel_tls_switch_splices_on_tokio() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(switched_over_tls(super::super::Tokio, true));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn a_user_space_tls_switch_does_not_splice_on_tokio() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(switched_over_tls(super::super::Tokio, false));
    }
}
