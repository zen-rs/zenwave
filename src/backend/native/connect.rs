//! Opening an HTTP/1.1 connection on `http-kit-io` sockets, through the
//! transport's proxy rules: the [`route`] the async-net connector follows,
//! with every leg on owned-buffer streams and TLS through `http-kit-tls`,
//! the origin's session inside the proxy's when the proxy is HTTPS.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::pin,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::{
    FutureExt,
    future::{Either, LocalBoxFuture, select},
};
use http::{HeaderValue, Method, header, uri::Scheme};
use http_kit::{Body, Request};
use http_kit_h1::{ClientConfig, ClientOutcome, RequestTarget, SendRequest, handshake_stream};
use http_kit_io::{
    BufResult, IntoInner, Io, IoBuf, Read, SendFile, Split, TcpOptions, Write, poll::CopyingPoll,
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
    /// Where the origin's TLS records are encrypted, for a TLS connection.
    #[cfg(all(test, target_os = "linux", feature = "native-kernel-tls"))]
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
    let connector =
        connector.with_kernel_tls(http_kit_tls::KernelTls::probe().map_err(Error::tls)?);
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
        let mut config = ClientConfig::default();
        config.request_target = match via {
            Via::Direct => RequestTarget::Origin,
            Via::HttpProxy { .. } => RequestTarget::Absolute,
        };
        config.read_timeout = self.read_timeout;
        let io = self.io.clone();
        if !secure {
            return Ok(start(stream, io, config, via));
        }
        let stream = self
            .tls
            .connect(server_name(host)?, stream, self.io)
            .await
            .map_err(Error::tls)?;
        #[cfg(all(test, target_os = "linux", feature = "native-kernel-tls"))]
        let tls_mode = Some(stream.mode());
        let dialed = start(stream, io, config, via);
        #[cfg(all(test, target_os = "linux", feature = "native-kernel-tls"))]
        let dialed = Dialed { tls_mode, ..dialed };
        Ok(dialed)
    }
}

/// `host` as the name a TLS handshake sends and verifies.
fn server_name(host: &str) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(host.to_owned()).map_err(Error::tls)
}

/// Runs the HTTP/1.1 client over `stream`; the driver logs how it ended, and
/// when a request switched the connection, holds the switched stream on this
/// thread until the request's [`Upgrade`] claims it.
fn start<S, T>(stream: S, timer: T, config: ClientConfig, via: Via) -> Dialed
where
    S: Split + 'static,
    S::ReadHalf: Read + 'static,
    S::WriteHalf: Write + SendFile + 'static,
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
                let switched = Switched::new(upgraded.read_buf, CopyingPoll::new(rejoined));
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
        #[cfg(all(test, target_os = "linux", feature = "native-kernel-tls"))]
        tls_mode: None,
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
    use http_kit_io::Listener as _;
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
    use crate::{Proxy, backend::shared::request_origin};

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
    async fn serve_once<I: NativeIo>(io: I, listener: I::TcpListener, tls: TlsAcceptor) {
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
    async fn https_runs_over_kernel_tls<I: NativeIo>(io: I) {
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
            let dialed = dial(&io, &transport, &tls, &origin)
                .await
                .expect("the dial succeeds");
            assert_eq!(
                dialed.tls_mode,
                Some(Mode::Kernel),
                "the handshake stayed in user space; is the kernel's `tls` module loaded?"
            );
            let mut request = Request::new(Body::from_bytes(GREETING.as_bytes().to_vec()));
            *request.method_mut() = Method::POST;
            *request.uri_mut() = "/echo".parse().expect("path");
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
            .block_on(https_runs_over_kernel_tls(super::super::Compio));
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
}
