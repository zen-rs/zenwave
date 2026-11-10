//! Opening an HTTP/1.1 connection on `http-kit-io` sockets, through the
//! transport's proxy rules: the [`route`] the async-net connector follows,
//! with every leg on owned-buffer streams and TLS through `http-kit-tls`.

use std::{future::Future, io, net::SocketAddr, time::Instant};

use futures_util::{FutureExt, future::LocalBoxFuture};
use http::{HeaderValue, Method, header, uri::Scheme};
use http_kit::{Body, Request};
use http_kit_h1::{ClientConfig, ClientOutcome, RequestTarget, SendRequest, handshake_stream};
use http_kit_io::{BufResult, IntoInner, Io, IoBuf, Read, SendFile, Split, Write};
use http_kit_tls::{TlsConnector, rustls::pki_types::ServerName};
use tracing::debug;

use crate::{
    Error, Transport,
    error::ProxyErrorKind,
    transport::{
        happy_eyeballs::{self, Dialer},
        route::{Origin, Protocols, Route, Target, Via, route},
        socks5::{self, Handshake},
    },
};

/// An `http-kit-io` implementation whose TCP streams `http-kit-tls` can run
/// over: every implementation `http-kit-io` ships is one.
pub trait NativeIo: Io<TcpStream: http_kit_tls::Transport> {}

impl<I: Io<TcpStream: http_kit_tls::Transport>> NativeIo for I {}

/// A fresh HTTP/1.1 connection: its handle, how requests on it are shaped,
/// and the future that drives its socket.
pub struct Dialed {
    pub send: SendRequest,
    pub via: Via,
    pub driver: LocalBoxFuture<'static, ()>,
}

/// Connects to `origin` the way the transport's rules say and runs the
/// HTTP/1.1 handshake over the result.
///
/// # Errors
///
/// Every leg's failure, and the paths `http-kit` cannot carry yet: a unix
/// domain socket, and TLS to the origin inside TLS to an HTTPS proxy.
pub async fn dial<I: NativeIo>(
    io: &I,
    transport: &Transport,
    tls: &TlsConnector,
    origin: &Origin,
) -> Result<Dialed, Error> {
    #[cfg(unix_socket)]
    if let Some(path) = transport.unix_socket() {
        return Err(unsupported(format!(
            "the native backend cannot dial the unix domain socket {}: \
             http-kit-io 0.3 has no Unix-domain connect",
            path.display()
        )));
    }

    let secure = origin.scheme == Scheme::HTTPS;
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
            finish(io, tls, &origin.host, secure, tcp, Via::Direct).await
        }
        Route::Forward {
            proxy,
            authorization,
        } => {
            let tcp = tcp(io, &proxy.host, proxy.port).await?;
            finish(
                io,
                tls,
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
            if proxy.tls {
                return Err(unsupported(
                    "the native backend cannot run TLS to the origin inside TLS to an \
                     HTTPS proxy: http-kit-tls 0.1 runs only over a socket's own halves",
                ));
            }
            let tcp = tcp(io, &proxy.host, proxy.port).await?;
            let tunneled = tunnel(io, tcp, &authority, authorization).await?;
            finish(io, tls, &origin.host, secure, tunneled, Via::Direct).await
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
            finish(io, tls, &origin.host, secure, tcp, Via::Direct).await
        }
    }
}

/// Wraps `stream` in TLS for `server_name` when `secure`, then starts
/// HTTP/1.1 on it.
async fn finish<I, S>(
    io: &I,
    tls: &TlsConnector,
    server_name: &str,
    secure: bool,
    stream: S,
    via: Via,
) -> Result<Dialed, Error>
where
    I: Io,
    S: http_kit_tls::Transport,
{
    let config = ClientConfig {
        request_target: match via {
            Via::Direct => RequestTarget::Origin,
            Via::HttpProxy { .. } => RequestTarget::Absolute,
        },
        ..ClientConfig::default()
    };
    if !secure {
        return Ok(start(stream, io.clone(), config, via));
    }
    let name = ServerName::try_from(server_name.to_owned()).map_err(Error::tls)?;
    let stream = tls.connect(name, stream, io).await.map_err(Error::tls)?;
    Ok(start(stream, io.clone(), config, via))
}

/// Runs the HTTP/1.1 client over `stream`; the driver logs how it ended.
fn start<S, T>(stream: S, timer: T, config: ClientConfig, via: Via) -> Dialed
where
    S: Split + 'static,
    S::WriteHalf: SendFile,
    T: http_kit_io::Timer + 'static,
{
    let (send, connection) = handshake_stream(stream, timer, config);
    let driver = async move {
        if let Err(error) = connection.run().await {
            debug!(%error, "HTTP/1.1 connection ended with an error");
        }
    }
    .boxed_local();
    Dialed { send, via, driver }
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

/// Happy eyeballs over an `http-kit-io` implementation.
///
/// `TCP_NODELAY` is left as the implementation sets it: `Io::connect` has no
/// socket-option hook, and its stream types do not expose the socket.
struct IoDialer<'a, I>(&'a I);

impl<I: Io> Dialer for IoDialer<'_, I> {
    type Stream = I::TcpStream;

    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<I::TcpStream>> {
        self.0.connect(addr)
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

/// A path `http-kit` cannot carry yet, as a transport error naming it.
fn unsupported(message: impl Into<String>) -> Error {
    Error::Transport(Box::new(io::Error::new(
        io::ErrorKind::Unsupported,
        message.into(),
    )))
}
