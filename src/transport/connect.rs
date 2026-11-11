//! Opening a connection to a target through a [`Transport`]: directly, through
//! an HTTP proxy (absolute-form requests or a `CONNECT` tunnel), or through a
//! SOCKS5 proxy.

#[cfg(unix_socket)]
use std::path::Path;

use async_net::TcpStream;
#[cfg(unix_socket)]
use async_net::unix::UnixStream;

#[cfg(http3)]
pub use super::route::proxied;
pub use super::route::{Protocols, Target, Via};
use super::{
    Transport, happy_eyeballs,
    route::{Route, route},
    socks5,
    stream::Stream,
    tunnel,
};
use crate::{Error, dns::Getaddrinfo};

/// The HTTP version a [`Connection`] negotiated, or will speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP/1.1 — always the answer for plaintext connections.
    Http1,
    /// HTTP/2, negotiated through ALPN on the innermost TLS layer.
    #[cfg(feature = "http2")]
    Http2,
}

/// An established connection.
#[derive(Debug)]
pub struct Connection {
    pub stream: Stream,
    pub via: Via,
    /// What the innermost TLS layer negotiated, [`Protocol::Http1`] for plaintext.
    #[cfg_attr(not(feature = "hyper-backend"), allow(dead_code))]
    // only the hyper backend acts on the negotiated protocol; websockets and
    // the CONNECT tunnel only need the stream
    pub protocol: Protocol,
}

/// Connect to `target` following the transport's proxy rules — or through
/// its unix domain socket when the transport was built with one: the socket
/// replaces host, port, and proxies alike, while `target` still decides
/// whether TLS wraps the stream and which server name the handshake sends.
pub async fn connect(transport: &Transport, target: Target<'_>) -> Result<Connection, Error> {
    #[cfg(unix_socket)]
    if let Some(path) = transport.unix_socket() {
        return unix_connect(transport, path, target).await;
    }

    match route(transport.proxy(), target)? {
        Route::Direct => {
            let tcp = tcp(target.host, target.port).await?;
            let stream = finish(transport, target, tcp).await?;
            connection(stream, Via::Direct, target)
        }
        Route::Forward {
            proxy,
            authorization,
        } => {
            let tcp = tcp(&proxy.host, proxy.port).await?;
            // Absolute-form requests to a forward proxy are HTTP/1.1, so the
            // TLS leg to the proxy offers no h2.
            let stream = if proxy.tls {
                Stream::Tls(Box::new(
                    transport
                        .tls()
                        .connect(&proxy.host, tcp, Protocols::Http1)
                        .await?,
                ))
            } else {
                Stream::Tcp(tcp)
            };
            connection(stream, Via::HttpProxy { authorization }, target)
        }
        Route::Tunnel {
            proxy,
            authority,
            authorization,
        } => {
            let tcp = tcp(&proxy.host, proxy.port).await?;
            let stream = if proxy.tls {
                let to_proxy = transport
                    .tls()
                    .connect(&proxy.host, tcp, Protocols::Http1)
                    .await?;
                let tunneled =
                    tunnel::connect(to_proxy, &authority, authorization.as_ref()).await?;
                if target.tls {
                    Stream::TlsOverTls(Box::new(
                        transport
                            .tls()
                            .connect(target.host, tunneled, target.protocols)
                            .await?,
                    ))
                } else {
                    Stream::Tls(Box::new(tunneled))
                }
            } else {
                let tunneled = tunnel::connect(tcp, &authority, authorization.as_ref()).await?;
                finish(transport, target, tunneled).await?
            };
            connection(stream, Via::Direct, target)
        }
        Route::Socks5 {
            host,
            port,
            credentials,
            resolve_remotely,
        } => {
            let tcp = tcp(&host, port).await?;
            let tcp = socks5::connect(
                tcp,
                &Getaddrinfo,
                target.host,
                target.port,
                credentials
                    .as_ref()
                    .map(|(user, password)| (user.as_str(), password.as_str())),
                resolve_remotely,
            )
            .await?;
            let stream = finish(transport, target, tcp).await?;
            connection(stream, Via::Direct, target)
        }
    }
}

/// The protocol a freshly built stream will speak: the innermost TLS layer's
/// negotiated ALPN for TLS targets, always [`Protocol::Http1`] for plaintext.
fn connection(stream: Stream, via: Via, target: Target<'_>) -> Result<Connection, Error> {
    let protocol = match (target.tls, stream.negotiated_alpn()?.as_deref()) {
        #[cfg(feature = "http2")]
        (true, Some(b"h2")) => Protocol::Http2,
        _ => Protocol::Http1,
    };
    Ok(Connection {
        stream,
        via,
        protocol,
    })
}

/// Open `target`'s connection on the transport's unix domain socket.
#[cfg(unix_socket)]
async fn unix_connect(
    transport: &Transport,
    path: &Path,
    target: Target<'_>,
) -> Result<Connection, Error> {
    let unix = UnixStream::connect(path)
        .await
        .map_err(|error| Error::Transport(Box::new(error)))?;
    let stream = if target.tls {
        Stream::TlsOverUnix(Box::new(
            transport
                .tls()
                .connect(target.host, unix, target.protocols)
                .await?,
        ))
    } else {
        Stream::Unix(unix)
    };
    connection(stream, Via::Direct, target)
}

/// Wrap a TCP stream that already reaches the target in TLS when asked.
async fn finish(
    transport: &Transport,
    target: Target<'_>,
    tcp: TcpStream,
) -> Result<Stream, Error> {
    if target.tls {
        Ok(Stream::Tls(Box::new(
            transport
                .tls()
                .connect(target.host, tcp, target.protocols)
                .await?,
        )))
    } else {
        Ok(Stream::Tcp(tcp))
    }
}

async fn tcp(host: &str, port: u16) -> Result<TcpStream, Error> {
    happy_eyeballs::connect(&happy_eyeballs::AsyncNet, &Getaddrinfo, host, port)
        .await
        .map_err(|error| Error::Transport(Box::new(error)))
}
