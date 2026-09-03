//! Opening a connection to a target through a [`Transport`]: directly, through
//! an HTTP proxy (absolute-form requests or a `CONNECT` tunnel), or through a
//! SOCKS5 proxy.

use async_net::TcpStream;
use http::{HeaderValue, Uri};

use super::{Transport, happy_eyeballs, socks5, stream::Stream, tunnel};
use crate::{Error, error::ProxyErrorKind};

/// Where a connection should end up.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    /// Speak TLS to the target.
    pub tls: bool,
    /// Through an HTTP proxy, tunnel even a plaintext target with `CONNECT`
    /// instead of sending absolute-form requests. Websockets need this.
    pub tunnel_plaintext: bool,
}

/// How requests on a [`Connection`] must be written.
#[derive(Clone, Debug)]
pub enum Via {
    /// The stream ends at the target: requests use origin-form.
    Direct,
    /// The stream ends at an HTTP proxy that forwards absolute-form requests.
    HttpProxy {
        /// `Proxy-Authorization` to attach to every request.
        #[cfg_attr(not(feature = "hyper-backend"), allow(dead_code))]
        // websockets always tunnel
        authorization: Option<HeaderValue>,
    },
}

/// An established connection.
#[derive(Debug)]
pub struct Connection {
    pub stream: Stream,
    pub via: Via,
}

/// Connect to `target` following the transport's proxy rules.
pub async fn connect(transport: &Transport, target: Target<'_>) -> Result<Connection, Error> {
    let Some(intercept) = transport.proxy().intercept(&destination_uri(target)?) else {
        let tcp = tcp(target.host, target.port).await?;
        let stream = finish(transport, target, tcp).await?;
        return Ok(Connection {
            stream,
            via: Via::Direct,
        });
    };

    let proxy_uri = intercept.uri();
    let scheme = proxy_uri.scheme_str().unwrap_or("http");
    let proxy_host = proxy_uri.host().ok_or(ProxyErrorKind::MissingHost)?;

    match scheme {
        "http" | "https" => {
            let proxy_tls = scheme == "https";
            let proxy_port = proxy_uri
                .port_u16()
                .unwrap_or(if proxy_tls { 443 } else { 80 });
            let tcp = tcp(proxy_host, proxy_port).await?;

            if !target.tls && !target.tunnel_plaintext {
                let stream = if proxy_tls {
                    Stream::Tls(Box::new(transport.tls().connect(proxy_host, tcp).await?))
                } else {
                    Stream::Tcp(tcp)
                };
                return Ok(Connection {
                    stream,
                    via: Via::HttpProxy {
                        authorization: intercept.basic_auth().cloned(),
                    },
                });
            }

            let authority = authority(target.host, target.port);
            let stream = if proxy_tls {
                let to_proxy = transport.tls().connect(proxy_host, tcp).await?;
                let tunneled =
                    tunnel::connect(to_proxy, &authority, intercept.basic_auth()).await?;
                if target.tls {
                    Stream::TlsOverTls(Box::new(
                        transport.tls().connect(target.host, tunneled).await?,
                    ))
                } else {
                    Stream::Tls(Box::new(tunneled))
                }
            } else {
                let tunneled = tunnel::connect(tcp, &authority, intercept.basic_auth()).await?;
                finish(transport, target, tunneled).await?
            };
            Ok(Connection {
                stream,
                via: Via::Direct,
            })
        }
        "socks5" | "socks5h" => {
            let proxy_port = proxy_uri.port_u16().unwrap_or(1080);
            let tcp = tcp(proxy_host, proxy_port).await?;
            let tcp = socks5::connect(
                tcp,
                target.host,
                target.port,
                intercept.raw_auth(),
                scheme == "socks5h",
            )
            .await?;
            let stream = finish(transport, target, tcp).await?;
            Ok(Connection {
                stream,
                via: Via::Direct,
            })
        }
        other => Err(ProxyErrorKind::UnsupportedScheme(other.to_owned()).into()),
    }
}

/// Wrap a TCP stream that already reaches the target in TLS when asked.
async fn finish(
    transport: &Transport,
    target: Target<'_>,
    tcp: TcpStream,
) -> Result<Stream, Error> {
    if target.tls {
        Ok(Stream::Tls(Box::new(
            transport.tls().connect(target.host, tcp).await?,
        )))
    } else {
        Ok(Stream::Tcp(tcp))
    }
}

async fn tcp(host: &str, port: u16) -> Result<TcpStream, Error> {
    let tcp = happy_eyeballs::connect(host, port)
        .await
        .map_err(|error| Error::Transport(Box::new(error)))?;
    tcp.set_nodelay(true)
        .map_err(|error| Error::Transport(Box::new(error)))?;
    Ok(tcp)
}

/// `host:port`, bracketing IPv6 literals.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The destination as the proxy matcher sees it: scheme decides which rule applies.
fn destination_uri(target: Target<'_>) -> Result<Uri, Error> {
    Uri::builder()
        .scheme(if target.tls { "https" } else { "http" })
        .authority(authority(target.host, target.port))
        .path_and_query("/")
        .build()
        .map_err(|error| Error::InvalidUri(error.to_string()))
}
