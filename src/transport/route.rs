//! Which path a connection takes to its target: directly, through an HTTP
//! proxy (absolute-form requests or a `CONNECT` tunnel), or through a SOCKS5
//! proxy. The decision follows the transport's proxy rules and is the same
//! for every connector; each connector then opens the legs it names on its
//! own sockets.

#[cfg(pooled)]
use std::time::Duration;

#[cfg(pooled)]
use http::uri::Scheme;
use http::{HeaderValue, Uri};

use super::{Proxy, proxy::Intercept};
use crate::{ConfigError, Error};

/// The HTTP versions a TLS connection may offer the server through ALPN.
#[derive(Clone, Copy, Debug)]
pub enum Protocols {
    /// Offer `http/1.1` only: plaintext connections, websockets, the TLS leg
    /// to a forward proxy (hyper's h2 client cannot speak absolute-form), and
    /// every native-backend connection.
    Http1,
    /// Offer `h2` and `http/1.1`, letting the server pick. Without the `http2`
    /// feature this offers `http/1.1` alone.
    #[cfg_attr(not(feature = "hyper-backend"), allow(dead_code))]
    // only the hyper backend asks for h2; websockets never do
    Http2OrHttp1,
}

/// How requests on a connection must be written.
#[derive(Clone, Debug)]
pub enum Via {
    /// The stream ends at the target: requests use origin-form.
    Direct,
    /// The stream ends at an HTTP proxy that forwards absolute-form requests.
    HttpProxy {
        /// `Proxy-Authorization` to attach to every request.
        #[cfg_attr(
            not(any(feature = "hyper-backend", feature = "native-backend")),
            allow(dead_code)
        )]
        // websockets always tunnel
        authorization: Option<HeaderValue>,
    },
}

/// The most HTTP/1.1 connections one origin may have open at once in a pool:
/// leased or dialing — parked idle connections hold no slot and a new lease
/// always takes one first.
#[cfg(pooled)]
pub const MAX_H1_PER_ORIGIN: usize = 6;

/// An idle h1 connection is dropped once it has gone unused for this long.
/// The same window bounds a pooled h3 connection: QUIC keep-alives stop the
/// protocol's own idle timeout from closing it, so the pool applies its own.
#[cfg(pooled)]
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// The authority a pooled connection belongs to.
#[cfg(pooled)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    /// `http` or `https`: whether the connection carries TLS.
    pub scheme: Scheme,
    /// The target's hostname.
    pub host: String,
    /// The target's port.
    pub port: u16,
}

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
    /// The HTTP versions offered to the target through ALPN.
    #[cfg_attr(not(connector), allow(dead_code))] // the native backend offers http/1.1 alone
    pub protocols: Protocols,
}

/// A proxy's own address, and whether the leg to it is TLS.
#[derive(Clone, Debug)]
pub struct ProxyHop {
    pub host: String,
    pub port: u16,
    /// `https://` proxy: the connection to the proxy itself is TLS.
    pub tls: bool,
}

/// The path to a target.
#[derive(Clone, Debug)]
pub enum Route {
    /// Straight to the target.
    Direct,
    /// To an HTTP proxy that forwards absolute-form requests: plaintext
    /// targets only.
    Forward {
        proxy: ProxyHop,
        /// `Proxy-Authorization` for every request.
        authorization: Option<HeaderValue>,
    },
    /// Through a `CONNECT` tunnel an HTTP proxy opens to `authority`.
    Tunnel {
        proxy: ProxyHop,
        /// The target's `host:port`.
        authority: String,
        /// `Proxy-Authorization` for the `CONNECT` request.
        authorization: Option<HeaderValue>,
    },
    /// Through a SOCKS5 proxy.
    Socks5 {
        host: String,
        port: u16,
        /// Username and password (RFC 1929).
        credentials: Option<(String, String)>,
        /// `socks5h://`: the proxy resolves the target's name.
        resolve_remotely: bool,
    },
}

/// The route `proxy`'s rules give `target`.
///
/// # Errors
///
/// The proxy URI names no host or a scheme no connector speaks.
pub fn route(proxy: &Proxy, target: Target<'_>) -> Result<Route, Error> {
    let Some(intercept) = proxy.intercept(&destination_uri(target)?) else {
        return Ok(Route::Direct);
    };
    let proxy_uri = intercept.uri();
    let scheme = proxy_uri.scheme_str().unwrap_or("http");
    let host = proxy_uri
        .host()
        .ok_or(Error::Config(ConfigError::ProxyHost))?
        .to_owned();
    match scheme {
        "http" | "https" => {
            let tls = scheme == "https";
            let hop = ProxyHop {
                host,
                port: proxy_uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
                tls,
            };
            let authorization = intercept.basic_auth().cloned();
            Ok(if !target.tls && !target.tunnel_plaintext {
                Route::Forward {
                    proxy: hop,
                    authorization,
                }
            } else {
                Route::Tunnel {
                    proxy: hop,
                    authority: authority(target.host, target.port),
                    authorization,
                }
            })
        }
        "socks5" | "socks5h" => Ok(Route::Socks5 {
            host,
            port: proxy_uri.port_u16().unwrap_or(1080),
            credentials: credentials(&intercept),
            resolve_remotely: scheme == "socks5h",
        }),
        other => Err(Error::Config(ConfigError::ProxyScheme(other.to_owned()))),
    }
}

/// Whether a connection to `target` would go through a proxy — HTTP/3 is
/// never dialed to a proxied origin: QUIC bypasses the proxy, so the pool
/// keeps such origins on TCP regardless of what they advertise.
#[cfg(https_rr)]
pub fn proxied(proxy: &Proxy, target: Target<'_>) -> Result<bool, Error> {
    Ok(proxy.intercept(&destination_uri(target)?).is_some())
}

fn credentials(intercept: &Intercept) -> Option<(String, String)> {
    intercept
        .raw_auth()
        .map(|(username, password)| (username.to_owned(), password.to_owned()))
}

/// `host:port`, bracketing IPv6 literals.
pub fn authority(host: &str, port: u16) -> String {
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
