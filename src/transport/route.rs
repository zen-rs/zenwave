//! Which path a connection takes to its target: directly, through an HTTP
//! proxy (absolute-form requests or a `CONNECT` tunnel), or through a SOCKS5
//! proxy. The decision follows the transport's proxy rules and is the same
//! for every connector; each connector then opens the legs it names on its
//! own sockets.

use http::{HeaderValue, Uri, uri::Scheme};

use super::{Proxy, connect::Protocols, proxy::Intercept};
use crate::{Error, error::ProxyErrorKind};

/// The authority a pooled connection belongs to.
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
        .ok_or(ProxyErrorKind::MissingHost)?
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
        other => Err(ProxyErrorKind::UnsupportedScheme(other.to_owned()).into()),
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
