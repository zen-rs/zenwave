//! SOCKS5 `CONNECT` (RFC 1928) with optional username/password
//! authentication (RFC 1929).
//!
//! The handshake is written once over [`Handshake`], the two operations it
//! needs from a stream; each connector supplies them for its own sockets.

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
};

use http_kit_io::Resolve;

use super::happy_eyeballs;
use crate::{ConnectFailure, Error, Hop, ResolveError, SocksError};

/// Why a SOCKS5 handshake did not give a tunnel: the proxy failed it, or the
/// target's name, which this side resolves for `socks5://` proxies, did not
/// resolve.
#[derive(Debug)]
pub enum Failure {
    /// The proxy refused or broke the handshake.
    Socks(SocksError),
    /// The target's name gave no address.
    Resolve(ResolveError),
}

impl Failure {
    /// The failure as a connect error: a handshake failure belongs to the
    /// `proxy` (host and port), a resolution failure to the target at
    /// `host`:`port`.
    pub fn into_error(self, proxy: (&str, u16), host: &str, port: u16) -> Error {
        match self {
            Self::Socks(error) => {
                Error::connect(Hop::Proxy, proxy.0, proxy.1, ConnectFailure::Socks(error))
            }
            Self::Resolve(error) => {
                Error::connect(Hop::Origin, host, port, ConnectFailure::Resolve(error))
            }
        }
    }
}

impl From<SocksError> for Failure {
    fn from(error: SocksError) -> Self {
        Self::Socks(error)
    }
}

impl From<ResolveError> for Failure {
    fn from(error: ResolveError) -> Self {
        Self::Resolve(error)
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Socks(SocksError::Io(error))
    }
}

/// The byte exchange a SOCKS5 handshake runs over.
pub trait Handshake {
    /// Writes all of `bytes`.
    fn send(&mut self, bytes: Vec<u8>) -> impl Future<Output = io::Result<()>>;

    /// Reads exactly `len` bytes.
    fn recv(&mut self, len: usize) -> impl Future<Output = io::Result<Vec<u8>>>;
}

/// A `futures_io` stream: async-net's sockets.
#[cfg(connector)]
impl Handshake for async_net::TcpStream {
    async fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        futures_util::AsyncWriteExt::write_all(self, &bytes).await
    }

    async fn recv(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; len];
        futures_util::AsyncReadExt::read_exact(self, &mut bytes).await?;
        Ok(bytes)
    }
}

const VERSION: u8 = 0x05;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xFF;
const COMMAND_CONNECT: u8 = 0x01;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_IPV6: u8 = 0x04;
const AUTH_VERSION: u8 = 0x01;

/// Ask the SOCKS5 proxy on `stream` to connect to `host:port`.
///
/// With `resolve_remotely` (`socks5h://`) the hostname is sent to the proxy;
/// otherwise (`socks5://`) `resolver` resolves it here first, as curl does.
pub async fn connect<S: Handshake, R: Resolve>(
    mut stream: S,
    resolver: &R,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
    resolve_remotely: bool,
) -> Result<S, Failure> {
    negotiate_method(&mut stream, credentials).await?;

    let mut request = vec![VERSION, COMMAND_CONNECT, 0x00];
    match destination(resolver, host, port, resolve_remotely).await? {
        Destination::Ip(SocketAddr::V4(addr)) => {
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&addr.ip().octets());
        }
        Destination::Ip(SocketAddr::V6(addr)) => {
            request.push(ADDRESS_IPV6);
            request.extend_from_slice(&addr.ip().octets());
        }
        Destination::Domain(name) => {
            let len = u8::try_from(name.len())
                .map_err(|_| SocksError::Protocol("hostname longer than 255 bytes"))?;
            request.push(ADDRESS_DOMAIN);
            request.push(len);
            request.extend_from_slice(name.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.send(request).await?;

    let head = stream.recv(4).await?;
    if head[0] != VERSION {
        return Err(SocksError::Protocol("proxy answered with a non-SOCKS5 version").into());
    }
    if head[1] != 0x00 {
        return Err(SocksError::Reply(head[1]).into());
    }
    let bound_address_len = match head[3] {
        ADDRESS_IPV4 => 4,
        ADDRESS_IPV6 => 16,
        ADDRESS_DOMAIN => usize::from(stream.recv(1).await?[0]),
        _ => {
            return Err(
                SocksError::Protocol("proxy reported an unknown bound address type").into(),
            );
        }
    };
    stream.recv(bound_address_len + 2).await?;
    Ok(stream)
}

async fn negotiate_method<S: Handshake>(
    stream: &mut S,
    credentials: Option<(&str, &str)>,
) -> Result<(), Failure> {
    let greeting = if credentials.is_some() {
        vec![VERSION, 2, METHOD_NONE, METHOD_USERNAME_PASSWORD]
    } else {
        vec![VERSION, 1, METHOD_NONE]
    };
    stream.send(greeting).await?;

    let choice = stream.recv(2).await?;
    if choice[0] != VERSION {
        return Err(SocksError::Protocol("proxy answered with a non-SOCKS5 version").into());
    }
    match choice[1] {
        METHOD_NONE => Ok(()),
        METHOD_USERNAME_PASSWORD => {
            let (username, password) = credentials.ok_or(SocksError::Auth)?;
            authenticate(stream, username, password).await
        }
        METHOD_UNACCEPTABLE => {
            Err(SocksError::Protocol("proxy accepts none of the offered methods").into())
        }
        _ => Err(SocksError::Protocol(
            "proxy chose an authentication method zenwave does not speak",
        )
        .into()),
    }
}

async fn authenticate<S: Handshake>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), Failure> {
    let username_len = u8::try_from(username.len())
        .map_err(|_| SocksError::Protocol("username longer than 255 bytes"))?;
    let password_len = u8::try_from(password.len())
        .map_err(|_| SocksError::Protocol("password longer than 255 bytes"))?;
    let mut message = vec![AUTH_VERSION, username_len];
    message.extend_from_slice(username.as_bytes());
    message.push(password_len);
    message.extend_from_slice(password.as_bytes());
    stream.send(message).await?;

    let status = stream.recv(2).await?;
    if status[1] == 0x00 {
        Ok(())
    } else {
        Err(SocksError::Auth.into())
    }
}

enum Destination<'a> {
    Ip(SocketAddr),
    Domain(&'a str),
}

async fn destination<'a, R: Resolve>(
    resolver: &R,
    host: &'a str,
    port: u16,
    resolve_remotely: bool,
) -> Result<Destination<'a>, Failure> {
    if let Ok(ip) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return Ok(Destination::Ip(SocketAddr::new(ip, port)));
    }
    if resolve_remotely {
        return Ok(Destination::Domain(host));
    }
    let addrs = happy_eyeballs::resolve(resolver, host, port).await?;
    addrs
        .into_iter()
        .next()
        // The resolution never succeeds with no address.
        .map(Destination::Ip)
        .ok_or_else(|| ResolveError::NoAddress.into())
}
