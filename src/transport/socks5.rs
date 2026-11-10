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

use super::happy_eyeballs;
use crate::{Error, error::ProxyErrorKind};

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
/// otherwise (`socks5://`) it is resolved here first, as curl does.
pub async fn connect<S: Handshake>(
    mut stream: S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
    resolve_remotely: bool,
) -> Result<S, Error> {
    negotiate_method(&mut stream, credentials).await?;

    let mut request = vec![VERSION, COMMAND_CONNECT, 0x00];
    match destination(host, port, resolve_remotely).await? {
        Destination::Ip(SocketAddr::V4(addr)) => {
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&addr.ip().octets());
        }
        Destination::Ip(SocketAddr::V6(addr)) => {
            request.push(ADDRESS_IPV6);
            request.extend_from_slice(&addr.ip().octets());
        }
        Destination::Domain(name) => {
            let len =
                u8::try_from(name.len()).map_err(|_| socks("hostname longer than 255 bytes"))?;
            request.push(ADDRESS_DOMAIN);
            request.push(len);
            request.extend_from_slice(name.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.send(request).await.map_err(io_error)?;

    let head = stream.recv(4).await.map_err(io_error)?;
    if head[0] != VERSION {
        return Err(socks("proxy answered with a non-SOCKS5 version"));
    }
    if head[1] != 0x00 {
        return Err(socks(reply_text(head[1])));
    }
    let bound_address_len = match head[3] {
        ADDRESS_IPV4 => 4,
        ADDRESS_IPV6 => 16,
        ADDRESS_DOMAIN => usize::from(stream.recv(1).await.map_err(io_error)?[0]),
        _ => return Err(socks("proxy reported an unknown bound address type")),
    };
    stream.recv(bound_address_len + 2).await.map_err(io_error)?;
    Ok(stream)
}

async fn negotiate_method<S: Handshake>(
    stream: &mut S,
    credentials: Option<(&str, &str)>,
) -> Result<(), Error> {
    let greeting = if credentials.is_some() {
        vec![VERSION, 2, METHOD_NONE, METHOD_USERNAME_PASSWORD]
    } else {
        vec![VERSION, 1, METHOD_NONE]
    };
    stream.send(greeting).await.map_err(io_error)?;

    let choice = stream.recv(2).await.map_err(io_error)?;
    if choice[0] != VERSION {
        return Err(socks("proxy answered with a non-SOCKS5 version"));
    }
    match choice[1] {
        METHOD_NONE => Ok(()),
        METHOD_USERNAME_PASSWORD => {
            let (username, password) =
                credentials.ok_or_else(|| socks("proxy requires credentials"))?;
            authenticate(stream, username, password).await
        }
        METHOD_UNACCEPTABLE => Err(socks("proxy accepts none of the offered methods")),
        _ => Err(socks(
            "proxy chose an authentication method zenwave does not speak",
        )),
    }
}

async fn authenticate<S: Handshake>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    let username_len =
        u8::try_from(username.len()).map_err(|_| socks("username longer than 255 bytes"))?;
    let password_len =
        u8::try_from(password.len()).map_err(|_| socks("password longer than 255 bytes"))?;
    let mut message = vec![AUTH_VERSION, username_len];
    message.extend_from_slice(username.as_bytes());
    message.push(password_len);
    message.extend_from_slice(password.as_bytes());
    stream.send(message).await.map_err(io_error)?;

    let status = stream.recv(2).await.map_err(io_error)?;
    if status[1] == 0x00 {
        Ok(())
    } else {
        Err(socks("proxy rejected the credentials"))
    }
}

enum Destination<'a> {
    Ip(SocketAddr),
    Domain(&'a str),
}

async fn destination(
    host: &str,
    port: u16,
    resolve_remotely: bool,
) -> Result<Destination<'_>, Error> {
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
    let resolved = happy_eyeballs::resolve(host, port)
        .await
        .map_err(|error| Error::Transport(Box::new(error)))?;
    resolved
        .into_iter()
        .next()
        .map(Destination::Ip)
        .ok_or_else(|| socks("hostname resolved to no address"))
}

const fn reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused by destination host",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown reply code",
    }
}

fn socks(message: &str) -> Error {
    ProxyErrorKind::Socks(message.to_owned()).into()
}

fn io_error(error: std::io::Error) -> Error {
    Error::Transport(Box::new(error))
}
