//! Name resolution: the [`Resolve`] implementations zenwave ships, and the
//! capabilities its HTTP/3 discovery asks of a resolver.
//!
//! The native backend takes its resolver as a value
//! ([`NativeBackend::on_current_thread`](crate::backend::NativeBackend::on_current_thread)),
//! so a host with a resolver of its own, and no `getaddrinfo`, supplies it.

#[cfg(getaddrinfo)]
use std::{io, net::IpAddr, thread};

#[cfg(getaddrinfo)]
use dns_lookup::{AddrFamily, AddrInfoHints, LookupError, LookupErrorKind, SockType, getaddrinfo};
#[cfg(getaddrinfo)]
use futures_channel::mpsc::unbounded;
#[cfg(getaddrinfo)]
use futures_util::Stream;
#[cfg(getaddrinfo)]
use http_kit_io::{Answer, Family, Resolve};

#[cfg(https_rr)]
pub use crate::transport::dns::HttpsRecord;
#[cfg(native_h3)]
pub use crate::transport::dns::ResolveHttps;
#[cfg(all(native_h3, getaddrinfo))]
pub use crate::transport::dns::System;

/// `getaddrinfo`, one thread per query.
///
/// A lookup sends three queries at once: the name's IPv6 addresses, its IPv4
/// addresses, and every address ranked by the system (RFC 6724), each answered
/// as it completes so a slow family holds nothing back.
#[cfg(getaddrinfo)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Getaddrinfo;

/// What one `getaddrinfo` call asks for: a family, or every address.
#[cfg(getaddrinfo)]
#[derive(Debug, Clone, Copy)]
enum Query {
    Family(Family),
    Ranked,
}

#[cfg(getaddrinfo)]
impl Resolve for Getaddrinfo {
    fn lookup(&self, host: &str) -> impl Stream<Item = Answer> {
        let (sender, receiver) = unbounded();
        for query in [
            Query::Family(Family::Ipv6),
            Query::Family(Family::Ipv4),
            Query::Ranked,
        ] {
            let host = host.to_owned();
            let sender = sender.clone();
            thread::spawn(move || {
                let addrs = query_addresses(&host, query);
                let answer = match query {
                    Query::Family(family) => Answer::Family(family, addrs),
                    Query::Ranked => Answer::Ranked(addrs),
                };
                // The lookup was dropped: nothing is waiting for the answer.
                let _ = sender.unbounded_send(answer);
            });
        }
        receiver
    }
}

/// The addresses `getaddrinfo` finds for `host`, in its order.
#[cfg(getaddrinfo)]
fn query_addresses(host: &str, query: Query) -> io::Result<Vec<IpAddr>> {
    let hints = AddrInfoHints {
        address: match query {
            Query::Family(Family::Ipv6) => AddrFamily::Inet6.into(),
            Query::Family(Family::Ipv4) => AddrFamily::Inet.into(),
            Query::Ranked => 0,
        },
        socktype: SockType::Stream.into(),
        ..AddrInfoHints::default()
    };
    let entries = getaddrinfo(Some(host), None, Some(hints)).map_err(io_error)?;
    entries
        .map(|entry| entry.map(|entry| entry.sockaddr.ip()))
        .collect()
}

/// `error` as an `io::Error`, with a name that does not exist as
/// [`io::ErrorKind::NotFound`] (`EAI_NONAME`, `EAI_NODATA`).
#[cfg(getaddrinfo)]
fn io_error(error: LookupError) -> io::Error {
    let missing = matches!(
        error.kind(),
        LookupErrorKind::NoName | LookupErrorKind::NoData
    );
    let error = io::Error::from(error);
    if missing {
        io::Error::new(io::ErrorKind::NotFound, error)
    } else {
        error
    }
}
