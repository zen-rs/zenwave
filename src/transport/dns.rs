//! HTTPS (SVCB) DNS record lookups (RFC 9460) for HTTP/3 discovery.
//!
//! `getaddrinfo` cannot return HTTPS records, so they are queried directly:
//! through `hickory-resolver` on the system resolver configuration for
//! desktop and Apple platforms — driven by an in-tree async-io/async-net
//! `RuntimeProvider` in `lookup::runtime` — and through
//! `android.net.DnsResolver` over JNI in `lookup::android`. A/AAAA
//! resolution stays on `getaddrinfo` in `happy_eyeballs` through a
//! `http_kit_io::Resolve`, and turning a record into an HTTP/3
//! decision is the connection pool's job (issue #69); this module defines
//! the record and the capability, and `lookup` resolves it wherever a
//! caller exists.

#[cfg(native_h3)]
use std::future::Future;
use std::time::Duration;

#[cfg(native_h3)]
use crate::Error;

// The resolver machinery, compiled only where something calls it.
#[cfg(https_lookup)]
mod lookup;

#[cfg(https_lookup)]
pub use lookup::Config;
#[cfg(all(https_lookup, not(target_os = "android")))]
pub(super) use lookup::HickoryResolver;
#[cfg(https_lookup)]
pub(super) use lookup::https_record;
#[cfg(all(test, http3, not(target_os = "android")))]
pub use lookup::test_support;

/// What a usable HTTPS record offers for an origin.
#[derive(Debug)]
pub struct HttpsRecord {
    /// ALPN protocol identifiers from `SvcParam` key 1, e.g. `["h2", "h3"]`.
    pub alpn: Vec<String>,
    /// Alternative endpoint port from `SvcParam` key 3.
    pub port: Option<u16>,
    /// How long the answer stays valid: the minimum TTL of the answer's
    /// records.
    pub ttl: Duration,
}

/// HTTPS record lookups (RFC 9460), for HTTP/3 discovery: the capability the
/// native backend's HTTP/3 path asks of a resolver on top of addresses.
///
/// Neither `getaddrinfo` nor `http_kit_io::Resolve` can return one, so a host
/// that cannot query them implements `Resolve` alone and builds the backend
/// without HTTP/3.
#[cfg(native_h3)]
pub trait ResolveHttps: http_kit_io::Resolve {
    /// The HTTPS record for `host`:`port`: `Ok(None)` when none exists, an
    /// error when the lookup itself failed. HTTP/3 discovery treats a failed
    /// lookup as an absent record.
    fn https_record(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Option<HttpsRecord>, Error>>;
}

/// The system resolver: `getaddrinfo` for addresses and the transport's own
/// resolver (`hickory-resolver` on the system's configuration, or
/// `android.net.DnsResolver` on Android) for HTTPS records.
///
/// It does not keep the transport alive: once the transport is dropped, an
/// HTTPS lookup fails.
#[cfg(all(native_h3, getaddrinfo))]
#[derive(Clone)]
pub struct System {
    transport: super::WeakTransport,
}

#[cfg(all(native_h3, getaddrinfo))]
impl System {
    /// The system resolver for `transport`'s HTTPS record lookups.
    #[must_use]
    pub fn new(transport: &super::Transport) -> Self {
        Self {
            transport: transport.downgrade(),
        }
    }
}

#[cfg(all(native_h3, getaddrinfo))]
impl std::fmt::Debug for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("System").finish_non_exhaustive()
    }
}

#[cfg(all(native_h3, getaddrinfo))]
impl http_kit_io::Resolve for System {
    fn lookup(&self, host: &str) -> impl futures_util::Stream<Item = http_kit_io::Answer> {
        http_kit_io::Resolve::lookup(&crate::dns::Getaddrinfo, host)
    }
}

#[cfg(all(native_h3, getaddrinfo))]
impl ResolveHttps for System {
    async fn https_record(&self, host: &str, port: u16) -> Result<Option<HttpsRecord>, Error> {
        let transport = self.transport.upgrade().ok_or_else(|| {
            Error::Transport(Box::new(std::io::Error::other(
                "the transport the system resolver was built for has been dropped",
            )))
        })?;
        // The resolver's background work, each future on a thread of its
        // own: the transport's resolver is shared by every pool and outlives
        // any one of them, so its tasks cannot live on a pool's thread.
        transport
            .https_record(std::sync::Arc::new(super::spawn_thread), host, port)
            .await
    }
}
