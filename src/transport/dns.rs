//! HTTPS (SVCB) DNS record lookups (RFC 9460) for HTTP/3 discovery.
//!
//! `getaddrinfo` cannot return HTTPS records, so they are queried directly:
//! through `hickory-resolver` on the system resolver configuration for
//! desktop and Apple platforms — driven by an in-tree async-io/async-net
//! `RuntimeProvider` in [`runtime`] — and through `android.net.DnsResolver`
//! over JNI in [`android`]. A/AAAA resolution stays on `getaddrinfo` in
//! `happy_eyeballs`, and turning a record into an HTTP/3 decision is the
//! connection pool's job (issue #69); this module only resolves it.

use std::{future::Future, net::IpAddr, time::Duration};

#[cfg(not(target_os = "android"))]
use std::str::FromStr;

#[cfg(not(target_os = "android"))]
use hickory_proto::rr::RecordType;
use hickory_proto::rr::{
    Name, RData, Record,
    rdata::svcb::{SVCB, SvcParamKey, SvcParamValue},
};
#[cfg(not(target_os = "android"))]
use hickory_resolver::{
    Resolver,
    config::{ResolverConfig, ResolverOpts},
    system_conf,
};
#[cfg(not(target_os = "android"))]
use runtime::AsyncIoRuntimeProvider;

use super::{Inner, Spawn};
use crate::Error;

#[cfg(target_os = "android")]
mod android;
#[cfg(not(target_os = "android"))]
pub mod runtime;
/// DNS fixtures shared with the backend's discovery tests.
#[cfg(all(test, not(target_os = "android")))]
pub mod test_support;

/// The resolver configuration a [`Transport`](crate::Transport) carries: the
/// system's, read once at build so no blocking `fs::read` ever runs per
/// lookup — or the reason it could not be read.
#[cfg(not(target_os = "android"))]
pub enum Config {
    /// The parsed system configuration, or a test's override.
    System(Box<SystemConfig>),
    /// Why the system configuration could not be read — `read_system_conf`'s
    /// error text (`Error` is not `Clone`). A host without one still
    /// resolves names through `getaddrinfo`, so this is a per-lookup
    /// failure of `https_record`, not a broken transport.
    Unavailable(String),
}

/// A `ResolverConfig`/`ResolverOpts` pair — boxed so [`Config`] stays small
/// on hosts without a resolver configuration.
#[cfg(not(target_os = "android"))]
pub struct SystemConfig {
    config: ResolverConfig,
    options: ResolverOpts,
}

/// The unit resolver configuration: Android's `DnsResolver` is configured by
/// the OS and consulted through the JVM.
#[cfg(target_os = "android")]
pub struct Config;

/// The hickory resolver a `Transport` owns. It is built on first use so its
/// runtime provider can take the caller's [`Spawn`], then reused so its
/// pooled name-server connections and TTL response cache survive lookups.
#[cfg(not(target_os = "android"))]
pub type HickoryResolver = Resolver<AsyncIoRuntimeProvider>;

#[cfg(not(target_os = "android"))]
impl Config {
    /// The system's resolver configuration, or the reason it could not be
    /// read.
    pub fn system() -> Self {
        match system_conf::read_system_conf() {
            Ok((config, options)) => Self::System(Box::new(SystemConfig { config, options })),
            Err(error) => Self::Unavailable(error.to_string()),
        }
    }

    /// An explicit configuration — the `TransportBuilder::dns_config`
    /// override for tests.
    #[allow(dead_code)] // only the tests construct one
    pub fn new(config: ResolverConfig, options: ResolverOpts) -> Self {
        Self::System(Box::new(SystemConfig { config, options }))
    }

    /// An unavailable configuration — only the tests construct one; at
    /// runtime `Unavailable` comes from `system()`.
    #[allow(dead_code)]
    pub(crate) fn unavailable(reason: &str) -> Self {
        Self::Unavailable(reason.to_owned())
    }
}

/// The resolver over `config`/`options` on the in-tree runtime.
/// `Resolver::build` only constructs the pool and cache — sockets open
/// lazily at the first query — so this is not a blocking call.
#[cfg(not(target_os = "android"))]
fn build_resolver(
    config: &ResolverConfig,
    options: &ResolverOpts,
    spawn: Spawn,
) -> Result<HickoryResolver, Error> {
    Resolver::builder_with_config(config.clone(), AsyncIoRuntimeProvider::new(spawn))
        .with_options(options.clone())
        .build()
        .map_err(|error| Error::Transport(Box::new(error)))
}

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

/// The HTTPS default port queries `host` directly; every other port queries
/// `_<port>._https.<host>` (RFC 9460 §3).
const HTTPS_DEFAULT_PORT: u16 = 443;

/// `AliasMode` answers are chased at most once (RFC 9460 §2.4.2).
const MAX_ALIAS_HOPS: u8 = 1;

/// Look up the HTTPS (SVCB) record for `host`:`port` through the transport's
/// resolver; `spawn` schedules the futures the resolver drives in the
/// background.
///
/// Returns `Ok(None)` when the host is an IP literal, when no record exists
/// (NODATA or NXDOMAIN), or on platforms that cannot answer the query (Android
/// before API 29). Every other failure — timeout, SERVFAIL, no resolver
/// configured — is `Err`; the caller decides whether it is fatal.
pub(super) async fn https_record(
    inner: &Inner,
    spawn: Spawn,
    host: &str,
    port: u16,
) -> Result<Option<HttpsRecord>, Error> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }

    #[cfg(target_os = "android")]
    {
        // `DnsResolver` is configured by the OS and schedules its own
        // callbacks; the stored configuration and `spawn` serve hickory.
        let _ = (&inner.dns, spawn);
        resolve(host, port, android::query_https).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let resolver = match &inner.dns {
            Config::System(system) => inner
                .resolver
                .get_or_try_init(|| build_resolver(&system.config, &system.options, spawn))?,
            // The resolver only feeds h3 discovery; the caller (#69) decides
            // what a missing configuration means for the origin.
            Config::Unavailable(reason) => {
                return Err(Error::Transport(Box::new(std::io::Error::other(
                    reason.clone(),
                ))));
            }
        };
        resolve(host, port, |domain| lookup_https(resolver, domain)).await
    }
}

/// One hickory `lookup` call as an answer set; NODATA and NXDOMAIN both
/// surface as `NoRecordsFound` — a definitive "there is no record", not a
/// failure — and come back as an empty set.
#[cfg(not(target_os = "android"))]
async fn lookup_https(resolver: &HickoryResolver, domain: String) -> Result<Vec<Record>, Error> {
    // A name that does not even parse is a caller error, not a transport
    // failure.
    let name =
        Name::from_str(&domain).map_err(|error| Error::InvalidUri(format!("{domain}: {error}")))?;
    match resolver.lookup(name, RecordType::HTTPS).await {
        Ok(lookup) => Ok(lookup.answers().to_vec()),
        Err(error) if error.is_no_records_found() => Ok(Vec::new()),
        Err(error) => Err(Error::Transport(Box::new(error))),
    }
}

/// The shared resolution loop: `query` maps a domain to the HTTPS `RRSets`
/// answered for it, and an `AliasMode` answer is re-queried once.
async fn resolve<F, Fut>(host: &str, port: u16, query: F) -> Result<Option<HttpsRecord>, Error>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<Vec<Record>, Error>>,
{
    let mut domain = query_domain(host, port);
    let mut hops = 0;
    let record = loop {
        let records = query(domain.clone()).await?;
        match classify(&records) {
            Answers::Service(svcb) => {
                break Some(https_record_of(&svcb, min_ttl(&records)));
            }
            // A second alias or a "." target has no usable endpoint.
            Answers::Alias(target) if hops < MAX_ALIAS_HOPS => {
                hops += 1;
                domain = target.to_string();
            }
            _ => break None,
        }
    };
    tracing::debug!(host, port, ?record, "HTTPS record lookup");
    Ok(record)
}

/// The name an HTTPS query is sent for (RFC 9460 §2.3/§3).
fn query_domain(host: &str, port: u16) -> String {
    if port == HTTPS_DEFAULT_PORT {
        host.to_owned()
    } else {
        format!("_{port}._https.{host}")
    }
}

/// What an HTTPS `RRSet` tells us: a usable `ServiceMode` record, an
/// `AliasMode` target to re-query, or no usable answer.
enum Answers {
    Service(SVCB),
    Alias(Name),
    Empty,
}

/// Pick the answer out of an HTTPS `RRSet` (RFC 9460 §2.4.1): an `AliasMode`
/// record voids every `ServiceMode` record beside it; otherwise the lowest
/// `SvcPriority` wins.
fn classify(records: &[Record]) -> Answers {
    let mut best: Option<&SVCB> = None;
    for record in records {
        let RData::HTTPS(https) = &record.data else {
            continue;
        };
        if https.svc_priority == 0 {
            // A "." AliasMode target declares the service unavailable (RFC 9460 §2.5.1).
            return if https.target_name.is_root() {
                Answers::Empty
            } else {
                Answers::Alias(https.target_name.clone())
            };
        }
        if best.is_none_or(|current| https.svc_priority < current.svc_priority) {
            best = Some(https);
        }
    }
    best.cloned().map_or(Answers::Empty, Answers::Service)
}

/// The [`HttpsRecord`] a `ServiceMode` SVCB/HTTPS record describes; `ttl` is
/// the minimum TTL of the answer's records.
fn https_record_of(svcb: &SVCB, ttl: Duration) -> HttpsRecord {
    let mut alpn = Vec::new();
    let mut port = None;
    for (key, value) in &svcb.svc_params {
        match (key, value) {
            (SvcParamKey::Alpn, SvcParamValue::Alpn(value)) => alpn.clone_from(&value.0),
            (SvcParamKey::Port, SvcParamValue::Port(value)) => port = Some(*value),
            _ => {}
        }
    }
    HttpsRecord { alpn, port, ttl }
}

/// The shortest TTL in an answer set — the answer is no fresher than its
/// least-fresh record.
fn min_ttl(records: &[Record]) -> Duration {
    records
        .iter()
        .map(|record| Duration::from_secs(u64::from(record.ttl)))
        .min()
        .unwrap_or(Duration::ZERO)
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use hickory_proto::{
        op::{Query, ResponseCode},
        rr::{
            RecordType,
            rdata::svcb::{Alpn, SvcParamKey, SvcParamValue},
        },
    };

    use super::{
        Config, HTTPS_DEFAULT_PORT, HttpsRecord,
        test_support::{TTL, answer, https, name, queried_name, resolver_config, serve, spawn},
    };
    use crate::{Error, transport::Transport};

    fn lookup(server: SocketAddr, host: &str, port: u16) -> Result<Option<HttpsRecord>, Error> {
        let (config, options) = resolver_config(server);
        let transport = Transport::builder()
            .dns_config(Config::new(config, options))
            .build()
            .expect("transport builds");
        async_io::block_on(transport.https_record(spawn(), host, port))
    }

    #[test]
    fn resolves_alpn() {
        let service = https(
            "example.test.",
            1,
            ".",
            vec![(
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h2".into(), "h3".into()])),
            )],
        );
        let (server, queried) =
            serve(move |query| answer(query, ResponseCode::NoError, vec![service.clone()]));

        let record = lookup(server, "example.test", HTTPS_DEFAULT_PORT)
            .expect("lookup")
            .expect("an HTTPS record");

        assert_eq!(record.alpn, ["h2", "h3"]);
        assert_eq!(record.port, None);
        assert_eq!(record.ttl, Duration::from_secs(u64::from(TTL)));
        assert_eq!(
            queried_name(&queried),
            (name("example.test."), RecordType::HTTPS)
        );
    }

    #[test]
    fn queries_prefixed_name_for_non_default_port() {
        let service = https(
            "_8443._https.example.test.",
            1,
            ".",
            vec![(SvcParamKey::Port, SvcParamValue::Port(8443))],
        );
        let (server, queried) =
            serve(move |query| answer(query, ResponseCode::NoError, vec![service.clone()]));

        let record = lookup(server, "example.test", 8443)
            .expect("lookup")
            .expect("an HTTPS record");

        assert_eq!(record.alpn, Vec::<String>::new());
        assert_eq!(record.port, Some(8443));
        assert_eq!(
            queried_name(&queried),
            (name("_8443._https.example.test."), RecordType::HTTPS)
        );
    }

    #[test]
    fn nodata_is_none() {
        let (server, _queried) = serve(|query| answer(query, ResponseCode::NoError, vec![]));

        let record = lookup(server, "example.test", HTTPS_DEFAULT_PORT).expect("lookup");

        assert!(record.is_none());
    }

    #[test]
    fn nxdomain_is_none() {
        let (server, _queried) = serve(|query| answer(query, ResponseCode::NXDomain, vec![]));

        let record = lookup(server, "example.test", HTTPS_DEFAULT_PORT).expect("lookup");

        assert!(record.is_none());
    }

    #[test]
    fn unavailable_resolver_is_a_per_lookup_error() {
        // A host without resolver configuration still builds a working
        // transport — A/AAAA go through `getaddrinfo` — and only the
        // HTTPS-record lookup reports it.
        let transport = Transport::builder()
            .dns_config(Config::unavailable("no system resolver configuration"))
            .build()
            .expect("transport builds without resolver configuration");

        let result =
            async_io::block_on(transport.https_record(spawn(), "example.test", HTTPS_DEFAULT_PORT));

        assert!(matches!(result, Err(Error::Transport(_))));
    }

    #[test]
    fn servfail_is_an_error() {
        let (server, _queried) = serve(|query| answer(query, ResponseCode::ServFail, vec![]));

        let result = lookup(server, "example.test", HTTPS_DEFAULT_PORT);

        assert!(matches!(result, Err(Error::Transport(_))));
    }

    #[test]
    fn follows_one_alias_mode_hop() {
        let (server, queried) = serve(|query| {
            let answers = if query.queries.first().map(Query::name) == Some(&name("alias.test.")) {
                vec![https("alias.test.", 0, "real.test.", vec![])]
            } else {
                vec![https(
                    "real.test.",
                    1,
                    ".",
                    vec![(
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["h3".into()])),
                    )],
                )]
            };
            answer(query, ResponseCode::NoError, answers)
        });

        let record = lookup(server, "alias.test", HTTPS_DEFAULT_PORT)
            .expect("lookup")
            .expect("an HTTPS record");

        assert_eq!(record.alpn, ["h3"]);
        assert_eq!(
            queried_name(&queried),
            (name("alias.test."), RecordType::HTTPS)
        );
        assert_eq!(
            queried_name(&queried),
            (name("real.test."), RecordType::HTTPS)
        );
    }
}
