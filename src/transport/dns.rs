//! HTTPS (SVCB) DNS record lookups (RFC 9460) for HTTP/3 discovery.
//!
//! `getaddrinfo` cannot return HTTPS records, so they are queried directly:
//! through `hickory-resolver` on the system resolver configuration for
//! desktop and Apple platforms — driven by an in-tree async-io/async-net
//! `RuntimeProvider` in [`runtime`] — and through `android.net.DnsResolver`
//! over JNI in [`android`]. A/AAAA resolution stays on `getaddrinfo` in
//! `happy_eyeballs`, and turning a record into an HTTP/3 decision is the
//! connection pool's job (issue #69); this module only resolves it.

use std::net::IpAddr;

#[cfg(not(target_os = "android"))]
use std::{future::Future, pin::Pin, str::FromStr, sync::Arc};

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

use crate::Error;

#[cfg(target_os = "android")]
mod android;
#[cfg(not(target_os = "android"))]
mod runtime;

/// How the resolver's background tasks are spawned. Issue #66 defines the
/// identical type for the QUIC runtime; issue #69 unifies the two.
#[cfg(not(target_os = "android"))]
pub type Spawn = Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>;

/// What a usable HTTPS record offers for an origin.
#[allow(dead_code)] // consumed by the connection pool's h3 discovery (issue #69)
#[derive(Debug)]
pub struct HttpsRecord {
    /// ALPN protocol identifiers from `SvcParam` key 1, e.g. `["h2", "h3"]`.
    pub alpn: Vec<String>,
    /// Alternative endpoint port from `SvcParam` key 3.
    pub port: Option<u16>,
}

/// The HTTPS default port queries `host` directly; every other port queries
/// `_<port>._https.<host>` (RFC 9460 §3).
const HTTPS_DEFAULT_PORT: u16 = 443;

/// `AliasMode` answers are chased at most once (RFC 9460 §2.4.2).
const MAX_ALIAS_HOPS: u8 = 1;

/// Look up the HTTPS (SVCB) record for `host`:`port`.
///
/// Returns `Ok(None)` when the host is an IP literal, when no record exists
/// (NODATA or NXDOMAIN), or on platforms that cannot answer the query (Android
/// before API 29). Every other failure — timeout, SERVFAIL, no resolver
/// configured — is `Err`; the caller decides whether it is fatal.
#[allow(dead_code)] // consumed by the connection pool's h3 discovery (issue #69)
pub async fn https_record(host: &str, port: u16) -> Result<Option<HttpsRecord>, Error> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }

    #[cfg(target_os = "android")]
    {
        resolve(host, port, android::query_https).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let (config, options) =
            system_conf::read_system_conf().map_err(|error| Error::Transport(Box::new(error)))?;
        https_record_with(config, options, host, port).await
    }
}

/// The lookup against an explicit resolver configuration, so tests can point
/// at an in-process DNS server instead of the system's.
#[cfg(not(target_os = "android"))]
async fn https_record_with(
    config: ResolverConfig,
    options: ResolverOpts,
    host: &str,
    port: u16,
) -> Result<Option<HttpsRecord>, Error> {
    let resolver = resolver(config, options)?;
    resolve(host, port, |domain| lookup_https(&resolver, domain)).await
}

#[cfg(not(target_os = "android"))]
fn resolver(
    config: ResolverConfig,
    options: ResolverOpts,
) -> Result<Resolver<AsyncIoRuntimeProvider>, Error> {
    Resolver::builder_with_config(config, AsyncIoRuntimeProvider::thread_per_task())
        .with_options(options)
        .build()
        .map_err(|error| Error::Transport(Box::new(error)))
}

/// One hickory `lookup` call as an answer set; NODATA and NXDOMAIN both
/// surface as `NoRecordsFound` — a definitive "there is no record", not a
/// failure — and come back as an empty set.
#[cfg(not(target_os = "android"))]
async fn lookup_https(
    resolver: &Resolver<AsyncIoRuntimeProvider>,
    domain: String,
) -> Result<Vec<Record>, Error> {
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
        match classify(&query(domain.clone()).await?) {
            Answers::Service(svcb) => break Some(https_record_of(&svcb)),
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

/// The [`HttpsRecord`] a `ServiceMode` SVCB/HTTPS record describes.
fn https_record_of(svcb: &SVCB) -> HttpsRecord {
    let mut alpn = Vec::new();
    let mut port = None;
    for (key, value) in &svcb.svc_params {
        match (key, value) {
            (SvcParamKey::Alpn, SvcParamValue::Alpn(value)) => alpn.clone_from(&value.0),
            (SvcParamKey::Port, SvcParamValue::Port(value)) => port = Some(*value),
            _ => {}
        }
    }
    HttpsRecord { alpn, port }
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use std::{
        net::{SocketAddr, UdpSocket},
        sync::mpsc::{self, Receiver},
        thread,
        time::Duration,
    };

    use hickory_proto::{
        op::{Message, MessageType, Query, ResponseCode},
        rr::rdata::{HTTPS, svcb::Alpn},
    };
    use hickory_resolver::config::{
        ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
    };

    use super::{
        HTTPS_DEFAULT_PORT, HttpsRecord, Name, RData, Record, RecordType, SVCB, SvcParamKey,
        SvcParamValue, https_record_with,
    };
    use crate::Error;

    /// TTL of the synthetic records.
    const TTL: u32 = 300;

    /// How long a test waits for a query to arrive at the server.
    const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

    /// A DNS name for tests.
    fn name(domain: &str) -> Name {
        domain.parse().expect("test domain must parse")
    }

    /// A UDP DNS server on a dedicated thread: `respond` answers every query,
    /// and each queried name and record type is observable on the returned
    /// channel. The thread lives until the test process ends.
    fn serve(
        respond: impl Fn(&Message) -> Message + Send + 'static,
    ) -> (SocketAddr, Receiver<(Name, RecordType)>) {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        let (names, queried) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = [0; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buffer) {
                let Ok(query) = Message::from_vec(&buffer[..len]) else {
                    continue;
                };
                if let Some(asked) = query.queries.first() {
                    let _ = names.send((asked.name().clone(), asked.query_type()));
                }
                if let Ok(response) = respond(&query).to_vec() {
                    let _ = socket.send_to(&response, peer);
                }
            }
        });
        (addr, queried)
    }

    /// A resolver config pointed at the in-process server.
    fn config(server: SocketAddr) -> (ResolverConfig, ResolverOpts) {
        let mut udp = ConnectionConfig::udp();
        udp.port = server.port();
        let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(
            server.ip(),
            true,
            vec![udp],
        )]);
        let mut options = ResolverOpts::default();
        options.attempts = 1;
        (config, options)
    }

    /// A response echoing the query's metadata, with `rcode` and `answers`.
    fn answer(query: &Message, rcode: ResponseCode, answers: Vec<Record>) -> Message {
        let mut response = Message::new(
            query.metadata.id,
            MessageType::Response,
            query.metadata.op_code,
        );
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.metadata.response_code = rcode;
        response.queries.clone_from(&query.queries);
        response.answers = answers;
        response
    }

    /// An HTTPS RR owned by `owner`.
    fn https(
        owner: &str,
        priority: u16,
        target: &str,
        params: Vec<(SvcParamKey, SvcParamValue)>,
    ) -> Record {
        Record::from_rdata(
            name(owner),
            TTL,
            RData::HTTPS(HTTPS(SVCB::new(priority, name(target), params))),
        )
    }

    fn lookup(server: SocketAddr, host: &str, port: u16) -> Result<Option<HttpsRecord>, Error> {
        let (config, options) = config(server);
        async_io::block_on(https_record_with(config, options, host, port))
    }

    fn queried_name(queried: &Receiver<(Name, RecordType)>) -> (Name, RecordType) {
        queried.recv_timeout(QUERY_TIMEOUT).unwrap()
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
