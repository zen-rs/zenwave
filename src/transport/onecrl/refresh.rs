//! Keeping the compiled baseline current: the `zenwave-onecrl` thread.
//!
//! `TransportBuilder::onecrl_refresh` opts a transport in. The thread this
//! module starts fetches the Remote Settings changeset since the newest
//! timestamp seen, folds the new records into the shared [`Additions`], and
//! persists them so the next process starts from them. It holds only a `Weak`
//! to the transport's inner state and exits at the first wake-up after the
//! transport is dropped — a dropped transport never keeps refreshing, and the
//! thread is never what keeps it alive.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};

use arc_swap::ArcSwap;
use futures_util::{
    FutureExt,
    future::{Either, select},
    pin_mut,
};
use http::{
    Request, StatusCode, Uri,
    header::{HOST, PROXY_AUTHORIZATION},
};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;

use super::{Additions, baseline_timestamp, record};
use crate::{
    Error,
    transport::{
        Inner, Transport,
        connect::{self, Protocols, Target, Via},
        hyper_io::HyperIo,
    },
};

/// The Remote Settings changeset endpoint: the OneCRL collection's
/// incremental view.
pub(crate) const DEFAULT_ENDPOINT: &str = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset";

/// The additions file inside the resolved cache directory.
const FILE_NAME: &str = "changes.json";

/// What `TransportBuilder` keeps for `onecrl_refresh`; `interval` doubles as
/// the enable flag — refresh is opt-in.
#[derive(Debug)]
pub(crate) struct Refresh {
    /// The round interval; `None` until `onecrl_refresh` is called.
    pub(crate) interval: Option<Duration>,
    /// The changeset endpoint; [`DEFAULT_ENDPOINT`] unless a test overrode it.
    pub(crate) endpoint: String,
    /// The directory `zenwave/onecrl/` persists additions under; `None`
    /// resolves the platform cache directory at `build()`.
    pub(crate) cache_dir: Option<PathBuf>,
}

impl Refresh {
    /// The resolved plan: `None` when refresh was never enabled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when refresh is enabled but no cache directory
    /// exists for the additions file.
    pub(crate) fn resolve(&self) -> Result<Option<Plan>, Error> {
        let Some(interval) = self.interval else {
            return Ok(None);
        };
        let root = match &self.cache_dir {
            Some(dir) => dir.clone(),
            None => cache_root()?,
        };
        Ok(Some(Plan {
            interval,
            endpoint: self.endpoint.clone(),
            dir: root.join("zenwave").join("onecrl"),
        }))
    }
}

impl Default for Refresh {
    fn default() -> Self {
        Self {
            interval: None,
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            cache_dir: None,
        }
    }
}

/// Refresh fully resolved: how often, where to fetch, and the directory
/// `changes.json` lives in.
pub(crate) struct Plan {
    interval: Duration,
    endpoint: String,
    dir: PathBuf,
}

/// A fetched or loaded changeset: its top-level timestamp and raw records.
struct Changeset {
    timestamp: u64,
    changes: Vec<serde_json::Value>,
}

/// Start the `zenwave-onecrl` refresher thread.
///
/// # Errors
///
/// Returns [`Error::Io`] when the thread cannot be spawned.
pub(crate) fn spawn(
    inner: &Arc<Inner>,
    additions: Arc<ArcSwap<Additions>>,
    plan: Plan,
) -> Result<(), Error> {
    let inner = Arc::downgrade(inner);
    std::thread::Builder::new()
        .name("zenwave-onecrl".to_owned())
        .spawn(move || async_io::block_on(run(inner, additions, plan)))?;
    Ok(())
}

/// Load the persisted additions, then run fetch-merge-persist rounds every
/// `plan.interval` until the transport is gone. The `Weak` is upgraded only
/// for the duration of a round — never held across the sleep.
async fn run(inner: Weak<Inner>, additions: Arc<ArcSwap<Additions>>, plan: Plan) {
    let mut seen = match load(&plan.dir) {
        Ok(Some(cached)) if cached.timestamp > baseline_timestamp() => {
            let mut merged = Additions::default();
            let mut kept = Vec::new();
            for record in cached.changes {
                match record::entry(&record) {
                    Ok(Some(entry)) => {
                        merged.insert(entry);
                        kept.push(record);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(error = %error, "skipping a malformed cached OneCRL record");
                    }
                }
            }
            merged.advance(cached.timestamp);
            additions.store(Arc::new(merged));
            kept
        }
        Ok(_) => Vec::new(),
        Err(error) => {
            tracing::warn!(%error, path = %plan.dir.join(FILE_NAME).display(), "ignoring the OneCRL additions cache");
            Vec::new()
        }
    };
    loop {
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let transport = Transport { inner };
        if let Err(error) = round(&transport, &plan, &additions, &mut seen).await {
            tracing::warn!(%error, "OneCRL refresh failed; keeping the current additions");
        }
        drop(transport);
        async_io::Timer::after(plan.interval).await;
    }
}

/// One fetch-merge-persist pass.
async fn round(
    transport: &Transport,
    plan: &Plan,
    additions: &Arc<ArcSwap<Additions>>,
    seen: &mut Vec<serde_json::Value>,
) -> Result<(), Error> {
    let changeset = fetch(transport, plan, since(additions)).await?;
    let current = additions.load_full();
    let mut next = (*current).clone();
    // The changeset's timestamp marks the round as seen even when `changes`
    // holds only tombstones or malformed records — otherwise every later
    // round fetches them again.
    next.advance(changeset.timestamp);
    let mut landed = false;
    for record in changeset.changes {
        match record::entry(&record) {
            Ok(Some(entry)) => {
                next.insert(entry);
                seen.push(record);
                landed = true;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "skipping a malformed OneCRL record");
            }
        }
    }
    if !landed && next.timestamp() == current.timestamp() {
        return Ok(());
    }
    let timestamp = next.timestamp();
    drop(current);
    additions.store(Arc::new(next));
    // A persist failure costs only the next process's warm start: the merged
    // additions already apply in memory, so it is not a round failure.
    if let Err(error) = persist(&plan.dir, timestamp, seen) {
        tracing::warn!(%error, path = %plan.dir.join(FILE_NAME).display(), "could not persist the OneCRL additions");
    }
    Ok(())
}

/// The `_since` parameter: the newest timestamp already covered, the
/// baseline's or the additions'.
fn since(additions: &ArcSwap<Additions>) -> u64 {
    additions.load().timestamp().max(baseline_timestamp())
}

/// GET `{endpoint}?_expected=0&_since="{since}"` through the transport, so
/// its proxy rules and trust roots apply and OneCRL checks the connection
/// too. Like `tunnel.rs`, the hyper connection is polled alongside the
/// request so the response body can stream in.
async fn fetch(transport: &Transport, plan: &Plan, since: u64) -> Result<Changeset, Error> {
    let separator = if plan.endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let uri: Uri = format!(
        "{}{separator}_expected=0&_since=%22{since}%22",
        plan.endpoint
    )
    .parse()
    .map_err(|error: http::uri::InvalidUri| Error::InvalidUri(error.to_string()))?;
    let host = uri
        .host()
        .ok_or_else(|| Error::InvalidUri(format!("{}: no host", plan.endpoint)))?
        .to_owned();
    let tls = uri.scheme_str() == Some("https");
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });

    let connection = connect::connect(
        transport,
        Target {
            host: &host,
            port,
            tls,
            tunnel_plaintext: false,
            protocols: Protocols::Http1,
        },
    )
    .await?;
    let (mut sender, driver) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(HyperIo(connection.stream))
            .await
            .map_err(|error| Error::Transport(Box::new(error)))?;

    let mut request = Request::get(
        uri.path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str),
    )
    .header(HOST, connect::authority(&host, port))
    .body(Empty::new())
    .map_err(|error| Error::InvalidRequest(error.to_string()))?;
    // An HTTP proxy serving a plaintext target speaks absolute-form; a
    // CONNECT tunnel or a direct connection returns `Via::Direct`.
    if let Via::HttpProxy { authorization } = connection.via {
        *request.uri_mut() = uri.clone();
        if let Some(authorization) = authorization {
            request
                .headers_mut()
                .insert(PROXY_AUTHORIZATION, authorization);
        }
    }

    let exchange = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| Error::Transport(Box::new(error)))?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| Error::Transport(Box::new(error)))?
            .to_bytes();
        Ok::<_, Error>((status, body))
    }
    .fuse();
    pin_mut!(exchange);
    let driver = driver.fuse();
    pin_mut!(driver);
    let (status, body) = match select(exchange, driver).await {
        Either::Left((result, _)) => result?,
        // The peer closed mid-exchange; buffered bytes may still complete it.
        Either::Right((driver_result, exchange)) => {
            driver_result.map_err(|error| Error::Transport(Box::new(error)))?;
            exchange.await?
        }
    };

    if status != StatusCode::OK {
        return Err(unavailable(format!(
            "the changeset endpoint answered {status}"
        )));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|error| Error::Transport(Box::new(error)))?;
    let timestamp = value["timestamp"]
        .as_u64()
        .ok_or_else(|| unavailable("the changeset has no timestamp"))?;
    let changes = value["changes"]
        .as_array()
        .ok_or_else(|| unavailable("the changeset has no changes array"))?
        .clone();
    Ok(Changeset { timestamp, changes })
}

/// The persisted additions, `Ok(None)` when no file exists.
///
/// # Errors
///
/// Returns `Err` when the file cannot be read or does not hold the changeset
/// shape — the caller warns and ignores it.
fn load(dir: &Path) -> Result<Option<Changeset>, Error> {
    let body = match std::fs::read(dir.join(FILE_NAME)) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::Io(error)),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|error| Error::Transport(Box::new(error)))?;
    let timestamp = value["timestamp"]
        .as_u64()
        .ok_or_else(|| unavailable("cached changes.json has no timestamp"))?;
    let changes = value["changes"]
        .as_array()
        .ok_or_else(|| unavailable("cached changes.json has no changes array"))?
        .clone();
    Ok(Some(Changeset { timestamp, changes }))
}

/// Atomically replace `dir/changes.json` with every addition seen: a temp
/// file in the same directory, then a rename over the old one.
fn persist(dir: &Path, timestamp: u64, records: &[serde_json::Value]) -> Result<(), Error> {
    std::fs::create_dir_all(dir).map_err(Error::Io)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "timestamp": timestamp,
        "changes": records,
    }))
    .map_err(|error| Error::Transport(Box::new(error)))?;
    let temporary = dir.join("changes.json.tmp");
    std::fs::write(&temporary, body).map_err(Error::Io)?;
    std::fs::rename(&temporary, dir.join(FILE_NAME)).map_err(Error::Io)?;
    Ok(())
}

/// A round failure: remote input or the network, never a bug — so `run`
/// warns and retries next interval.
fn unavailable(message: impl Into<String>) -> Error {
    Error::Transport(Box::new(std::io::Error::other(message.into())))
}

/// The platform cache directory.
///
/// # Errors
///
/// Returns [`Error::Io`] when the platform reports no cache directory.
#[cfg(not(target_os = "android"))]
fn cache_root() -> Result<PathBuf, Error> {
    dirs::cache_dir().ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no cache directory for the OneCRL additions",
        ))
    })
}

/// `Context.getCacheDir().getAbsolutePath()` through JNI — `dirs` knows no
/// Android cache directory. The JVM handle comes from `ndk-context`, the
/// same way `transport::dns::android` reaches it.
///
/// # Errors
///
/// Returns `Err` when the JVM call fails.
#[cfg(target_os = "android")]
fn cache_root() -> Result<PathBuf, Error> {
    use jni::{
        JavaVM, jni_sig, jni_str,
        objects::{JObject, JString},
    };

    let context = ndk_context::android_context();
    // SAFETY: ndk-context's VM pointer is the app's live `JavaVM`.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) };
    vm.attach_current_thread(|env| -> Result<PathBuf, jni::errors::Error> {
        // SAFETY: `context` is the app's live `Context` jobject, wrapped
        // only for the duration of these calls inside `env`'s local frame.
        let context = unsafe { JObject::from_raw(env, context.context().cast()) };
        let file = env
            .call_method(
                &context,
                jni_str!("getCacheDir"),
                jni_sig!("()Ljava/io/File;"),
                &[],
            )?
            .l()?;
        let path = env
            .call_method(
                &file,
                jni_str!("getAbsolutePath"),
                jni_sig!("()Ljava/lang/String;"),
                &[],
            )?
            .l()?;
        Ok(PathBuf::from(JString::cast_local(env, path)?.to_string()))
    })
    .map_err(|error| Error::Transport(Box::new(error)))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use base64::Engine as _;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use rustls::{
        ServerConfig,
        crypto::ring,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use serde_json::json;
    use time::{Duration as TimeDelta, OffsetDateTime};

    use crate::{
        Proxy, Transport,
        transport::connect::{self, Protocols, Target},
    };

    /// How long a test waits for a refresh round to land.
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    /// The test changesets' timestamp — far past any baseline Remote
    /// Settings has published, so a cached file always counts as newer.
    const TIMESTAMP: u64 = 9_999_999_999_999;

    /// A CA with `name` as common name: its `Issuer` signs descendants.
    fn ca_params(name: &str) -> CertificateParams {
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = now - TimeDelta::days(1);
        params.not_after = now + TimeDelta::days(365);
        params
    }

    /// A self-signed root CA.
    fn root(name: &str) -> (Issuer<'static, KeyPair>, CertificateDer<'static>) {
        let params = ca_params(name);
        let key = KeyPair::generate().expect("root key");
        let cert = params.self_signed(&key).expect("root self-sign");
        (Issuer::new(params, key), cert.der().clone())
    }

    /// An intermediate CA signed by `parent`.
    fn intermediate(
        name: &str,
        parent: &Issuer<'static, KeyPair>,
    ) -> (Issuer<'static, KeyPair>, CertificateDer<'static>) {
        let params = ca_params(name);
        let key = KeyPair::generate().expect("intermediate key");
        let cert = params.signed_by(&key, parent).expect("intermediate sign");
        (Issuer::new(params, key), cert.der().clone())
    }

    /// A `localhost`/`127.0.0.1` leaf signed by `issuer`.
    fn leaf(
        issuer: &Issuer<'static, KeyPair>,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let now = OffsetDateTime::now_utc();
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = now - TimeDelta::days(1);
        params.not_after = now + TimeDelta::days(365);
        let cert = params.signed_by(&key, issuer).expect("leaf sign");
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    /// Serve `chain` + `key` over TLS on a bound `127.0.0.1` port forever;
    /// returns the port. Each connection is closed once the handshake lands —
    /// the client only needs the verification verdict.
    fn serve_tls(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> u16 {
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = futures_rustls::TlsAcceptor::from(Arc::new(config));
        let (listener, port) = async_io::block_on(async {
            let listener = async_net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("test listener must bind");
            let port = listener.local_addr().expect("test address").port();
            (listener, port)
        });
        thread::spawn(move || {
            async_io::block_on(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    thread::spawn(move || {
                        let _ = async_io::block_on(acceptor.accept(tcp));
                    });
                }
            });
        });
        port
    }

    /// A plaintext changeset server answering every request with `body` and
    /// counting them. When `gate` is held, the first answer waits until the
    /// matching sender is dropped — a test can prove a chain verifies before
    /// the first round lands.
    struct Changeset {
        url: String,
        hits: Arc<AtomicUsize>,
    }

    fn serve_changeset(body: String, gate: Option<mpsc::Receiver<()>>) -> Changeset {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("changeset listener");
        let port = listener.local_addr().expect("changeset address").port();
        let hits = Arc::new(AtomicUsize::new(0));
        thread::spawn({
            let hits = hits.clone();
            move || {
                let mut gate = gate;
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else {
                        continue;
                    };
                    if let Some(gate) = gate.take() {
                        let _ = gate.recv();
                    }
                    let mut head = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(read) => head.extend_from_slice(&buffer[..read]),
                        }
                        if head.len() >= 64 * 1024 {
                            break;
                        }
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        });
        Changeset {
            url: format!("http://127.0.0.1:{port}"),
            hits,
        }
    }

    /// Re-wrap DER SEQUENCE content in its tag and length — OneCRL records
    /// store whole TLVs while webpki reports the content.
    fn sequence_tlv(content: &[u8]) -> Vec<u8> {
        let mut tlv = vec![0x30];
        if content.len() < 0x80 {
            tlv.push(u8::try_from(content.len()).expect("short form"));
        } else {
            let bytes = content.len().to_be_bytes();
            let significant =
                &bytes[usize::try_from(content.len().leading_zeros()).expect("len") / 8..];
            tlv.push(0x80 | u8::try_from(significant.len()).expect("at most 8"));
            tlv.extend_from_slice(significant);
        }
        tlv.extend_from_slice(content);
        tlv
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A record listing `der`'s certificate by issuer name and serial.
    fn issuer_serial_record(der: &CertificateDer<'_>) -> serde_json::Value {
        let cert = webpki::EndEntityCert::try_from(der).expect("certificate parses");
        json!({
            "issuerName": b64(&sequence_tlv(cert.issuer())),
            "serialNumber": b64(cert.serial()),
        })
    }

    /// A record listing `der`'s certificate by subject name and SPKI hash.
    fn subject_key_record(der: &CertificateDer<'_>) -> serde_json::Value {
        let cert = webpki::EndEntityCert::try_from(der).expect("certificate parses");
        let spki = cert.subject_public_key_info();
        json!({
            "subject": b64(&sequence_tlv(cert.subject())),
            "pubKeyHash": b64(::ring::digest::digest(&::ring::digest::SHA256, spki.as_ref()).as_ref()),
        })
    }

    fn changeset_body(changes: Vec<serde_json::Value>) -> String {
        json!({"timestamp": TIMESTAMP, "changes": changes}).to_string()
    }

    /// A real TLS handshake through the transport's connector — the OneCRL
    /// verifier runs on the presented chain.
    async fn handshake(transport: &Transport, port: u16) -> Result<(), crate::Error> {
        connect::connect(
            transport,
            Target {
                host: "localhost",
                port,
                tls: true,
                tunnel_plaintext: false,
                protocols: Protocols::Http1,
            },
        )
        .await
        .map(|_| ())
    }

    /// `true` when the handshake died on `CertificateError::Revoked`.
    fn revoked(result: &Result<(), crate::Error>) -> bool {
        matches!(result, Err(error) if error.to_string().contains("Revoked"))
    }

    /// Retry the handshake until the chain is refused, at most `TEST_TIMEOUT`
    /// — a refresh round lands asynchronously.
    fn wait_for_revoked(transport: &Transport, port: u16) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            let result = async_io::block_on(handshake(transport, port));
            if revoked(&result) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the chain was still accepted after {TEST_TIMEOUT:?}: {result:?}"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    /// A root → intermediate → leaf chain served over TLS, where
    /// `intermediate` is the certificate a changeset record can list.
    struct Fixture {
        /// The TLS server presenting `[leaf, intermediate]`.
        port: u16,
        /// The root the test transport trusts through `extra_root`.
        root: CertificateDer<'static>,
        intermediate: CertificateDer<'static>,
    }

    impl Fixture {
        fn new() -> Self {
            let (root_issuer, root) = root("zenwave test root");
            let (inter_issuer, inter_der) = intermediate("zenwave test intermediate", &root_issuer);
            let (leaf_der, leaf_key) = leaf(&inter_issuer);
            Self {
                port: serve_tls(vec![leaf_der, inter_der.clone()], leaf_key),
                root,
                intermediate: inter_der,
            }
        }
    }

    /// A transport that trusts `root`, proxies nothing, and refreshes hourly
    /// from `changeset`, persisting under `dir`. The interval never matters:
    /// the first round runs as soon as the cache is loaded.
    fn transport(root: &CertificateDer<'static>, changeset: &Changeset, dir: &Path) -> Transport {
        Transport::builder()
            .proxy(Proxy::none())
            .extra_root_certificate_der(root.to_vec())
            .onecrl_refresh(Duration::from_secs(3600))
            .onecrl_refresh_endpoint(&changeset.url, dir.to_path_buf())
            .build()
            .expect("transport builds")
    }

    /// A poll for the persisted additions file — the round stores the merged
    /// map before writing it.
    fn wait_for_file(path: &Path) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "changes.json was not persisted within {TEST_TIMEOUT:?}"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn persisted_file(dir: &Path) -> PathBuf {
        dir.join("zenwave").join("onecrl").join("changes.json")
    }

    /// (a) A chain listed only in a newer changeset verifies against the
    /// compiled baseline, then is refused once the refresh round lands.
    #[test]
    fn a_refreshed_issuer_serial_listing_refuses_the_chain() {
        let fixture = Fixture::new();
        let (release, gate) = mpsc::channel();
        let changeset = serve_changeset(
            changeset_body(vec![issuer_serial_record(&fixture.intermediate)]),
            Some(gate),
        );
        let dir = tempfile::tempdir().expect("cache dir");
        let transport = transport(&fixture.root, &changeset, dir.path());

        // The first round is parked on the gate: the baseline does not list
        // the chain, so it still verifies.
        async_io::block_on(handshake(&transport, fixture.port))
            .expect("the chain verifies before the refresh round lands");

        drop(release);
        wait_for_revoked(&transport, fixture.port);
        wait_for_file(&persisted_file(dir.path()));
    }

    /// (b) A second transport on the same cache directory refuses the chain
    /// from the persisted additions alone — its endpoint answers an empty
    /// changeset.
    #[test]
    fn persisted_additions_refuse_without_new_records() {
        let fixture = Fixture::new();
        let dir = tempfile::tempdir().expect("cache dir");
        let populated = serve_changeset(
            changeset_body(vec![issuer_serial_record(&fixture.intermediate)]),
            None,
        );
        let first = transport(&fixture.root, &populated, dir.path());
        wait_for_revoked(&first, fixture.port);
        wait_for_file(&persisted_file(dir.path()));
        drop(first);

        let empty = serve_changeset(changeset_body(Vec::new()), None);
        let second = transport(&fixture.root, &empty, dir.path());
        wait_for_revoked(&second, fixture.port);
    }

    /// (c) Without `onecrl_refresh` nothing contacts Remote Settings: the
    /// same chain verifies and the changeset server sees no request.
    #[test]
    fn without_refresh_the_endpoint_is_never_contacted() {
        let fixture = Fixture::new();
        let changeset = serve_changeset(
            changeset_body(vec![issuer_serial_record(&fixture.intermediate)]),
            None,
        );
        let dir = tempfile::tempdir().expect("cache dir");
        // The endpoint is pointed at the counting server but no interval is
        // set: `None` must mean no refresher thread at all.
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .extra_root_certificate_der(fixture.root.to_vec())
            .onecrl_refresh_endpoint(&changeset.url, dir.path().to_path_buf())
            .build()
            .expect("transport builds");

        async_io::block_on(handshake(&transport, fixture.port))
            .expect("the chain verifies against the compiled baseline");
        assert_eq!(
            changeset.hits.load(Ordering::SeqCst),
            0,
            "a transport without refresh fetched Remote Settings"
        );
    }

    /// (d) A subject+pubKeyHash addition is refused too.
    #[test]
    fn a_refreshed_subject_key_listing_refuses_the_chain() {
        let fixture = Fixture::new();
        let changeset = serve_changeset(
            changeset_body(vec![subject_key_record(&fixture.intermediate)]),
            None,
        );
        let dir = tempfile::tempdir().expect("cache dir");
        let transport = transport(&fixture.root, &changeset, dir.path());

        wait_for_revoked(&transport, fixture.port);
    }
}
