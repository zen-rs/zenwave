//! The native backend against in-process `http-kit` servers on the same
//! thread: HTTP/1.1 in plaintext and over `http-kit-tls`, through an HTTPS
//! proxy's tunnel, on connections the server closes after each response,
//! and HTTP/3 over `http-kit-h3` once the TLS server advertises it, each on
//! compio and on tokio with the pool on the calling thread.
#![cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "native-compio", feature = "native-tokio")
))]
#![expect(
    clippy::future_not_send,
    reason = "every scenario runs on one thread's local executor, beside the pool it drives"
)]

use std::{
    cell::{Cell, RefCell},
    future::Future,
    net::SocketAddr,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use executor_core::{LocalExecutor, Task as _};
use futures_util::{future::select, pin_mut};
use http_kit::{Body, Request, Response};
use http_kit_io::{BufResult, FromStd, Listen, Listener, Read, Split as _, Write};
use http_kit_tls::TlsAcceptor;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
};
use rustls::{
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use time::{Duration as TimeDelta, OffsetDateTime};
use zenwave::{
    Client as _, ConnectFailure, ConnectPhase, Error, ExchangeFailure, Hop, Proxy, ResolveError,
    ResponseExt as _, TimedOut, TlsFailure, Transport,
    backend::{NativeBackend, NativeIo},
};

/// What the scenarios need of an `http-kit-io` implementation: the native
/// backend's own bounds, and sockets to serve on whose accepted streams a
/// TLS acceptor takes (with kernel TLS that asks more of a stream than
/// being one).
trait TestIo: NativeIo + FromStd + Listen<Listener: Listener<Stream: http_kit_tls::Transport>> {}

impl<I> TestIo for I where
    I: NativeIo + FromStd + Listen<Listener: Listener<Stream: http_kit_tls::Transport>>
{
}

/// A backend on the current thread over `io`, resolving through the system's
/// resolver.
fn backend<I: TestIo, E: LocalExecutor>(
    transport: Transport,
    io: I,
    executor: &E,
) -> NativeBackend {
    #[cfg(feature = "native-http3")]
    let resolver = zenwave::dns::System::new(&transport);
    #[cfg(not(feature = "native-http3"))]
    let resolver = zenwave::dns::Getaddrinfo;
    NativeBackend::on_current_thread(transport, io, resolver, executor)
}

/// A request body in Chinese, Japanese and Korean, echoed back by every
/// server below.
const GREETING: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

/// A throwaway CA and one `localhost` leaf it signed.
struct Pki {
    ca_der: CertificateDer<'static>,
    leaf_der: CertificateDer<'static>,
    #[cfg_attr(not(feature = "native-http3"), expect(dead_code))]
    leaf_pem: String,
    leaf_key: KeyPair,
}

impl Pki {
    fn new() -> Self {
        let now = OffsetDateTime::now_utc();
        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "zenwave native test CA");
        ca.not_before = now - TimeDelta::days(1);
        ca.not_after = now + TimeDelta::days(30);
        let ca_der = ca.self_signed(&ca_key).expect("self-sign CA").der().clone();
        let issuer = Issuer::new(ca, ca_key);

        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf params");
        leaf.distinguished_name
            .push(DnType::CommonName, "localhost");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.not_before = now - TimeDelta::days(1);
        leaf.not_after = now + TimeDelta::days(30);
        let leaf = leaf.signed_by(&leaf_key, &issuer).expect("sign leaf");
        Self {
            ca_der,
            leaf_der: leaf.der().clone(),
            leaf_pem: leaf.pem(),
            leaf_key,
        }
    }

    /// A transport trusting this CA, with no proxy whatever the environment
    /// says.
    fn transport(&self) -> Transport {
        self.transport_through(Proxy::none())
    }

    /// A transport trusting this CA, following `proxy`.
    fn transport_through(&self, proxy: Proxy) -> Transport {
        Transport::builder()
            .proxy(proxy)
            .extra_root_certificate_der(self.ca_der.to_vec())
            .build()
            .expect("transport builds")
    }

    fn tls_acceptor(&self) -> TlsAcceptor {
        let mut config =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("default versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![self.leaf_der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der())),
                )
                .expect("server certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsAcceptor::new(Arc::new(config))
    }
}

/// How [`serve_h1`] serves.
#[derive(Clone, Default)]
struct H1Options {
    /// TLS on every connection.
    tls: Option<TlsAcceptor>,
    /// An `Alt-Svc` field on every response.
    alt_svc: Option<String>,
    /// `Connection: close` on every response.
    close: bool,
    /// How long every connection after the first waits before its TLS
    /// handshake.
    stall_after_first: Option<Duration>,
    /// Counts the connections accepted.
    accepted: Rc<Cell<usize>>,
}

/// Echoes the request body after the method and path, labelled with the
/// protocol that carried it, with the fields `options` asks for.
async fn echo(request: Request, protocol: &'static str, options: &H1Options) -> Response {
    if request.uri().path() == "/trailers" {
        return trailers_response(protocol);
    }
    let head = format!("{} {} ", request.method(), request.uri().path());
    let body = request
        .into_body()
        .into_bytes()
        .await
        .expect("request body reads");
    let mut response = Response::new(Body::from_bytes([head.as_bytes(), body.as_ref()].concat()));
    let headers = response.headers_mut();
    headers.insert("x-protocol", protocol.parse().expect("header value"));
    if let Some(alt_svc) = &options.alt_svc {
        headers.insert(
            http::header::ALT_SVC,
            alt_svc.parse().expect("header value"),
        );
    }
    if options.close {
        headers.insert(http::header::CONNECTION, "close".parse().expect("value"));
    }
    response
}

/// The CJK greeting followed by two trailer fields.
fn trailers_response(protocol: &'static str) -> Response {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-checksum", "abc123".parse().expect("header value"));
    trailers.insert("x-status", "complete".parse().expect("header value"));
    let mut response = Response::new(Body::from_frames(futures_util::stream::iter([
        Ok::<_, std::io::Error>(http_kit::BodyFrame::Data(GREETING.as_bytes().into())),
        Ok(http_kit::BodyFrame::Trailers(trailers)),
    ])));
    response
        .headers_mut()
        .insert("x-protocol", protocol.parse().expect("header value"));
    response
}

/// Serves HTTP/1.1 on `listener` as `options` says, one local task per
/// connection; runs until dropped.
async fn serve_h1<I: TestIo, E: LocalExecutor>(
    io: I,
    executor: &E,
    listener: I::Listener,
    options: H1Options,
) {
    let mut accepted = 0_usize;
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        accepted += 1;
        options.accepted.set(accepted);
        let stall = options.stall_after_first.filter(|_| accepted > 1);
        let io = io.clone();
        let options = options.clone();
        let connection = async move {
            let tls = options.tls.clone();
            let service = move |request: Request| {
                let options = options.clone();
                async move { echo(request, "h1", &options).await }
            };
            let config = http_kit_h1::ServerConfig::default();
            let served = match tls {
                Some(tls) => {
                    if let Some(stall) = stall {
                        io.sleep(stall).await;
                    }
                    let stream = tls.accept(stream, &io).await.expect("TLS handshake");
                    http_kit_h1::ServerConnection::from_stream(stream, io, config)
                        .serve(&service)
                        .await
                        .map(drop)
                }
                None => http_kit_h1::ServerConnection::from_stream(stream, io, config)
                    .serve(&service)
                    .await
                    .map(drop),
            };
            served.expect("connection serves");
        };
        executor.spawn_local(connection).detach();
    }
}

/// An HTTPS proxy: TLS with `tls` on every connection, then one `CONNECT`
/// to a loopback port, recorded in `connects`, and the bytes relayed both
/// ways. Runs until dropped.
async fn serve_tls_proxy<I: TestIo, E: LocalExecutor>(
    io: I,
    executor: &E,
    listener: I::Listener,
    tls: TlsAcceptor,
    connects: Rc<RefCell<Vec<String>>>,
) {
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let io = io.clone();
        let tls = tls.clone();
        let connects = Rc::clone(&connects);
        let tunnel = async move {
            let stream = tls.accept(stream, &io).await.expect("proxy TLS handshake");
            let (mut read, mut write) = stream.split();
            let head = read_head(&mut read).await;
            let authority = head
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("CONNECT "))
                .and_then(|rest| rest.strip_suffix(" HTTP/1.1"))
                .unwrap_or_else(|| panic!("a CONNECT request, got:\n{head}"))
                .to_owned();
            let port = authority
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .expect("the CONNECT target names a port");
            connects.borrow_mut().push(authority);
            let upstream = io
                .connect(SocketAddr::from(([127, 0, 0, 1], port)))
                .await
                .expect("upstream connects");
            let BufResult(answered, _) = write
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec())
                .await;
            answered.expect("the tunnel answer writes");
            let (upstream_read, upstream_write) = upstream.split();
            futures_util::join!(pump(read, upstream_write), pump(upstream_read, write));
        };
        executor.spawn_local(tunnel).detach();
    }
}

/// Reads a request head; the client sends nothing after it before the
/// answer, so nothing past it is read.
async fn read_head(read: &mut impl Read) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let BufResult(filled, chunk) = read.read(Vec::with_capacity(1024)).await;
        assert!(
            filled.expect("the head reads") > 0,
            "the client closed before its head ended"
        );
        head.extend_from_slice(&chunk);
    }
    String::from_utf8(head).expect("an ASCII head")
}

/// Copies `from` into `to` until either side ends.
async fn pump(mut from: impl Read, mut to: impl Write) {
    loop {
        let BufResult(filled, chunk) = from.read(Vec::with_capacity(16 * 1024)).await;
        if !matches!(filled, Ok(1..)) {
            break;
        }
        if to.write_all(chunk).await.0.is_err() {
            break;
        }
    }
    to.shutdown().await.ok();
}

/// Runs `client` while `server` runs beside it; the server is dropped once
/// the client finishes.
async fn against<T>(server: impl Future<Output = ()>, client: impl Future<Output = T>) -> T {
    pin_mut!(server, client);
    match select(client, server).await {
        futures_util::future::Either::Left((done, _)) => done,
        futures_util::future::Either::Right(((), _)) => unreachable!("servers run forever"),
    }
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback address")
}

/// Plaintext HTTP/1.1: a GET and a POST with a CJK body reuse one
/// connection from the thread's pool.
async fn plaintext<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_h1(io.clone(), executor, listener, H1Options::default());
    let transport = Transport::builder()
        .proxy(Proxy::none())
        .build()
        .expect("transport builds");
    let mut client = backend(transport, io, executor);
    against(server, async {
        for _ in 0..2 {
            let response = client
                .post(format!("http://127.0.0.1:{port}/echo"))
                .expect("request builds")
                .bytes_body(GREETING.as_bytes().to_vec())
                .await
                .expect("plaintext POST succeeds");
            assert_eq!(response.headers()["x-protocol"], "h1");
            assert_eq!(
                &*response.into_string().await.expect("body reads"),
                format!("POST /echo {GREETING}")
            );
        }
        let status = client
            .get(format!("http://127.0.0.1:{port}/missing"))
            .expect("request builds")
            .await;
        assert!(
            status.is_ok(),
            "the echo server answers every path: {status:?}"
        );
    })
    .await;
}

/// What the server sends in the same write as its `101` head, before the
/// client speaks the new protocol.
const EARLY: &str = "协议已切换。プロトコルを切り替えました。프로토콜이 전환되었습니다.";
const PING: &str = "乒——ピン——핑";
const PONG: &str = "乓——ポン——퐁";

/// Reads from `read` until `len` bytes have arrived.
async fn read_len(read: &mut impl Read, len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < len {
        let BufResult(filled, chunk) = read.read(Vec::with_capacity(1024)).await;
        assert!(
            filled.expect("the stream reads") > 0,
            "the peer closed early"
        );
        bytes.extend_from_slice(&chunk);
    }
    bytes
}

/// A request that asks to switch protocols gets the `101`, then the
/// switched stream: first the bytes the server wrote right behind its head,
/// then a ping out and a pong back on the same connection.
async fn upgrade<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    switch(io, executor, None).await;
}

/// The switched stream belongs to its owner: a pong that takes three times
/// the transport's read timeout still arrives on it.
async fn upgrade_outlives_read_timeout<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    switch(io, executor, Some(Duration::from_millis(200))).await;
}

/// The upgrade scenario, on a transport with `read_timeout`; the server
/// holds its pong back for three times that long.
async fn switch<I: TestIo, E: LocalExecutor>(io: I, executor: &E, read_timeout: Option<Duration>) {
    use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
    use zenwave::backend::Upgrade;

    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server_io = io.clone();
    let server = async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (mut read, mut write) = stream.split();
        let head = read_head(&mut read).await.to_ascii_lowercase();
        assert!(
            head.contains("upgrade: echo"),
            "the request asks to switch: {head}"
        );
        let mut answer =
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n"
                .to_vec();
        answer.extend_from_slice(EARLY.as_bytes());
        write.write_all(answer).await.0.expect("the 101 writes");
        let ping = read_len(&mut read, PING.len()).await;
        assert_eq!(ping, PING.as_bytes());
        if let Some(read_timeout) = read_timeout {
            server_io.sleep(read_timeout * 3).await;
        }
        write
            .write_all(PONG.as_bytes().to_vec())
            .await
            .0
            .expect("the pong writes");
        futures_util::future::pending::<()>().await;
    };
    let mut transport = Transport::builder().proxy(Proxy::none());
    if let Some(read_timeout) = read_timeout {
        transport = transport.read_timeout(read_timeout);
    }
    let transport = transport.build().expect("transport builds");
    let mut client = backend(transport, io, executor);
    against(server, async {
        let mut response = client
            .get(format!("http://127.0.0.1:{port}/echo"))
            .expect("request builds")
            .header("connection", "upgrade")
            .expect("header")
            .header("upgrade", "echo")
            .expect("header")
            .await
            .expect("the upgrade is answered");
        assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
        let mut switched = Upgrade::on(&mut response)
            .expect("a 101 carries its upgrade")
            .switched()
            .await
            .expect("the switched stream is handed over");

        let mut early = vec![0; EARLY.len()];
        switched.read_exact(&mut early).await.expect("early bytes");
        assert_eq!(early, EARLY.as_bytes());
        switched.write_all(PING.as_bytes()).await.expect("ping");
        switched.flush().await.expect("flush");
        let mut pong = vec![0; PONG.len()];
        switched.read_exact(&mut pong).await.expect("pong");
        assert_eq!(pong, PONG.as_bytes());
    })
    .await;
}

/// A server that closes every connection after its response: the pool
/// never hands a closed connection out again, so each POST, a request no
/// client may send twice once written, goes out on a new one and succeeds.
async fn closing<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_h1(
        io.clone(),
        executor,
        listener,
        H1Options {
            close: true,
            ..H1Options::default()
        },
    );
    let transport = Transport::builder()
        .proxy(Proxy::none())
        .build()
        .expect("transport builds");
    let mut client = backend(transport, io, executor);
    against(server, async {
        for round in 0..10 {
            let response = client
                .post(format!("http://127.0.0.1:{port}/order/{round}"))
                .expect("request builds")
                .bytes_body(GREETING.as_bytes().to_vec())
                .await
                .unwrap_or_else(|error| panic!("POST {round} succeeds: {error}"));
            assert_eq!(
                &*response.into_string().await.expect("body reads"),
                format!("POST /order/{round} {GREETING}")
            );
        }
    })
    .await;
}

/// HTTP/1.1 over `http-kit-tls`, verified against the test CA by the
/// platform verifier.
async fn tls<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let pki = Pki::new();
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_h1(
        io.clone(),
        executor,
        listener,
        H1Options {
            tls: Some(pki.tls_acceptor()),
            ..H1Options::default()
        },
    );
    let mut client = backend(pki.transport(), io.clone(), executor);
    against(server, async {
        let response = client
            // `/安全`, percent-encoded as a URI path carries it.
            .put(format!("https://localhost:{port}/%E5%AE%89%E5%85%A8"))
            .expect("request builds")
            .bytes_body(GREETING.as_bytes().to_vec())
            .await
            .expect("HTTPS PUT succeeds");
        assert_eq!(response.headers()["x-protocol"], "h1");
        assert_eq!(
            &*response.into_string().await.expect("body reads"),
            format!("PUT /%E5%AE%89%E5%85%A8 {GREETING}")
        );
    })
    .await;

    // A server whose certificate no configured root signed is refused.
    let stranger = Pki::new();
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_h1(
        io.clone(),
        executor,
        listener,
        H1Options {
            tls: Some(stranger.tls_acceptor()),
            ..H1Options::default()
        },
    );
    let mut client = backend(pki.transport(), io, executor);
    against(server, async {
        let error = client
            .get(format!("https://localhost:{port}/"))
            .expect("request builds")
            .await
            .expect_err("an untrusted certificate fails the handshake");
        assert!(error.to_string().contains("TLS"), "{error}");
    })
    .await;
}

/// An https origin through an HTTPS proxy: the origin's TLS session runs
/// inside the proxy's, both verified against the test CA, and the tunnel
/// is pooled like any connection.
async fn https_proxy<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let pki = Pki::new();
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let origin = serve_h1(
        io.clone(),
        executor,
        listener,
        H1Options {
            tls: Some(pki.tls_acceptor()),
            ..H1Options::default()
        },
    );
    let proxy_listener = io.bind_tcp(loopback()).expect("bind");
    let proxy_port = proxy_listener.local_addr().expect("local address").port();
    let connects = Rc::new(RefCell::new(Vec::new()));
    let proxy = serve_tls_proxy(
        io.clone(),
        executor,
        proxy_listener,
        pki.tls_acceptor(),
        Rc::clone(&connects),
    );
    let server = async {
        futures_util::join!(origin, proxy);
    };
    let rules = Proxy::builder()
        .https(format!("https://localhost:{proxy_port}"))
        .build();
    let mut client = backend(pki.transport_through(rules), io, executor);
    against(server, async {
        for _ in 0..2 {
            let response = client
                .post(format!("https://localhost:{port}/tunnel"))
                .expect("request builds")
                .bytes_body(GREETING.as_bytes().to_vec())
                .await
                .expect("POST through the HTTPS proxy succeeds");
            assert_eq!(response.headers()["x-protocol"], "h1");
            assert_eq!(
                &*response.into_string().await.expect("body reads"),
                format!("POST /tunnel {GREETING}")
            );
        }
    })
    .await;
    assert_eq!(
        *connects.borrow(),
        [format!("localhost:{port}")],
        "one tunnel carries both requests"
    );
}

/// The read timeout the timeout scenarios run under.
const READ_TIMEOUT: Duration = Duration::from_millis(300);

/// A transport with no proxy, bounded as given.
fn bounded(connect: Option<Duration>, read: Option<Duration>) -> Transport {
    let mut builder = Transport::builder().proxy(Proxy::none());
    if let Some(connect) = connect {
        builder = builder.connect_timeout(connect);
    }
    if let Some(read) = read {
        builder = builder.read_timeout(read);
    }
    builder.build().expect("transport builds")
}

/// What a scripted server writes once it has read a request head: each
/// part after its delay. Then it writes nothing more and holds the
/// connection open.
type Script = Vec<(Duration, Vec<u8>)>;

/// Plays `script` on every connection `listener` accepts, inside TLS with
/// `tls` when given; runs until dropped.
async fn serve_script<I: TestIo, E: LocalExecutor>(
    io: I,
    executor: &E,
    listener: I::Listener,
    tls: Option<TlsAcceptor>,
    script: Script,
) {
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let io = io.clone();
        let tls = tls.clone();
        let script = script.clone();
        let connection = async move {
            match tls {
                Some(tls) => {
                    let stream = tls.accept(stream, &io).await.expect("TLS handshake");
                    play(&io, stream, script).await;
                }
                None => play(&io, stream, script).await,
            }
        };
        executor.spawn_local(connection).detach();
    }
}

async fn play<I: NativeIo, S: http_kit_io::Split>(io: &I, stream: S, script: Script) {
    let (mut read, mut write) = stream.split();
    read_head(&mut read).await;
    for (delay, bytes) in script {
        io.sleep(delay).await;
        write
            .write_all(bytes)
            .await
            .0
            .expect("the scripted bytes write");
    }
    futures_util::future::pending::<()>().await;
}

/// A server that accepts TCP and never answers the TLS handshake: the
/// connect timeout fails the request with `TimedOut::Connect` in the TLS
/// phase, about when it runs out.
async fn stalled_connect<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    // The one dial is accepted and held open, unanswered.
    let server = async move {
        let _held = listener.accept().await.expect("accept");
        futures_util::future::pending::<()>().await;
    };
    let timeout = Duration::from_millis(300);
    let mut client = backend(bounded(Some(timeout), None), io, executor);
    against(server, async {
        let started = Instant::now();
        let error = client
            .get(format!("https://127.0.0.1:{port}/"))
            .expect("request builds")
            .await
            .expect_err("a handshake the server never answers fails");
        let elapsed = started.elapsed();
        assert!(
            matches!(
                error,
                Error::Timeout(TimedOut::Connect {
                    during: ConnectPhase::Tls
                })
            ),
            "a connect timeout in the TLS phase, got {error:?}"
        );
        assert!(
            elapsed >= timeout && elapsed < timeout * 10,
            "the connect timeout bounds the dial: {elapsed:?}"
        );
    })
    .await;
}

/// A server that reads the request and never answers: the read timeout
/// fails the request with `TimedOut::ResponseHead`, in plaintext or over
/// TLS.
async fn stalled_head_on<I: TestIo, E: LocalExecutor>(io: I, executor: &E, pki: Option<&Pki>) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_script(
        io.clone(),
        executor,
        listener,
        pki.map(Pki::tls_acceptor),
        Vec::new(),
    );
    let mut transport = Transport::builder()
        .proxy(Proxy::none())
        .read_timeout(READ_TIMEOUT);
    if let Some(pki) = pki {
        transport = transport.extra_root_certificate_der(pki.ca_der.to_vec());
    }
    let url = if pki.is_some() {
        format!("https://localhost:{port}/")
    } else {
        format!("http://127.0.0.1:{port}/")
    };
    let transport = transport.build().expect("transport builds");
    let mut client = backend(transport, io, executor);
    against(server, async {
        let started = Instant::now();
        let error = client
            .get(url)
            .expect("request builds")
            .await
            .expect_err("a head that never comes fails");
        let elapsed = started.elapsed();
        assert!(
            matches!(error, Error::Timeout(TimedOut::ResponseHead)),
            "a response-head timeout, got {error:?}"
        );
        assert!(
            elapsed >= READ_TIMEOUT && elapsed < READ_TIMEOUT * 10,
            "the read timeout bounds the wait for the head: {elapsed:?}"
        );
    })
    .await;
}

async fn stalled_head<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    stalled_head_on(io, executor, None).await;
}

async fn stalled_head_tls<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    stalled_head_on(io, executor, Some(&Pki::new())).await;
}

/// A server that sends the head and half the body, then stalls: the
/// response arrives, and reading its body fails as a stalled receive, which
/// is `TimedOut::BodyIdle` as a zenwave error.
async fn stalled_body<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let half = GREETING.as_bytes();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
        half.len() * 2
    );
    let server = serve_script(
        io.clone(),
        executor,
        listener,
        None,
        vec![(Duration::ZERO, [head.as_bytes(), half].concat())],
    );
    let mut client = backend(bounded(None, Some(READ_TIMEOUT)), io, executor);
    against(server, async {
        let response = client
            .get(format!("http://127.0.0.1:{port}/"))
            .expect("request builds")
            .await
            .expect("the head arrives");
        let error = response
            .into_body()
            .into_bytes()
            .await
            .expect_err("a body that stalls halfway fails");
        assert!(
            matches!(
                error,
                http_kit::BodyError::Receive(http_kit::ReceiveError::Stalled)
            ),
            "a stalled receive, got {error:?}"
        );
        assert!(
            matches!(Error::from(error), Error::Timeout(TimedOut::BodyIdle)),
            "a body-idle timeout"
        );
    })
    .await;
}

/// A body that arrives in eight parts a third of the read timeout apart,
/// taking well over the read timeout in all: every part restarts the wait,
/// so the whole body arrives.
async fn slow_body<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let body = GREETING.repeat(8).into_bytes();
    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
    let mut script = vec![(Duration::ZERO, head.into_bytes())];
    script.extend(
        body.chunks(body.len().div_ceil(8))
            .map(|part| (READ_TIMEOUT / 3, part.to_vec())),
    );
    let server = serve_script(io.clone(), executor, listener, None, script);
    let mut client = backend(bounded(None, Some(READ_TIMEOUT)), io, executor);
    against(server, async {
        let started = Instant::now();
        let response = client
            .get(format!("http://127.0.0.1:{port}/"))
            .expect("request builds")
            .await
            .expect("the head arrives");
        let received = response.into_body().into_bytes().await.expect("body reads");
        assert_eq!(received.as_ref(), body.as_slice());
        assert!(
            started.elapsed() > READ_TIMEOUT * 2,
            "the body took longer than the read timeout in all"
        );
    })
    .await;
}

/// A resolver that finds no address for any name: every lookup answers
/// that the name does not exist.
#[derive(Clone, Copy)]
struct Unresolvable;

impl http_kit_io::Resolve for Unresolvable {
    fn lookup(&self, _host: &str) -> impl futures_util::Stream<Item = http_kit_io::Answer> {
        futures_util::stream::iter([http_kit_io::Answer::Ranked(Err(
            std::io::ErrorKind::NotFound.into(),
        ))])
    }
}

#[cfg(feature = "native-http3")]
impl zenwave::dns::ResolveHttps for Unresolvable {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait's method is async and this resolver has nothing to await"
    )]
    async fn https_record(
        &self,
        _host: &str,
        _port: u16,
    ) -> Result<Option<zenwave::dns::HttpsRecord>, ResolveError> {
        Ok(None)
    }
}

/// A name the resolver does not know fails the request as a connect failure
/// on the origin, with [`ResolveError::NoAddress`].
async fn unresolved_name<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let mut client =
        NativeBackend::on_current_thread(bounded(None, None), io, Unresolvable, executor);
    let error = client
        .get("http://no-such-host.example:8080/")
        .expect("request builds")
        .await
        .expect_err("a name with no address fails");
    let Error::Connect(connect) = &error else {
        panic!("a connect failure, got {error:?}");
    };
    assert_eq!(connect.hop, Hop::Origin);
    assert_eq!(connect.host, "no-such-host.example");
    assert_eq!(connect.port, 8080);
    assert!(
        matches!(
            connect.failure,
            ConnectFailure::Resolve(ResolveError::NoAddress)
        ),
        "no address, got {:?}",
        connect.failure
    );
}

/// Nothing listens on the port: the one address's attempt is refused, and
/// the failure names the address and keeps the OS's error kind.
async fn refused_connection<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    let mut client = backend(bounded(None, None), io, executor);
    let error = client
        .get(format!("http://127.0.0.1:{port}/"))
        .expect("request builds")
        .await
        .expect_err("a closed port refuses");
    let Error::Connect(connect) = &error else {
        panic!("a connect failure, got {error:?}");
    };
    let ConnectFailure::Tcp(tcp) = &connect.failure else {
        panic!("a TCP failure, got {:?}", connect.failure);
    };
    let [attempt] = tcp.attempts.as_slice() else {
        panic!("one attempt, got {tcp:?}");
    };
    assert_eq!(attempt.addr, Some(SocketAddr::from(([127, 0, 0, 1], port))));
    assert_eq!(attempt.error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(error.is_transient(), "a refusal is worth retrying");
}

/// Accepts TLS connections and ignores how each handshake ends; runs until
/// dropped.
async fn serve_handshakes<I: TestIo, E: LocalExecutor>(
    io: I,
    executor: &E,
    listener: I::Listener,
    tls: TlsAcceptor,
) {
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let io = io.clone();
        let tls = tls.clone();
        let handshake = async move {
            // The client ends these: with an alert, or by hanging up.
            let accepted = tls.accept(stream, &io).await;
            drop(accepted);
        };
        executor.spawn_local(handshake).detach();
    }
}

/// How the client's handshake with a server ends, as the request's error.
async fn handshake_failure<I: TestIo, E: LocalExecutor>(
    io: I,
    executor: &E,
    transport: Transport,
    acceptor: TlsAcceptor,
) -> (Error, Hop) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_handshakes(io.clone(), executor, listener, acceptor);
    let mut client = backend(transport, io, executor);
    let error = against(server, async {
        client
            .get(format!("https://localhost:{port}/"))
            .expect("request builds")
            .await
            .expect_err("the handshake fails")
    })
    .await;
    let Error::Connect(connect) = &error else {
        panic!("a connect failure, got {error:?}");
    };
    let hop = connect.hop;
    (error, hop)
}

/// A certificate the system's roots do not vouch for fails the handshake as
/// [`TlsFailure::Certificate`], with no request sent and no retry worth
/// making.
async fn untrusted_certificate<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let pki = Pki::new();
    let (error, hop) =
        handshake_failure(io, executor, bounded(None, None), pki.tls_acceptor()).await;
    assert_eq!(hop, Hop::Origin);
    let Error::Connect(connect) = &error else {
        unreachable!("checked by handshake_failure");
    };
    assert!(
        matches!(
            &connect.failure,
            ConnectFailure::Tls(tls) if tls.failure == TlsFailure::Certificate
        ),
        "an untrusted certificate, got {:?}",
        connect.failure
    );
    assert!(!error.is_transient(), "retrying cannot make the CA trusted");
}

/// A server that answers the `ClientHello` with a fatal `handshake_failure`
/// alert (RFC 8446 §6.2, description 40) ends the handshake as
/// [`TlsFailure::AlertReceived`] with that description.
async fn received_alert<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    const HANDSHAKE_FAILURE: u8 = 40;
    /// A TLS record (RFC 8446 §5.1: type 21, the legacy version 1.2, a
    /// length of 2) holding a fatal alert.
    const ALERT_RECORD: [u8; 7] = [21, 3, 3, 0, 2, 2, HANDSHAKE_FAILURE];
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = async {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            let connection = async move {
                let (mut read, mut write) = stream.split();
                // The ClientHello is one flight.
                let BufResult(hello, _) = read.read(Vec::with_capacity(4096)).await;
                hello.expect("the ClientHello reads");
                write
                    .write_all(ALERT_RECORD.to_vec())
                    .await
                    .0
                    .expect("the alert writes");
                write.shutdown().await.ok();
            };
            executor.spawn_local(connection).detach();
        }
    };
    let mut client = backend(Pki::new().transport(), io, executor);
    let error = against(server, async {
        client
            .get(format!("https://localhost:{port}/"))
            .expect("request builds")
            .await
            .expect_err("the handshake fails")
    })
    .await;
    let Error::Connect(connect) = &error else {
        panic!("a connect failure, got {error:?}");
    };
    assert!(
        matches!(
            &connect.failure,
            ConnectFailure::Tls(tls)
                if tls.failure == TlsFailure::AlertReceived { alert: HANDSHAKE_FAILURE }
        ),
        "a received alert, got {:?}",
        connect.failure
    );
    assert!(!error.is_transient(), "the server refused the handshake");
}

/// A server that writes `bytes` after reading a request head, then closes.
async fn serve_truncated<I: TestIo, E: LocalExecutor>(
    executor: &E,
    listener: I::Listener,
    bytes: Vec<u8>,
) {
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let bytes = bytes.clone();
        let connection = async move {
            let (mut read, mut write) = stream.split();
            read_head(&mut read).await;
            write
                .write_all(bytes)
                .await
                .0
                .expect("the scripted bytes write");
            write.shutdown().await.ok();
        };
        executor.spawn_local(connection).detach();
    }
}

/// A server that announces twice the body it sends and closes: the response
/// arrives, and reading its body fails as an incomplete receive, which is an
/// [`ExchangeFailure::Incomplete`] exchange failure as a zenwave error.
async fn early_end<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let half = GREETING.as_bytes();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
        half.len() * 2
    );
    let server = serve_truncated::<I, E>(executor, listener, [head.as_bytes(), half].concat());
    let mut client = backend(bounded(None, None), io, executor);
    against(server, async {
        let response = client
            .get(format!("http://127.0.0.1:{port}/"))
            .expect("request builds")
            .await
            .expect("the head arrives");
        let error = response
            .into_body()
            .into_bytes()
            .await
            .expect_err("a body that ends halfway fails");
        assert!(
            matches!(
                error,
                http_kit::BodyError::Receive(http_kit::ReceiveError::Incomplete)
            ),
            "an incomplete receive, got {error:?}"
        );
        let error = Error::from(error);
        assert!(
            matches!(
                &error,
                Error::Exchange(exchange) if exchange.failure == ExchangeFailure::Incomplete
            ),
            "an incomplete exchange, got {error:?}"
        );
        assert!(error.is_transient());
    })
    .await;
}

/// A pooled connection is not waiting for anything: one left idle for
/// three times the read timeout still carries the next request.
async fn idle_outlives_read_timeout<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let accepted = Rc::new(Cell::new(0));
    let server = serve_h1(
        io.clone(),
        executor,
        listener,
        H1Options {
            accepted: Rc::clone(&accepted),
            ..H1Options::default()
        },
    );
    let mut client = backend(bounded(None, Some(READ_TIMEOUT)), io.clone(), executor);
    against(server, async {
        for round in 0..2 {
            if round > 0 {
                io.sleep(READ_TIMEOUT * 3).await;
            }
            let response = client
                .post(format!("http://127.0.0.1:{port}/idle"))
                .expect("request builds")
                .bytes_body(GREETING.as_bytes().to_vec())
                .await
                .unwrap_or_else(|error| panic!("POST {round} succeeds: {error}"));
            assert_eq!(
                &*response.into_string().await.expect("body reads"),
                format!("POST /idle {GREETING}")
            );
        }
    })
    .await;
    assert_eq!(accepted.get(), 1, "the idle connection carried both");
}

/// A response body whose consumer offers a pipe arrives as pipe frames, the
/// bytes of a run still in the kernel; one polled without an offer is plain
/// data on the same pooled connection, which the first body's end released.
#[cfg(target_os = "linux")]
async fn pipe_body<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    use futures_util::future::poll_fn;
    use http_kit::{BodyFrame, PipeOffer};

    let payload = GREETING.repeat(20_000);
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let reply = payload.clone();
    let server = async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (mut read, mut write) = stream.split();
        for _ in 0..2 {
            read_head(&mut read).await;
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", reply.len());
            write
                .write_all(head.into_bytes())
                .await
                .0
                .expect("the head writes");
            write
                .write_all(reply.clone().into_bytes())
                .await
                .0
                .expect("the body writes");
        }
        futures_util::future::pending::<()>().await;
    };
    let mut client = backend(
        Transport::builder()
            .proxy(Proxy::none())
            .build()
            .expect("transport builds"),
        io,
        executor,
    );
    against(server, async {
        let url = format!("http://127.0.0.1:{port}/big");
        let mut body = client
            .get(&url)
            .expect("request builds")
            .await
            .expect("the GET succeeds")
            .into_body();
        let mut offer = PipeOffer::new(64 * 1024);
        let mut received = Vec::new();
        let mut pipes = 0_usize;
        while let Some(frame) =
            poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame_offering(cx, Some(&mut offer)))
                .await
        {
            match frame.expect("the frame reads") {
                BodyFrame::Data(data) => received.extend_from_slice(&data),
                BodyFrame::Pipe(pipe) => {
                    pipes += 1;
                    let (data, _empty) = pipe.read_out().expect("the pipe reads out");
                    received.extend_from_slice(&data);
                }
                frame => panic!("a response body holds no {frame:?}"),
            }
        }
        assert!(pipes > 0, "no run of the body arrived as a pipe frame");
        assert_eq!(received, payload.as_bytes());

        let again = client
            .get(&url)
            .expect("request builds")
            .await
            .expect("the second GET succeeds");
        assert_eq!(&*again.into_string().await.expect("body reads"), payload);
    })
    .await;
}

/// The switched stream of a plain TCP connection splices: the bytes the
/// server wrote behind its `101` head go to the tunnel's other end first,
/// then each direction is forwarded by the kernel until both end.
#[cfg(target_os = "linux")]
async fn splice_upgrade<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
    use http_kit::utils::Bytes;
    use http_kit_io::splice::SpliceDuplex;
    use zenwave::backend::Upgrade;

    let upstream = io.bind_tcp(loopback()).expect("bind");
    let port = upstream.local_addr().expect("local address").port();
    let peer = io.bind_tcp(loopback()).expect("bind");
    let peer_addr = peer.local_addr().expect("local address");
    let server = async move {
        let (stream, _) = upstream.accept().await.expect("accept");
        let (mut read, mut write) = stream.split();
        read_head(&mut read).await;
        let mut answer =
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n"
                .to_vec();
        answer.extend_from_slice(EARLY.as_bytes());
        write.write_all(answer).await.0.expect("the 101 writes");
        assert_eq!(read_len(&mut read, PING.len()).await, PING.as_bytes());
        write
            .write_all(PONG.as_bytes().to_vec())
            .await
            .0
            .expect("the pong writes");
        write.shutdown().await.expect("the server ends its side");
    };
    let far_end = async move {
        let (stream, _) = peer.accept().await.expect("accept");
        let (mut read, mut write) = stream.split();
        assert_eq!(read_len(&mut read, EARLY.len()).await, EARLY.as_bytes());
        write
            .write_all(PING.as_bytes().to_vec())
            .await
            .0
            .expect("the ping writes");
        assert_eq!(read_len(&mut read, PONG.len()).await, PONG.as_bytes());
        write.shutdown().await.expect("the far end ends its side");
    };
    let mut client = backend(
        Transport::builder()
            .proxy(Proxy::none())
            .build()
            .expect("transport builds"),
        io.clone(),
        executor,
    );
    let tunnel = async {
        let mut response = client
            .get(format!("http://127.0.0.1:{port}/echo"))
            .expect("request builds")
            .header("connection", "upgrade")
            .expect("header")
            .header("upgrade", "echo")
            .expect("header")
            .await
            .expect("the upgrade is answered");
        let switched = Upgrade::on(&mut response)
            .expect("a 101 carries its upgrade")
            .switched()
            .await
            .expect("the switched stream is handed over");
        assert!(switched.can_splice());
        let ours = switched.into_splice().expect("a plain socket splices");
        let (read, write) = io.connect(peer_addr).await.expect("connect").split();
        let theirs = SpliceDuplex::new(Bytes::new(), read, write);
        let (forward, backward) = ours.join(theirs).await.expect("the tunnel forwards");
        assert_eq!(forward, (EARLY.len() + PONG.len()) as u64);
        assert_eq!(backward, PING.len() as u64);
    };
    futures_util::join!(server, far_end, tunnel);
}

#[cfg(feature = "native-compio")]
mod compio_runtime {
    use http_kit_io::compio::Compio;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_response_body_arrives_as_pipe_frames() {
        run(super::pipe_body);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_switched_plain_socket_splices() {
        run(super::splice_upgrade);
    }

    fn run(test: impl AsyncFnOnce(Compio, &compio::runtime::Runtime)) {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime");
        runtime.block_on(test(Compio::default(), &runtime));
    }

    #[test]
    fn an_unknown_name_is_a_resolve_failure() {
        run(super::unresolved_name);
    }

    #[test]
    fn a_closed_port_is_a_tcp_failure() {
        run(super::refused_connection);
    }

    #[test]
    fn an_untrusted_certificate_is_a_tls_certificate_failure() {
        run(super::untrusted_certificate);
    }

    #[test]
    fn a_fatal_alert_is_a_received_alert() {
        run(super::received_alert);
    }

    #[test]
    fn a_body_that_ends_early_is_an_incomplete_exchange() {
        run(super::early_end);
    }

    #[test]
    fn connect_timeout_bounds_a_stalled_handshake() {
        run(super::stalled_connect);
    }

    #[test]
    fn read_timeout_bounds_a_stalled_head() {
        run(super::stalled_head);
    }

    #[test]
    fn read_timeout_bounds_a_stalled_head_over_tls() {
        run(super::stalled_head_tls);
    }

    #[test]
    fn read_timeout_bounds_a_stalled_body() {
        run(super::stalled_body);
    }

    #[test]
    fn read_timeout_lets_a_slow_body_through() {
        run(super::slow_body);
    }

    #[test]
    fn read_timeout_spares_idle_connections() {
        run(super::idle_outlives_read_timeout);
    }

    #[test]
    fn read_timeout_spares_the_switched_stream() {
        run(super::upgrade_outlives_read_timeout);
    }

    #[test]
    fn plaintext_h1() {
        run(super::plaintext);
    }

    #[test]
    fn upgrade_hands_over_the_switched_stream() {
        run(super::upgrade);
    }

    #[test]
    fn closing_connections_are_not_reused() {
        run(super::closing);
    }

    #[test]
    fn tls_h1() {
        run(super::tls);
    }

    #[test]
    fn tls_inside_an_https_proxy() {
        run(super::https_proxy);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_after_alt_svc() {
        run(super::h3::upgrade);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_delivers_response_trailers() {
        run(super::h3::trailers);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_wins_the_race_against_a_stalled_tcp_dial() {
        run(super::h3::race);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_refuses_an_untrusted_chain() {
        run(super::h3::untrusted);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_black_hole_falls_back() {
        run(super::h3::black_hole);
    }
}

#[cfg(feature = "native-tokio")]
mod tokio_runtime {
    use http_kit_io::tokio::Tokio;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_response_body_arrives_as_pipe_frames() {
        run(super::pipe_body);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_switched_plain_socket_splices() {
        run(super::splice_upgrade);
    }

    fn run(test: impl AsyncFnOnce(Tokio, &tokio::task::LocalSet)) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, test(Tokio, &local));
    }

    #[test]
    fn an_unknown_name_is_a_resolve_failure() {
        run(super::unresolved_name);
    }

    #[test]
    fn a_closed_port_is_a_tcp_failure() {
        run(super::refused_connection);
    }

    #[test]
    fn an_untrusted_certificate_is_a_tls_certificate_failure() {
        run(super::untrusted_certificate);
    }

    #[test]
    fn a_fatal_alert_is_a_received_alert() {
        run(super::received_alert);
    }

    #[test]
    fn a_body_that_ends_early_is_an_incomplete_exchange() {
        run(super::early_end);
    }

    #[test]
    fn connect_timeout_bounds_a_stalled_handshake() {
        run(super::stalled_connect);
    }

    #[test]
    fn read_timeout_bounds_a_stalled_head() {
        run(super::stalled_head);
    }

    #[test]
    fn read_timeout_bounds_a_stalled_head_over_tls() {
        run(super::stalled_head_tls);
    }

    #[test]
    fn read_timeout_bounds_a_stalled_body() {
        run(super::stalled_body);
    }

    #[test]
    fn read_timeout_lets_a_slow_body_through() {
        run(super::slow_body);
    }

    #[test]
    fn read_timeout_spares_idle_connections() {
        run(super::idle_outlives_read_timeout);
    }

    #[test]
    fn read_timeout_spares_the_switched_stream() {
        run(super::upgrade_outlives_read_timeout);
    }

    #[test]
    fn plaintext_h1() {
        run(super::plaintext);
    }

    #[test]
    fn upgrade_hands_over_the_switched_stream() {
        run(super::upgrade);
    }

    #[test]
    fn closing_connections_are_not_reused() {
        run(super::closing);
    }

    #[test]
    fn tls_h1() {
        run(super::tls);
    }

    #[test]
    fn tls_inside_an_https_proxy() {
        run(super::https_proxy);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_after_alt_svc() {
        run(super::h3::upgrade);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_delivers_response_trailers() {
        run(super::h3::trailers);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_wins_the_race_against_a_stalled_tcp_dial() {
        run(super::h3::race);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_refuses_an_untrusted_chain() {
        run(super::h3::untrusted);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_black_hole_falls_back() {
        run(super::h3::black_hole);
    }
}

#[cfg(feature = "native-http3")]
mod h3 {
    use std::{
        net::{Ipv6Addr, UdpSocket},
        time::Instant,
    };

    use http_kit_io::Datagram;

    use super::*;

    /// Serves HTTP/3 with `pki`'s leaf on a dual-stack UDP socket —
    /// `localhost` may resolve to `::1` first — and returns its port.
    fn bind_h3<I: TestIo>(
        io: &I,
        pki: &Pki,
    ) -> (http_kit_h3::Server<<I as Datagram>::UdpSocket, I>, u16) {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("UDP socket");
        socket.set_only_v6(false).expect("dual stack");
        socket
            .bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into())
            .expect("UDP binds");
        let socket: UdpSocket = socket.into();
        let port = socket.local_addr().expect("local address").port();
        let identity =
            http_kit_h3::Identity::from_pem(pki.leaf_pem.clone(), pki.leaf_key.serialize_pem());
        let config = http_kit_h3::ServerConfig::new(identity, 64 * 1024);
        let server = http_kit_h3::Server::new(
            io.udp_socket(socket).expect("adopt UDP socket"),
            io.clone(),
            &config,
        )
        .expect("h3 server");
        (server, port)
    }

    /// A TLS HTTP/1.1 server signed by `pki` advertising an HTTP/3 server
    /// signed by `h3_pki`, both running until dropped, and the TCP port.
    fn advertised<'a, I: TestIo, E: LocalExecutor>(
        io: &I,
        executor: &'a E,
        pki: &Pki,
        h3_pki: &Pki,
        stall_after_first: Option<Duration>,
    ) -> (impl Future<Output = ()> + 'a, u16) {
        let (h3_server, h3_port) = bind_h3(io, h3_pki);
        let listener = io.bind_tcp(loopback()).expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let h1 = serve_h1(
            io.clone(),
            executor,
            listener,
            H1Options {
                tls: Some(pki.tls_acceptor()),
                alt_svc: Some(format!("h3=\":{h3_port}\"; ma=60")),
                stall_after_first,
                ..H1Options::default()
            },
        );
        let h3 = async move {
            let options = H1Options::default();
            let service = |request: Request| echo(request, "h3", &options);
            h3_server.serve(&service).await.expect("h3 server runs");
        };
        let server = async {
            futures_util::join!(h1, h3);
        };
        (server, port)
    }

    /// GETs `uri` and returns the protocol that carried it. With `keep`
    /// off the body is left unread, so the connection is not pooled and
    /// the next request dials.
    async fn get(client: &mut NativeBackend, uri: &str, keep: bool) -> String {
        let response = client
            .get(uri)
            .expect("request builds")
            .await
            .expect("GET succeeds over either protocol");
        let protocol = response.headers()["x-protocol"]
            .to_str()
            .expect("ASCII")
            .to_owned();
        if keep {
            response.into_string().await.expect("body reads");
        }
        protocol
    }

    /// `Alt-Svc` names a UDP port that swallows every datagram. The request
    /// that races the QUIC dial finds TCP first, and no request waits for
    /// the QUIC connect timeout: QUIC only ever runs beside TCP.
    pub async fn black_hole<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
        let pki = Pki::new();
        let hole = UdpSocket::bind("[::]:0").expect("UDP binds");
        let hole_port = hole.local_addr().expect("local address").port();
        let listener = io.bind_tcp(loopback()).expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let server = serve_h1(
            io.clone(),
            executor,
            listener,
            H1Options {
                tls: Some(pki.tls_acceptor()),
                alt_svc: Some(format!("h3=\":{hole_port}\"; ma=60")),
                ..H1Options::default()
            },
        );
        let mut client = backend(pki.transport(), io.clone(), executor);
        against(server, async {
            let uri = format!("https://localhost:{port}/fallback");
            let started = Instant::now();
            // The first request learns the advertisement and leaves no idle
            // connection, so the second races a TCP dial against QUIC.
            assert_eq!(get(&mut client, &uri, false).await, "h1");
            for _ in 0..3 {
                assert_eq!(get(&mut client, &uri, true).await, "h1");
                io.sleep(Duration::from_millis(200)).await;
            }
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_secs(4),
                "no request waits on the black-holed QUIC dial: {elapsed:?}"
            );
        })
        .await;
        drop(hole);
    }

    /// The TLS server advertises the h3 one through `Alt-Svc`; requests
    /// move to HTTP/3 once the pool's QUIC dial completes its handshake,
    /// a POST with a CJK body among them.
    pub async fn upgrade<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
        let pki = Pki::new();
        let (server, port) = advertised(&io, executor, &pki, &pki, None);
        let mut client = backend(pki.transport(), io.clone(), executor);
        against(server, async {
            let uri = format!("https://localhost:{port}/upgrade");
            let mut protocol = String::new();
            for _ in 0..50 {
                protocol = get(&mut client, &uri, true).await;
                if protocol == "h3" {
                    break;
                }
                io.sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(protocol, "h3", "the advertised h3 endpoint takes over");

            let response = client
                .post(&uri)
                .expect("request builds")
                .bytes_body(GREETING.as_bytes().to_vec())
                .await
                .expect("POST over HTTP/3 succeeds");
            assert_eq!(response.headers()["x-protocol"], "h3");
            assert_eq!(
                &*response.into_string().await.expect("body reads"),
                format!("POST /upgrade {GREETING}")
            );
        })
        .await;
    }

    /// A response over HTTP/3 delivers its trailers after the body, the
    /// CJK body intact.
    pub async fn trailers<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
        use futures_util::StreamExt as _;

        let pki = Pki::new();
        let (server, port) = advertised(&io, executor, &pki, &pki, None);
        let mut client = backend(pki.transport(), io.clone(), executor);
        against(server, async {
            let uri = format!("https://localhost:{port}/upgrade");
            let mut protocol = String::new();
            for _ in 0..50 {
                protocol = get(&mut client, &uri, true).await;
                if protocol == "h3" {
                    break;
                }
                io.sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(protocol, "h3", "the advertised h3 endpoint takes over");

            let response = client
                .get(format!("https://localhost:{port}/trailers"))
                .expect("request builds")
                .await
                .expect("GET succeeds over HTTP/3");
            assert_eq!(response.headers()["x-protocol"], "h3");
            let mut data = Vec::new();
            let mut trailers = None;
            let mut body = response.into_body();
            while let Some(frame) = body.next().await {
                match frame.expect("frame is valid") {
                    http_kit::BodyFrame::Data(chunk) => data.extend_from_slice(&chunk),
                    http_kit::BodyFrame::Trailers(map) => trailers = Some(map),
                    _ => unreachable!("no file frames"),
                }
            }
            assert_eq!(std::str::from_utf8(&data).expect("UTF-8"), GREETING);
            let trailers = trailers.expect("the trailers frame arrives");
            assert_eq!(trailers["x-checksum"], "abc123");
            assert_eq!(trailers["x-status"], "complete");
        })
        .await;
    }

    /// Once h3 is advertised, a request with no connection to reuse races
    /// a QUIC dial against a TCP dial whose server stalls: the QUIC
    /// handshake completes first and carries the request.
    pub async fn race<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
        const STALL: Duration = Duration::from_secs(3);
        let pki = Pki::new();
        let (server, port) = advertised(&io, executor, &pki, &pki, Some(STALL));
        let mut client = backend(pki.transport(), io.clone(), executor);
        against(server, async {
            let uri = format!("https://localhost:{port}/race");
            assert_eq!(get(&mut client, &uri, false).await, "h1");
            let started = Instant::now();
            assert_eq!(get(&mut client, &uri, true).await, "h3");
            let elapsed = started.elapsed();
            assert!(
                elapsed < STALL,
                "QUIC wins without waiting on the stalled TCP dial: {elapsed:?}"
            );
        })
        .await;
    }

    /// The advertised HTTP/3 server presents a chain no configured root
    /// signed: the transport's verifier refuses it, QUIC backs off, and
    /// every request stays on TCP, the one that raced QUIC included.
    pub async fn untrusted<I: TestIo, E: LocalExecutor>(io: I, executor: &E) {
        let pki = Pki::new();
        let stranger = Pki::new();
        let (server, port) = advertised(&io, executor, &pki, &stranger, None);
        let mut client = backend(pki.transport(), io.clone(), executor);
        against(server, async {
            let uri = format!("https://localhost:{port}/untrusted");
            assert_eq!(get(&mut client, &uri, false).await, "h1");
            for _ in 0..5 {
                assert_eq!(get(&mut client, &uri, true).await, "h1");
                io.sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
    }
}
