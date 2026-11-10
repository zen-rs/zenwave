//! The native backend against in-process `http-kit` servers on the same
//! thread: HTTP/1.1 in plaintext, HTTP/1.1 over `http-kit-tls`, and HTTP/3
//! over `http-kit-h3` once the TLS server advertises it, each on compio and
//! on tokio with the pool on the calling thread.
#![cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "native-compio", feature = "native-tokio")
))]
#![expect(
    clippy::future_not_send,
    reason = "every scenario runs on one thread's local executor, beside the pool it drives"
)]

use std::{future::Future, net::SocketAddr, sync::Arc};

use executor_core::{LocalExecutor, Task as _};
use futures_util::{future::select, pin_mut};
use http_kit::{Body, Request, Response};
use http_kit_io::Listener as _;
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
    Client as _, Proxy, ResponseExt as _, Transport,
    backend::{NativeBackend, NativeIo},
};

/// A request body in Chinese, Japanese and Korean, echoed back by every
/// server below.
const GREETING: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

/// A throwaway CA and one `localhost` leaf it signed.
struct Pki {
    ca_der: CertificateDer<'static>,
    leaf_der: CertificateDer<'static>,
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
        let leaf_der = leaf
            .signed_by(&leaf_key, &issuer)
            .expect("sign leaf")
            .der()
            .clone();
        Self {
            ca_der,
            leaf_der,
            leaf_key,
        }
    }

    /// A transport trusting this CA, with no proxy whatever the environment
    /// says.
    fn transport(&self) -> Transport {
        Transport::builder()
            .proxy(Proxy::none())
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

/// Echoes the request body after the method and path, labelled with the
/// protocol that carried it, and advertises `alt_svc` when given.
async fn echo(request: Request, protocol: &'static str, alt_svc: Option<String>) -> Response {
    let head = format!("{} {} ", request.method(), request.uri().path());
    let body = request
        .into_body()
        .into_bytes()
        .await
        .expect("request body reads");
    let mut response = Response::new(Body::from_bytes([head.as_bytes(), body.as_ref()].concat()));
    response
        .headers_mut()
        .insert("x-protocol", protocol.parse().expect("header value"));
    if let Some(alt_svc) = alt_svc {
        response.headers_mut().insert(
            http::header::ALT_SVC,
            alt_svc.parse().expect("header value"),
        );
    }
    response
}

/// Serves HTTP/1.1 on `listener`, over TLS when `tls` is given, one local
/// task per connection; runs until dropped.
async fn serve_h1<I: NativeIo, E: LocalExecutor>(
    io: I,
    executor: &E,
    listener: I::TcpListener,
    tls: Option<TlsAcceptor>,
    alt_svc: Option<String>,
) {
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let io = io.clone();
        let tls = tls.clone();
        let alt_svc = alt_svc.clone();
        let connection = async move {
            let service = move |request: Request| echo(request, "h1", alt_svc.clone());
            let config = http_kit_h1::ServerConfig::default();
            let served = match tls {
                Some(tls) => {
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
async fn plaintext<I: NativeIo, E: LocalExecutor>(io: I, executor: &E) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_h1(io.clone(), executor, listener, None, None);
    let transport = Transport::builder()
        .proxy(Proxy::none())
        .build()
        .expect("transport builds");
    let mut client = NativeBackend::on_current_thread(transport, io, executor);
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

/// HTTP/1.1 over `http-kit-tls`, verified against the test CA by the
/// platform verifier.
async fn tls<I: NativeIo, E: LocalExecutor>(io: I, executor: &E) {
    let pki = Pki::new();
    let listener = io.bind_tcp(loopback()).expect("bind");
    let port = listener.local_addr().expect("local address").port();
    let server = serve_h1(
        io.clone(),
        executor,
        listener,
        Some(pki.tls_acceptor()),
        None,
    );
    let mut client = NativeBackend::on_current_thread(pki.transport(), io.clone(), executor);
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
        Some(stranger.tls_acceptor()),
        None,
    );
    let mut client = NativeBackend::on_current_thread(pki.transport(), io, executor);
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

#[cfg(feature = "native-compio")]
mod compio_runtime {
    use http_kit_io::compio::Compio;

    fn run(test: impl AsyncFnOnce(Compio, &compio::runtime::Runtime)) {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime");
        runtime.block_on(test(Compio, &runtime));
    }

    #[test]
    fn plaintext_h1() {
        run(super::plaintext);
    }

    #[test]
    fn tls_h1() {
        run(super::tls);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_after_alt_svc() {
        run(super::h3::upgrade);
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

    fn run(test: impl AsyncFnOnce(Tokio, &tokio::task::LocalSet)) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, test(Tokio, &local));
    }

    #[test]
    fn plaintext_h1() {
        run(super::plaintext);
    }

    #[test]
    fn tls_h1() {
        run(super::tls);
    }

    #[cfg(feature = "native-http3")]
    #[test]
    fn h3_after_alt_svc() {
        run(super::h3::upgrade);
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
        time::Duration,
    };

    use http_kit_io::Io;

    use super::*;

    /// Serves HTTP/3 on a dual-stack UDP socket — `localhost` may resolve
    /// to `::1` first — and returns its port.
    fn bind_h3<I: Io>(io: &I, pki: &Pki) -> (http_kit_h3::Server<I::UdpSocket, I>, u16) {
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
        let identity = http_kit_h3::Identity::from_pem(
            pem::encode(&pem::Pem::new("CERTIFICATE", pki.leaf_der.to_vec())),
            pki.leaf_key.serialize_pem(),
        );
        let config = http_kit_h3::ServerConfig::new(identity, 64 * 1024);
        let server = http_kit_h3::Server::new(
            io.udp_socket(socket).expect("adopt UDP socket"),
            io.clone(),
            &config,
        )
        .expect("h3 server");
        (server, port)
    }

    /// `Alt-Svc` names a UDP port that swallows every datagram: the request
    /// that tries the unproven connection is abandoned at the connect
    /// timeout and goes over TCP, and later ones stay there.
    pub async fn black_hole<I: NativeIo, E: LocalExecutor>(io: I, executor: &E) {
        let pki = Pki::new();
        let hole = UdpSocket::bind("[::]:0").expect("UDP binds");
        let hole_port = hole.local_addr().expect("local address").port();
        let listener = io.bind_tcp(loopback()).expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let server = serve_h1(
            io.clone(),
            executor,
            listener,
            Some(pki.tls_acceptor()),
            Some(format!("h3=\":{hole_port}\"; ma=60")),
        );
        let mut client = NativeBackend::on_current_thread(pki.transport(), io.clone(), executor);
        against(server, async {
            let uri = format!("https://localhost:{port}/fallback");
            let started = std::time::Instant::now();
            for _ in 0..3 {
                let response = client
                    .get(&uri)
                    .expect("request builds")
                    .await
                    .expect("GET succeeds over TCP");
                assert_eq!(response.headers()["x-protocol"], "h1");
                // Room for the pool to dial the advertised endpoint, so the
                // next request meets the unproven connection.
                io.sleep(Duration::from_millis(200)).await;
            }
            let elapsed = started.elapsed();
            assert!(
                elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(9),
                "exactly one request waits out the connect timeout: {elapsed:?}"
            );
        })
        .await;
        drop(hole);
    }

    /// The TLS server advertises the h3 one through `Alt-Svc`; requests
    /// move to HTTP/3 once the pool has dialed it, an idempotent one first
    /// while the connection is unproven, then a POST with a CJK body.
    pub async fn upgrade<I: NativeIo, E: LocalExecutor>(io: I, executor: &E) {
        let pki = Pki::new();
        let (h3_server, h3_port) = bind_h3(&io, &pki);
        let listener = io.bind_tcp(loopback()).expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let h1 = serve_h1(
            io.clone(),
            executor,
            listener,
            Some(pki.tls_acceptor()),
            Some(format!("h3=\":{h3_port}\"; ma=60")),
        );
        let h3 = async {
            let service = |request: Request| echo(request, "h3", None);
            h3_server.serve(&service).await.expect("h3 server runs");
        };
        let server = async {
            futures_util::join!(h1, h3);
        };
        let mut client = NativeBackend::on_current_thread(pki.transport(), io.clone(), executor);
        against(server, async {
            let uri = format!("https://localhost:{port}/upgrade");
            let mut protocol = String::new();
            for _ in 0..50 {
                let response = client
                    .get(&uri)
                    .expect("request builds")
                    .await
                    .expect("GET succeeds over either protocol");
                protocol = response.headers()["x-protocol"]
                    .to_str()
                    .expect("ASCII")
                    .to_owned();
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
                .expect("POST over the proven h3 connection succeeds");
            assert_eq!(response.headers()["x-protocol"], "h3");
            assert_eq!(
                &*response.into_string().await.expect("body reads"),
                format!("POST /upgrade {GREETING}")
            );
        })
        .await;
    }
}
