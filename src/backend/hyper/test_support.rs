//! Fixtures shared by the hyper backend's test modules: a throwaway CA, the
//! TLS TCP server, the QUIC/h3 server, and a thread-per-future spawner.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

#[cfg(any(feature = "http2", http3))]
use async_net::TcpListener;
#[cfg(http3)]
use bytes::Buf;
#[cfg(http3)]
use futures_channel::oneshot;
#[cfg(any(feature = "http2", http3))]
use futures_rustls::TlsAcceptor;
#[cfg(feature = "http2")]
use http::{Version, header::HOST};
#[cfg(any(feature = "http2", http3))]
use http_body_util::{BodyExt, Full};
#[cfg(any(feature = "http2", http3))]
use hyper::body::Bytes;
#[cfg(any(feature = "http2", http3))]
use hyper::{body::Incoming, service::service_fn};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
#[cfg(http3)]
use std::net::UdpSocket;
#[cfg(feature = "http2")]
use std::sync::mpsc;
use time::{Duration as TimeDelta, OffsetDateTime};

#[cfg(http3)]
use super::h3::H3Connection;
#[cfg(any(feature = "http2", http3))]
use super::rt::Spawner;
use crate::Transport;
#[cfg(any(feature = "http2", http3))]
use crate::transport::hyper_io::HyperIo;
#[cfg(http3)]
use crate::transport::{
    Spawn,
    quic::{self, AsyncIoRuntime},
};

/// How long a test waits for a server-side observation.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Spawn each future on its own thread running `async_io::block_on`,
/// mirroring `HyperBackend`'s fallback when no executor is supplied.
#[cfg(http3)]
pub fn thread_spawn() -> Spawn {
    Arc::new(|future| {
        thread::spawn(move || {
            async_io::block_on(future);
        });
    })
}

/// Run `future` to completion inside the test timeout.
#[cfg(http3)]
pub fn block_on_test<F: std::future::Future>(future: F) -> F::Output {
    async_io::block_on(async {
        let future = std::pin::pin!(future);
        let timeout = std::pin::pin!(async_io::Timer::after(TEST_TIMEOUT));
        match futures_util::future::select(future, timeout).await {
            futures_util::future::Either::Left((output, _)) => output,
            futures_util::future::Either::Right(_) => {
                panic!("test timed out after {TEST_TIMEOUT:?}")
            }
        }
    })
}

/// Poll `ready` every 10 ms until it holds — a wait on a real event (a
/// detached task landing its result in the pool), not a fixed sleep.
#[cfg(http3)]
pub async fn wait_until(ready: impl Fn() -> bool) {
    for _ in 0..(TEST_TIMEOUT.as_millis() / 10) {
        if ready() {
            return;
        }
        async_io::Timer::after(Duration::from_millis(10)).await;
    }
    panic!("the awaited condition did not arrive within {TEST_TIMEOUT:?}");
}

/// A throwaway certificate authority signing `localhost` leaves: the leaf
/// serves a test server and `ca_der` goes to the client through
/// `extra_root_certificate_der`.
pub struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    /// This CA's certificate, for `TransportBuilder::extra_root_certificate_der`.
    pub(crate) ca_der: CertificateDer<'static>,
}

impl TestCa {
    pub(crate) fn new() -> Self {
        let now = OffsetDateTime::now_utc();
        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "zenwave test CA");
        ca_params.not_before = now - TimeDelta::days(1);
        ca_params.not_after = now + TimeDelta::days(365);
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        Self {
            issuer: Issuer::new(ca_params, ca_key),
            ca_der: ca_cert.der().clone(),
        }
    }

    /// A freshly generated leaf for `localhost`/`127.0.0.1` signed by this CA.
    pub(crate) fn leaf(&self) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let now = OffsetDateTime::now_utc();
        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.not_before = now - TimeDelta::days(1);
        leaf_params.not_after = now + TimeDelta::days(365);
        let leaf = leaf_params
            .signed_by(&leaf_key, &self.issuer)
            .expect("sign leaf certificate");
        (
            leaf.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
    }

    /// A transport that trusts this CA and proxies nothing — an ambient
    /// `HTTPS_PROXY` must not turn a loopback request into a proxied one.
    pub(crate) fn transport(&self) -> Transport {
        Transport::builder()
            .proxy(crate::Proxy::none())
            .extra_root_certificate_der(self.ca_der.to_vec())
            .build()
            .expect("test transport must build")
    }
}

/// What a [`TlsServer`] observed on one request.
#[cfg(feature = "http2")]
#[derive(Debug)]
pub struct Observed {
    /// The HTTP version the request arrived over.
    pub(crate) version: Version,
    /// The `:authority` the request carried, for h2.
    pub(crate) authority: Option<String>,
    /// The `Host` header, for h1.
    pub(crate) host: Option<String>,
    /// The request body.
    pub(crate) body: Vec<u8>,
}

/// A TLS server that speaks h2 or h1 depending on the negotiated ALPN and
/// reports every request it sees.
#[cfg(any(feature = "http2", http3))]
pub struct TlsServer {
    address: SocketAddr,
    #[cfg(feature = "http2")]
    accepts: Arc<AtomicUsize>,
    #[cfg(feature = "http2")]
    observed: mpsc::Receiver<Observed>,
}

#[cfg(any(feature = "http2", http3))]
impl TlsServer {
    /// Start a server offering `alpn_protocols`, in preference order.
    #[cfg(feature = "http2")]
    pub(crate) fn start(ca: &TestCa, alpn_protocols: &[&[u8]]) -> Self {
        Self::serve(ca, alpn_protocols, Vec::new(), Duration::ZERO)
    }

    /// Start a server that emits each `alt_svc` value as its own `Alt-Svc`
    /// header field on every response, and stalls each TLS handshake by
    /// `handshake_delay` — enough for a racing QUIC dial to the same origin
    /// to win deterministically on loopback.
    pub(crate) fn serve(
        ca: &TestCa,
        alpn_protocols: &[&[u8]],
        alt_svc: Vec<String>,
        handshake_delay: Duration,
    ) -> Self {
        let (leaf, key) = ca.leaf();
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("server certificate");
        config.alpn_protocols = alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (listener, address) = async_io::block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("test listener must bind");
            let address = listener.local_addr().expect("test address must exist");
            (listener, address)
        });
        #[cfg(feature = "http2")]
        let (observed_tx, observed) = mpsc::channel();
        #[cfg(feature = "http2")]
        let accepts = Arc::new(AtomicUsize::new(0));
        #[cfg(feature = "http2")]
        let accept_count = accepts.clone();
        thread::spawn(move || {
            async_io::block_on(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    #[cfg(feature = "http2")]
                    accept_count.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    #[cfg(feature = "http2")]
                    let observed_tx = observed_tx.clone();
                    let alt_svc = alt_svc.clone();
                    thread::spawn(move || {
                        async_io::block_on(serve_tls(
                            acceptor,
                            tcp,
                            #[cfg(feature = "http2")]
                            observed_tx,
                            alt_svc,
                            handshake_delay,
                        ));
                    });
                }
            });
        });
        Self {
            address,
            #[cfg(feature = "http2")]
            accepts,
            #[cfg(feature = "http2")]
            observed,
        }
    }

    /// The address the server listens on.
    pub(crate) const fn addr(&self) -> SocketAddr {
        self.address
    }

    /// How many TCP connections the server has accepted.
    #[cfg(feature = "http2")]
    pub(crate) fn accept_count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// A `https://localhost:<port>` URI for `path`.
    pub(crate) fn uri(&self, path: &str) -> String {
        format!("https://localhost:{}{}", self.address.port(), path)
    }

    /// The next request the server saw.
    #[cfg(feature = "http2")]
    pub(crate) fn next_request(&self) -> Observed {
        self.observed
            .recv_timeout(TEST_TIMEOUT)
            .expect("server must see the request")
    }
}

/// Accept TLS on `tcp` — after `handshake_delay`, so a racing QUIC dial can
/// win — and serve every request on the connection with the HTTP version
/// ALPN negotiated. Each `alt_svc` value goes out as its own header field on
/// every response.
#[cfg(any(feature = "http2", http3))]
async fn serve_tls(
    acceptor: TlsAcceptor,
    tcp: async_net::TcpStream,
    #[cfg(feature = "http2")] observed: mpsc::Sender<Observed>,
    alt_svc: Vec<String>,
    handshake_delay: Duration,
) {
    if !handshake_delay.is_zero() {
        async_io::Timer::after(handshake_delay).await;
    }
    let Ok(tls) = acceptor.accept(tcp).await else {
        return;
    };
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        #[cfg(feature = "http2")]
        let observed = observed.clone();
        let alt_svc = alt_svc.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = body
                .collect()
                .await
                .expect("request body must be readable")
                .to_bytes()
                .to_vec();
            #[cfg(feature = "http2")]
            observed
                .send(Observed {
                    version: parts.version,
                    authority: parts
                        .uri
                        .authority()
                        .map(|authority| authority.as_str().to_owned()),
                    host: parts
                        .headers
                        .get(HOST)
                        .map(|value| value.to_str().expect("Host is ASCII").to_owned()),
                    body,
                })
                .expect("observed channel must be open");
            // Nothing observes the request under http3-only builds, but the
            // body still has to be drained for the connection to stay
            // reusable.
            #[cfg(not(feature = "http2"))]
            drop((parts, body));
            let mut response = hyper::Response::new(Full::new(Bytes::from_static(b"zenwave")));
            for value in &alt_svc {
                response.headers_mut().append(
                    http::header::ALT_SVC,
                    http::header::HeaderValue::from_str(value)
                        .expect("Alt-Svc test value must be a header value"),
                );
            }
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let io = HyperIo(tls);
    let _ = match negotiated.as_deref() {
        Some(b"h2") => {
            hyper::server::conn::http2::Builder::new(Spawner::new(None))
                .serve_connection(io, service)
                .await
        }
        _ => {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
        }
    };
}

#[cfg(http3)]
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// A QUIC/h3 server on its own UDP socket. Every response carries
/// `x-zenwave-protocol: h3` so a client can prove which transport answered.
#[cfg(http3)]
pub struct H3Server {
    addr: SocketAddr,
    ca_der: CertificateDer<'static>,
    /// QUIC connections the server accepted; h3 multiplexes, so one pooled
    /// `H3Connection` must produce exactly one.
    connection_count: Arc<AtomicUsize>,
    /// Requests the server has answered.
    served: Arc<AtomicUsize>,
    /// The server endpoint; `close` ends every connection on it.
    endpoint: quinn::Endpoint,
    /// Releases the second `/slow` response chunk.
    pub(crate) release_slow: oneshot::Sender<()>,
}

#[cfg(http3)]
impl H3Server {
    /// Start an h3 server with a leaf certificate signed by `ca`.
    pub(crate) fn start(ca: &TestCa) -> Self {
        let (leaf_der, key) = ca.leaf();
        let mut tls =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 is supported")
                .with_no_client_auth()
                .with_single_cert(vec![leaf_der], key)
                .expect("server certificate is valid");
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC server config");
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));

        // Dual-stack like the client's endpoint: `localhost` resolves to ::1
        // first on most systems, and an IPv4-only socket would never see the
        // racer's datagrams.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("UDP socket");
        socket.set_only_v6(false).expect("dual stack");
        socket
            .bind(&SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0).into())
            .expect("UDP socket binds");
        let socket: UdpSocket = socket.into();
        let addr = socket.local_addr().expect("local address");
        let spawn = thread_spawn();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(AsyncIoRuntime {
                spawn: spawn.clone(),
            }),
        )
        .expect("server endpoint binds");

        let connection_count = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(AtomicUsize::new(0));
        let (release_slow, slow_rx) = oneshot::channel();
        thread::spawn({
            let connection_count = connection_count.clone();
            let served = served.clone();
            let spawn = spawn.clone();
            let endpoint = endpoint.clone();
            move || {
                async_io::block_on(async move {
                    let mut slow_rx = Some(slow_rx);
                    while let Some(incoming) = endpoint.accept().await {
                        connection_count.fetch_add(1, Ordering::SeqCst);
                        (spawn)(Box::pin(serve_h3_connection(
                            incoming,
                            spawn.clone(),
                            served.clone(),
                            slow_rx.take(),
                        )));
                    }
                });
            }
        });

        Self {
            addr,
            ca_der: ca.ca_der.clone(),
            connection_count,
            served,
            endpoint,
            release_slow,
        }
    }

    /// The UDP address clients dial: the socket is bound dual-stack on
    /// `[::]`, which is not itself a valid remote, so report `::1`.
    pub(crate) fn addr(&self) -> SocketAddr {
        SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), self.addr.port())
    }

    /// How many QUIC connections the server accepted.
    pub(crate) fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::SeqCst)
    }

    /// How many requests the server has answered.
    pub(crate) fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    /// Close the endpoint and every connection on it.
    pub(crate) fn close(&self) {
        self.endpoint.close(0u32.into(), b"gone");
    }

    /// A `https://localhost:<port>` URI for `path`.
    pub(crate) fn uri(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.addr.port())
    }
}

/// A client h3 connection to `server`, over a transport trusting its CA.
/// The returned `Transport` owns the shared QUIC endpoint and must outlive
/// the connection.
#[cfg(http3)]
pub async fn h3_connection(server: &H3Server) -> (Transport, H3Connection) {
    let transport = Transport::builder()
        .extra_root_certificate_der(server.ca_der.to_vec())
        .build()
        .expect("transport builds");
    let spawn = thread_spawn();
    let endpoint = transport
        .quic_endpoint(spawn.clone())
        .expect("client endpoint binds");
    let config = quic::client_config(transport.tls().client_config()).expect("QUIC client config");
    let connection = H3Connection::connect(endpoint, config, server.addr(), "localhost", &spawn)
        .await
        .expect("h3 connection is established");
    (transport, connection)
}

#[cfg(http3)]
async fn serve_h3_connection(
    incoming: quinn::Incoming,
    spawn: Spawn,
    served: Arc<AtomicUsize>,
    mut slow_release: Option<oneshot::Receiver<()>>,
) {
    let connection = incoming.await.expect("QUIC handshake completes");
    let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
        .await
        .expect("h3 handshake completes");
    // `Ok(None)` is a graceful close and an error means the client went
    // away — either ends the connection.
    while let Ok(Some(resolver)) = h3.accept().await {
        let release = slow_release.take();
        let served = served.clone();
        (spawn)(Box::pin(serve_h3_request(resolver, release, served)));
    }
}

#[cfg(http3)]
async fn serve_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    slow_release: Option<oneshot::Receiver<()>>,
    served: Arc<AtomicUsize>,
) {
    let (request, mut stream) = resolver.resolve_request().await.expect("request resolves");
    let result = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/hello") => serve_body(&mut stream, Bytes::from_static(b"hello over h3")).await,
        ("POST", "/echo") => serve_echo(&mut stream).await,
        ("GET", "/slow") => {
            serve_slow(&mut stream, slow_release.expect("one /slow per test")).await
        }
        _ => serve_status(&mut stream, http::StatusCode::NOT_FOUND).await,
    };
    result.expect("request is served");
    served.fetch_add(1, Ordering::SeqCst);
}

#[cfg(http3)]
fn h3_response() -> http::Response<()> {
    http::Response::builder()
        .status(http::StatusCode::OK)
        .header("x-zenwave-protocol", "h3")
        .body(())
        .expect("response builds")
}

#[cfg(http3)]
async fn serve_body(stream: &mut ServerStream, body: Bytes) -> Result<(), h3::error::StreamError> {
    stream.send_response(h3_response()).await?;
    stream.send_data(body).await?;
    stream.finish().await
}

#[cfg(http3)]
async fn serve_echo(stream: &mut ServerStream) -> Result<(), h3::error::StreamError> {
    stream.send_response(h3_response()).await?;
    while let Some(mut chunk) = stream.recv_data().await? {
        let data = chunk.copy_to_bytes(chunk.remaining());
        stream.send_data(data).await?;
    }
    stream.finish().await
}

/// The second chunk waits for the test to release it: a client that buffers
/// the whole body before answering hangs here forever.
#[cfg(http3)]
async fn serve_slow(
    stream: &mut ServerStream,
    release: oneshot::Receiver<()>,
) -> Result<(), h3::error::StreamError> {
    stream.send_response(h3_response()).await?;
    stream.send_data(Bytes::from_static(&[0xA5; 64])).await?;
    let _ = release.await;
    stream.send_data(Bytes::from_static(&[0x5A; 64])).await?;
    stream.finish().await
}

#[cfg(http3)]
async fn serve_status(
    stream: &mut ServerStream,
    status: http::StatusCode,
) -> Result<(), h3::error::StreamError> {
    let response = http::Response::builder()
        .status(status)
        .header("x-zenwave-protocol", "h3")
        .body(())
        .expect("response builds");
    stream.send_response(response).await?;
    stream.finish().await
}
