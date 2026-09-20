//! Local HTTPS and WSS servers signed by a throwaway CA.
//!
//! The CA is not in any trust store, so a client only succeeds against these
//! servers when it was handed the CA through `Transport::extra_root_certificates_pem`.
#![allow(dead_code)]

#[cfg(feature = "ws")]
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc, thread};

use async_net::TcpListener;
use futures_rustls::TlsAcceptor;
#[cfg(feature = "ws")]
use futures_util::StreamExt;
use futures_util::{AsyncReadExt, AsyncWriteExt};
use once_cell::sync::OnceCell;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use time::{Duration, OffsetDateTime};

/// Local TLS endpoints and the PEM of the CA that signed them.
#[derive(Debug)]
pub struct TlsFixture {
    pub ca_pem: Vec<u8>,
    https_addr: SocketAddr,
    #[cfg(feature = "ws")]
    wss_addr: SocketAddr,
    /// The ALPN protocol negotiated on the latest wss connection, if any.
    #[cfg(feature = "ws")]
    wss_alpn: Arc<Mutex<Option<Vec<u8>>>>,
}

impl TlsFixture {
    /// `https://localhost:<port>/<path>` on the JSON server, for direct connections.
    pub fn https_uri(&self, path: &str) -> String {
        format!(
            "https://localhost:{}/{}",
            self.https_addr.port(),
            path.trim_start_matches('/')
        )
    }

    /// The JSON server under [`FIXTURE_HOST`](super::FIXTURE_HOST): reachable
    /// only through the test proxies, which resolve that name.
    pub fn proxied_https_uri(&self, path: &str) -> String {
        format!(
            "https://{}:{}/{}",
            super::FIXTURE_HOST,
            self.https_addr.port(),
            path.trim_start_matches('/')
        )
    }

    /// `wss://localhost:<port>` on the echo server, for direct connections.
    #[cfg(feature = "ws")]
    pub fn wss_uri(&self) -> String {
        format!("wss://localhost:{}", self.wss_addr.port())
    }

    /// The echo server under [`FIXTURE_HOST`](super::FIXTURE_HOST).
    #[cfg(feature = "ws")]
    pub fn proxied_wss_uri(&self) -> String {
        format!("wss://{}:{}", super::FIXTURE_HOST, self.wss_addr.port())
    }

    /// The ALPN protocol negotiated on the most recent wss connection.
    ///
    /// The wss listener offers `h2` and `http/1.1`, so this reports what the
    /// client asked for: websockets must negotiate `http/1.1` only.
    #[cfg(feature = "ws")]
    pub fn wss_alpn(&self) -> Option<Vec<u8>> {
        self.wss_alpn.lock().expect("wss ALPN lock").clone()
    }
}

pub fn tls_fixture() -> &'static TlsFixture {
    static INSTANCE: OnceCell<TlsFixture> = OnceCell::new();
    INSTANCE.get_or_init(start)
}

/// A throwaway CA and a leaf `ServerConfig` covering `sans`, signed by it.
/// Returns the CA certificate in PEM for `extra_root_certificates_pem`.
fn signed_server_config(sans: Vec<String>) -> (Vec<u8>, ServerConfig) {
    let now = OffsetDateTime::now_utc();

    let ca_key = KeyPair::generate().expect("generate CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "zenwave test CA");
    ca_params.not_before = now - Duration::days(1);
    ca_params.not_after = now + Duration::days(365);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem().into_bytes();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let mut leaf_params = CertificateParams::new(sans).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = now - Duration::days(1);
    leaf_params.not_after = now + Duration::days(365);
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign leaf certificate");

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .expect("server certificate");
    (ca_pem, config)
}

/// A TLS endpoint that answers like [`tls_fixture`]'s HTTPS server plus an
/// `Alt-Svc: <alt_svc>` header on every response — the HTTP/3-through-a-proxy
/// test advertises a counting UDP socket and asserts it stays silent.
/// Returns the CA in PEM and the listen address.
pub fn alt_svc_server(alt_svc: String) -> (Vec<u8>, SocketAddr) {
    let (ca_pem, config) = signed_server_config(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        super::FIXTURE_HOST.to_owned(),
    ]);
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (listener, addr) = bind();
    thread::spawn(move || {
        smol::block_on(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept HTTPS");
                let acceptor = acceptor.clone();
                let alt_svc = alt_svc.clone();
                smol::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        serve_json(tls, Some(&alt_svc)).await;
                    }
                })
                .detach();
            }
        });
    });
    (ca_pem, addr)
}

fn start() -> TlsFixture {
    let (ca_pem, config) = signed_server_config(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        super::FIXTURE_HOST.to_owned(),
    ]);

    // The wss listener offers h2 alongside http/1.1 so tests can assert the
    // client only asked for http/1.1 — the websocket handshake is an HTTP/1.1
    // upgrade and must not negotiate h2.
    #[cfg(feature = "ws")]
    let wss_acceptor = {
        let mut wss_config = config.clone();
        wss_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(wss_config))
    };
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let (https_listener, https_addr) = bind();
    #[cfg(feature = "ws")]
    let (wss_listener, wss_addr) = bind();

    #[cfg(feature = "ws")]
    let wss_alpn = Arc::new(Mutex::new(None));
    #[cfg(feature = "ws")]
    {
        let recorded = wss_alpn.clone();
        thread::spawn(move || {
            smol::block_on(async move {
                loop {
                    let (stream, _) = wss_listener.accept().await.expect("accept WSS");
                    let acceptor = wss_acceptor.clone();
                    let recorded = recorded.clone();
                    smol::spawn(async move {
                        if let Ok(tls) = acceptor.accept(stream).await {
                            *recorded.lock().expect("wss ALPN lock") =
                                tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                            echo_websocket(tls).await;
                        }
                    })
                    .detach();
                }
            });
        });
    }

    thread::spawn(move || {
        smol::block_on(async move {
            loop {
                let (stream, _) = https_listener.accept().await.expect("accept HTTPS");
                let acceptor = acceptor.clone();
                smol::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        serve_json(tls, None).await;
                    }
                })
                .detach();
            }
        });
    });

    TlsFixture {
        ca_pem,
        https_addr,
        #[cfg(feature = "ws")]
        wss_addr,
        #[cfg(feature = "ws")]
        wss_alpn,
    }
}

fn bind() -> (TcpListener, SocketAddr) {
    smol::block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local TLS server");
        let addr = listener.local_addr().expect("local address");
        (listener, addr)
    })
}

async fn serve_json<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S, alt_svc: Option<&str>) {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let Ok(read) = stream.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    let body = br#"{"secure":true}"#;
    let alt_svc = alt_svc.map_or(String::new(), |value| format!("Alt-Svc: {value}\r\n"));
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{alt_svc}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.flush().await;
    let _ = stream.close().await;
}

#[cfg(feature = "ws")]
async fn echo_websocket<S: AsyncReadExt + AsyncWriteExt + Unpin>(stream: S) {
    let Ok(mut socket) = async_tungstenite::accept_async(stream).await else {
        return;
    };
    while let Some(Ok(message)) = socket.next().await {
        if message.is_close() {
            break;
        }
        if socket.send(message).await.is_err() {
            break;
        }
    }
}
