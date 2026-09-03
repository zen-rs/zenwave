//! Local HTTPS and WSS servers signed by a throwaway CA.
//!
//! The CA is not in any trust store, so a client only succeeds against these
//! servers when it was handed the CA through `Transport::extra_root_certificates_pem`.
#![allow(dead_code)]

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
}

pub fn tls_fixture() -> &'static TlsFixture {
    static INSTANCE: OnceCell<TlsFixture> = OnceCell::new();
    INSTANCE.get_or_init(start)
}

fn start() -> TlsFixture {
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
    let mut leaf_params = CertificateParams::new(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        super::FIXTURE_HOST.to_owned(),
    ])
    .expect("leaf params");
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
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let (https_listener, https_addr) = bind();
    #[cfg(feature = "ws")]
    let (wss_listener, wss_addr) = bind();

    #[cfg(feature = "ws")]
    {
        let wss_acceptor = acceptor.clone();
        thread::spawn(move || {
            smol::block_on(async move {
                loop {
                    let (stream, _) = wss_listener.accept().await.expect("accept WSS");
                    let acceptor = wss_acceptor.clone();
                    smol::spawn(async move {
                        if let Ok(tls) = acceptor.accept(stream).await {
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
                        serve_json(tls).await;
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

async fn serve_json<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S) {
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
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
