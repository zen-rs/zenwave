//! The webpki verification paths must refuse chains OneCRL lists, even where
//! the platform trust store still accepts them. The compromised eMudhra
//! intermediate's private key is public knowledge (`d = 4`), so the forged
//! chain is a real one: a leaf signed by that key, presented with the genuine
//! cross-sign from Sectigo's `AAA Certificate Services`, which Linux trust
//! stores still carry.
#![cfg(all(
    feature = "hyper-backend",
    feature = "onecrl",
    not(target_arch = "wasm32"),
    not(target_vendor = "apple"),
    not(windows)
))]

use std::{net::SocketAddr, sync::Arc, thread};

use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair,
};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
use time::{Duration, OffsetDateTime};
use zenwave::{Client as _, Proxy, StatusCode, Transport, backend::HyperBackend};

/// The compromised `EM OV TLS CA - G3C` private key, as PKCS#8.
const COMPROMISED_KEY: &str = include_str!("onecrl/em-ov-tls-ca-g3c.key.pem");
/// `EM OV TLS CA - G3C` cross-signed by `AAA Certificate Services`; OneCRL
/// lists it by subject and key.
const CROSS_SIGNED: &str = include_str!("onecrl/em-ov-tls-ca-g3c-by-aaa.pem");
/// `EM OV TLS CA - G3C` issued by `emSign Root TLS CA - G3`; OneCRL lists it
/// by issuer and serial.
const EMSIGN_ISSUED: &str = include_str!("onecrl/em-ov-tls-ca-g3c-by-emsign.pem");

fn pem(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).expect("test certificate must parse")
}

/// A `localhost`/`127.0.0.1` leaf signed by `issuer`.
fn localhost_leaf(
    issuer: &Issuer<'static, KeyPair>,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let leaf_key = KeyPair::generate().expect("leaf key must generate");
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("leaf params must build");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = OffsetDateTime::now_utc();
    leaf_params.not_before = now - Duration::days(1);
    leaf_params.not_after = now + Duration::days(1);
    let leaf = leaf_params
        .signed_by(&leaf_key, issuer)
        .expect("leaf must sign");
    (
        leaf.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}

/// A throwaway CA, trusted through `extra_root_certificate_der`.
fn throwaway_ca() -> (Certificate, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().expect("CA key must generate");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "zenwave test CA");
    let cert = params.self_signed(&key).expect("CA must self-sign");
    (cert, Issuer::new(params, key))
}

/// Accept connections on a bound `127.0.0.1` port forever, serving `chain` +
/// `key` over TLS and answering each completed handshake with one canned
/// HTTP/1.1 response.
fn serve(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> SocketAddr {
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server certificate");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = futures_rustls::TlsAcceptor::from(Arc::new(config));
    let (listener, address) = async_io::block_on(async {
        let listener = async_net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener must bind");
        let address = listener.local_addr().expect("test address");
        (listener, address)
    });
    thread::spawn(move || {
        async_io::block_on(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    async_io::block_on(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let mut head = Vec::new();
                        let mut buffer = [0_u8; 1024];
                        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                            let Ok(read) = tls.read(&mut buffer).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            head.extend_from_slice(&buffer[..read]);
                        }
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await;
                        let _ = tls.close().await;
                    });
                });
            }
        });
    });
    address
}

/// A transport that proxies nothing, so an ambient `HTTPS_PROXY` cannot turn
/// the loopback request into a proxied one, trusting `extra_root` on top of
/// the platform roots.
fn transport(extra_root: Option<&Certificate>) -> Transport {
    let builder = Transport::builder().proxy(Proxy::none());
    match extra_root {
        Some(root) => builder.extra_root_certificate_der(root.der().to_vec()),
        None => builder,
    }
    .build()
    .expect("transport must build")
}

async fn get(transport: Transport, address: SocketAddr) -> Result<StatusCode, zenwave::Error> {
    let mut client = HyperBackend::new(transport);
    client
        .get(format!("https://localhost:{}/", address.port()))
        .expect("request must build")
        .await
        .map(|response| response.status())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), wasm_lite::wasm_lite_test)]
async fn a_chain_listed_by_subject_and_key_is_refused() {
    let key = KeyPair::from_pem(COMPROMISED_KEY).expect("compromised key must load");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("issuer params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // The leaf's issuer must be the presented intermediate's subject.
    for (dn, value) in [
        (DnType::CountryName, "US"),
        (DnType::OrganizationName, "eMudhra Inc"),
        (DnType::CommonName, "EM OV TLS CA - G3C"),
    ] {
        params.distinguished_name.push(dn, value);
    }
    let (leaf, leaf_key) = localhost_leaf(&Issuer::new(params, key));
    let address = serve(vec![leaf, pem(CROSS_SIGNED)], leaf_key);

    let error = get(transport(None), address)
        .await
        .expect_err("a forged chain must be refused");
    assert!(
        error.to_string().contains("Revoked"),
        "the chain must be refused as revoked, got: {error}"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), wasm_lite::wasm_lite_test)]
async fn a_chain_listed_by_issuer_and_serial_is_refused() {
    // An otherwise valid chain that also presents the listed intermediate:
    // webpki ignores the extra certificate, OneCRL must not.
    let (ca, issuer) = throwaway_ca();
    let (leaf, leaf_key) = localhost_leaf(&issuer);
    let address = serve(vec![leaf, pem(EMSIGN_ISSUED)], leaf_key);

    let error = get(transport(Some(&ca)), address)
        .await
        .expect_err("a chain carrying a listed certificate must be refused");
    assert!(
        error.to_string().contains("Revoked"),
        "the chain must be refused as revoked, got: {error}"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), wasm_lite::wasm_lite_test)]
async fn an_ordinary_chain_verifies() {
    let (ca, issuer) = throwaway_ca();
    let (leaf, leaf_key) = localhost_leaf(&issuer);
    let address = serve(vec![leaf], leaf_key);

    let status = get(transport(Some(&ca)), address)
        .await
        .expect("an ordinary chain must verify");
    assert_eq!(status, StatusCode::OK);
}
