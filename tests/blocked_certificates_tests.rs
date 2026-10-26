//! The TLS layer must refuse chains through the compromised eMudhra
//! intermediates even while a stale platform trust store still accepts them.
//! The private keys are public knowledge — every P-384 private scalar is an
//! integer below 256 — so the test forges a real leaf signed by one.
#![cfg(all(
    not(target_arch = "wasm32"),
    feature = "hyper-backend",
    feature = "rustls"
))]

use std::{net::SocketAddr, sync::Arc, thread};

use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
use time::{Duration, OffsetDateTime};
use zenwave::{Client as _, Proxy, StatusCode, Transport, backend::HyperBackend};

/// The real compromised `EM OV TLS CA - G3C` private key — scalar `d = 4`,
/// readable off the public key — serialized as PKCS#8.
const COMPROMISED_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAShZANiAAQTglHNUqyS
mMHIqtl3Mh3rl+cJvQtMoKylXcitUdz8nRWJoVl+OlEg4e/WMcY+GDXKyuKYaaYu
FjHoooGBq1ZhbcRdkYq8CfOrDmPPeSqk3O1zh743u6VpVJ8cArJw7Wc=
-----END PRIVATE KEY-----
";

/// The genuine `EM OV TLS CA - G3C` intermediate issued by Sectigo's `AAA
/// Certificate Services` — the cross-sign, chaining to a root every
/// platform store ships.
const COMPROMISED_INTERMEDIATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAI1aSBGTnvRH13ERzdmEmukwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv
1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSf
HAKycO1no4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECAjANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECbjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAHlbhZpjhkPEAQVhPHRtBDaHqiisVD20pQ1TUeSx3l62Qe7NQ0b7vWQy7DN0i
KOu7BGpP5EnIjvXbz9FhpfPJ4FhKEt3tQ51rqXz2oD8vRaryvExWPobDUz3j7HN6
OzBsVMIe3PD7AAkpky0x8zMSi/ep5R9OMzybmNptbtppyuB5ytgq+h7lQdRIP+CQ
TaJX3qTgfMqzntYre5GljmEB5hU2/rSn8zoSU2APkJidlZFpghtgbD4I2VRHZvCw
FFr/SrFM9pwrgbJNZ1MtyTSVgI5NlNb0aMfLR+/r6jJt3ROeY2yh2QQ2dx+Yqgdb
uL5ChFWOQU+ErSDnUq7yr+pjBQ==
-----END CERTIFICATE-----
";

/// A `localhost`/`127.0.0.1` leaf signed by `issuer`; the counterpart of
/// `test_support::TestCa::leaf`.
fn localhost_leaf(issuer: &Issuer<'static, KeyPair>) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let leaf_key = KeyPair::generate().expect("leaf key must generate");
    let mut leaf_params = CertificateParams::new(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
    ])
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

/// A `localhost` leaf signed by the compromised key — the very forgery the
/// incident enables — presented with the genuine cross-signed intermediate,
/// exactly the chain a man-in-the-middle would send.
fn forged_chain() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let issuer_key = KeyPair::from_pem(COMPROMISED_KEY_PEM).expect("compromised key must load");
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).expect("issuer params");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // The leaf's issuer must be the presented intermediate's subject.
    for (dn, value) in [
        (DnType::CountryName, "US"),
        (DnType::OrganizationName, "eMudhra Inc"),
        (DnType::CommonName, "EM OV TLS CA - G3C"),
    ] {
        issuer_params.distinguished_name.push(dn, value);
    }
    let issuer = Issuer::new(issuer_params, issuer_key);
    let (leaf, key) = localhost_leaf(&issuer);
    let intermediate = CertificateDer::from_pem_slice(COMPROMISED_INTERMEDIATE_PEM.as_bytes())
        .expect("the real intermediate must parse");
    (vec![leaf, intermediate], key)
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

/// A transport that proxies nothing — an ambient `HTTPS_PROXY` must not
/// turn the loopback request into a proxied one.
fn transport() -> Transport {
    Transport::builder()
        .proxy(Proxy::none())
        .build()
        .expect("transport must build")
}

#[test_executors::async_test]
async fn a_chain_through_a_compromised_ca_key_is_refused() {
    let (chain, key) = forged_chain();
    let address = serve(chain, key);
    let mut client = HyperBackend::new(transport());
    let error = client
        .get(format!("https://localhost:{}/", address.port()))
        .expect("request must build")
        .await
        .expect_err("a forged chain must be refused");
    assert!(
        error.to_string().contains("EM OV TLS CA - G3C"),
        "the error must name the compromised certificate, got: {error}"
    );
}

#[test_executors::async_test]
async fn an_ordinary_chain_is_still_served() {
    // A throwaway CA trusted through `extra_root_certificate_der` — the
    // ordinary path the blocklist must not disturb.
    let ca_key = KeyPair::generate().expect("CA key must generate");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "zenwave test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA must self-sign");
    let (leaf, key) = localhost_leaf(&Issuer::new(ca_params, ca_key));
    let address = serve(vec![leaf], key);

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificate_der(ca_cert.der().to_vec())
        .build()
        .expect("transport must build");
    let mut client = HyperBackend::new(transport);
    let response = client
        .get(format!("https://localhost:{}/", address.port()))
        .expect("request must build")
        .await
        .expect("an ordinary chain must verify");
    assert_eq!(response.status(), StatusCode::OK);
}
