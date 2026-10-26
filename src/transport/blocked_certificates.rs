//! Certificates whose private keys are publicly compromised, refused during
//! verification regardless of what the platform trust store still trusts.
//!
//! Browser vendors distribute such distrust as revocation data — Firefox's
//! `OneCRL`, Chrome's `CRLSets` — but a client verifying against a system CA
//! bundle that is refreshed rarely, the Linux and container-image case, keeps
//! trusting the compromised intermediates until the bundle is rebuilt.
//! Checking the presented chain's keys here removes that dependency.
//!
//! Entries key on the certificate's DER-encoded `SubjectPublicKeyInfo`, the
//! same keying `OneCRL` uses for intermediates (subject + pubkey hash): the
//! Sectigo "AAA Certificate Services" cross-signs share keys with the
//! eMudhra-issued originals, and any certificate minted under the same key
//! is caught too.

use std::{fmt, sync::Arc};

use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, OtherError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerifier, ServerCertVerified},
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// October 2026 eMudhra compromise: eight P-384 intermediate CA
/// certificates minted in April 2025 whose private keys are recoverable by
/// inspection — every private scalar is an integer below 256, the weakest
/// literally `4` — so a forgery under any of them validates against every
/// trust store that has not distrusted the intermediates.
///
/// <https://emudhra.we-have-a-problem.com/>
///
/// Each entry is `(common name, DER-encoded SubjectPublicKeyInfo)`; the
/// `spki_sha256` values published in the advisory are the SHA-256 of each
/// byte string here. The two code-signing intermediates are included too —
/// the keys are compromised the same way.
const COMPROMISED_KEYS: &[(&str, [u8; 120])] = &[
    // spki_sha256 ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105
    ("EM DV TLS CA - G3B", unhex("3076301006072a8648ce3d020106052b8104002203620004e79ed9c04a9773c4735e51111da85ac2bd5e64ab374b80e12cbc2038ec1e4f0e3b812fc9859e1e67afb04e2f8bc97f7485ba65aa911ee8a4e45b62d5cc03d56be678b3c38cb4dc937ca2460e238453c892935d29d44f91e15606b63ccedab468")),
    // spki_sha256 43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b
    ("EM OV TLS CA - G3B", unhex("3076301006072a8648ce3d020106052b810400220362000473897aa0eb3cfdca8b12402ffaf0abc4e1212baf8dee778ac9ee2d6db83fac280c5e05638ae7a2acd71c322a8e361cdeb9f69c4302b9dd8d73d1cc6caab2cc0aee4e216ce979dd518a4af4b626e5684cdd658037ed0c854e4cc12f4cf8646d0d")),
    // spki_sha256 e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41
    ("EM EV TLS CA - G3B", unhex("3076301006072a8648ce3d020106052b810400220362000425dba85a64d397da0b1052e9ea546e487befea9c9d9d68a0c5eadcfeef75a69bb5d6fc01f42bfbca6eb40bcd64c0767e36ffd05d97a813c5aa0c6c9530e79cf5f0866468f13806420aa5c851840b1e252540e790e4b654c3852ed64af1e8657d")),
    // spki_sha256 49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f
    ("EM DV TLS CA - G3C", unhex("3076301006072a8648ce3d020106052b81040022036200043a7a7862c8c44d324ddd69033a6782c0efeefe4055e68a123fa0371ba3bd9194514ee172a433e3630f02bd188037d9e5149f9b77db94a281df987b2fea888b74bdfe8fda4c1099ee6ca19566fe3ef0e5f6b09a556ccc8ba50561df1b2a441d01")),
    // spki_sha256 63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8
    ("EM OV TLS CA - G3C", unhex("3076301006072a8648ce3d020106052b8104002203620004138251cd52ac9298c1c8aad977321deb97e709bd0b4ca0aca55dc8ad51dcfc9d1589a1597e3a5120e1efd631c63e1835cacae29869a62e1631e8a28181ab56616dc45d918abc09f3ab0e63cf792aa4dced7387be37bba569549f1c02b270ed67")),
    // spki_sha256 5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0
    ("EM EV TLS CA - G3C", unhex("3076301006072a8648ce3d020106052b81040022036200042d56e829a6fb82c64a4697d960af951e9067ae91f926d34306da48a8aaeb7869b6a67e6d27426e0442aa03b36e1988dff636514ee1cf07f5ba4b3ff2a06645ae7d31d5866ad31aa3d246eb0b3177ee99cb7566c516ce74808a668f91f0c47fca")),
    // spki_sha256 ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6
    ("EM OV CS CA - G3B", unhex("3076301006072a8648ce3d020106052b8104002203620004aabb0fb0666acfcf01fad52bfcfd4c2bf2cb3c3497de73950e5819b61fe695098741c8c491439b34a0431caffe5bf9b4c1c8e8ae0001f9f4dc8ad82c59f3639e96cd6c3d4db0cefec26c3d62517b37761372743f8e8add77b10064f2abe5e050")),
    // spki_sha256 92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30
    ("EM OV CS CA - G3C", unhex("3076301006072a8648ce3d020106052b8104002203620004b9f0e0634702a69ca6aadd443cfd62c41b9ba4b20924697d7974e7691a126fb96afb3e34c2fd3bc5f483061f265dc2a58436347323510436b28f04f3862363067980e2503e02532d6546235a7165a259a1ef496f741b5fdee7787208e4b8faef")),
];

/// `cert`'s public key is one of the compromised CA keys; returns the
/// compromised certificate's common name when so.
///
/// A certificate that does not parse is left for the real verifier, which
/// rejects it on its own.
fn compromised_name(cert: &CertificateDer<'_>) -> Option<&'static str> {
    let anchor = webpki::anchor_from_trusted_cert(cert).ok()?;
    // `subject_public_key_info` is the SPKI SEQUENCE's contents; the table
    // holds the complete DER encoding so every constant still hashes to the
    // advisory's `spki_sha256` — the `30 76` tag and length bytes come off.
    let spki = anchor.subject_public_key_info;
    COMPROMISED_KEYS
        .iter()
        .find(|(_, key)| spki.as_ref() == &key[2..])
        .map(|(name, _)| *name)
}

// Every entry shares the `30 76` header — a SEQUENCE of 118 contents bytes —
// that the comparison above strips.
const _: () = {
    let mut i = 0;
    while i < COMPROMISED_KEYS.len() {
        let key = &COMPROMISED_KEYS[i].1;
        assert!(key[0] == 0x30 && key[1] == 0x76);
        i += 1;
    }
};

/// A [`ServerCertVerifier`] refusing chains that carry a compromised CA key
/// before delegating to `inner` — the platform's own verification accepts
/// them while its store is stale.
#[derive(Debug)]
pub(super) struct BlockedKeyVerifier {
    inner: Arc<dyn ServerCertVerifier>,
}

impl BlockedKeyVerifier {
    /// Wrap `inner` so the compromised-key check runs ahead of it.
    pub(super) fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self { inner }
    }
}

impl ServerCertVerifier for BlockedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if let Some(name) = intermediates
            .iter()
            .chain(std::iter::once(end_entity))
            .find_map(compromised_name)
        {
            return Err(Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(CompromisedCa(name))),
            )));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// `verify_server_cert` rejected a chain through [`COMPROMISED_KEYS`].
#[derive(Debug)]
struct CompromisedCa(&'static str);

impl fmt::Display for CompromisedCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the certificate chain includes `{0}`, whose private key is publicly compromised",
            self.0
        )
    }
}

impl std::error::Error for CompromisedCa {}

/// Decode a hex literal at compile time, keeping the table legible against
/// the advisory's published digests without a runtime pass or a hex crate.
const fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 2 * N);
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = digit(bytes[2 * i]) << 4 | digit(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// One hex digit of [`unhex`].
const fn digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("non-hex digit in a compromised-key constant"),
    }
}

#[cfg(test)]
mod tests {
    use rustls_pki_types::pem::PemObject;

    use super::*;

    /// The genuine `EM OV TLS CA - G3C` intermediate as issued by Sectigo's
    /// `AAA Certificate Services` cross-sign.
    const G3C_PEM: &str = "-----BEGIN CERTIFICATE-----
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

    #[test]
    fn the_compromised_intermediate_is_flagged() {
        let der = CertificateDer::from_pem_slice(G3C_PEM.as_bytes()).expect("PEM parses");
        assert_eq!(compromised_name(&der), Some("EM OV TLS CA - G3C"));
    }

    #[test]
    fn an_unrelated_certificate_is_not_flagged() {
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("self-sign");
        assert_eq!(compromised_name(cert.der()), None);
    }
}
