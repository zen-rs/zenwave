//! The OneCRL revocation baseline, wrapped around the verifiers that check
//! certificate chains with webpki (rustls-platform-verifier's disk-root
//! verifier and the Android disk-root verifier). Apple and Windows builds
//! carry no table: their OS trust service ships its own distrust.
//!
//! Matching follows Firefox's `RemoteSecuritySettings.sys.mjs`: a presented
//! certificate — leaf or intermediate — is refused when its `(issuer, serial)`
//! pair is listed, or when its `subject` is listed and the SHA-256 of its full
//! SPKI matches. The list is a sorted binary table compiled by `build.rs` from
//! the pinned snapshot and searched in place; nothing is decoded or allocated
//! at run time.
//!
//! The table layout, all offsets little-endian `u32` from byte 0:
//!
//! ```text
//! u32 issuer_count | u32 subject_count
//! issuer index:  issuer_count × { name_off, name_len, serials_off, serials_len }
//! subject index: subject_count × { name_off, name_len, hashes_off, hashes_len }
//! areas:         per issuer, serials_len × { off, len } serial sub-index
//!                entries, then per subject hashes_len × 32-byte hashes
//! byte area:     every name and serial value, concatenated
//! ```

use std::{cmp::Ordering, sync::Arc};

use rustls::{
    CertificateError, DigitallySignedStruct, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// The pinned snapshot table, compiled by `build.rs`.
const TABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/onecrl.bin"));

/// A [`ServerCertVerifier`] that refuses OneCRL-listed certificates before
/// delegating to `inner`.
#[derive(Debug)]
pub struct OneCrlVerifier {
    inner: Arc<dyn ServerCertVerifier>,
}

impl OneCrlVerifier {
    pub fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self { inner }
    }
}

impl ServerCertVerifier for OneCrlVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        for der in std::iter::once(end_entity).chain(intermediates.iter()) {
            // A certificate that does not parse is the inner verifier's call.
            if let Ok(cert) = webpki::EndEntityCert::try_from(der) {
                if listed(&cert).is_some() {
                    return Err(Error::InvalidCertificate(CertificateError::Revoked));
                }
            }
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

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Which index listed a certificate — the distinction tests need to prove
/// each mechanism works.
#[derive(Debug, PartialEq, Eq)]
enum Listing {
    IssuerSerial,
    SubjectKey,
}

/// The record covering `cert`, if any.
fn listed(cert: &webpki::Cert<'_>) -> Option<Listing> {
    if issuer_serial_hit(cert.issuer(), cert.serial()) {
        return Some(Listing::IssuerSerial);
    }
    if let Some(hashes) = name_entry(subject_index(), subject_count(), cert.subject()) {
        // The SPKI hash costs a SHA-256 pass; only pay it on a subject hit.
        let spki = cert.subject_public_key_info();
        let hash = ring::digest::digest(&ring::digest::SHA256, spki.as_ref());
        let found = search(hashes.1, |i| {
            TABLE[hashes.0 + i * 32..hashes.0 + i * 32 + 32].cmp(hash.as_ref())
        })
        .is_some();
        if found {
            return Some(Listing::SubjectKey);
        }
    }
    None
}

fn issuer_serial_hit(issuer: &[u8], serial: &[u8]) -> bool {
    let Some(serials) = name_entry(8, issuer_count(), issuer) else {
        return false;
    };
    search(serials.1, |i| {
        let entry = serials.0 + i * 8;
        TABLE[u32_at(entry)..u32_at(entry) + u32_at(entry + 4)].cmp(serial)
    })
    .is_some()
}

/// Binary-search the name index at `base` (16-byte
/// `{name_off, name_len, list_off, list_len}` entries); on hit return the
/// listed area's offset and element count.
fn name_entry(base: usize, count: usize, name: &[u8]) -> Option<(usize, usize)> {
    search(count, |i| {
        let entry = base + i * 16;
        TABLE[u32_at(entry)..u32_at(entry) + u32_at(entry + 4)].cmp(name)
    })
    .map(|i| (u32_at(base + i * 16 + 8), u32_at(base + i * 16 + 12)))
}

fn issuer_count() -> usize {
    u32_at(0)
}

fn subject_count() -> usize {
    u32_at(4)
}

fn subject_index() -> usize {
    8 + issuer_count() * 16
}

fn u32_at(offset: usize) -> usize {
    u32::from_le_bytes(TABLE[offset..offset + 4].try_into().unwrap()) as usize
}

/// `cmp(i)` orders element `i` of a `len`-element sorted run against the key.
fn search(len: usize, mut cmp: impl FnMut(usize) -> Ordering) -> Option<usize> {
    let (mut lo, mut hi) = (0, len);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match cmp(mid) {
            Ordering::Less => lo = mid + 1,
            Ordering::Greater => hi = mid,
            Ordering::Equal => return Some(mid),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::{
        DigitallySignedStruct, Error, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
    };

    use super::*;

    /// The genuine `EM OV TLS CA - G3C` cross-signed by Sectigo's `AAA
    /// Certificate Services` — listed by subject+pubKeyHash only.
    const CROSS_SIGNED: &str = "-----BEGIN CERTIFICATE-----
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

    /// The same CA's certificate issued by `emSign Root TLS CA - G3` — listed
    /// by issuer+serial (and also subject+key; the issuer index is checked
    /// first). From emudhra.we-have-a-problem.com.
    const EMSIGN_ISSUED: &str = "-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3
NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ
fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+
N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44c
NVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR79
4rSb9vGqxZzelQth
-----END CERTIFICATE-----
";

    /// `EM OV CS CA - G3B` issued by `emSign Root CS CA - G3` — a code-signing
    /// CA, not in the OneCRL snapshot at all.
    const UNLISTED: &str = "-----BEGIN CERTIFICATE-----
MIIDWzCCAuCgAwIBAgIPeBiTP4+FtGGaKzX7qD0KMAoGCCqGSM49BAMDMFUxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MR8wHQYDVQQDDBZlbVNpZ24gUm9vdCBDUyBDQSAtIEczMB4XDTI1MDQzMDE2MDgy
N1oXDTQwMDQyODE4MzAwMFowPjELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRo
cmEgQlYxGjAYBgNVBAMMEUVNIE9WIENTIENBIC0gRzNCMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUOb
NKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jord
d7EAZPKr5eBQo4IBizCCAYcwHwYDVR0jBBgwFoAUaHQD+IXKjVRQVx0W4MjeRQ2r
zS0wHQYDVR0OBBYEFHn66OzP2w11jaRY1p+27dx8Sd7mMBMGA1UdJQQMMAoGCCsG
AQUFBwMDMF4GA1UdIARXMFUwOQYLKwYBBAGDjiEBAAEwKjAoBggrBgEFBQcCARYc
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbTAOBgwrBgEEAYOOIQECgUgwCAYG
Z4EMAQQBMHQGCCsGAQUFBwEBBGgwZjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3At
Yi5lbXNpZ24uY29tMD4GCCsGAQUFBzAChjJodHRwOi8vcmVwb3NpdG9yeS5lbXNp
Z24uY29tL2NlcnRzL0VNT1ZDU0NBRzNCLnA3YzA2BgNVHR8ELzAtMCugKaAnhiVo
dHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3Rjc2NhZzMuY3JsMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMDA2kAMGYCMQC/zr03
YEELsNKqzUtH2dVFi4BaKFdyrr/6G1dIWp8KAVgsw2/u4lyyboUDaC9jDvICMQC9
HTxku84tNX9dmHOtH7aC2Nu/JM0jTf6KjZAvovCJzzv1IFWSZpVLZibynMLXOrM=
-----END CERTIFICATE-----
";

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).expect("PEM must decode")
    }

    fn listed_for(pem: &str) -> Option<Listing> {
        let der = der(pem);
        let cert = webpki::EndEntityCert::try_from(&der).expect("certificate must parse");
        listed(&cert)
    }

    /// The inner verifier never sees a refused chain; any answer it gives is
    /// passed through for an unlisted one.
    #[derive(Debug)]
    struct Inner;

    impl ServerCertVerifier for Inner {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            Vec::new()
        }
    }

    #[test]
    fn listed_by_subject_and_key() {
        assert_eq!(listed_for(CROSS_SIGNED), Some(Listing::SubjectKey));
    }

    #[test]
    fn listed_by_issuer_and_serial() {
        assert_eq!(listed_for(EMSIGN_ISSUED), Some(Listing::IssuerSerial));
    }

    #[test]
    fn unlisted_certificate() {
        assert_eq!(listed_for(UNLISTED), None);
    }

    #[test]
    fn verifier_refuses_and_delegates() {
        let verifier = OneCrlVerifier::new(Arc::new(Inner));
        let name = ServerName::try_from("example.com").expect("server name");
        let refused =
            verifier.verify_server_cert(&der(CROSS_SIGNED), &[], &name, &[], UnixTime::now());
        assert!(matches!(
            refused,
            Err(Error::InvalidCertificate(CertificateError::Revoked))
        ));
        verifier
            .verify_server_cert(&der(UNLISTED), &[], &name, &[], UnixTime::now())
            .expect("an unlisted certificate delegates to the inner verifier");
    }
}
