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
//! at run time. Records Remote Settings publishes after that baseline reach a
//! transport only when it opted in with
//! [`TransportBuilder::onecrl_refresh`](crate::TransportBuilder::onecrl_refresh);
//! [`refresh`] keeps them in [`Additions`], which `listed` checks after the
//! compiled table.
//!
//! The table layout — the header's timestamp little-endian `u64`, every
//! offset little-endian `u32` from byte 0:
//!
//! ```text
//! u64 timestamp | u32 issuer_count | u32 subject_count
//! issuer index:  issuer_count × { name_off, name_len, serials_off, serials_len }
//! subject index: subject_count × { name_off, name_len, hashes_off, hashes_len }
//! areas:         per issuer, serials_len × { off, len } serial sub-index
//!                entries, then per subject hashes_len × 32-byte hashes
//! byte area:     every name and serial value, concatenated
//! ```

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use arc_swap::ArcSwap;
use rustls::{
    CertificateError, DigitallySignedStruct, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

pub mod record;
pub mod refresh;

/// The pinned snapshot table, compiled by `build.rs`.
const TABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/onecrl.bin"));

/// The changeset timestamp the compiled table covers — the refresher asks
/// Remote Settings for everything after it.
pub fn baseline_timestamp() -> u64 {
    u64::from_le_bytes(TABLE[..8].try_into().expect("the table has a header"))
}

/// Records published after the compiled baseline, fetched by the refresher
/// and persisted under the cache directory. The maps are replaced wholesale
/// under `ArcSwap`, so a verification never observes a half-merged round.
#[derive(Clone, Debug, Default)]
pub struct Additions {
    /// The newest changeset timestamp the maps cover; 0 while only the
    /// baseline applies.
    timestamp: u64,
    /// Issuer name → listed serials.
    issuers: BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>>,
    /// Subject name → listed SPKI SHA-256s.
    subjects: BTreeMap<Vec<u8>, BTreeSet<[u8; 32]>>,
}

impl Additions {
    /// The newest changeset timestamp the maps cover.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Advance the covered timestamp to `timestamp` when it is newer. A
    /// changeset with no usable records still counts as seen.
    pub fn advance(&mut self, timestamp: u64) {
        self.timestamp = self.timestamp.max(timestamp);
    }

    /// Fold `entry` in.
    pub fn insert(&mut self, entry: record::Entry) {
        match entry {
            record::Entry::IssuerSerial { issuer, serial } => {
                self.issuers.entry(issuer).or_default().insert(serial);
            }
            record::Entry::SubjectKey { subject, hash } => {
                self.subjects.entry(subject).or_default().insert(hash);
            }
        }
    }

    fn issuer_serial_hit(&self, issuer: &[u8], serial: &[u8]) -> bool {
        self.issuers
            .get(issuer)
            .is_some_and(|serials| serials.contains(serial))
    }

    fn subject_hashes(&self, subject: &[u8]) -> Option<&BTreeSet<[u8; 32]>> {
        self.subjects.get(subject)
    }
}

/// A [`ServerCertVerifier`] that refuses OneCRL-listed certificates before
/// delegating to `inner`.
#[derive(Debug)]
pub struct OneCrlVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// Records fetched past the baseline; `None` unless the transport opted
    /// into refresh.
    additions: Option<Arc<ArcSwap<Additions>>>,
}

impl OneCrlVerifier {
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        additions: Option<Arc<ArcSwap<Additions>>>,
    ) -> Self {
        Self { inner, additions }
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
        let additions = self.additions.as_deref().map(ArcSwap::load_full);
        for der in std::iter::once(end_entity).chain(intermediates.iter()) {
            // A certificate that does not parse is the inner verifier's call.
            if let Ok(cert) = webpki::EndEntityCert::try_from(der)
                && listed(&cert, additions.as_deref()).is_some()
            {
                return Err(Error::InvalidCertificate(CertificateError::Revoked));
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

/// The record covering `cert`, if any: the compiled table first, then the
/// fetched additions.
fn listed(cert: &webpki::Cert<'_>, additions: Option<&Additions>) -> Option<Listing> {
    if issuer_serial_hit(cert.issuer(), cert.serial())
        || additions
            .is_some_and(|additions| additions.issuer_serial_hit(cert.issuer(), cert.serial()))
    {
        return Some(Listing::IssuerSerial);
    }
    let compiled = name_entry(subject_index(), subject_count(), cert.subject());
    let extra = additions.and_then(|additions| additions.subject_hashes(cert.subject()));
    if compiled.is_none() && extra.is_none() {
        return None;
    }
    // The SPKI hash costs a SHA-256 pass; only pay it on a subject hit.
    let spki = cert.subject_public_key_info();
    let hash = ring::digest::digest(&ring::digest::SHA256, spki.as_ref());
    if let Some(hashes) = compiled
        && search(hashes.1, |i| {
            TABLE[hashes.0 + i * 32..hashes.0 + i * 32 + 32].cmp(hash.as_ref())
        })
        .is_some()
    {
        return Some(Listing::SubjectKey);
    }
    if extra.is_some_and(|hashes| hashes.contains(hash.as_ref())) {
        return Some(Listing::SubjectKey);
    }
    None
}

fn issuer_serial_hit(issuer: &[u8], serial: &[u8]) -> bool {
    let Some(serials) = name_entry(16, issuer_count(), issuer) else {
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
    u32_at(8)
}

fn subject_count() -> usize {
    u32_at(12)
}

fn subject_index() -> usize {
    16 + issuer_count() * 16
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
    const CROSS_SIGNED: &str = include_str!("../../tests/onecrl/em-ov-tls-ca-g3c-by-aaa.pem");

    /// The same CA's certificate issued by `emSign Root TLS CA - G3` — listed
    /// by issuer+serial (and also subject+key; the issuer index is checked
    /// first). From emudhra.we-have-a-problem.com.
    const EMSIGN_ISSUED: &str = include_str!("../../tests/onecrl/em-ov-tls-ca-g3c-by-emsign.pem");

    /// `EM OV CS CA - G3B` issued by `emSign Root CS CA - G3` — a code-signing
    /// CA, not in the OneCRL snapshot at all.
    const UNLISTED: &str = include_str!("../../tests/onecrl/em-ov-cs-ca-g3b-by-emsign.pem");

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).expect("PEM must decode")
    }

    fn listed_for(pem: &str) -> Option<Listing> {
        let der = der(pem);
        let cert = webpki::EndEntityCert::try_from(&der).expect("certificate must parse");
        listed(&cert, None)
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
        let verifier = OneCrlVerifier::new(Arc::new(Inner), None);
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
