//! The system trust anchors on Android, for the rustls engine.
//!
//! Android exposes its trust store to native code only through the Java
//! runtime, and the verifier that goes through it (`rustls-platform-verifier`)
//! reports every certificate whose issuer publishes revocation through a CRL
//! alone as revoked (rustls/rustls-platform-verifier#221). Let's Encrypt,
//! Google Trust Services and SSL.com all do, so that verdict covers most of
//! the public web. zenwave therefore verifies chains itself, with webpki,
//! against the anchors the system store keeps on disk: the Conscrypt mainline
//! module's directory on Android 14 and newer, the system image's directory
//! before that. Revocation is not checked, which is the posture of every
//! webpki client. Certificates the user installed are not trusted, which is
//! also Android's own default for applications.
use std::path::Path;

use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, pem::PemObject};

use crate::Error;

/// Where Android keeps the system trust anchors, one PEM file per anchor
/// (each followed by a textual dump the PEM parser skips).
const ANCHOR_DIRECTORIES: [&str; 2] = [
    "/apex/com.android.conscrypt/cacerts",
    "/system/etc/security/cacerts",
];

/// Every system trust anchor the process can read.
///
/// An anchor file that cannot be read or parsed is skipped with a warning, as
/// on the other platforms; a store with no anchor at all is an error, because
/// no TLS connection could ever succeed through it.
pub fn system_roots() -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();
    for directory in ANCHOR_DIRECTORIES.map(Path::new) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) => {
                    tracing::warn!(%error, directory = %directory.display(), "skipping an unreadable trust anchor entry");
                    continue;
                }
            };
            match CertificateDer::from_pem_file(&path) {
                Ok(anchor) => match store.add(anchor) {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(%error, path = %path.display(), "skipping a trust anchor webpki rejects");
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, path = %path.display(), "skipping an unreadable trust anchor");
                }
            }
        }
    }
    if store.is_empty() {
        return Err(Error::tls(format!(
            "no system trust anchors could be read from {}",
            ANCHOR_DIRECTORIES.join(" or ")
        )));
    }
    tracing::debug!(
        anchors = store.len(),
        "loaded the Android system trust anchors"
    );
    Ok(store)
}
