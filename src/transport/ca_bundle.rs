//! A PEM bundle of the platform roots plus the extra roots, for engines that
//! take a whole bundle instead of additional anchors (libcurl's `CAINFO_BLOB`).

use rustls_pki_types::CertificateDer;

use crate::Error;

/// Encode the system roots and `extra_roots` as one PEM document.
///
/// Only called when there are extra roots: without them the engine keeps its
/// own view of the platform store, which is the more faithful one.
pub fn platform_roots_with(extra_roots: &[CertificateDer<'static>]) -> Result<Vec<u8>, Error> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        let details = loaded
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::tls(format!(
            "no platform root certificates could be loaded: {details}"
        )));
    }
    for error in &loaded.errors {
        tracing::warn!(%error, "skipping an unreadable platform root certificate");
    }

    let pems = loaded
        .certs
        .iter()
        .chain(extra_roots)
        .map(|certificate| pem::Pem::new("CERTIFICATE", certificate.as_ref()))
        .collect::<Vec<_>>();
    Ok(pem::encode_many(&pems).into_bytes())
}
