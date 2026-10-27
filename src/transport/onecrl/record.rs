//! One Remote Settings changeset record, decoded into the two lookup shapes.
//!
//! This file is deliberately free of `crate::` paths: `build.rs` includes it
//! with `#[path]` to compile the pinned snapshot, so both build-time
//! validation and the runtime refresher share one parser. Malformed input is
//! `Err` — the build panics on it, the refresher logs and skips the record.

use base64::Engine as _;

/// What a record lists, decoded: either an issuer name with a serial number,
/// or a subject name with the SHA-256 of its SPKI. The names are the DER
/// `SEQUENCE` content only — tag and length stripped the way
/// `webpki::Cert::issuer()` and `subject()` report them.
#[derive(Debug)]
pub enum Entry {
    /// An `issuerName` + `serialNumber` record.
    IssuerSerial {
        /// The issuer name (DER SEQUENCE content).
        issuer: Vec<u8>,
        /// The serial number (DER INTEGER content).
        serial: Vec<u8>,
    },
    /// A `subject` + `pubKeyHash` record.
    SubjectKey {
        /// The subject name (DER SEQUENCE content).
        subject: Vec<u8>,
        /// The SHA-256 of the certificate's SPKI.
        hash: [u8; 32],
    },
}

/// Decode one changeset record. `Ok(None)` is a tombstone (`"deleted":
/// true`) — deletions are ignored.
///
/// # Errors
///
/// Returns `Err` when a base64 field does not decode, a name is not one DER
/// SEQUENCE TLV, `pubKeyHash` is not 32 bytes, or the record is neither
/// shape.
pub fn entry(record: &serde_json::Value) -> Result<Option<Entry>, String> {
    if record["deleted"].as_bool() == Some(true) {
        return Ok(None);
    }
    match (
        field(record, "issuerName")?,
        field(record, "serialNumber")?,
        field(record, "subject")?,
        field(record, "pubKeyHash")?,
    ) {
        (Some(issuer), Some(serial), None, None) => Ok(Some(Entry::IssuerSerial {
            issuer: name(&issuer)?,
            serial,
        })),
        (None, None, Some(subject), Some(hash)) => Ok(Some(Entry::SubjectKey {
            subject: name(&subject)?,
            hash: hash
                .try_into()
                .map_err(|_| "a OneCRL pubKeyHash must be a 32-byte SHA-256".to_owned())?,
        })),
        _ => {
            Err("a OneCRL record must be issuerName+serialNumber or subject+pubKeyHash".to_owned())
        }
    }
}

/// Base64-decode `record[name]`; `None` when the field is absent.
fn field(record: &serde_json::Value, name: &'static str) -> Result<Option<Vec<u8>>, String> {
    record[name]
        .as_str()
        .map(|value| {
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|error| format!("a OneCRL record's {name}: {error}"))
        })
        .transpose()
}

/// The content of a DER `SEQUENCE` TLV — `webpki::Cert::issuer()` and
/// `subject()` report names without the outer tag and length, so records are
/// stored the same way. Anything that is not exactly one SEQUENCE is not a
/// Name.
///
/// # Errors
///
/// Returns `Err` when `der` is not one complete DER SEQUENCE TLV.
pub fn name(der: &[u8]) -> Result<Vec<u8>, String> {
    if der.first() != Some(&0x30) {
        return Err("a OneCRL name must be a SEQUENCE".to_owned());
    }
    let Some(&first) = der.get(1) else {
        return Err("a OneCRL name's length must be DER".to_owned());
    };
    let (content, total) = match first {
        short if short < 0x80 => (2, 2 + usize::from(short)),
        first => {
            let n = usize::from(first & 0x7f);
            if !(1..=4).contains(&n) || der.len() < 2 + n {
                return Err("a OneCRL name's length must be DER".to_owned());
            }
            let mut len = 0usize;
            for byte in &der[2..2 + n] {
                len = len << 8 | usize::from(*byte);
            }
            (2 + n, 2 + n + len)
        }
    };
    if total != der.len() {
        return Err("a OneCRL name must be exactly one SEQUENCE TLV".to_owned());
    }
    Ok(der[content..].to_vec())
}
