//! Emits `cfg` aliases so platform and feature conditions read the same everywhere.
use cfg_aliases::cfg_aliases;

/// The changeset record parser — the same file `src/transport/onecrl.rs`
/// compiles, so the snapshot and the refresher's fetched records decode
/// identically.
#[cfg(feature = "onecrl")]
#[path = "src/transport/onecrl/record.rs"]
mod record;

/// Fetch-and-verify shared by the pinned assets (OneCRL snapshot, Public
/// Suffix List): a packaged crate ships the file at its root, a git build
/// downloads it from the pinned URL. Either way the SHA-256 is checked
/// against the pin before the bytes are used.
#[cfg(any(feature = "onecrl", feature = "public-suffix"))]
mod pinned {
    use std::{fs, path::Path};

    /// The verified bytes of the pinned asset `pin_file` names: `asset` is
    /// the file's name both at the manifest root (the copy a packaged crate
    /// ships) and under `OUT_DIR` (where a git build's download is kept);
    /// `label` is how error messages call it.
    pub fn fetch(
        manifest: &Path,
        out_dir: &Path,
        pin_file: &str,
        asset: &str,
        label: &str,
    ) -> Vec<u8> {
        let pin: serde_json::Value = serde_json::from_slice(
            &fs::read(manifest.join(pin_file))
                .unwrap_or_else(|error| panic!("read {pin_file}: {error}")),
        )
        .unwrap_or_else(|error| panic!("parse {pin_file}: {error}"));
        let url = pin["url"]
            .as_str()
            .unwrap_or_else(|| panic!("{pin_file} needs url"));
        let expected = pin["sha256"]
            .as_str()
            .unwrap_or_else(|| panic!("{pin_file} needs sha256"));
        let bytes = if manifest.join(asset).exists() {
            fs::read(manifest.join(asset))
                .unwrap_or_else(|error| panic!("read packaged {asset}: {error}"))
        } else {
            let response = minreq::get(url)
                .send()
                .unwrap_or_else(|e| panic!("downloading {label} from {url}: {e}"));
            assert!(
                response.status_code == 200,
                "downloading {label} from {url}: HTTP {}",
                response.status_code
            );
            let bytes = response.into_bytes();
            fs::write(out_dir.join(asset), &bytes)
                .unwrap_or_else(|error| panic!("write downloaded {asset}: {error}"));
            bytes
        };
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        assert!(
            digest.as_ref() == hex(expected).as_slice(),
            "{label}'s SHA-256 does not match {pin_file}'s {expected}"
        );
        bytes
    }

    /// Decode a lowercase hex string such as a pin's `sha256`.
    fn hex(value: &str) -> Vec<u8> {
        assert!(
            value.len().is_multiple_of(2),
            "the pinned sha256 must be hex"
        );
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(str::from_utf8(pair).unwrap(), 16)
                    .expect("the pinned sha256 must be hex")
            })
            .collect()
    }
}

fn main() {
    cfg_aliases! {
        // Anything that is not the browser/Workers Fetch backend.
        native: { not(target_arch = "wasm32") },
        // The shared TCP/TLS connector is needed by hyper and by native websockets.
        connector: { all(not(target_arch = "wasm32"), any(feature = "hyper-backend", feature = "ws")) },
        // TLS engine compiled into that connector; an engine feature enabled
        // next to curl or URLSession alone has nothing to serve. Features are
        // additive, so `rustls` wins when both engines are enabled.
        tls_rustls: { all(connector, feature = "rustls") },
        tls_native: { all(connector, feature = "native-tls", not(feature = "rustls")) },
        tls_engine: { any(tls_rustls, tls_native) },
        // rustls-platform-verifier needs a JVM handle on Android.
        android_verifier: { all(target_os = "android", tls_rustls) },
        // QUIC transport and the h3 connection type exist only where the
        // shared connector, the hyper backend and the rustls engine do.
        http3: { all(connector, feature = "hyper-backend", feature = "http3") },
        // Unix domain sockets: every `unix` target has AF_UNIX, but wasm32-wasi
        // is `unix` without being `native` — the connector does not exist there.
        unix_socket: { all(unix, native) },
        // The OneCRL baseline, enforced where the rustls engine verifies chains
        // with webpki: rustls-platform-verifier's disk-root verifier (every
        // `unix` but Apple and Android) and the Android disk-root verifier.
        // Apple and Windows verify through the OS trust service, which ships
        // its own distrust.
        onecrl: { all(tls_rustls, feature = "onecrl", not(target_vendor = "apple"), not(windows)) },
        // Which backend `DefaultBackend` resolves to: hyper wins, then URLSession, then libcurl.
        apple_backend: { all(target_vendor = "apple", feature = "apple-backend") },
        default_hyper: { all(not(target_arch = "wasm32"), feature = "hyper-backend") },
        default_apple: { all(target_vendor = "apple", feature = "apple-backend", not(feature = "hyper-backend")) },
        default_curl: { all(
            not(target_arch = "wasm32"),
            feature = "curl-backend",
            not(feature = "hyper-backend"),
            not(all(target_vendor = "apple", feature = "apple-backend"))
        ) },
    }

    // The pins and their packaged assets are inputs to the compiled tables; a
    // missing asset (a git build) still gets a rerun edge so its later
    // appearance regenerates.
    println!("cargo:rerun-if-changed=onecrl.pin.json");
    println!("cargo:rerun-if-changed=onecrl.json");
    println!("cargo:rerun-if-changed=public_suffix.pin.json");
    println!("cargo:rerun-if-changed=public_suffix_list.dat");

    #[cfg(feature = "onecrl")]
    onecrl::generate();
    #[cfg(feature = "public-suffix")]
    public_suffix::generate();
}

#[cfg(feature = "public-suffix")]
mod public_suffix {
    use std::{env, fs, path::PathBuf};

    /// The pinned Public Suffix List, verbatim under `OUT_DIR` for
    /// `src/cookie.rs` to `include_str!`.
    pub fn generate() {
        let manifest =
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
        let list = crate::pinned::fetch(
            &manifest,
            &out_dir,
            "public_suffix.pin.json",
            "public_suffix_list.dat",
            "the Public Suffix List",
        );
        fs::write(out_dir.join("public_suffix_list.dat"), list)
            .expect("write public_suffix_list.dat");
    }
}

#[cfg(feature = "onecrl")]
mod onecrl {
    use std::{collections::BTreeMap, env, fs, path::PathBuf};

    /// Generate the table, but only when the *target* — not the host running
    /// this build script — compiles the `onecrl` cfg. Feature cfgs apply to a
    /// build script's own compilation, so the target conditions come from the
    /// `CARGO_CFG_*`/`CARGO_FEATURE_*` environment instead.
    pub fn generate() {
        let feature = |name: &str| env::var_os(format!("CARGO_FEATURE_{name}")).is_some();
        let connector = feature("HYPER_BACKEND") || feature("WS");
        let tls_rustls = connector && feature("RUSTLS");
        let applies = tls_rustls
            && env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32")
            && env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple")
            && env::var_os("CARGO_CFG_WINDOWS").is_none();
        if !applies {
            return;
        }

        let manifest =
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
        let snapshot = crate::pinned::fetch(
            &manifest,
            &out_dir,
            "onecrl.pin.json",
            "onecrl.json",
            "the OneCRL snapshot",
        );
        fs::write(out_dir.join("onecrl.bin"), compile(&snapshot)).expect("write onecrl.bin");
    }

    /// The changeset grouped into the two indexable forms: issuer name to its
    /// serial values, subject name to its SPKI SHA-256s.
    struct Indexes {
        timestamp: u64,
        issuers: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
        subjects: BTreeMap<Vec<u8>, Vec<[u8; 32]>>,
    }

    /// The changeset grouped into the two indexable forms.
    fn records(snapshot: &[u8]) -> Indexes {
        let changeset: serde_json::Value =
            serde_json::from_slice(snapshot).expect("parse the OneCRL snapshot");
        let timestamp = changeset["timestamp"]
            .as_u64()
            .expect("the OneCRL snapshot needs a timestamp");
        let changes = changeset["changes"]
            .as_array()
            .expect("the OneCRL snapshot's changes must be an array");
        let mut issuers = BTreeMap::new();
        let mut subjects = BTreeMap::new();
        for record in changes {
            match crate::record::entry(record).expect("a OneCRL record must decode") {
                Some(crate::record::Entry::IssuerSerial { issuer, serial }) => {
                    issuers.entry(issuer).or_insert_with(Vec::new).push(serial);
                }
                Some(crate::record::Entry::SubjectKey { subject, hash }) => {
                    subjects.entry(subject).or_insert_with(Vec::new).push(hash);
                }
                None => {}
            }
        }
        Indexes {
            timestamp,
            issuers,
            subjects,
        }
    }

    /// Compile the changeset into the binary table `src/transport/onecrl.rs`
    /// searches in place:
    ///
    /// ```text
    /// u64 timestamp | u32 issuer_count | u32 subject_count
    /// issuer index:  issuer_count × { name_off, name_len, serials_off, serials_len }
    /// subject index: subject_count × { name_off, name_len, hashes_off, hashes_len }
    /// areas:         per issuer, serials_len × { off, len } serial sub-index
    ///                entries, then per subject hashes_len × 32-byte hashes
    /// byte area:     every name and serial value, concatenated
    /// ```
    ///
    /// `timestamp` is the changeset's top-level timestamp, little-endian
    /// `u64`; the refresher asks Remote Settings for everything after it. All
    /// other offsets are little-endian `u32` measured from byte 0; each index
    /// is sorted by the bytes it keys on so lookups binary-search.
    fn compile(snapshot: &[u8]) -> Vec<u8> {
        let Indexes {
            timestamp,
            issuers,
            subjects,
        } = records(snapshot);
        let mut table = Vec::new();
        table.extend_from_slice(&timestamp.to_le_bytes());
        write_u32(&mut table, 8, issuers.len());
        write_u32(&mut table, 12, subjects.len());
        table.resize(16 + (issuers.len() + subjects.len()) * 16, 0);
        let issuer_index = 16;
        let subject_index = 16 + issuers.len() * 16;
        let areas_base = subject_index + subjects.len() * 16;

        let mut areas = Vec::new();
        let mut bytes = Vec::new();
        let mut byte_area = |value: &[u8]| -> (usize, usize) {
            let at = bytes.len();
            bytes.extend_from_slice(value);
            (at, value.len())
        };

        let mut issuer_entries = Vec::new();
        for (issuer, mut serials) in issuers {
            let (name_off, name_len) = byte_area(&issuer);
            let serials_off = areas.len();
            serials.sort();
            serials.dedup();
            for serial in &serials {
                let (off, len) = byte_area(serial);
                areas.extend_from_slice(&u32::try_from(off).unwrap().to_le_bytes());
                areas.extend_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
            }
            issuer_entries.push((name_off, name_len, serials_off, serials.len()));
        }

        let serials_end = areas.len();
        let mut subject_entries = Vec::new();
        for (subject, mut hashes) in subjects {
            let (name_off, name_len) = byte_area(&subject);
            let hashes_off = areas.len();
            hashes.sort_unstable();
            hashes.dedup();
            for hash in &hashes {
                areas.extend_from_slice(hash);
            }
            subject_entries.push((name_off, name_len, hashes_off, hashes.len()));
        }

        let bytes_base = areas_base + areas.len();
        // Serial sub-index entries point into the byte area like names do.
        for off in (0..serials_end).step_by(8) {
            let relative = u32::from_le_bytes(areas[off..off + 4].try_into().unwrap()) as usize;
            areas[off..off + 4]
                .copy_from_slice(&u32::try_from(bytes_base + relative).unwrap().to_le_bytes());
        }
        for (i, (name_off, name_len, serials_off, serials_len)) in issuer_entries.iter().enumerate()
        {
            write_u32(&mut table, issuer_index + i * 16, bytes_base + name_off);
            write_u32(&mut table, issuer_index + i * 16 + 4, *name_len);
            write_u32(
                &mut table,
                issuer_index + i * 16 + 8,
                areas_base + serials_off,
            );
            write_u32(&mut table, issuer_index + i * 16 + 12, *serials_len);
        }
        for (i, (name_off, name_len, hashes_off, hashes_len)) in subject_entries.iter().enumerate()
        {
            write_u32(&mut table, subject_index + i * 16, bytes_base + name_off);
            write_u32(&mut table, subject_index + i * 16 + 4, *name_len);
            write_u32(
                &mut table,
                subject_index + i * 16 + 8,
                areas_base + hashes_off,
            );
            write_u32(&mut table, subject_index + i * 16 + 12, *hashes_len);
        }
        table.extend_from_slice(&areas);
        table.extend_from_slice(&bytes);
        table
    }

    fn write_u32(table: &mut Vec<u8>, offset: usize, value: usize) {
        if table.len() < offset + 4 {
            table.resize(offset + 4, 0);
        }
        table[offset..offset + 4].copy_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
    }
}
