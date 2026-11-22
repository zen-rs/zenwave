//! Lean `no_std + alloc` TLS 1.3 [`CryptoProvider`] for embedded MCUs.
//!
//! Supplies RFC 8446's mandatory-to-implement `TLS13_AES_128_GCM_SHA256` suite,
//! X25519 + NIST P-256 ECDHE key exchange, and ECDSA-P256-SHA256 certificate
//! chain verification without linking RSA (`crypto_bigint`), SHA-384/512,
//! P-384, Ed25519, `ChaCha20`, or a global `getrandom` symbol.
//!
//! Both entropy (`rng: R`) and SHA-256 (`sha256: H`, used across the TLS 1.3
//! transcript hash, RFC 2104 HMAC/HKDF key schedule, and ECDSA prehash
//! verification) are injected by value so MCU peripherals such as ESP32-C6's
//! hardware `Rng` and `ShaBackend` replace software hashing and dead-code
//! eliminate `sha2` under LTO.

use alloc::{boxed::Box, sync::Arc, vec};

use aes_gcm::{
    Aes128Gcm,
    aead::{AeadInOut, Buffer, KeyInit, KeySizeUser},
};
use p256::{
    ecdsa::{DerSignature, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::Generate,
};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, NamedGroup, PeerMisbehaved,
    ProtocolVersion, SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
    crypto::{
        ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, KeyProvider, SecureRandom,
        SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms,
        cipher::{
            self, AeadKey, BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, Iv,
            MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
            PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
        },
        hash::{self, Hash, HashAlgorithm},
        hmac::{Hmac, Key as HmacKey, Tag},
        tls13::HkdfUsingHmac,
    },
    sign::SigningKey,
};
use rustls_pki_types::{
    AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm, alg_id,
};

/// AES-128-GCM authentication tag length in octets (RFC 5116 §5.1).
const GCM_TAG_LEN: usize = 16;

/// RFC 8446 §5.5 record confidentiality limit for AES-GCM (`2^23` records).
const AES_GCM_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;

/// SHA-256 block size in octets (FIPS 180-4 §5.1.1).
const SHA256_BLOCK_LEN: usize = 64;

/// SHA-256 digest size in octets (FIPS 180-4 §1).
const SHA256_OUTPUT_LEN: usize = 32;

/// Software SHA-256 implementation backed by `sha2::Sha256`.
///
/// Used by [`ecdsa_tls13_provider`]; [`ecdsa_tls13_provider_with_sha256`] avoids
/// referencing this type so LTO drops software SHA-256 when a hardware engine
/// supplies [`Hash`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SoftwareSha256;

#[derive(Clone)]
struct SoftwareSha256Context(sha2::Sha256);

impl Hash for SoftwareSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        use sha2::Digest as _;
        Box::new(SoftwareSha256Context(sha2::Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        use sha2::Digest as _;
        hash::Output::new(&sha2::Sha256::digest(data))
    }

    fn output_len(&self) -> usize {
        SHA256_OUTPUT_LEN
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

impl hash::Context for SoftwareSha256Context {
    fn fork_finish(&self) -> hash::Output {
        use sha2::Digest as _;
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> hash::Output {
        use sha2::Digest as _;
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.0.update(data);
    }
}

/// Build a lean TLS 1.3 [`CryptoProvider`] drawing randomness from `rng` and
/// hashing with [`SoftwareSha256`].
#[must_use]
pub fn ecdsa_tls13_provider<R>(rng: R) -> CryptoProvider
where
    R: SecureRandom + 'static,
{
    ecdsa_tls13_provider_with_sha256(rng, SoftwareSha256)
}

/// Build a lean TLS 1.3 [`CryptoProvider`] drawing randomness from `rng` and
/// routing every SHA-256 operation (TLS 1.3 transcript hash, HKDF key schedule,
/// and ECDSA-P256 signature verification) through `sha256`.
#[must_use]
pub fn ecdsa_tls13_provider_with_sha256<R, H>(rng: R, sha256: H) -> CryptoProvider
where
    R: SecureRandom + 'static,
    H: Hash + 'static,
{
    let parts = Box::leak(Box::new(ProviderFirstStage { rng, sha256 }));
    let second = Box::leak(Box::new(ProviderSecondStage {
        hmac: HmacOverHash(&parts.sha256),
        kx_x25519: X25519Kx(&parts.rng),
        kx_p256: Secp256r1Kx(&parts.rng),
        verify_p256: EcdsaP256Sha256Verify(&parts.sha256),
    }));
    let third = Box::leak(Box::new(ProviderThirdStage {
        hkdf: HkdfUsingHmac(&second.hmac),
        verify_list: [&second.verify_p256],
    }));
    let fourth = Box::leak(Box::new(ProviderFourthStage {
        suite: Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &parts.sha256,
                confidentiality_limit: AES_GCM_CONFIDENTIALITY_LIMIT,
            },
            hkdf_provider: &third.hkdf,
            aead_alg: &Tls13Aes128Gcm,
            quic: None,
        },
        verify_mapping: [(
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &third.verify_list[..],
        )],
    }));

    CryptoProvider {
        cipher_suites: vec![SupportedCipherSuite::Tls13(&fourth.suite)],
        kx_groups: vec![&second.kx_x25519, &second.kx_p256],
        signature_verification_algorithms: WebPkiSupportedAlgorithms {
            all: &third.verify_list,
            mapping: &fourth.verify_mapping,
        },
        secure_random: &parts.rng,
        key_provider: &NoClientAuthKeys,
    }
}

struct ProviderFirstStage<R, H> {
    rng: R,
    sha256: H,
}

struct ProviderSecondStage {
    hmac: HmacOverHash,
    kx_x25519: X25519Kx,
    kx_p256: Secp256r1Kx,
    verify_p256: EcdsaP256Sha256Verify,
}

struct ProviderThirdStage {
    hkdf: HkdfUsingHmac<'static>,
    verify_list: [&'static dyn SignatureVerificationAlgorithm; 1],
}

struct ProviderFourthStage {
    suite: Tls13CipherSuite,
    verify_mapping: [(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    ); 1],
}

#[derive(Debug)]
struct NoClientAuthKeys;

impl KeyProvider for NoClientAuthKeys {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        Err(rustls::Error::General(
            "embedded-tls-ecdsa does not load client-authentication private keys".into(),
        ))
    }
}

struct HmacOverHash(&'static dyn Hash);

struct HmacKeyOverHash {
    inner_prefix: Box<dyn hash::Context>,
    outer_prefix: Box<dyn hash::Context>,
}

impl Hmac for HmacOverHash {
    fn with_key(&self, key: &[u8]) -> Box<dyn HmacKey> {
        let mut block_key = [0u8; SHA256_BLOCK_LEN];
        if key.len() > SHA256_BLOCK_LEN {
            let hashed = self.0.hash(key);
            let digest = hashed.as_ref();
            block_key[..digest.len()].copy_from_slice(digest);
        } else {
            block_key[..key.len()].copy_from_slice(key);
        }

        // RFC 2104 §2: ipad = 0x36 repeated B times, opad = 0x5c repeated B times.
        let mut ipad = [0x36u8; SHA256_BLOCK_LEN];
        let mut opad = [0x5cu8; SHA256_BLOCK_LEN];
        for i in 0..SHA256_BLOCK_LEN {
            ipad[i] ^= block_key[i];
            opad[i] ^= block_key[i];
        }

        let mut inner_prefix = self.0.start();
        inner_prefix.update(&ipad);
        let mut outer_prefix = self.0.start();
        outer_prefix.update(&opad);

        Box::new(HmacKeyOverHash {
            inner_prefix,
            outer_prefix,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len()
    }
}

impl HmacKey for HmacKeyOverHash {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut inner = self.inner_prefix.fork();
        inner.update(first);
        for slice in middle {
            inner.update(slice);
        }
        inner.update(last);
        let inner_digest = inner.finish();

        let mut outer = self.outer_prefix.fork();
        outer.update(inner_digest.as_ref());
        Tag::new(outer.finish().as_ref())
    }

    fn tag_len(&self) -> usize {
        SHA256_OUTPUT_LEN
    }
}

struct Tls13Aes128Gcm;

struct Tls13Aes128GcmCipher(Aes128Gcm, Iv);

impl Tls13AeadAlgorithm for Tls13Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let cipher = Aes128Gcm::new_from_slice(key.as_ref())
            .expect("TLS13_AES_128_GCM_SHA256 supplies a 16-byte key");
        Box::new(Tls13Aes128GcmCipher(cipher, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let cipher = Aes128Gcm::new_from_slice(key.as_ref())
            .expect("TLS13_AES_128_GCM_SHA256 supplies a 16-byte key");
        Box::new(Tls13Aes128GcmCipher(cipher, iv))
    }

    fn key_len(&self) -> usize {
        Aes128Gcm::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

struct EncryptPayload<'a>(&'a mut PrefixedPayload);

impl AsRef<[u8]> for EncryptPayload<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for EncryptPayload<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Buffer for EncryptPayload<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

struct DecryptPayload<'a, 'p>(&'a mut BorrowedPayload<'p>);

impl AsRef<[u8]> for DecryptPayload<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl AsMut<[u8]> for DecryptPayload<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Buffer for DecryptPayload<'_, '_> {
    fn extend_from_slice(&mut self, _other: &[u8]) -> aes_gcm::aead::Result<()> {
        Err(aes_gcm::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

impl MessageEncrypter for Tls13Aes128GcmCipher {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        self.0
            .encrypt_in_place(&nonce.into(), &aad, &mut EncryptPayload(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + GCM_TAG_LEN
    }
}

impl MessageDecrypter for Tls13Aes128GcmCipher {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut msg.payload;
        let nonce = Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(payload.len());
        self.0
            .decrypt_in_place(&nonce.into(), &aad, &mut DecryptPayload(payload))
            .map_err(|_| rustls::Error::DecryptError)?;
        msg.into_tls13_unpadded_message()
    }
}

struct Seed32Rng {
    bytes: [u8; 32],
}

impl rand_core::TryRng for Seed32Rng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
        ]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5],
            self.bytes[6],
            self.bytes[7],
        ]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let copy_len = dst.len().min(self.bytes.len());
        dst[..copy_len].copy_from_slice(&self.bytes[..copy_len]);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Seed32Rng {}

#[derive(Debug)]
struct RngError;

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecureRandom::fill failed")
    }
}

impl core::error::Error for RngError {}

struct SecureRandomRng<'a>(&'a dyn SecureRandom);

impl rand_core::TryRng for SecureRandomRng<'_> {
    type Error = RngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.0.fill(&mut buf).map_err(|_| RngError)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.0.fill(&mut buf).map_err(|_| RngError)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(dst).map_err(|_| RngError)
    }
}

impl rand_core::TryCryptoRng for SecureRandomRng<'_> {}

#[derive(Debug)]
struct X25519Kx(&'static dyn SecureRandom);

struct X25519Active {
    secret: x25519_dalek::EphemeralSecret,
    pub_key: x25519_dalek::PublicKey,
}

impl SupportedKxGroup for X25519Kx {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let mut bytes = [0u8; 32];
        self.0
            .fill(&mut bytes)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let mut seed_rng = Seed32Rng { bytes };
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut seed_rng);
        let pub_key = (&secret).into();
        Ok(Box::new(X25519Active { secret, pub_key }))
    }
}

impl ActiveKeyExchange for X25519Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_bytes: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&peer_bytes.into());
        Ok(shared.as_bytes().as_slice().into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[derive(Debug)]
struct Secp256r1Kx(&'static dyn SecureRandom);

struct Secp256r1Active {
    secret: p256::ecdh::EphemeralSecret,
    pub_key: Box<[u8]>,
}

impl SupportedKxGroup for Secp256r1Kx {
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let mut rng = SecureRandomRng(self.0);
        let secret = p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut rng)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let pub_key = p256::PublicKey::from(&secret).to_sec1_bytes();
        Ok(Box::new(Secp256r1Active { secret, pub_key }))
    }
}

impl ActiveKeyExchange for Secp256r1Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let their_pub = p256::PublicKey::from_sec1_bytes(peer_pub_key)
            .map_err(|_| rustls::Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&their_pub);
        Ok(shared.raw_secret_bytes().as_slice().into())
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

struct EcdsaP256Sha256Verify(&'static dyn Hash);

impl core::fmt::Debug for EcdsaP256Sha256Verify {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EcdsaP256Sha256Verify")
    }
}

impl SignatureVerificationAlgorithm for EcdsaP256Sha256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let sig = DerSignature::from_bytes(signature).map_err(|_| InvalidSignature)?;
        let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let digest = self.0.hash(message);
        vk.verify_prehash(digest.as_ref(), &sig)
            .map_err(|_| InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::Transport;

    #[derive(Debug)]
    struct CountingRng<'a>(&'a AtomicUsize);

    impl SecureRandom for CountingRng<'_> {
        fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            self.0.fetch_add(1, Ordering::Relaxed);
            rustls::crypto::ring::default_provider()
                .secure_random
                .fill(buf)
        }
    }

    struct CountingSha256<'a>(&'a AtomicUsize);

    impl Hash for CountingSha256<'_> {
        fn start(&self) -> Box<dyn hash::Context> {
            self.0.fetch_add(1, Ordering::Relaxed);
            SoftwareSha256.start()
        }

        fn hash(&self, data: &[u8]) -> hash::Output {
            self.0.fetch_add(1, Ordering::Relaxed);
            SoftwareSha256.hash(data)
        }

        fn output_len(&self) -> usize {
            SoftwareSha256.output_len()
        }

        fn algorithm(&self) -> HashAlgorithm {
            SoftwareSha256.algorithm()
        }
    }

    #[derive(Debug)]
    struct FixedTime(rustls_pki_types::UnixTime);

    impl rustls::time_provider::TimeProvider for FixedTime {
        fn current_time(&self) -> Option<rustls_pki_types::UnixTime> {
            Some(self.0)
        }
    }

    #[test]
    fn custom_rng_and_sha256_drive_tls13_handshake_and_ticket_resumption() {
        static RNG_CALLS: AtomicUsize = AtomicUsize::new(0);
        static SHA_CALLS: AtomicUsize = AtomicUsize::new(0);

        let certified = rcgen::generate_simple_self_signed(vec!["esp32c6.local".to_owned()])
            .expect("self-signed ECDSA P-256 cert");
        let cert_pem = certified.cert.pem();
        let cert_der = rustls_pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let now = rustls_pki_types::UnixTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
        );

        let time_provider: Arc<dyn rustls::time_provider::TimeProvider> = Arc::new(FixedTime(now));
        let ring_provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut srv_cfg =
            rustls::ServerConfig::builder_with_details(ring_provider, Arc::clone(&time_provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap();
        srv_cfg.send_tls13_tickets = 1;
        let srv_cfg = Arc::new(srv_cfg);

        let lean_provider = Arc::new(ecdsa_tls13_provider_with_sha256(
            CountingRng(&RNG_CALLS),
            CountingSha256(&SHA_CALLS),
        ));
        let transport = Transport::builder()
            .extra_root_certificates_pem(cert_pem.as_bytes())
            .unwrap()
            .embedded_tls_provider(lean_provider, time_provider)
            .build()
            .unwrap();

        let client_cfg = transport.embedded_tls().unwrap();
        for expected_kind in [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed] {
            let server_name =
                rustls_pki_types::ServerName::try_from("esp32c6.local".to_owned()).unwrap();
            let mut client = rustls::client::UnbufferedClientConnection::new(
                Arc::clone(client_cfg),
                server_name,
            )
            .unwrap();
            let mut server =
                rustls::server::UnbufferedServerConnection::new(Arc::clone(&srv_cfg)).unwrap();
            let mut c2s = alloc::vec::Vec::new();
            let mut s2c = alloc::vec::Vec::new();

            for _ in 0..16 {
                step_client(&mut client, &mut s2c, &mut c2s);
                step_server(&mut server, &mut c2s, &mut s2c);
            }
            assert_eq!(server.handshake_kind(), Some(expected_kind));
        }

        assert!(RNG_CALLS.load(Ordering::Relaxed) >= 2);
        assert!(SHA_CALLS.load(Ordering::Relaxed) >= 4);
    }

    fn step_client(
        conn: &mut rustls::client::UnbufferedClientConnection,
        rx: &mut alloc::vec::Vec<u8>,
        tx: &mut alloc::vec::Vec<u8>,
    ) {
        use rustls::unbuffered::ConnectionState;
        loop {
            let status = conn.process_tls_records(rx);
            let discard = status.discard;
            match status.state.unwrap() {
                ConnectionState::EncodeTlsData(mut enc) => {
                    let mut buf = vec![0u8; 4096];
                    let n = enc.encode(&mut buf).unwrap();
                    tx.extend_from_slice(&buf[..n]);
                    rx.drain(..discard);
                }
                ConnectionState::TransmitTlsData(done) => {
                    done.done();
                    rx.drain(..discard);
                }
                ConnectionState::WriteTraffic(mut wt) => {
                    rx.drain(..discard);
                    let mut buf = vec![0u8; 128];
                    let n = wt.encrypt(b"ping", &mut buf).unwrap();
                    tx.extend_from_slice(&buf[..n]);
                    break;
                }
                _ => {
                    rx.drain(..discard);
                    break;
                }
            }
        }
    }

    fn step_server(
        conn: &mut rustls::server::UnbufferedServerConnection,
        rx: &mut alloc::vec::Vec<u8>,
        tx: &mut alloc::vec::Vec<u8>,
    ) {
        use rustls::unbuffered::ConnectionState;
        loop {
            let status = conn.process_tls_records(rx);
            let mut discard = status.discard;
            match status.state.unwrap() {
                ConnectionState::EncodeTlsData(mut enc) => {
                    let mut buf = vec![0u8; 4096];
                    let n = enc.encode(&mut buf).unwrap();
                    tx.extend_from_slice(&buf[..n]);
                    rx.drain(..discard);
                }
                ConnectionState::TransmitTlsData(done) => {
                    done.done();
                    rx.drain(..discard);
                }
                ConnectionState::ReadTraffic(mut rt) => {
                    while let Some(Ok(rec)) = rt.next_record() {
                        discard += rec.discard;
                        assert_eq!(rec.payload, b"ping");
                    }
                    rx.drain(..discard);
                }
                _ => {
                    rx.drain(..discard);
                    break;
                }
            }
        }
    }
}
