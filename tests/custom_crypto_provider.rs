//! Without `rustls-ring`, `zenwave` compiles no built-in cryptography provider:
//! building a `Transport` fails with a TLS configuration error until the
//! application installs a process-default `rustls::crypto::CryptoProvider`.
#![cfg(all(
    not(target_arch = "wasm32"),
    feature = "rustls",
    not(ring)
))]

use zenwave::Transport;

#[test]
fn requires_and_uses_process_default_crypto_provider() {
    let missing = Transport::builder()
        .build()
        .expect_err("Transport::build must fail before a CryptoProvider is installed");
    let rendered = missing.to_string();
    assert!(
        rendered.contains("CryptoProvider"),
        "expected CryptoProvider message, got: {rendered}"
    );

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("process-default CryptoProvider installs once");

    Transport::builder()
        .build()
        .expect("Transport::build succeeds once CryptoProvider::install_default has run");
}
