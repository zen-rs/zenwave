//! Shared test utilities for running against a local httpbin-like server.
//!
//! The real httpbin/httpbingo services are flaky or rate-limited in CI, so we
//! run a lightweight local replacement that implements just the endpoints the
//! test suite needs. Native tests share the in-process server in `fixture`;
//! the wasm lanes reach the standalone build of it (`tests/fixture-server`)
//! through `ZENWAVE_TEST_BASE_URL`, baked in at compile time by
//! `scripts/test-wasm.sh`.

#[cfg(not(target_arch = "wasm32"))]
#[path = "fixture.rs"]
mod fixture;
#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_imports)]
pub use fixture::*;

#[cfg(not(target_arch = "wasm32"))]
pub mod proxy;

/// A hostname for the TLS fixture that no resolver knows: only the test
/// proxies map it to the loopback server. Proxy tests reach the fixture
/// through this name because `CFNetwork` never proxies a literal loopback
/// address, and every backend must hand the name to the proxy unresolved.
#[allow(dead_code)]
pub const FIXTURE_HOST: &str = "zenwave-fixture.test";

/// Resolve a destination the way the test proxies do: the fixture hostname is
/// the loopback server, anything else goes to the system resolver.
#[allow(dead_code)]
pub fn resolve_for_proxy(host: &str, port: u16) -> (String, u16) {
    if host == FIXTURE_HOST {
        ("127.0.0.1".to_owned(), port)
    } else {
        (host.to_owned(), port)
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub mod socks5;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;

#[cfg(target_arch = "wasm32")]
mod local {
    /// The fixture URL is baked in at compile time: a browser has no runtime
    /// environment to consult, and falling back to a public service would make
    /// the lanes depend on it silently.
    const HTTPBIN_BASE: &str = match option_env!("ZENWAVE_TEST_BASE_URL") {
        Some(base) => base,
        None => panic!(
            "ZENWAVE_TEST_BASE_URL must be set when compiling the wasm tests; \
             scripts/test-wasm.sh starts the fixture and exports it"
        ),
    };

    pub fn httpbin_base() -> String {
        HTTPBIN_BASE.trim_end_matches('/').to_string()
    }

    pub fn httpbin_uri(path: &str) -> String {
        format!("{}/{}", httpbin_base(), path.trim_start_matches('/'))
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(unused_imports)]
pub use local::*;
