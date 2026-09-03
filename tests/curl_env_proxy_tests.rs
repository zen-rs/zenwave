//! libcurl reads `http_proxy` on its own unless told not to. zenwave's proxy
//! rules are the only source of truth, so with `Proxy::none()` a poisoned
//! environment must not divert the request. Lives in its own binary because
//! it mutates the process environment.
#![cfg(all(not(target_arch = "wasm32"), feature = "curl-backend"))]

mod common;

use common::httpbin_uri;
use zenwave::{Client, Proxy, Transport, backend::CurlBackend};

#[test_executors::async_test]
async fn libcurl_does_not_read_the_environment_on_its_own() {
    // A proxy nothing listens on: if libcurl consulted the variable, the
    // request would fail with a connection error instead of succeeding.
    // SAFETY: this is the only test in this binary, so nothing else observes
    // the environment concurrently.
    unsafe {
        std::env::set_var("http_proxy", "http://127.0.0.1:1");
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:1");
        std::env::set_var("all_proxy", "http://127.0.0.1:1");
    }
    let transport = Transport::builder()
        .proxy(Proxy::none())
        .build()
        .expect("transport builds");
    let mut client = CurlBackend::new(transport);
    client
        .get(httpbin_uri("/get"))
        .expect("valid request")
        .await
        .expect("Proxy::none() means a direct connection whatever the environment says");
}
