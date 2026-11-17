//! Compile- and unit-checked WASI Preview 3 backend tests (`wasi-backend`).
//!
//! Verifies that `WasiBackend`, `DefaultBackend`, `DefaultClient`, `client()`,
//! one-shot functions, `OAuth2ClientCredentials`, `Transport` timeout setters,
//! `WasiClock`, and middleware combinators compose cleanly on `wasm32-wasip2`
//! and `wasm32-wasip3`.
#![cfg(wasi_backend)]
#![expect(
    dead_code,
    reason = "some functions verify async Send/Client bounds at compile time without a WASI runtime"
)]

use std::time::Duration;

use zenwave::{
    Client, OAuth2ClientCredentials, Transport, backend::WasiBackend, client, client_with,
    clock::Clocked, delete, get, post, put,
};

#[test]
fn backend_and_transport_build_with_timeouts() {
    let transport = Transport::builder()
        .connect_timeout(Duration::from_secs(2))
        .response_head_timeout(Duration::from_secs(5))
        .body_idle_timeout(Duration::from_secs(10))
        .build()
        .expect("transport builds");

    let backend = WasiBackend::new(transport.clone());
    let _clock = backend.clock();

    let default_client = client_with(transport);
    let _client_clock = default_client.clock();
    let _default = client();
    let _oauth = OAuth2ClientCredentials::new("https://auth.example.com/token", "id", "secret");
}

fn combined_client() -> impl Clocked {
    client()
        .timeout(Duration::from_secs(5))
        .retry(2)
        .bearer_auth("token")
        .enable_cookie()
        .error_for_status()
}

async fn exercises_api_bounds() {
    let mut c = combined_client();
    let _ = c.get("https://example.com/").unwrap().await;
    let _ = get("https://example.com/").await;
    let _ = post("https://example.com/").await;
    let _ = put("https://example.com/").await;
    let _ = delete("https://example.com/").await;
}

#[cfg(native)]
async fn rejects_unsupported_native_transport_options() {
    use http_kit::Endpoint as _;
    use zenwave::{ConfigError, Error, Proxy};

    let proxy = Proxy::builder().all("http://127.0.0.1:8080").build();
    let proxied_transport = Transport::builder()
        .proxy(proxy)
        .build()
        .expect("proxy transport builds");
    let mut backend = WasiBackend::new(proxied_transport);
    let mut req = zenwave::Request::new(zenwave::Body::empty());
    *req.uri_mut() = "https://example.com/".parse().expect("valid URI");
    let err = backend.respond(&mut req).await.unwrap_err();
    assert!(matches!(
        err,
        Error::Config(ConfigError::Unsupported { .. })
    ));

    let cert_transport = Transport::builder()
        .extra_root_certificate_der(vec![0x30, 0x00])
        .build()
        .expect("extra root transport builds");
    let mut backend = WasiBackend::new(cert_transport);
    let err = backend.respond(&mut req).await.unwrap_err();
    assert!(matches!(
        err,
        Error::Config(ConfigError::Unsupported { .. })
    ));
}
