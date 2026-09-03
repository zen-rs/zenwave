//! The TLS cases that need the JVM on Android: what `tests/transport_tests.rs`
//! and `tests/proxy_tests.rs` assert on every other platform.

use base64::Engine as _;
use zenwave::{Client, Error, Proxy, ResponseExt as _, Transport, backend::HyperBackend};

use crate::common::{FIXTURE_HOST, proxy::HttpProxy, tls::tls_fixture};

/// Run every case; the report has one line per failure.
pub async fn run() -> String {
    let mut failures = Vec::new();
    let cases: [(&str, Result<(), String>); 4] = [
        (
            "system roots reject the fixture CA",
            system_roots_reject().await,
        ),
        (
            "extra roots trust the fixture CA",
            extra_roots_trust().await,
        ),
        (
            "CONNECT tunnel with extra roots",
            tunnelled_with_extra_roots().await,
        ),
        (
            "websocket through CONNECT",
            websocket_through_connect().await,
        ),
    ];
    for (name, outcome) in cases {
        if let Err(reason) = outcome {
            failures.push(format!("{name}: {reason}"));
        }
    }
    failures.join("\n")
}

fn transport_with_test_ca(proxy: Option<Proxy>) -> Result<Transport, String> {
    let mut builder = Transport::builder()
        .extra_root_certificates_pem(&tls_fixture().ca_pem)
        .map_err(|error| format!("test CA does not parse: {error}"))?;
    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|error| format!("transport does not build: {error}"))
}

fn basic(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

async fn system_roots_reject() -> Result<(), String> {
    let fixture = tls_fixture();
    let mut client = HyperBackend::default();
    let request = client
        .get(fixture.https_uri("/"))
        .map_err(|error| error.to_string())?;
    match request.await {
        Err(Error::Tls(_)) => Ok(()),
        other => Err(format!("expected Error::Tls, got {other:?}")),
    }
}

async fn extra_roots_trust() -> Result<(), String> {
    let fixture = tls_fixture();
    let mut client = HyperBackend::new(transport_with_test_ca(None)?);
    let response = client
        .get(fixture.https_uri("/"))
        .map_err(|error| error.to_string())?
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    let body: serde_json::Value = response
        .into_json()
        .await
        .map_err(|error| format!("body is not JSON: {error}"))?;
    (body["secure"] == true)
        .then_some(())
        .ok_or_else(|| format!("unexpected body {body}"))
}

async fn tunnelled_with_extra_roots() -> Result<(), String> {
    let proxy = HttpProxy::start_requiring(&basic("bob", "hunter2"));
    let fixture = tls_fixture();
    let rules = Proxy::builder()
        .https(proxy.uri_with_credentials("bob", "hunter2"))
        .build();
    let mut client = HyperBackend::new(transport_with_test_ca(Some(rules))?);
    let response = client
        .get(fixture.proxied_https_uri("/"))
        .map_err(|error| error.to_string())?
        .await
        .map_err(|error| format!("tunnelled request failed: {error}"))?;
    let body: serde_json::Value = response
        .into_json()
        .await
        .map_err(|error| format!("body is not JSON: {error}"))?;
    if body["secure"] != true {
        return Err(format!("unexpected body {body}"));
    }
    let requests = proxy.requests();
    let tunnel = requests
        .last()
        .ok_or_else(|| "the proxy saw no request".to_owned())?;
    if tunnel.method != "CONNECT" || !tunnel.target.starts_with(FIXTURE_HOST) {
        return Err(format!("unexpected proxy traffic {requests:?}"));
    }
    Ok(())
}

#[cfg(feature = "ws")]
async fn websocket_through_connect() -> Result<(), String> {
    use zenwave::websocket::{self, WebSocketConfig, WebSocketMessage};

    let proxy = HttpProxy::start();
    let fixture = tls_fixture();
    let rules = Proxy::builder().all(proxy.uri()).build();
    let transport = transport_with_test_ca(Some(rules))?;
    let socket = websocket::connect_with(
        fixture.proxied_wss_uri(),
        &transport,
        WebSocketConfig::default(),
    )
    .await
    .map_err(|error| format!("websocket did not connect: {error}"))?;
    socket
        .send_text("via proxy")
        .await
        .map_err(|error| format!("send failed: {error}"))?;
    let echoed = socket
        .recv()
        .await
        .map_err(|error| format!("recv failed: {error}"))?
        .ok_or_else(|| "the echo server closed".to_owned())?;
    if echoed != WebSocketMessage::Text("via proxy".into()) {
        return Err(format!("unexpected echo {echoed:?}"));
    }
    socket
        .close()
        .await
        .map_err(|error| format!("close failed: {error}"))?;
    let saw_connect = proxy
        .requests()
        .iter()
        .any(|request| request.method == "CONNECT");
    saw_connect
        .then_some(())
        .ok_or_else(|| "the proxy saw no CONNECT".to_owned())
}

#[cfg(not(feature = "ws"))]
async fn websocket_through_connect() -> Result<(), String> {
    Ok(())
}
