//! Proxy rules through `Transport`: absolute-form forwarding, `CONNECT`
//! tunnels, SOCKS5, `no_proxy`, and the errors a misbehaving proxy produces.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use base64::Engine as _;
#[cfg(not(target_os = "android"))]
use common::{FIXTURE_HOST, tls::tls_fixture};
use common::{
    httpbin_uri,
    proxy::{HttpProxy, ProxiedRequest},
    socks5::{Socks5Proxy, SocksDestination},
};
use zenwave::{Client, Proxy, ResponseExt as _, Transport, backend::DefaultBackend};

fn transport(proxy: Proxy) -> Transport {
    Transport::builder()
        .proxy(proxy)
        .build()
        .expect("transport builds")
}

#[cfg(not(target_os = "android"))]
fn transport_with_test_ca(proxy: Proxy) -> Transport {
    Transport::builder()
        .proxy(proxy)
        .extra_root_certificates_pem(&tls_fixture().ca_pem)
        .expect("test CA parses")
        .build()
        .expect("transport builds")
}

fn basic(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

#[test_executors::async_test]
async fn http_target_is_forwarded_in_absolute_form_with_credentials() {
    let proxy = HttpProxy::start_requiring(&basic("alice", "s3cret"));
    let rules = Proxy::builder()
        .http(proxy.uri_with_credentials("alice", "s3cret"))
        .build();
    let mut client = DefaultBackend::new(transport(rules));

    let response = client
        .get(httpbin_uri("/get"))
        .expect("valid request")
        .await
        .expect("request through the proxy succeeds");
    let body: serde_json::Value = response.into_json().await.expect("JSON body");
    assert_eq!(body["origin"], "httpbin");

    // Some engines send credentials up front, URLSession only after a 407:
    // either way the proxy ends up with exactly this request.
    let requests = proxy.requests();
    assert_eq!(
        requests.last(),
        Some(&ProxiedRequest {
            method: "GET".to_owned(),
            target: httpbin_uri("/get"),
            proxy_authorization: Some(basic("alice", "s3cret")),
        }),
        "{requests:?}"
    );
    assert!(requests.len() <= 2, "{requests:?}");
}

#[test_executors::async_test]
async fn no_proxy_bypasses_the_proxy() {
    let proxy = HttpProxy::start();
    let rules = Proxy::builder()
        .http(proxy.uri())
        .no_proxy("127.0.0.1, localhost")
        .build();
    let mut client = DefaultBackend::new(transport(rules));

    client
        .get(httpbin_uri("/get"))
        .expect("valid request")
        .await
        .expect("direct request succeeds");
    assert!(proxy.requests().is_empty(), "{:?}", proxy.requests());
}

#[test_executors::async_test]
async fn proxy_none_ignores_everything() {
    let proxy = HttpProxy::start();
    let mut client = DefaultBackend::new(transport(Proxy::none()));
    client
        .get(httpbin_uri("/get"))
        .expect("valid request")
        .await
        .expect("direct request succeeds");
    assert!(proxy.requests().is_empty());
}

// The plain Android test binary has no JVM for the platform verifier; TLS on
// Android is exercised by the instrumented app under `tests/android`.
#[cfg(not(target_os = "android"))]
#[test_executors::async_test]
async fn https_target_is_tunnelled_with_connect() {
    let proxy = HttpProxy::start_requiring(&basic("bob", "hunter2"));
    let fixture = tls_fixture();
    let rules = Proxy::builder()
        .https(proxy.uri_with_credentials("bob", "hunter2"))
        .build();
    let mut client = DefaultBackend::new(transport_with_test_ca(rules));

    let response = client
        .get(fixture.proxied_https_uri("/"))
        .expect("valid request")
        .await
        .expect("tunnelled TLS request succeeds");
    let body: serde_json::Value = response.into_json().await.expect("JSON body");
    assert_eq!(body["secure"], true);

    let requests = proxy.requests();
    let tunnel = requests.last().expect("the proxy saw the CONNECT");
    assert!(requests.len() <= 2, "{requests:?}");
    assert_eq!(tunnel.method, "CONNECT");
    assert_eq!(
        tunnel.target.rsplit_once(':').map(|(host, _)| host),
        Some(FIXTURE_HOST),
        "{}",
        tunnel.target
    );
    assert_eq!(tunnel.proxy_authorization, Some(basic("bob", "hunter2")));
}

#[cfg(not(target_os = "android"))]
#[test_executors::async_test]
async fn rejected_tunnel_is_an_error() {
    let proxy = HttpProxy::start_requiring(&basic("bob", "hunter2"));
    let fixture = tls_fixture();
    let rules = Proxy::builder().https(proxy.uri()).build();
    let mut client = DefaultBackend::new(transport_with_test_ca(rules));

    let error = client
        .get(fixture.proxied_https_uri("/"))
        .expect("valid request")
        .await
        .expect_err("the proxy demands credentials");
    #[cfg(any(default_hyper, default_apple))]
    assert!(
        matches!(
            error,
            zenwave::Error::Proxy(zenwave::error::ProxyErrorKind::TunnelRejected(status)) if status.as_u16() == 407
        ),
        "{error:?}"
    );
    #[cfg(default_curl)]
    assert!(error.is_network_error(), "{error:?}");
}

/// `socks5://` resolves on the client. `CFNetwork` always hands the hostname to
/// the proxy, so the Apple backend has no client-side flavour to test.
#[cfg(not(default_apple))]
#[test_executors::async_test]
async fn socks5_resolves_locally_and_authenticates() {
    let proxy = Socks5Proxy::start_requiring("carol", "pw");
    let rules = Proxy::builder()
        .all(proxy.uri_with_credentials("socks5", "carol", "pw"))
        .build();
    let mut client = DefaultBackend::new(transport(rules));

    let response = client
        .get(httpbin_uri("/get"))
        .expect("valid request")
        .await
        .expect("request through SOCKS5 succeeds");
    let body: serde_json::Value = response.into_json().await.expect("JSON body");
    assert_eq!(body["origin"], "httpbin");

    let destinations = proxy.destinations();
    assert_eq!(destinations.len(), 1, "{destinations:?}");
    assert!(
        matches!(destinations[0], SocksDestination::Ip(_)),
        "socks5:// resolves on the client: {destinations:?}"
    );
}

#[cfg(not(target_os = "android"))]
#[test_executors::async_test]
async fn socks5h_sends_the_hostname_to_the_proxy() {
    let proxy = Socks5Proxy::start_requiring("erin", "pw");
    let fixture = tls_fixture();
    let rules = Proxy::builder()
        .all(proxy.uri_with_credentials("socks5h", "erin", "pw"))
        .build();
    let mut client = DefaultBackend::new(transport_with_test_ca(rules));

    let response = client
        .get(fixture.proxied_https_uri("/"))
        .expect("valid request")
        .await
        .expect("TLS over SOCKS5 succeeds");
    let body: serde_json::Value = response.into_json().await.expect("JSON body");
    assert_eq!(body["secure"], true);

    let destinations = proxy.destinations();
    assert_eq!(destinations.len(), 1, "{destinations:?}");
    assert!(
        matches!(&destinations[0], SocksDestination::Domain(name, _) if name == FIXTURE_HOST),
        "socks5h:// leaves resolution to the proxy: {destinations:?}"
    );
}

#[cfg(not(default_curl))]
#[test_executors::async_test]
async fn socks4_is_refused() {
    let rules = Proxy::builder().all("socks4://127.0.0.1:1").build();
    let mut client = DefaultBackend::new(transport(rules));
    let error = client
        .get(httpbin_uri("/get"))
        .expect("valid request")
        .await
        .expect_err("socks4 is not spoken by this backend");
    assert!(
        matches!(
            error,
            zenwave::Error::Proxy(zenwave::error::ProxyErrorKind::UnsupportedScheme(ref scheme)) if scheme == "socks4"
        ),
        "{error:?}"
    );
}

// TLS needs the JVM on Android; see `tests/android`.
#[cfg(all(feature = "ws", not(target_os = "android")))]
mod websocket {
    use zenwave::{
        Proxy,
        websocket::{self, WebSocketConfig, WebSocketMessage},
    };

    use crate::{
        basic,
        common::{proxy::HttpProxy, tls::tls_fixture},
        transport_with_test_ca,
    };

    #[test_executors::async_test]
    async fn wss_is_tunnelled_with_connect() {
        let proxy = HttpProxy::start();
        let fixture = tls_fixture();
        let rules = Proxy::builder()
            .all(proxy.uri_with_credentials("dave", "pw"))
            .build();
        let transport = transport_with_test_ca(rules);

        let socket = websocket::connect_with(
            fixture.proxied_wss_uri(),
            &transport,
            WebSocketConfig::default(),
        )
        .await
        .expect("websocket through the proxy connects");
        socket.send_text("via proxy").await.expect("send");
        let echoed = socket.recv().await.expect("recv").expect("message");
        assert_eq!(echoed, WebSocketMessage::Text("via proxy".into()));
        socket.close().await.expect("close");

        let requests = proxy.requests();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert_eq!(requests[0].method, "CONNECT");
        assert_eq!(requests[0].proxy_authorization, Some(basic("dave", "pw")));
    }
}
