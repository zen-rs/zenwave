//! Proxy rules through `Transport`: absolute-form forwarding, `CONNECT`
//! tunnels, SOCKS5, `no_proxy`, and the errors a misbehaving proxy produces.
#![cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "hyper-backend", feature = "curl-backend")
))]

mod common;

use base64::Engine as _;
use common::{
    httpbin_uri,
    proxy::{HttpProxy, ProxiedRequest},
    socks5::{Socks5Proxy, SocksDestination},
    tls::tls_fixture,
};
use zenwave::{Client, Proxy, ResponseExt as _, Transport, backend::DefaultBackend};

fn transport(proxy: Proxy) -> Transport {
    Transport::builder()
        .proxy(proxy)
        .build()
        .expect("transport builds")
}

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
    let proxy = HttpProxy::start();
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

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(
        requests[0],
        ProxiedRequest {
            method: "GET".to_owned(),
            target: httpbin_uri("/get"),
            proxy_authorization: Some(basic("alice", "s3cret")),
        }
    );
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

#[test_executors::async_test]
async fn https_target_is_tunnelled_with_connect() {
    let proxy = HttpProxy::start();
    let fixture = tls_fixture();
    let rules = Proxy::builder()
        .https(proxy.uri_with_credentials("bob", "hunter2"))
        .build();
    let mut client = DefaultBackend::new(transport_with_test_ca(rules));

    let response = client
        .get(fixture.https_uri("/"))
        .expect("valid request")
        .await
        .expect("tunnelled TLS request succeeds");
    let body: serde_json::Value = response.into_json().await.expect("JSON body");
    assert_eq!(body["secure"], true);

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].method, "CONNECT");
    assert!(
        requests[0].target.starts_with("localhost:"),
        "{}",
        requests[0].target
    );
    assert_eq!(
        requests[0].proxy_authorization,
        Some(basic("bob", "hunter2"))
    );
}

#[test_executors::async_test]
async fn rejected_tunnel_is_an_error() {
    let proxy = HttpProxy::start_requiring(&basic("bob", "hunter2"));
    let fixture = tls_fixture();
    let rules = Proxy::builder().https(proxy.uri()).build();
    let mut client = DefaultBackend::new(transport_with_test_ca(rules));

    let error = client
        .get(fixture.https_uri("/"))
        .expect("valid request")
        .await
        .expect_err("the proxy demands credentials");
    #[cfg(feature = "hyper-backend")]
    assert!(
        matches!(
            error,
            zenwave::Error::Proxy(zenwave::error::ProxyErrorKind::TunnelRejected(status)) if status.as_u16() == 407
        ),
        "{error:?}"
    );
    #[cfg(not(feature = "hyper-backend"))]
    assert!(error.is_network_error(), "{error:?}");
}

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

#[test_executors::async_test]
async fn socks5h_sends_the_hostname_to_the_proxy() {
    let proxy = Socks5Proxy::start();
    let fixture = tls_fixture();
    let rules = Proxy::builder().all(proxy.uri("socks5h")).build();
    let mut client = DefaultBackend::new(transport_with_test_ca(rules));

    let response = client
        .get(fixture.https_uri("/"))
        .expect("valid request")
        .await
        .expect("TLS over SOCKS5 succeeds");
    let body: serde_json::Value = response.into_json().await.expect("JSON body");
    assert_eq!(body["secure"], true);

    let destinations = proxy.destinations();
    assert_eq!(destinations.len(), 1, "{destinations:?}");
    assert!(
        matches!(&destinations[0], SocksDestination::Domain(name, _) if name == "localhost"),
        "socks5h:// leaves resolution to the proxy: {destinations:?}"
    );
}

#[cfg(feature = "hyper-backend")]
#[test_executors::async_test]
async fn socks4_is_refused_by_hyper() {
    let rules = Proxy::builder().all("socks4://127.0.0.1:1").build();
    let mut client = DefaultBackend::new(transport(rules));
    let error = client
        .get(httpbin_uri("/get"))
        .expect("valid request")
        .await
        .expect_err("socks4 is not spoken by the hyper backend");
    assert!(
        matches!(
            error,
            zenwave::Error::Proxy(zenwave::error::ProxyErrorKind::UnsupportedScheme(ref scheme)) if scheme == "socks4"
        ),
        "{error:?}"
    );
}

#[cfg(feature = "ws")]
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

        let socket =
            websocket::connect_with(fixture.wss_uri(), &transport, WebSocketConfig::default())
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
