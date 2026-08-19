//! Tests for proxy matching: which destinations get proxied and which do not.

#![cfg(all(not(target_arch = "wasm32"), feature = "proxy"))]

mod common;

use http::Uri;
use zenwave::Proxy;

/// A destination is proxied when the matcher intercepts it.
fn is_proxied(proxy: &Proxy, uri: &str) -> bool {
    let uri: Uri = uri.parse().expect("test uri must parse");
    proxy.intercepts(&uri)
}

#[test]
fn an_http_proxy_applies_only_to_http_destinations() {
    let proxy = Proxy::builder().http("http://proxy.local:8080").build();

    assert!(is_proxied(&proxy, "http://example.com/path"));
    assert!(
        !is_proxied(&proxy, "https://example.com/path"),
        "an HTTP-only proxy must not intercept HTTPS"
    );
}

#[test]
fn an_https_proxy_applies_only_to_https_destinations() {
    let proxy = Proxy::builder().https("http://proxy.local:8080").build();

    assert!(is_proxied(&proxy, "https://example.com/path"));
    assert!(!is_proxied(&proxy, "http://example.com/path"));
}

#[test]
fn an_all_proxy_covers_both_schemes() {
    let proxy = Proxy::builder().all("http://proxy.local:8080").build();

    assert!(is_proxied(&proxy, "http://example.com/"));
    assert!(is_proxied(&proxy, "https://example.com/"));
}

#[test]
fn a_scheme_specific_proxy_takes_precedence_over_all() {
    let proxy = Proxy::builder()
        .all("http://all.local:8080")
        .https("http://secure.local:8443")
        .build();

    // Both are intercepted; the HTTPS destination must use the HTTPS proxy.
    assert!(is_proxied(&proxy, "https://example.com/"));
    assert_eq!(
        proxy.proxy_uri(&"https://example.com/".parse().expect("uri must parse")),
        Some("http://secure.local:8443".to_string())
    );
    assert_eq!(
        proxy.proxy_uri(&"http://example.com/".parse().expect("uri must parse")),
        Some("http://all.local:8080".to_string())
    );
}

#[test]
fn a_no_proxy_entry_exempts_its_host() {
    let proxy = Proxy::builder()
        .all("http://proxy.local:8080")
        .no_proxy("internal.test,localhost")
        .build();

    assert!(!is_proxied(&proxy, "http://internal.test/path"));
    assert!(!is_proxied(&proxy, "http://localhost:3000/path"));
    assert!(is_proxied(&proxy, "http://example.com/path"));
}

#[test]
fn a_no_proxy_entry_exempts_subdomains_but_not_lookalikes() {
    let proxy = Proxy::builder()
        .all("http://proxy.local:8080")
        .no_proxy("example.com")
        .build();

    assert!(!is_proxied(&proxy, "http://example.com/"));
    assert!(!is_proxied(&proxy, "http://api.example.com/"));
    assert!(
        is_proxied(&proxy, "http://notexample.com/"),
        "a host that merely ends with the entry must still be proxied"
    );
}

#[test]
fn no_proxy_matching_ignores_case() {
    let proxy = Proxy::builder()
        .all("http://proxy.local:8080")
        .no_proxy("Internal.TEST")
        .build();

    assert!(!is_proxied(&proxy, "http://INTERNAL.test/path"));
}

#[test]
fn an_unconfigured_proxy_intercepts_nothing() {
    let proxy = Proxy::builder().build();

    assert!(!is_proxied(&proxy, "http://example.com/"));
    assert!(!is_proxied(&proxy, "https://example.com/"));
}

#[test]
fn a_non_http_scheme_is_never_proxied() {
    let proxy = Proxy::builder().all("http://proxy.local:8080").build();

    assert!(!is_proxied(&proxy, "ftp://example.com/file"));
    assert!(!is_proxied(&proxy, "ws://example.com/socket"));
}

#[test]
fn a_uri_without_a_host_is_never_proxied() {
    let proxy = Proxy::builder().all("http://proxy.local:8080").build();
    assert!(!is_proxied(&proxy, "/relative/path"));
}

#[test]
fn credentials_in_a_proxy_url_become_basic_auth() {
    let proxy = Proxy::builder()
        .all("http://user:secret@proxy.local:8080")
        .build();
    let uri: Uri = "http://example.com/".parse().expect("uri must parse");

    assert!(proxy.intercepts(&uri));
    // base64("user:secret")
    assert_eq!(
        proxy.proxy_authorization(&uri),
        Some("Basic dXNlcjpzZWNyZXQ=".to_string()),
        "proxy credentials must be encoded for Proxy-Authorization"
    );
}

#[test]
fn a_proxy_without_credentials_needs_no_authorization() {
    let proxy = Proxy::builder().all("http://proxy.local:8080").build();
    let uri: Uri = "http://example.com/".parse().expect("uri must parse");

    assert!(proxy.intercepts(&uri));
    assert_eq!(proxy.proxy_authorization(&uri), None);
}

#[test]
fn an_unparseable_proxy_url_is_ignored_rather_than_panicking() {
    // No authority means nothing to connect to.
    let proxy = Proxy::builder().all("not a url").build();
    assert!(!is_proxied(&proxy, "http://example.com/"));
}

// ------------------------------------------------- end-to-end through a proxy

#[cfg(feature = "hyper-backend")]
mod through_a_proxy {
    use std::{
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        thread,
    };

    use super::common;
    use http_kit::Endpoint as _;
    use zenwave::{Proxy, backend::HyperBackend};

    /// A minimal forward proxy that answers plain-HTTP requests itself.
    ///
    /// It asserts the request arrived in absolute form, which is what a proxy
    /// needs in order to route it.
    struct FakeProxy {
        address: SocketAddr,
        worker: thread::JoinHandle<Option<String>>,
    }

    impl FakeProxy {
        fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("proxy must bind");
            let address = listener.local_addr().expect("proxy must have an address");
            let worker = thread::spawn(move || {
                let (mut socket, _) = listener.accept().ok()?;
                let mut buffer = [0_u8; 2048];
                let read = socket.read(&mut buffer).ok()?;
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();

                let body = "proxied";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).ok()?;
                Some(request)
            });
            Self { address, worker }
        }

        fn request_line(self) -> String {
            self.worker
                .join()
                .expect("proxy thread must finish")
                .expect("proxy must have served a request")
                .lines()
                .next()
                .expect("request must have a request line")
                .to_string()
        }
    }

    #[test_executors::async_test]
    async fn a_plain_http_request_is_forwarded_in_absolute_form() {
        let proxy_server = FakeProxy::start();
        let proxy = Proxy::builder()
            .all(format!("http://{}", proxy_server.address))
            .build();

        let mut backend = HyperBackend::with_proxy(proxy);
        let mut request = http::Request::builder()
            .uri("http://example.invalid/resource?q=1")
            .body(http_kit::Body::empty())
            .expect("test request must build");

        let response = backend
            .respond(&mut request)
            .await
            .expect("the proxy must answer the request");
        let body = response
            .into_body()
            .into_string()
            .await
            .expect("body must read");
        assert_eq!(body, "proxied");

        // The proxy must receive the full target URL, not just the path.
        assert_eq!(
            proxy_server.request_line(),
            "GET http://example.invalid/resource?q=1 HTTP/1.1"
        );
    }

    #[test_executors::async_test]
    async fn a_no_proxy_destination_bypasses_the_proxy_entirely() {
        // The proxy address is a closed port: if it were used, the request would
        // fail. NO_PROXY must send it straight to the real server instead.
        let proxy = Proxy::builder()
            .all("http://127.0.0.1:9")
            .no_proxy("127.0.0.1")
            .build();

        let mut backend = HyperBackend::with_proxy(proxy);
        let mut request = http::Request::builder()
            .uri(common::httpbin_uri("/get"))
            .body(http_kit::Body::empty())
            .expect("test request must build");

        let response = backend
            .respond(&mut request)
            .await
            .expect("an exempt destination must be reached directly");
        assert!(response.status().is_success());
    }

    #[test_executors::async_test]
    async fn an_unreachable_proxy_surfaces_as_a_transport_error() {
        // Port 9 (discard) refuses connections.
        let proxy = Proxy::builder().all("http://127.0.0.1:9").build();

        let mut backend = HyperBackend::with_proxy(proxy);
        let mut request = http::Request::builder()
            .uri("http://example.invalid/resource")
            .body(http_kit::Body::empty())
            .expect("test request must build");

        let error = backend
            .respond(&mut request)
            .await
            .expect_err("a dead proxy must fail the request");
        assert!(error.is_network_error(), "got {error:?}");
    }
}

#[cfg(feature = "hyper-backend")]
#[test_executors::async_test]
async fn a_socks_proxy_is_rejected_by_the_hyper_backend() {
    use http_kit::Endpoint as _;

    // SOCKS needs the curl backend; the hyper backend must say so rather than
    // silently treating the proxy as an HTTP one.
    let proxy = Proxy::builder().all("socks5://127.0.0.1:1080").build();
    let mut backend = zenwave::backend::HyperBackend::with_proxy(proxy);
    let mut request = http::Request::builder()
        .uri("http://example.invalid/resource")
        .body(http_kit::Body::empty())
        .expect("test request must build");

    let error = backend
        .respond(&mut request)
        .await
        .expect_err("a SOCKS proxy must be reported as unsupported");
    assert!(
        error.to_string().contains("socks5"),
        "the error must name the unsupported scheme: {error}"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_default_client_accepts_a_proxy_matcher() {
    use zenwave::Client as _;

    let proxy = Proxy::builder().all("http://proxy.local:8080").build();
    let mut client = zenwave::client_with_proxy(proxy);
    // The builder must be usable, not merely constructible.
    client
        .get("http://example.invalid/resource")
        .expect("a proxied client must still build requests");
}
