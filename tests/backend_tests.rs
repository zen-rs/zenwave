//! Tests for backend implementations.

#![cfg(any(feature = "hyper-backend", feature = "curl-backend"))]

use http_kit::{Endpoint, Method};

mod common;
use common::httpbin_uri;

/// Build a request for the local test server.
fn request(method: Method, path: &str) -> http_kit::Request {
    http::Request::builder()
        .method(method)
        .uri(httpbin_uri(path))
        .body(http_kit::Body::empty())
        .expect("test request must build")
}

#[cfg(feature = "hyper-backend")]
mod hyper_backend {
    use super::{Endpoint, Method, httpbin_uri, request};
    use zenwave::backend::{DEFAULT_USER_AGENT, HyperBackend};

    #[test_executors::async_test]
    async fn performs_a_get_request() {
        let mut backend = HyperBackend::new();
        let mut req = request(Method::GET, "/get");
        let response = backend
            .respond(&mut req)
            .await
            .expect("GET must reach the test server");
        assert!(response.status().is_success());
    }

    #[test_executors::async_test]
    async fn performs_a_post_request_with_a_body() {
        let mut backend = HyperBackend::new();
        let mut req = http::Request::builder()
            .method(Method::POST)
            .uri(httpbin_uri("/echo"))
            .body(http_kit::Body::from("payload"))
            .expect("test request must build");

        let response = backend
            .respond(&mut req)
            .await
            .expect("POST must reach the test server");
        let text = response
            .into_body()
            .into_string()
            .await
            .expect("body must read");
        assert!(text.contains("body=payload"), "got {text}");
    }

    #[test_executors::async_test]
    async fn a_uri_without_a_host_is_rejected() {
        let mut backend = HyperBackend::new();
        let mut req = http::Request::builder()
            .method(Method::GET)
            .uri("/no-host")
            .body(http_kit::Body::empty())
            .expect("test request must build");
        let error = backend
            .respond(&mut req)
            .await
            .expect_err("a host-less uri must not be dispatched");
        assert!(
            error.is_request_error() || error.is_network_error(),
            "got {error:?}"
        );
    }

    #[test_executors::async_test]
    async fn a_non_success_status_surfaces_as_an_error_with_the_status() {
        let mut backend = HyperBackend::new();
        let mut req = request(Method::GET, "/status/404");
        let error = backend
            .respond(&mut req)
            .await
            .expect_err("404 must surface as Err");
        assert!(error.is_client_error(), "got {error:?}");
        assert_eq!(
            error.response().map(http::Response::status),
            Some(http::StatusCode::NOT_FOUND)
        );
    }

    #[test_executors::async_test]
    async fn an_error_response_body_is_captured_in_the_error() {
        let mut backend = HyperBackend::new();
        let mut req = request(Method::GET, "/status/500");
        let error = backend
            .respond(&mut req)
            .await
            .expect_err("500 must surface as Err");
        assert_eq!(error.response_body(), Some("status 500"));
    }

    /// The caller's request must survive a dispatch so `Retry` can resend it.
    #[test_executors::async_test]
    async fn dispatching_leaves_the_callers_request_intact() {
        let mut backend = HyperBackend::new();
        let uri = httpbin_uri("/get");
        let mut req = http::Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header("x-test", "kept")
            .body(http_kit::Body::empty())
            .expect("test request must build");

        backend
            .respond(&mut req)
            .await
            .expect("GET must reach the test server");

        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri().to_string(), uri);
        assert_eq!(
            req.headers()
                .get("x-test")
                .and_then(|value| value.to_str().ok()),
            Some("kept"),
            "headers must survive dispatch"
        );
    }

    #[test_executors::async_test]
    async fn a_default_user_agent_is_sent_when_the_caller_sets_none() {
        let mut backend = HyperBackend::new();
        let mut req = request(Method::GET, "/user-agent");
        let response = backend
            .respond(&mut req)
            .await
            .expect("request must succeed");
        let text = response
            .into_body()
            .into_string()
            .await
            .expect("body must read");
        assert_eq!(text.trim(), format!("user-agent: {DEFAULT_USER_AGENT}"));
    }

    #[test_executors::async_test]
    async fn a_caller_supplied_user_agent_is_not_overridden() {
        let mut backend = HyperBackend::new();
        let mut req = http::Request::builder()
            .method(Method::GET)
            .uri(httpbin_uri("/user-agent"))
            .header(http::header::USER_AGENT, "my-app/1.0")
            .body(http_kit::Body::empty())
            .expect("test request must build");

        let response = backend
            .respond(&mut req)
            .await
            .expect("request must succeed");
        let text = response
            .into_body()
            .into_string()
            .await
            .expect("body must read");
        assert_eq!(text.trim(), "user-agent: my-app/1.0");
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "curl-backend"))]
mod curl_backend {
    use super::{Endpoint, Method, httpbin_uri, request};
    use zenwave::backend::CurlBackend;

    #[test_executors::async_test]
    async fn performs_a_get_request() {
        let mut backend = CurlBackend::new();
        let mut req = request(Method::GET, "/get");
        let response = backend
            .respond(&mut req)
            .await
            .expect("GET must reach the test server");
        assert!(response.status().is_success());
    }

    #[test_executors::async_test]
    async fn a_non_success_status_surfaces_as_an_error() {
        let mut backend = CurlBackend::new();
        let mut req = request(Method::GET, "/status/500");
        let error = backend
            .respond(&mut req)
            .await
            .expect_err("500 must surface as Err");
        assert!(error.is_server_error(), "got {error:?}");
    }

    /// A HEAD response has headers but no body. libcurl must be told so, or it
    /// waits for a body that never arrives and the request hangs.
    #[test_executors::async_test]
    async fn a_head_request_completes_without_waiting_for_a_body() {
        let mut backend = CurlBackend::new();
        let mut req = request(Method::HEAD, "/get");
        let response = backend
            .respond(&mut req)
            .await
            .expect("HEAD must complete rather than hang");
        assert!(response.status().is_success());
        let body = response
            .into_body()
            .into_bytes()
            .await
            .expect("HEAD body must read");
        assert!(body.is_empty(), "HEAD must not return a body");
    }

    /// The caller's request must survive a dispatch so `Retry` can resend it.
    #[test_executors::async_test]
    async fn dispatching_leaves_the_callers_request_intact() {
        let mut backend = CurlBackend::new();
        let uri = httpbin_uri("/get");
        let mut req = http::Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header("x-test", "kept")
            .body(http_kit::Body::empty())
            .expect("test request must build");

        backend
            .respond(&mut req)
            .await
            .expect("GET must reach the test server");

        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri().to_string(), uri);
        assert_eq!(
            req.headers()
                .get("x-test")
                .and_then(|value| value.to_str().ok()),
            Some("kept")
        );
    }
}
