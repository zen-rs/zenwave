//! End-to-end tests exercising the default client against a local HTTP server.

use serde_json::Value;
mod common;
use common::httpbin_uri;
use zenwave::{Client, Method, ResponseExt, client, get};

#[test_executors::async_test]
async fn a_json_api_response_deserializes() {
    let json: Value = get(httpbin_uri("/json"))
        .await
        .expect("request must succeed")
        .into_json()
        .await
        .expect("response must be JSON");
    assert_eq!(json["slideshow"]["author"], "zenwave");
}

#[test_executors::async_test]
async fn the_client_sends_a_user_agent() {
    let text = get(httpbin_uri("/user-agent"))
        .await
        .expect("request must succeed")
        .into_string()
        .await
        .expect("body must read");

    let user_agent = text
        .trim()
        .strip_prefix("user-agent: ")
        .expect("the route echoes the user agent");
    assert!(
        user_agent.starts_with("zenwave/"),
        "expected the default zenwave agent, got {user_agent:?}"
    );
}

#[test_executors::async_test]
async fn custom_request_headers_reach_the_server() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .header("x-test", "integration")
        .expect("header must be valid")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("X-Test: integration"), "got {body}");
}

#[test_executors::async_test]
async fn a_json_body_round_trips_to_the_server() {
    let mut client = client();
    let text = client
        .post(httpbin_uri("/echo"))
        .expect("uri must parse")
        .json_body(&serde_json::json!({ "hello": "world" }))
        .expect("payload must serialize")
        .string()
        .await
        .expect("request must succeed");

    assert!(text.contains("method=POST"), "got {text}");
    assert!(text.contains("content-type=application/json"), "got {text}");
    assert!(text.contains(r#""hello":"world""#), "got {text}");
}

#[test_executors::async_test]
async fn success_statuses_are_returned_and_error_statuses_surface_as_errors() {
    for status in [200_u16, 201, 204] {
        let response = get(httpbin_uri(&format!("/status/{status}")))
            .await
            .unwrap_or_else(|error| panic!("{status} must succeed: {error}"));
        assert_eq!(response.status().as_u16(), status);
    }

    for status in [400_u16, 401, 403, 404, 500, 502, 503] {
        let Err(error) = get(httpbin_uri(&format!("/status/{status}"))).await else {
            panic!("{status} must surface as Err");
        };
        assert_eq!(
            error.response().map(|response| response.status().as_u16()),
            Some(status),
            "the error must carry the original status"
        );
        assert!(
            error.to_string().contains(&status.to_string()),
            "got {error}"
        );
    }
}

#[test_executors::async_test]
async fn a_long_redirect_chain_is_followed_to_completion() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/redirect/5"))
        .expect("uri must parse")
        .string()
        .await
        .expect("five redirects are within the default limit");
    assert_eq!(body.trim(), "redirect complete");
}

#[test_executors::async_test]
async fn a_multi_kilobyte_body_is_read_in_full() {
    let bytes = get(httpbin_uri("/bytes/4096"))
        .await
        .expect("request must succeed")
        .into_bytes()
        .await
        .expect("body must read");
    assert_eq!(bytes.len(), 4096, "the whole body must be collected");
    assert!(bytes.iter().all(|byte| *byte == 0xAB));
}

#[test_executors::async_test]
async fn a_base64_route_decodes_to_its_payload() {
    let bytes = get(httpbin_uri("/base64/aGVsbG8gd29ybGQ="))
        .await
        .expect("request must succeed")
        .into_bytes()
        .await
        .expect("body must read");
    assert_eq!(bytes.as_ref(), b"hello world");
}

#[test_executors::async_test]
async fn cookies_persist_across_requests_on_one_client() {
    let mut client = client().enable_cookie();

    client
        .get(httpbin_uri("/cookies/set/test/cookievalue"))
        .expect("uri must parse")
        .await
        .expect("setting a cookie must succeed");

    let body = client
        .get(httpbin_uri("/cookies"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("test=cookievalue"), "got {body}");
}

#[test_executors::async_test]
async fn every_method_reaches_its_route() {
    let mut client = client();
    for (method, path) in [
        (Method::GET, "/get"),
        (Method::POST, "/post"),
        (Method::PUT, "/put"),
        (Method::DELETE, "/delete"),
        (Method::PATCH, "/patch"),
    ] {
        let response = client
            .method(method.clone(), httpbin_uri(path))
            .expect("uri must parse")
            .await
            .unwrap_or_else(|error| panic!("{method} {path} must succeed: {error}"));
        assert!(
            response.status().is_success(),
            "{method} {path} returned {}",
            response.status()
        );
    }
}

#[test_executors::async_test]
async fn error_for_status_passes_a_success_response_through() {
    let response = get(httpbin_uri("/get"))
        .await
        .expect("request must succeed")
        .error_for_status()
        .await
        .expect("a 2xx must pass through unchanged");
    assert!(response.status().is_success());
}
