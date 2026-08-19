//! Tests for the module-level convenience functions.
//!
//! These only need to prove that each helper dispatches the right method through
//! a default client; the request builder itself is covered by `client_tests`.

mod common;
use common::httpbin_uri;
use zenwave::{delete, get, post, put};

#[test_executors::async_test]
async fn each_helper_dispatches_its_own_method() {
    let get_body = get(httpbin_uri("/echo"))
        .await
        .expect("GET must succeed")
        .into_body()
        .into_string()
        .await
        .expect("body must read");
    assert!(get_body.contains("method=GET"), "got {get_body}");

    let post_body = post(httpbin_uri("/echo"))
        .await
        .expect("POST must succeed")
        .into_body()
        .into_string()
        .await
        .expect("body must read");
    assert!(post_body.contains("method=POST"), "got {post_body}");

    let put_body = put(httpbin_uri("/echo"))
        .await
        .expect("PUT must succeed")
        .into_body()
        .into_string()
        .await
        .expect("body must read");
    assert!(put_body.contains("method=PUT"), "got {put_body}");

    let delete_body = delete(httpbin_uri("/echo"))
        .await
        .expect("DELETE must succeed")
        .into_body()
        .into_string()
        .await
        .expect("body must read");
    assert!(delete_body.contains("method=DELETE"), "got {delete_body}");
}

#[test_executors::async_test]
async fn the_convenience_client_follows_redirects() {
    let body = get(httpbin_uri("/redirect/2"))
        .await
        .expect("redirects must be followed")
        .into_body()
        .into_string()
        .await
        .expect("body must read");
    assert_eq!(body.trim(), "redirect complete");
}

#[test_executors::async_test]
async fn an_invalid_uri_is_reported_rather_than_dispatched() {
    let error = get("invalid-uri")
        .await
        .expect_err("a host-less uri must not be dispatched");
    assert!(
        error.is_request_error() || error.is_network_error(),
        "got {error:?}"
    );
}
