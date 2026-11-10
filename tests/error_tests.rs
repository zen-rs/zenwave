//! Tests for error handling in Zenwave

use http_kit::Method;
mod common;
use common::httpbin_uri;
use zenwave::{Client, client, get};

#[test_executors::async_test]
async fn test_invalid_url_error() {
    let result = get("not-a-valid-url").await;
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_invalid_scheme_error() {
    // Refused while building the request: no backend may reach the network
    // for a protocol it does not speak (libcurl would happily talk FTP).
    let error = get("ftp://example.com")
        .await
        .expect_err("a non-HTTP scheme must be refused");
    assert!(
        matches!(error, zenwave::Error::InvalidUri(_)),
        "unexpected error: {error}"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_client_invalid_url_error() {
    let mut client = client();
    let result = client.get("");
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_unreachable_host_error() {
    let result = get("https://this-host-definitely-does-not-exist-12345.com").await;
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_timeout_behavior() {
    // Test with a very slow endpoint
    let result = get(httpbin_uri("/delay/1")).await;
    // This should succeed but take some time
    assert!(result.is_ok());
}

#[test_executors::async_test]
async fn test_json_parsing_error() {
    use serde_json::Value;

    let mut client = client();
    // Get plain text and try to parse as JSON
    let result: Result<Value, _> = client.get(httpbin_uri("/html")).unwrap().json().await;
    assert!(result.is_err());
}

/// The default client answers an error status with the response; a client
/// that opted into `error_for_status` fails with `Error::Http` naming it.
async fn error_status(status: u16) {
    let path = format!("/status/{status}");
    let response = get(httpbin_uri(&path))
        .await
        .expect("an error status is a response");
    assert_eq!(response.status().as_u16(), status);

    let error = client()
        .error_for_status()
        .get(httpbin_uri(&path))
        .unwrap()
        .await
        .expect_err("an opted-in client fails on an error status");
    let error: zenwave::Error = error.into();
    assert!(
        matches!(&error, zenwave::Error::Http { status: got, .. } if got.as_u16() == status),
        "unexpected error: {error}"
    );
    assert!(
        format!("{error}").contains(&status.to_string()),
        "error message should mention status code: {error}"
    );
}

#[test_executors::async_test]
async fn test_404_not_found() {
    error_status(404).await;
}

#[test_executors::async_test]
async fn test_500_server_error() {
    error_status(500).await;
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_method_construction_with_invalid_uri() {
    let mut client = client();
    let result = client.method(Method::GET, "");
    assert!(result.is_err());
}

#[test_executors::async_test]
async fn test_empty_response_handling() {
    let result = get(httpbin_uri("/status/204")).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status().as_u16(), 204);

    // Getting the body of a 204 should work (empty body)
    let body = response.into_body().into_string().await;
    assert!(body.is_ok());
    let body_str = body.unwrap();
    assert!(body_str.is_empty());
}

/// The h1 pool must return its connection on every response path: error
/// statuses read to the end like any other, a 204's empty body may never be
/// polled, a streamed body is read to the end, and a `POST` carries a body.
/// The fixture's accept counter proves each of them reused the single
/// connection the first request dialed — a dropped lease would free its
/// slot without returning the connection, forcing a visible redial. Only a
/// body abandoned mid-stream legitimately dials again: unread bytes make
/// the h1 connection unusable. The pool is the hyper or native backend's;
/// the curl and Apple backends reuse connections on their own terms.
#[cfg(any(default_hyper, default_native))]
#[test_executors::async_test]
async fn test_pooled_connection_released_on_every_path() {
    use futures_util::StreamExt as _;

    // A dedicated server: the shared fixture serves every test in the binary
    // in parallel, so accepts on it cannot be attributed to this sequence.
    let server = common::TestServer::standalone();
    let before = server.accepted();

    // Every fully-consumed path reuses the connection the first request
    // dialed: error statuses, a 204's empty body, and a streamed body, each
    // read to the end.
    for path in [
        "/status/200",
        "/status/204",
        "/stream",
        "/status/500",
        "/status/404",
    ] {
        get(server.uri(path))
            .await
            .expect("every status is a response")
            .into_body()
            .into_bytes()
            .await
            .expect("the response body must read to the end");
    }
    let mut client = client();
    let response = client
        .post(server.uri("/post"))
        .expect("post request must build")
        .bytes_body(b"reused".to_vec())
        .await
        .expect("post must succeed");
    response
        .into_body()
        .into_bytes()
        .await
        .expect("the post response body must read");

    // A body abandoned mid-stream poisons its connection: hyper cannot drain
    // a body that never ends, so it closes the connection; the lease returns
    // a dead sender and the next request dials a fresh connection.
    let abandoned = ["/stream/stalled"];
    for path in abandoned {
        let mut body = get(server.uri(path))
            .await
            .expect("request must succeed")
            .into_body();
        drop(body.next().await);
        drop(body);
        get(server.uri("/status/200"))
            .await
            .expect("the redialed request must succeed")
            .into_body()
            .into_bytes()
            .await
            .expect("the redialed body must read");
    }

    // One dial for all the reused paths, plus one redial per abandoned body.
    let expected = 1 + abandoned.len();
    assert_eq!(
        server.accepted() - before,
        expected,
        "consumed bodies must reuse the pooled connection; abandoned ones redial"
    );
}
