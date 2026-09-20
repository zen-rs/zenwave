//! The local fixture's CORS contract: the wasm lanes call it from the
//! wasm-bindgen server's origin, so every response must carry the origin
//! headers and a preflight must be answered on any path.

mod common;
use common::httpbin_uri;
use zenwave::{Client, Method, client, get};

fn header<'a>(response: &'a zenwave::Response, name: &str) -> Option<&'a str> {
    response.headers().get(name).and_then(|v| v.to_str().ok())
}

#[test_executors::async_test]
async fn fixture_answers_cors_preflight() {
    let response = client()
        .method(Method::OPTIONS, httpbin_uri("/post"))
        .unwrap()
        .header("Access-Control-Request-Method", "POST")
        .unwrap()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 204);
    assert_eq!(
        header(&response, "access-control-allow-methods"),
        Some("GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
    );
    assert_eq!(header(&response, "access-control-allow-headers"), Some("*"));
    assert_eq!(header(&response, "access-control-max-age"), Some("600"));
    assert!(header(&response, "access-control-allow-credentials").is_none());
}

#[test_executors::async_test]
async fn fixture_responses_carry_cors_origin() {
    let response = get(httpbin_uri("/get")).await.unwrap();
    assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
    assert_eq!(
        header(&response, "access-control-expose-headers"),
        Some("*")
    );
}
