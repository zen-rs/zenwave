//! Tests for the `Client` trait and its request builder.

use http_kit::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
mod common;
use common::httpbin_uri;
use zenwave::{
    Client, client,
    multipart::{Multipart, MultipartPart},
};

/// Parsed form of the `/echo` route's reflection of a request.
struct Echo {
    method: String,
    content_type: String,
    query: String,
    body: String,
}

impl Echo {
    fn parse(text: &str) -> Self {
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap_or_default()
                .to_string()
        };
        // `body=` is last and may itself contain newlines.
        let body = text
            .split_once("body=")
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default();
        Self {
            method: field("method"),
            content_type: field("content-type"),
            query: field("query"),
            body,
        }
    }
}

#[test_executors::async_test]
async fn get_returns_a_successful_response() {
    let mut client = client();
    let response = client
        .get(httpbin_uri("/get"))
        .expect("uri must parse")
        .await
        .expect("request must succeed");
    assert!(response.status().is_success());
}

#[test_executors::async_test]
async fn every_method_helper_sends_that_method() {
    let mut client = client();
    for (method, expected) in [
        (Method::GET, "GET"),
        (Method::POST, "POST"),
        (Method::PUT, "PUT"),
        (Method::PATCH, "PATCH"),
        (Method::DELETE, "DELETE"),
        (Method::OPTIONS, "OPTIONS"),
    ] {
        let text = client
            .method(method.clone(), httpbin_uri("/echo"))
            .expect("uri must parse")
            .string()
            .await
            .unwrap_or_else(|error| panic!("{method} request must succeed: {error}"));
        assert_eq!(Echo::parse(&text).method, expected);
    }
}

#[test_executors::async_test]
async fn patch_helper_sends_a_patch_request() {
    let mut client = client();
    let text = client
        .patch(httpbin_uri("/echo"))
        .expect("uri must parse")
        .string()
        .await
        .expect("PATCH must succeed");
    assert_eq!(Echo::parse(&text).method, "PATCH");
}

#[test_executors::async_test]
async fn options_helper_sends_an_options_request() {
    let mut client = client();
    let text = client
        .options(httpbin_uri("/echo"))
        .expect("uri must parse")
        .string()
        .await
        .expect("OPTIONS must succeed");
    assert_eq!(Echo::parse(&text).method, "OPTIONS");
}

#[test_executors::async_test]
async fn head_returns_headers_without_a_body() {
    let mut client = client();
    let response = client
        .head(httpbin_uri("/get"))
        .expect("uri must parse")
        .await
        .expect("HEAD must succeed");
    assert!(response.status().is_success());
    let body = response
        .into_body()
        .into_bytes()
        .await
        .expect("HEAD body must read");
    assert!(body.is_empty(), "HEAD must not return a body");
}

#[test_executors::async_test]
async fn json_body_sets_the_payload_and_content_type() {
    #[derive(Serialize)]
    struct Payload {
        name: &'static str,
        count: u8,
    }

    let mut client = client();
    let text = client
        .post(httpbin_uri("/echo"))
        .expect("uri must parse")
        .json_body(&Payload {
            name: "zenwave",
            count: 2,
        })
        .expect("payload must serialize")
        .string()
        .await
        .expect("request must succeed");

    let echo = Echo::parse(&text);
    assert_eq!(echo.content_type, "application/json");
    let sent: Value = serde_json::from_str(&echo.body).expect("body must be the JSON we sent");
    assert_eq!(sent["name"], "zenwave");
    assert_eq!(sent["count"], 2);
}

#[test_executors::async_test]
async fn form_body_sets_urlencoded_payload_and_content_type() {
    #[derive(Serialize)]
    struct Login {
        user: &'static str,
        password: &'static str,
    }

    let mut client = client();
    let text = client
        .post(httpbin_uri("/echo"))
        .expect("uri must parse")
        .form_body(&Login {
            user: "ada",
            password: "s p a c e",
        })
        .expect("payload must serialize")
        .string()
        .await
        .expect("request must succeed");

    let echo = Echo::parse(&text);
    assert_eq!(echo.content_type, "application/x-www-form-urlencoded");
    assert!(echo.body.contains("user=ada"), "got {}", echo.body);
    assert!(
        echo.body.contains("password=s+p+a+c+e")
            || echo.body.contains("password=s%20p%20a%20c%20e"),
        "spaces must be encoded: {}",
        echo.body
    );
}

#[test_executors::async_test]
async fn bytes_body_sends_raw_bytes() {
    let mut client = client();
    let text = client
        .post(httpbin_uri("/echo"))
        .expect("uri must parse")
        .bytes_body(b"raw-bytes".to_vec())
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(Echo::parse(&text).body, "raw-bytes");
}

#[test_executors::async_test]
async fn text_body_sends_utf8_text() {
    let mut client = client();
    let text = client
        .post(httpbin_uri("/echo"))
        .expect("uri must parse")
        .text_body("héllo")
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(Echo::parse(&text).body, "héllo");
}

#[test_executors::async_test]
async fn multipart_body_sets_a_matching_boundary() {
    let form = Multipart::new()
        .with_part(MultipartPart::text("field", "value"))
        .with_part(MultipartPart::binary(
            "file",
            "data.bin",
            "application/octet-stream",
            vec![1_u8, 2, 3],
        ));

    let mut client = client();
    let text = client
        .post(httpbin_uri("/echo"))
        .expect("uri must parse")
        .multipart_body(form)
        .string()
        .await
        .expect("request must succeed");

    let echo = Echo::parse(&text);
    let boundary = echo
        .content_type
        .split_once("boundary=")
        .map(|(_, boundary)| boundary.to_string())
        .expect("content-type must carry a boundary");
    assert!(
        echo.content_type.starts_with("multipart/form-data;"),
        "got {}",
        echo.content_type
    );
    // The body must be delimited by exactly the advertised boundary.
    assert!(
        echo.body.contains(&format!("--{boundary}\r\n")),
        "body must open with the advertised boundary: {}",
        echo.body
    );
    assert!(
        echo.body.contains(&format!("--{boundary}--")),
        "body must close with the advertised boundary: {}",
        echo.body
    );
    assert!(echo.body.contains("name=\"field\""), "got {}", echo.body);
    assert!(
        echo.body.contains("filename=\"data.bin\""),
        "got {}",
        echo.body
    );
}

#[test_executors::async_test]
async fn query_appends_encoded_parameters() {
    let mut client = client();
    let text = client
        .get(httpbin_uri("/echo"))
        .expect("uri must parse")
        .query([("q", "rust http"), ("page", "2")])
        .expect("query must encode")
        .string()
        .await
        .expect("request must succeed");

    let query = Echo::parse(&text).query;
    assert!(query.contains("q=rust+http"), "got {query}");
    assert!(query.contains("page=2"), "got {query}");
}

#[test_executors::async_test]
async fn query_preserves_existing_parameters() {
    let mut client = client();
    let text = client
        .get(httpbin_uri("/echo?existing=1"))
        .expect("uri must parse")
        .query([("added", "2")])
        .expect("query must encode")
        .string()
        .await
        .expect("request must succeed");

    let query = Echo::parse(&text).query;
    assert!(query.contains("existing=1"), "got {query}");
    assert!(query.contains("added=2"), "got {query}");
}

#[test_executors::async_test]
async fn query_with_no_parameters_leaves_the_uri_alone() {
    let mut client = client();
    let text = client
        .get(httpbin_uri("/echo"))
        .expect("uri must parse")
        .query(Vec::<(String, String)>::new())
        .expect("an empty query must be accepted")
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(Echo::parse(&text).query, "");
}

#[test_executors::async_test]
async fn header_sets_a_custom_request_header() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .header("x-test", "custom-value")
        .expect("header must be valid")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("X-Test: custom-value"), "got {body}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn header_rejects_a_value_that_cannot_be_sent() {
    let mut client = client();
    let error = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .header("x-test", "bad\nInjected: yes")
        .expect_err("a newline in a header value must be rejected");
    assert!(error.is_request_error(), "got {error:?}");
}

#[test_executors::async_test]
async fn string_returns_the_response_body() {
    let mut client = client();
    let text = client
        .get(httpbin_uri("/get"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert!(text.contains("httpbin"), "got {text}");
}

#[test_executors::async_test]
async fn bytes_returns_the_exact_payload() {
    let mut client = client();
    let bytes = client
        .get(httpbin_uri("/bytes/4096"))
        .expect("uri must parse")
        .bytes()
        .await
        .expect("request must succeed");
    assert_eq!(bytes.len(), 4096);
    assert!(bytes.iter().all(|byte| *byte == 0xAB));
}

#[test_executors::async_test]
async fn bytes_with_limit_rejects_an_oversized_body() {
    let mut client = client();
    let error = client
        .get(httpbin_uri("/bytes/4096"))
        .expect("uri must parse")
        .bytes_with_limit(1024)
        .await
        .expect_err("a 4 KiB body must exceed a 1 KiB limit");
    assert!(
        matches!(error, zenwave::Error::ResponseBodyTooLarge { limit: 1024 }),
        "got {error:?}"
    );
}

#[test_executors::async_test]
async fn bytes_with_limit_accepts_a_body_within_the_limit() {
    let mut client = client();
    let bytes = client
        .get(httpbin_uri("/bytes/4096"))
        .expect("uri must parse")
        .bytes_with_limit(4096)
        .await
        .expect("a body exactly at the limit must be accepted");
    assert_eq!(bytes.len(), 4096);
}

#[test_executors::async_test]
async fn json_deserializes_into_a_typed_value() {
    #[derive(Deserialize)]
    struct Slideshow {
        title: String,
        author: String,
    }
    #[derive(Deserialize)]
    struct Payload {
        slideshow: Slideshow,
    }

    let mut client = client();
    let payload: Payload = client
        .get(httpbin_uri("/json"))
        .expect("uri must parse")
        .json()
        .await
        .expect("response must deserialize");
    assert_eq!(payload.slideshow.title, "httpbin local");
    assert_eq!(payload.slideshow.author, "zenwave");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn an_empty_uri_is_rejected_before_dispatch() {
    let mut client = client();
    let error = client
        .get("")
        .expect_err("an empty uri must not build a request");
    assert!(error.is_request_error(), "got {error:?}");
}
