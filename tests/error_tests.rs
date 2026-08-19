//! Tests for error reporting and classification.

use serde::Deserialize;
mod common;
use common::httpbin_uri;
use zenwave::{Client, ErrorKind, client, get};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn an_unparseable_uri_is_rejected_when_the_request_is_built() {
    let mut client = client();
    let error = client.get("").expect_err("an empty uri must be rejected");
    assert!(error.is_request_error(), "got {error:?}");
    assert_eq!(error.kind(), ErrorKind::Request);
}

#[test_executors::async_test]
async fn a_uri_without_a_host_fails_rather_than_dispatching() {
    let error = get("not-a-valid-url")
        .await
        .expect_err("a host-less uri must not be dispatched");
    assert!(
        error.is_request_error() || error.is_network_error(),
        "got {error:?}"
    );
}

#[test_executors::async_test]
async fn an_unsupported_scheme_is_rejected() {
    let error = get("ftp://example.com/file")
        .await
        .expect_err("ftp is not an HTTP scheme");
    assert!(
        error.is_request_error() || error.is_network_error(),
        "got {error:?}"
    );
}

#[test_executors::async_test]
async fn a_404_reports_the_status_and_body() {
    let error = get(httpbin_uri("/status/404"))
        .await
        .expect_err("404 must surface as Err");

    assert_eq!(error.kind(), ErrorKind::Http);
    assert!(error.is_client_error(), "got {error:?}");
    assert!(!error.is_server_error(), "404 is not a server error");
    assert!(error.to_string().contains("404"), "got {error}");
    assert_eq!(
        error.response().map(http::Response::status),
        Some(http::StatusCode::NOT_FOUND)
    );
    assert_eq!(error.response_body(), Some("status 404"));
}

#[test_executors::async_test]
async fn a_500_is_classified_as_a_server_error() {
    let error = get(httpbin_uri("/status/500"))
        .await
        .expect_err("500 must surface as Err");

    assert!(error.is_server_error(), "got {error:?}");
    assert!(!error.is_client_error(), "500 is not a client error");
    assert!(error.to_string().contains("500"), "got {error}");
}

#[test_executors::async_test]
async fn a_structured_error_body_can_be_deserialized() {
    #[derive(Deserialize)]
    struct ApiError {
        code: String,
        message: String,
    }

    let error = get(httpbin_uri("/error-json"))
        .await
        .expect_err("422 must surface as Err");

    let api_error: ApiError = error
        .deserialize_http_error()
        .expect("a JSON error body must deserialize");
    assert_eq!(api_error.code, "invalid_field");
    assert_eq!(api_error.message, "name is required");
}

#[test_executors::async_test]
async fn deserializing_a_non_json_error_body_returns_none() {
    #[derive(Deserialize)]
    struct ApiError {
        #[allow(dead_code)]
        code: String,
    }

    let error = get(httpbin_uri("/status/404"))
        .await
        .expect_err("404 must surface as Err");
    assert!(
        error.deserialize_http_error::<ApiError>().is_none(),
        "a plain-text body must not deserialize as JSON"
    );
}

#[test_executors::async_test]
async fn a_non_http_error_exposes_no_response() {
    let error = get("http://127.0.0.1:9/unreachable")
        .await
        .expect_err("the discard port must refuse connections");
    assert!(error.response().is_none());
    assert!(error.response_body().is_none());
    assert!(
        error
            .deserialize_http_error::<serde_json::Value>()
            .is_none(),
        "a transport error carries no body"
    );
}

#[test_executors::async_test]
async fn a_body_that_is_not_json_reports_a_parse_error() {
    let mut client = client();
    let error = client
        .get(httpbin_uri("/html"))
        .expect("uri must parse")
        .json::<serde_json::Value>()
        .await
        .expect_err("HTML must not parse as JSON");
    assert_eq!(error.kind(), ErrorKind::BodyParse);
}

#[test_executors::async_test]
async fn a_204_response_has_an_empty_body() {
    let response = get(httpbin_uri("/status/204"))
        .await
        .expect("204 is a success status");
    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);

    let body = response
        .into_body()
        .into_string()
        .await
        .expect("an empty body must read");
    assert!(body.is_empty(), "got {body:?}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn error_kinds_render_as_stable_labels() {
    assert_eq!(ErrorKind::Http.to_string(), "http");
    assert_eq!(ErrorKind::Transport.to_string(), "transport");
    assert_eq!(ErrorKind::Timeout.to_string(), "timeout");
    assert_eq!(ErrorKind::Redirect.to_string(), "redirect");
    assert_eq!(ErrorKind::BodyParse.to_string(), "body_parse");
    assert_eq!(
        ErrorKind::ResponseBodyLimit.to_string(),
        "response_body_limit"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn classification_helpers_agree_with_the_error_kind() {
    let timeout = zenwave::Error::Timeout;
    assert!(timeout.is_timeout());
    assert!(!timeout.is_network_error());
    assert_eq!(timeout.kind(), ErrorKind::Timeout);

    let redirect = zenwave::Error::TooManyRedirects { max: 10 };
    assert!(redirect.is_redirect_error());
    assert_eq!(redirect.kind(), ErrorKind::Redirect);
    assert!(redirect.to_string().contains("10"), "got {redirect}");

    let uri = zenwave::Error::InvalidUri("bad".to_string());
    assert!(uri.is_request_error());
    assert_eq!(uri.kind(), ErrorKind::Request);

    let too_large = zenwave::Error::ResponseBodyTooLarge { limit: 42 };
    assert_eq!(too_large.kind(), ErrorKind::ResponseBodyLimit);
    assert!(too_large.to_string().contains("42"), "got {too_large}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn http_errors_map_to_gateway_statuses() {
    use http_kit::HttpError as _;

    assert_eq!(
        zenwave::Error::Timeout.status(),
        http::StatusCode::GATEWAY_TIMEOUT
    );
    assert_eq!(
        zenwave::Error::InvalidRedirectLocation.status(),
        http::StatusCode::INTERNAL_SERVER_ERROR
    );
}
