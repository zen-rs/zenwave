//! Tests for convenience functions in Zenwave

mod common;
use common::httpbin_uri;
use zenwave::{delete, get, post, put};

#[test_executors::async_test]
async fn test_convenience_get() {
    let response = get(httpbin_uri("/get")).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[test_executors::async_test]
async fn test_convenience_post() {
    let response = post(httpbin_uri("/post")).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[test_executors::async_test]
async fn test_convenience_put() {
    let response = put(httpbin_uri("/put")).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[test_executors::async_test]
async fn test_convenience_delete() {
    let response = delete(httpbin_uri("/delete")).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[test_executors::async_test]
async fn test_convenience_get_invalid_uri() {
    let response = get("invalid-uri").await;
    assert!(response.is_err());
}

#[test_executors::async_test]
async fn test_convenience_get_response_text() {
    let response = get(httpbin_uri("/get")).await.unwrap();
    let text = response.into_body().into_string().await;
    assert!(text.is_ok());
    let text = text.unwrap();
    assert!(!text.is_empty());
    assert!(text.contains("httpbin"));
}

#[test_executors::async_test]
async fn test_convenience_get_response_json() {
    use serde_json::Value;

    let response = get(httpbin_uri("/json")).await.unwrap();
    let json: Result<Value, _> = response.into_body().into_json().await;
    assert!(json.is_ok());
    let json = json.unwrap();
    assert!(json.is_object());
}
