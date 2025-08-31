use crate::{get, post, put, delete};

#[tokio::test]
async fn test_convenience_get() {
    let response = get("https://httpbin.org/get").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_convenience_post() {
    let response = post("https://httpbin.org/post").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_convenience_put() {
    let response = put("https://httpbin.org/put").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_convenience_delete() {
    let response = delete("https://httpbin.org/delete").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_convenience_get_invalid_uri() {
    let response = get("invalid-uri").await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_convenience_get_response_text() {
    let mut response = get("https://httpbin.org/get").await.unwrap();
    let text = response.into_string().await;
    assert!(text.is_ok());
    let text = text.unwrap();
    assert!(!text.is_empty());
    assert!(text.contains("httpbin"));
}

#[tokio::test]
async fn test_convenience_get_response_json() {
    use serde_json::Value;
    
    let mut response = get("https://httpbin.org/json").await.unwrap();
    let json: Result<Value, _> = response.into_json().await;
    assert!(json.is_ok());
    let json = json.unwrap();
    assert!(json.is_object());
}