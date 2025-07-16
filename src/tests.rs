use crate::{Client, client};

#[tokio::test]
pub async fn https() {
    let request = client().get("https://example.com/").await;
    assert!(request.is_ok());
    let response = request.unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
pub async fn http() {
    let request = client().get("http://example.com/").await;
    assert!(request.is_ok());
    let response = request.unwrap();
    assert!(response.status().is_success());
}
