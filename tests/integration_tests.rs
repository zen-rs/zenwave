//! Integration tests for Zenwave using real HTTP requests.

use std::env;

use serde_json::Value;
use zenwave::{Client, Method, client, get};

fn base_url() -> String {
    env::var("ZENWAVE_TEST_BASE_URL").unwrap_or_else(|_| "https://httpbingo.org".to_string())
}

fn endpoint(path: &str) -> String {
    format!(
        "{}/{}",
        base_url().trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_real_world_api_request() {
    // Test with a real JSON API
    let response = get(endpoint("/json")).await.unwrap();
    assert!(response.status().is_success());

    let json: Value = response.into_body().into_json().await.unwrap();
    assert!(json.is_object());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_user_agent_header() {
    let response = get(endpoint("/user-agent")).await.unwrap();
    let text = response.into_body().into_string().await.unwrap();

    // Should contain some user agent info
    assert!(!text.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_custom_headers() {
    let mut client = client();
    let response = client.get(endpoint("/headers")).await.unwrap();
    let text = response.into_body().into_string().await.unwrap();

    // Should contain header information
    assert!(text.contains("headers"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_post_with_json_body() {
    let mut client = client();
    let request = client.method(Method::POST, endpoint("/post"));
    // Note: In a real implementation, you'd want to add a body() method to RequestBuilder
    let response = request.await;

    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_response_status_codes() {
    for status_code in [200, 201, 400, 401, 403, 404, 500, 502, 503] {
        let url = endpoint(&format!("/status/{status_code}"));
        let response = get(url).await;
        if status_code < 400 {
            let response = response.unwrap();
            assert_eq!(response.status().as_u16(), status_code);
        } else {
            let error = response.expect_err("expected error status to surface as Err");
            let description = format!("{error}");
            assert!(
                description.contains(&status_code.to_string()),
                "error message should mention status code {status_code}: {description}"
            );
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_redirect_chain() {
    let client = client().follow_redirect();
    let mut client = client;

    // Test a redirect chain
    let response = client.get(endpoint("/redirect/5")).await.unwrap();
    assert!(response.status().is_success());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_large_response() {
    // Test handling of larger responses
    let response = get(endpoint("/base64/aGVsbG8gd29ybGQ=")).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    let body = response.into_body().into_bytes().await;
    assert!(body.is_ok());
    let bytes = body.unwrap();
    assert!(!bytes.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_gzip_compression() {
    // httpbin.org supports gzip compression
    let response = get(endpoint("/gzip")).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    let bytes = response.into_body().into_bytes().await.unwrap();
    // Should get some response data (gzipped content is handled by the HTTP client)
    assert!(!bytes.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_cookie_persistence() {
    let client = client().enable_cookie();
    let mut client = client;

    // Set a cookie
    let _response = client
        .get("https://httpbin.org/cookies/set/test/cookievalue")
        .await
        .unwrap();

    // Verify cookie is sent in subsequent request
    let response = client.get("https://httpbin.org/cookies").await.unwrap();
    let body = response.into_body().into_string().await.unwrap();
    assert!(body.contains("test"));
    assert!(body.contains("cookievalue"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), async_std::test)]
async fn test_method_overrides() {
    let mut client = client();

    // Test different HTTP methods
    let methods = [
        (Method::GET, "/get"),
        (Method::POST, "/post"),
        (Method::PUT, "/put"),
        (Method::DELETE, "/delete"),
        (Method::PATCH, "/patch"),
    ];

    for (method, url) in methods {
        let method_clone = method.clone();
        let response = client.method(method, endpoint(url)).await;
        assert!(response.is_ok(), "Failed for method: {method_clone:?}");
        let response = response.unwrap();
        assert!(
            response.status().is_success(),
            "Failed for method: {method_clone:?}"
        );
    }
}
