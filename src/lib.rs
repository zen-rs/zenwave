#![allow(clippy::multiple_crate_versions)]

//! # Ergonomic HTTP client framework
//! Zenwave is an ergonomic HTTP client framework.
//! It has a lot of features:
//! - Follow redirect
//! - Cookie store
//! - Bearer and Basic authentication
//! - Powerful middleware system (Add features you need!)
//! - Streaming body transfer
//! - Cross-platform websocket client
//!
//! # Quick start
//! ```rust,no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use zenwave::get;
//! let response = get("https://example.com/").await?;
//! let text = response.into_body().into_string().await?;
//! println!("{text}");
//! # Ok(())
//! # }
//! ```

pub mod backend;
pub use backend::ClientBackend;
use backend::DefaultBackend;
pub use cache::Cache;
pub use client::Client;
pub use http_kit::*;
pub use oauth2::OAuth2ClientCredentials;

pub mod auth;
pub mod cache;
pub mod cookie;
pub mod oauth2;
pub mod timeout;

mod client;
pub mod redirect;

mod ext;
/// Multipart/form-data utilities.
pub mod multipart;
#[cfg(all(not(target_arch = "wasm32"), feature = "proxy"))]
pub mod proxy;
/// Websocket utilities.
pub mod websocket;

pub use ext::ResponseExt;
#[cfg(all(not(target_arch = "wasm32"), feature = "proxy"))]
pub use proxy::{Proxy, ProxyBuilder};
pub use timeout::Timeout;

/// Create a default HTTP client backend.
#[must_use]
pub fn client() -> DefaultBackend {
    DefaultBackend::default()
}

/// Construct the default backend configured with a proxy matcher.
///
/// This helper only exists when the default backend is proxy-capable (Hyper or
/// curl). Apple (`apple-backend`) and Web (`wasm32`) targets do not compile this
/// API because their backends ignore proxy settings.
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "proxy",
    not(all(target_vendor = "apple", feature = "apple-backend"))
))]
#[must_use]
#[allow(clippy::missing_const_for_fn)]
pub fn client_with_proxy(proxy: Proxy) -> DefaultBackend {
    DefaultBackend::with_proxy(proxy)
}

/// Create a default HTTP client backend.
/// Send a GET request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn get<U>(uri: U) -> Result<Response, <DefaultBackend as Endpoint>::Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::GET, uri).await
}

/// Send a POST request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn post<U>(uri: U) -> Result<Response, <DefaultBackend as Endpoint>::Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::POST, uri).await
}

/// Send a PUT request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn put<U>(uri: U) -> Result<Response, <DefaultBackend as Endpoint>::Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::PUT, uri).await
}

/// Send a DELETE request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn delete<U>(uri: U) -> Result<Response, <DefaultBackend as Endpoint>::Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::DELETE, uri).await
}
