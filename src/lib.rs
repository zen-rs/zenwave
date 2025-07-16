//! # Ergonomic HTTP client framework
//! Zenwave is an ergonomic, and full-featured HTTP client framework.
//! It has a lot of features:
//! - Follow redirect
//! - Cookie store
//! - Powerful middleware system (Add features you need!)
//! - Streaming body transfer
//! - Backend and runtime
//!
//! # Quick start
//! ```rust,no_run
//! use zenwave::get;
//! let response = get("https://example.com/").await?;
//! let text = response.into_string().await?;
//! println!("{text}");
//! ```

pub mod backend;
#[cfg(test)]
mod tests;
pub use backend::ClientBackend;
use backend::DefaultBackend;
pub use client::Client;
pub use http_kit::*;

pub(crate) mod cookie_store;

mod client;
pub(crate) mod redirect;

pub fn client() -> DefaultBackend {
    DefaultBackend::default()
}

pub async fn get<U>(uri: U) -> Result<Response>
where
    U: TryInto<Uri> + Send + Sync,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::GET, uri).await
}

pub async fn post<U>(uri: U) -> Result<Response>
where
    U: TryInto<Uri> + Send + Sync,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::POST, uri).await
}

pub async fn put<U>(uri: U) -> Result<Response>
where
    U: TryInto<Uri> + Send + Sync,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::PUT, uri).await
}

pub async fn delete<U>(uri: U) -> Result<Response>
where
    U: TryInto<Uri> + Send + Sync,
    U::Error: core::fmt::Debug,
{
    let mut client = DefaultBackend::default();
    client.method(Method::DELETE, uri).await
}
