//! # Ergonomic HTTP client framework
//!
//! Zenwave is an ergonomic HTTP client framework.
//! It has a lot of features:
//! - Follow redirect
//! - Cookie store
//! - Bearer and Basic authentication
//! - Powerful middleware system (Add features you need!)
//! - Streaming body transfer
//! - Cross-platform websocket client (optional `ws` feature, enabled by default)
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
//!
//! # Backend Selection
//!
//! ## WASM (wasm32)
//! On WebAssembly targets, Zenwave automatically uses the built-in web backend
//! powered by the browser's Fetch API. No configuration is needed or available.
//! **Note:** Explicitly selecting a backend on wasm32 will result in a compile error.
//!
//! ## Native Platforms
//! On native platforms, Zenwave supports multiple HTTP client backends and,
//! for hyper and websockets, two TLS engines.
//!
//! ### Default
//! `hyper-backend` + `rustls` + `ws`. rustls verifies certificates through the
//! operating system (`rustls-platform-verifier`): Security.framework on
//! Apple platforms, `CryptoAPI` on Windows, the Android trust manager, and the
//! system CA bundle on Linux. See [`Transport`] for adding roots.
//!
//! ### Features
//! - **`hyper-backend`**: hyper over async-io. Needs `rustls` or `native-tls`.
//! - **`rustls`** / **`native-tls`**: the TLS engine for hyper and websockets. Exactly one.
//! - **`curl-backend`**: libcurl-based backend with its own TLS.
//! - **`apple-backend`**: Apple's native `NSURLSession` (macOS/iOS only).
//! - **`ws`**: websocket support.
//!
//! ```toml
//! # Use curl backend instead
//! zenwave = { version = "*", default-features = false, features = ["curl-backend"] }
//!
//! # Use hyper with native-tls explicitly
//! zenwave = { version = "*", default-features = false, features = ["hyper-native-tls", "ws"] }
//! ```

#![allow(clippy::multiple_crate_versions)]

// Exactly one TLS engine serves hyper and native websockets.
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "rustls",
    feature = "native-tls"
))]
compile_error!(
    "`rustls` and `native-tls` are mutually exclusive TLS engines; enable exactly one \
     (the default feature set enables `rustls`)."
);

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "hyper-backend", feature = "ws"),
    not(any(feature = "rustls", feature = "native-tls"))
))]
compile_error!(
    "`hyper-backend` and `ws` need a TLS engine: enable `rustls` (default) or `native-tls`."
);

pub mod backend;
use backend::DefaultBackend;
pub use cache::Cache;
pub use client::Client;
pub use http_kit::*;
pub use oauth2::OAuth2ClientCredentials;
pub mod transport;
#[cfg(not(target_arch = "wasm32"))]
pub use transport::{Proxy, ProxyBuilder};
pub use transport::{Transport, TransportBuilder};

pub mod auth;
pub mod cache;
pub mod cookie;
pub mod error;
pub mod oauth2;
pub mod timeout;

mod client;
pub mod redirect;
pub mod retry;

// Re-export the unified error type
pub use error::Error;

mod ext;
/// Multipart/form-data utilities.
pub mod multipart;
/// Websocket utilities (requires the `ws` feature).
#[cfg(feature = "ws")]
pub mod websocket;

pub use ext::ResponseExt;
pub use timeout::Timeout;

/// The default Zenwave client.
///
/// This wraps the platform backend with redirect following enabled so
/// `zenwave::client()` behaves like a modern HTTP client out of the box.
#[derive(Debug)]
pub struct DefaultClient {
    inner: redirect::FollowRedirect<DefaultBackend>,
}

impl DefaultClient {
    /// Create a default client with redirect following enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DefaultBackend::default().follow_redirect(),
        }
    }

    /// Remove redirect middleware and recover the raw backend.
    #[must_use]
    pub fn disable_redirect(self) -> DefaultBackend {
        self.inner.disable_redirect()
    }

    /// Create a raw backend without redirect middleware.
    #[must_use]
    pub fn raw() -> DefaultBackend {
        DefaultBackend::default()
    }
}

impl Default for DefaultClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Endpoint for DefaultClient {
    type Error = Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.inner.respond(request).await.map_err(Into::into)
    }
}

impl Client for DefaultClient {}

/// Create a default HTTP client backend.
#[must_use]
pub fn client() -> DefaultClient {
    DefaultClient::new()
}

/// Create a raw default backend without redirect middleware.
#[must_use]
pub fn raw_client() -> DefaultBackend {
    DefaultClient::raw()
}

/// Create a default HTTP client backend.
/// Send a GET request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn get<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::GET, uri)?.await
}

/// Send a POST request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn post<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::POST, uri)?.await
}

/// Send a PUT request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn put<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::PUT, uri)?.await
}

/// Send a DELETE request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn delete<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::DELETE, uri)?.await
}
