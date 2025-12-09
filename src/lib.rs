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
//! On native platforms, Zenwave supports multiple HTTP client backends.
//!
//! ### Default Backend (`default-backend` feature)
//! The default configuration uses platform-specific TLS selection:
//! - **Apple platforms (macOS/iOS):** hyper + native-tls (Security.framework)
//! - **Other platforms:** hyper + rustls with system certificates
//!
//! ### Explicit Backend Selection
//! Available backends (enable via Cargo features):
//! - **`hyper-rustls`**: Hyper with rustls TLS (uses system certificates).
//! - **`hyper-native-tls`**: Hyper with native TLS (OpenSSL, `SChannel`, or Security.framework).
//! - **`curl-backend`**: libcurl-based backend with proxy support.
//! - **`apple-backend`**: Apple's native `NSURLSession` (macOS/iOS only).
//!
//! To use a different backend, disable default features and enable your choice:
//! ```toml
//! # Use curl backend instead
//! zenwave = { version = "*", default-features = false, features = ["curl-backend"] }
//!
//! # Use hyper with native-tls explicitly
//! zenwave = { version = "*", default-features = false, features = ["hyper-native-tls"] }
//!
//! # Use hyper with rustls explicitly
//! zenwave = { version = "*", default-features = false, features = ["hyper-rustls"] }
//! ```

#![allow(clippy::multiple_crate_versions)]

// Compile-time check: native-tls and rustls are mutually exclusive,
// UNLESS `default-backend` is enabled (which intentionally enables both for
// platform-specific selection at compile time).
#[cfg(all(
    feature = "native-tls",
    feature = "rustls",
    not(feature = "default-backend")
))]
compile_error!(
    "Features `native-tls` and `rustls` are mutually exclusive. \
     Please enable only one TLS backend, or use `default-backend` for automatic platform selection."
);

// TLS features are only applicable to hyper-backend on native platforms.
// Other backends (apple-backend, curl-backend) have their own TLS implementations.
// Note: wasm32 check is omitted here because TLS deps aren't even available on wasm32.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "native-tls", feature = "rustls"),
    not(feature = "hyper-backend"),
    any(
        all(target_vendor = "apple", feature = "apple-backend"),
        feature = "curl-backend"
    )
))]
compile_error!(
    "The `native-tls` and `rustls` features only apply to `hyper-backend`. \
     Your current backend (apple-backend or curl-backend) has its own TLS implementation. \
     Please disable these TLS features."
);

pub mod backend;
use backend::DefaultBackend;
pub use cache::Cache;
pub use client::Client;
pub use http_kit::*;
pub use oauth2::OAuth2ClientCredentials;

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
#[cfg(all(not(target_arch = "wasm32"), feature = "proxy"))]
pub mod proxy;
/// Websocket utilities (requires the `ws` feature).
#[cfg(feature = "ws")]
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
/// This helper only exists when the default backend is curl-backend, which
/// supports proxy configuration. Other backends do not support this API.
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "curl-backend",
    not(all(target_vendor = "apple", feature = "apple-backend")),
    not(feature = "hyper-backend")
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
