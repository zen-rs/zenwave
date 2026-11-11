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
//! ## WASI (`wasm32-wasip2`)
//! Only `native-backend` exists: `NativeBackend::on_current_thread` over the
//! host's `http-kit-io` sockets, resolver and clock. See [`backend`].
//!
//! ## Native Platforms
//! On native platforms, Zenwave supports multiple HTTP client backends and,
//! for hyper and websockets, two TLS engines.
//!
//! ### Default
//! `hyper-backend` + `rustls` + `ws`. rustls verifies certificates through the
//! operating system (`rustls-platform-verifier`): Security.framework on
//! Apple platforms, `CryptoAPI` on Windows, and the system CA bundle on Linux.
//! On Android it verifies with webpki against the system trust anchors read
//! from disk, because the platform verifier there reports every CRL-only
//! certificate as revoked (rustls/rustls-platform-verifier#221). See
//! [`Transport`] for adding roots.
//!
//! ### Features
//! - **`hyper-backend`**: hyper over async-io. Needs `rustls` or `native-tls`.
//! - **`native-compio`** / **`native-tokio`**: HTTP/1.1 (and HTTP/3 with
//!   `native-http3`) on http-kit's owned-buffer I/O, driven by compio or
//!   tokio; the default backend when `hyper-backend` is off. `native-backend`
//!   alone gives the runtime-neutral backend for callers that drive it on
//!   their own thread; such a build has no default backend, so
//!   `zenwave::client()`, `DefaultClient`, the one-shot request functions and
//!   the `OAuth2` middleware (which fetches its token through `client()`)
//!   are absent.
//! - **`rustls`** / **`native-tls`**: the TLS engine for hyper and websockets.
//!   Both may be enabled; `rustls` takes precedence.
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

#[cfg(all(
    native,
    any(feature = "hyper-backend", feature = "ws"),
    not(any(feature = "rustls", feature = "native-tls"))
))]
compile_error!(
    "`hyper-backend` and `ws` need a TLS engine: enable `rustls` (default) or `native-tls`."
);

pub mod backend;
pub use auth::{BasicAuth, BearerAuth};
pub use cache::Cache;
pub use client::Client;
pub use cookie::CookieStore;
pub use http_kit::*;
#[cfg(default_backend)]
pub use oauth2::OAuth2ClientCredentials;
pub mod transport;
#[cfg(native)]
pub use transport::{Proxy, ProxyBuilder};
pub use transport::{Transport, TransportBuilder};

pub mod auth;
pub mod cache;
pub mod cookie;
pub mod error;
#[cfg(default_backend)]
pub mod oauth2;
pub mod timeout;

mod client;
pub mod clock;
#[cfg(any(getaddrinfo, https_rr))]
pub mod dns;
pub mod redirect;
pub mod retry;
#[cfg(browser)]
mod single_threaded;
pub mod status;

// Re-export the unified error type
pub use error::Error;

mod ext;
/// Multipart/form-data utilities.
pub mod multipart;
/// Websocket utilities (requires the `ws` feature).
#[cfg(feature = "ws")]
pub mod websocket;

pub use ext::ResponseExt;
pub use status::ErrorForStatus;
pub use timeout::Timeout;

#[cfg(default_backend)]
mod default_client;
#[cfg(default_backend)]
pub use default_client::{DefaultClient, client, client_with, delete, get, post, put};
