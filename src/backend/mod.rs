//! HTTP client backends.
//!
//! This module defines the `ClientBackend` trait and provides
//! default implementations for different platforms.
//!
//! # Backend Selection
//!
//! ## WASM (wasm32)
//! On wasm32 targets, the built-in [`WebBackend`] is always used automatically.
//! No backend selection is available or needed - the web backend uses the browser's
//! native Fetch API.
//!
//! ## Native Platforms
//! On native platforms, users can choose their preferred backend:
//!
//! - **`hyper-backend`** (default): Uses hyper with async-io/async-net. Supports
//!   both `rustls` (default) and `native-tls` for TLS.
//! - **`curl-backend`**: Uses libcurl via the `curl` crate. Includes proxy support.
//! - **`apple-backend`**: Uses Apple's native NSURLSession (macOS/iOS only).
//!
//! The default configuration uses `hyper-backend` with `rustls` TLS.

#[cfg(all(not(target_arch = "wasm32"), feature = "hyper-backend"))]
mod hyper;
#[cfg(all(not(target_arch = "wasm32"), feature = "hyper-backend"))]
pub use hyper::HyperBackend;

#[cfg(all(not(target_arch = "wasm32"), feature = "curl-backend"))]
mod curl;
#[cfg(all(not(target_arch = "wasm32"), feature = "curl-backend"))]
pub use curl::CurlBackend;

#[cfg(all(target_vendor = "apple", feature = "apple-backend"))]
mod apple;
#[cfg(all(target_vendor = "apple", feature = "apple-backend"))]
pub use apple::AppleBackend;

/// Trait for HTTP client backends.
pub trait ClientBackend: http_kit::Endpoint + Default + 'static {}

// ============================================================================
// Default backend selection for native platforms (non-wasm32)
// ============================================================================

/// The default HTTP client backend: Apple's NSURLSession.
/// This is selected when `apple-backend` feature is enabled on Apple platforms.
#[cfg(all(
    not(target_arch = "wasm32"),
    target_vendor = "apple",
    feature = "apple-backend"
))]
pub type DefaultBackend = AppleBackend;

/// The default HTTP client backend: Hyper with async-io.
/// This is the recommended default for most native platforms.
#[cfg(all(
    not(target_arch = "wasm32"),
    not(all(target_vendor = "apple", feature = "apple-backend")),
    feature = "hyper-backend"
))]
pub type DefaultBackend = HyperBackend;

/// The default HTTP client backend: libcurl.
/// This is selected when `curl-backend` is enabled but `hyper-backend` is not.
#[cfg(all(
    not(target_arch = "wasm32"),
    not(all(target_vendor = "apple", feature = "apple-backend")),
    not(feature = "hyper-backend"),
    feature = "curl-backend"
))]
pub type DefaultBackend = CurlBackend;

// ============================================================================
// WASM backend (always used on wasm32, no user selection)
// ============================================================================

#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::WebBackend;

/// The default HTTP client backend for WebAssembly.
/// On wasm32 targets, the built-in web backend using the Fetch API is always used.
/// This cannot be changed - it's the only backend available for wasm32.
#[cfg(target_arch = "wasm32")]
pub type DefaultBackend = WebBackend;

// ============================================================================
// Compile-time validation for native platforms
// ============================================================================

#[cfg(all(
    not(target_arch = "wasm32"),
    not(all(target_vendor = "apple", feature = "apple-backend")),
    not(feature = "hyper-backend"),
    not(feature = "curl-backend")
))]
compile_error!(
    "No backend enabled for native platform. \
     Please enable one of: `hyper-backend` (recommended), `curl-backend`, or `apple-backend` (Apple platforms only). \
     The default feature set includes `hyper-backend` with `rustls` TLS."
);
