//! Platform-specific HTTP client backends.
//!
//! This module exposes backend implementations for each supported target and
//! picks a [`DefaultBackend`] alias based on the current platform and enabled
//! Cargo features.
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
//! - **`apple-backend`**: Uses Apple's native `NSURLSession` (macOS/iOS only).
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

// ============================================================================
// Default backend selection for native platforms (non-wasm32)
// ============================================================================

/// The default HTTP client backend: Apple's `NSURLSession`.
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

// ============================================================================
// Compile-time validation for wasm32: backend selection is NOT allowed
// ============================================================================

// Users cannot explicitly select backends on wasm32 - the web backend is always used.
// These compile errors help catch misconfigurations early.

#[cfg(all(target_arch = "wasm32", feature = "hyper-native-tls"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `hyper-native-tls` feature when targeting wasm32."
);

#[cfg(all(target_arch = "wasm32", feature = "hyper-rustls"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `hyper-rustls` feature when targeting wasm32."
);

#[cfg(all(target_arch = "wasm32", feature = "apple-backend"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `apple-backend` feature when targeting wasm32."
);

#[cfg(all(target_arch = "wasm32", feature = "curl-backend"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `curl-backend` feature when targeting wasm32."
);
