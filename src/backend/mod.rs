//! HTTP client backends.
//!! This module defines the `ClientBackend` trait and provides
//! default implementations for different platforms.

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

/// The default HTTP client backend for the current platform.
#[cfg(all(
    not(target_arch = "wasm32"),
    target_vendor = "apple",
    feature = "apple-backend"
))]
pub type DefaultBackend = AppleBackend;

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "hyper-backend"
))]
pub type DefaultBackend = HyperBackend;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(feature = "hyper-backend"),
    feature = "curl-backend"
))]
pub type DefaultBackend = CurlBackend;

#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::WebBackend;

/// The default HTTP client backend for the current platform.
#[cfg(target_arch = "wasm32")]
pub type DefaultBackend = WebBackend;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(feature = "hyper-backend"),
    not(feature = "curl-backend"),
    not(all(target_vendor = "apple", feature = "apple-backend"))
))]
compile_error!(
    "Enable at least one of `hyper-backend` or `curl-backend` for native zenwave builds."
);
