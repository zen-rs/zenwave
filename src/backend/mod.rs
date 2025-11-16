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

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
pub use apple::AppleBackend;

/// Trait for HTTP client backends.
pub trait ClientBackend: http_kit::Endpoint + Default + 'static {}

/// The default HTTP client backend for the current platform.
#[cfg(all(not(target_arch = "wasm32"), target_vendor = "apple"))]
pub type DefaultBackend = AppleBackend;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_vendor = "apple"),
    feature = "hyper-backend"
))]
pub type DefaultBackend = HyperBackend;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_vendor = "apple"),
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
    not(target_vendor = "apple"),
    not(feature = "hyper-backend"),
    not(feature = "curl-backend")
))]
compile_error!(
    "Enable at least one of `hyper-backend` or `curl-backend` for native zenwave builds."
);
