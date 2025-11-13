//! HTTP client backends.
//!! This module defines the `ClientBackend` trait and provides
//! default implementations for different platforms.

mod hyper;
pub use hyper::HyperBackend;

/// Trait for HTTP client backends.
pub trait ClientBackend: http_kit::Endpoint + Default + 'static {}

/// The default HTTP client backend for the current platform.
#[cfg(not(target_arch = "wasm32"))]
pub type DefaultBackend = HyperBackend;

#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::WebBackend;

/// The default HTTP client backend for the current platform.
#[cfg(target_arch = "wasm32")]
pub type DefaultBackend = WebBackend;
