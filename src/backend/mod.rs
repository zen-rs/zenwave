mod hyper;
pub use hyper::HyperBackend;

pub trait ClientBackend: http_kit::Endpoint + Default + 'static {}

#[cfg(not(target_arch = "wasm32"))]
pub type DefaultBackend = HyperBackend;

#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::WebBackend;
#[cfg(target_arch = "wasm32")]
pub type DefaultBackend = WebBackend;
