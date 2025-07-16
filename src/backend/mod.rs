mod hyper;
pub use hyper::HyperBackend;

pub trait ClientBackend: http_kit::Endpoint + Default + 'static {}

pub type DefaultBackend = HyperBackend;

mod web;
pub use web::WebBackend;
