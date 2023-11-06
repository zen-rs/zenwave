mod hyper;
pub use hyper::HyperBackend;

pub trait ClientBackend: http_kit::Endpoint + Default {}
