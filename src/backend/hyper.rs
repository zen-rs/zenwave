use async_trait::async_trait;
use http_kit::{Endpoint, Request, Response};
use hyper::client::HttpConnector;
use hyper::http;

use crate::ClientBackend;

#[derive(Debug, Default)]
pub struct HyperBackend {
    client: hyper::Client<HttpConnector, hyper::Body>,
}

#[async_trait]
impl Endpoint for HyperBackend {
    async fn call_endpoint(&self, request: Request) -> http_kit::Result<Response> {
        let request: http::Request<http_kit::Body> = request.into();
        let request = request.map(|body| hyper::Body::wrap_stream(body));

        let response = self.client.request(request).await?;

        let response = response
            .map(|body| http_kit::Body::from_stream(body))
            .into();

        Ok(response)
    }
}

impl ClientBackend for HyperBackend {}
