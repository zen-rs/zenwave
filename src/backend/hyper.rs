use std::mem::replace;

use http_body_util::BodyDataStream;
use http_kit::{Endpoint, Method, Request, Response};
use hyper::http;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::ClientBackend;

#[derive(Debug)]
pub struct HyperBackend {
    client: HyperClient<HttpConnector, http_kit::Body>,
}

impl Default for HyperBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperBackend {
    pub fn new() -> Self {
        let client = HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new());

        Self { client }
    }
}

impl Endpoint for HyperBackend {
    async fn respond(&mut self, request: &mut Request) -> http_kit::Result<Response> {
        let request: http::Request<http_kit::Body> =
            replace(request, Request::new(Method::GET, "/")).into();

        let response = self.client.request(request).await?;

        let response = response
            .map(|body| {
                let stream = BodyDataStream::new(body);
                http_kit::Body::from_stream(stream)
            })
            .into();

        Ok(response)
    }
}

impl ClientBackend for HyperBackend {}
