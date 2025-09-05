use std::mem::replace;

use http_body_util::BodyDataStream;
use http_kit::{Endpoint, Method, Request, Response};
use hyper::http;
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::ClientBackend;

#[derive(Debug)]
pub struct HyperBackend {
    client: HyperClient<HttpsConnector<HttpConnector>, http_kit::Body>,
}

impl Default for HyperBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperBackend {
    pub fn new() -> Self {
        let client = HyperClient::builder(TokioExecutor::new()).build(HttpsConnector::new());

        Self { client }
    }
}

impl Endpoint for HyperBackend {
    async fn respond(&mut self, request: &mut Request) -> http_kit::Result<Response> {
        let dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(http_kit::Body::empty())
            .unwrap();
        let request: http::Request<http_kit::Body> = replace(request, dummy_request);

        let response = self.client.request(request).await?;

        let response = response.map(|body| {
            let stream = BodyDataStream::new(body);
            http_kit::Body::from_stream(stream)
        });

        Ok(response)
    }
}

impl ClientBackend for HyperBackend {}
