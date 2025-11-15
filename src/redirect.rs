//! Middleware for following HTTP redirects.

use http::Uri;
use http_kit::{
    Endpoint, Method, ResultExt,
    header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, HOST, LOCATION},
};
use url::Url;

use crate::{Body, Error, Request, Response, Result, StatusCode, client::Client};

/// Middleware that follows HTTP redirects.
#[derive(Debug, Clone)]
pub struct FollowRedirect<C: Client> {
    client: C,
}

impl<C: Client> Client for FollowRedirect<C> {}

impl<C: Client> FollowRedirect<C> {
    /// Create a new `FollowRedirect` middleware wrapping the given client.
    pub const fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        const MAX_REDIRECTS: u32 = 10;
        let initial_headers = request.headers().clone();
        let mut current_method = request.method().clone();
        let mut current_url = Url::parse(&request.uri().to_string()).map_err(|err| {
            Error::msg(format!("Invalid request URI: {err}")).set_status(StatusCode::BAD_REQUEST)
        })?;
        let mut redirect_count = 0;

        loop {
            let response = self.client.respond(request).await?;

            if !response.status().is_redirection() {
                return Ok(response);
            }

            if redirect_count >= MAX_REDIRECTS {
                return Err(Error::msg("Too many redirects"));
            }

            let location = response
                .headers()
                .get(LOCATION)
                .ok_or_else(|| {
                    Error::msg("Missing Location header").set_status(StatusCode::BAD_REQUEST)
                })?
                .to_str()
                .status(StatusCode::BAD_REQUEST)?;

            let redirect_url = Url::parse(location)
                .or_else(|_| current_url.join(location))
                .map_err(|err| {
                    Error::msg(format!("Invalid redirect location: {err}"))
                        .set_status(StatusCode::BAD_REQUEST)
                })?;

            let next_uri: Uri = redirect_url.as_str().parse().map_err(|err| {
                Error::msg(format!("Invalid redirect URI: {err}"))
                    .set_status(StatusCode::BAD_REQUEST)
            })?;

            let next_method = match response.status() {
                StatusCode::SEE_OTHER => Method::GET,
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                    if current_method != Method::GET && current_method != Method::HEAD =>
                {
                    Method::GET
                }
                _ => current_method.clone(),
            };

            let mut new_request = http::Request::builder()
                .method(next_method.clone())
                .uri(next_uri)
                .body(Body::empty())
                .unwrap();

            let mut headers = initial_headers.clone();
            headers.remove(HOST);
            headers.remove(CONTENT_LENGTH);
            if current_url.host_str() != redirect_url.host_str() {
                headers.remove(AUTHORIZATION);
                headers.remove(COOKIE);
            }
            *new_request.headers_mut() = headers;

            *request = new_request;
            current_url = redirect_url;
            current_method = next_method;
            redirect_count += 1;
        }
    }
}
