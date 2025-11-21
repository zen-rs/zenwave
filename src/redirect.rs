//! Middleware for following HTTP redirects.

use http::Uri;
use http_kit::{
    Endpoint, HttpError, Method,
    header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, HOST, LOCATION},
};
use url::Url;

use crate::{Body, Request, Response, StatusCode, client::Client};

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

#[derive(Debug, thiserror::Error)]
pub enum FollowRedirectError<H: HttpError> {
    #[error("URL parse error: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("Remote error: {0}")]
    RemoteError(H),

    #[error("Too many redirects")]
    TooManyRedirects,

    #[error("Missing Location header in redirect response")]
    MissingLocationHeader,

    #[error("Invalid Location header in redirect response")]
    InvalidLocationHeader,
}

impl<H: HttpError> HttpError for FollowRedirectError<H> {
    fn status(&self) -> Option<StatusCode> {
        match self {
            Self::RemoteError(err) => err.status(),
            _ => None,
        }
    }
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    type Error = FollowRedirectError<C::Error>;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        const MAX_REDIRECTS: u32 = 10;
        let initial_headers = request.headers().clone();
        let mut current_method = request.method().clone();
        let mut current_url = Url::parse(&request.uri().to_string())?;
        let mut redirect_count = 0;

        loop {
            let response = self
                .client
                .respond(request)
                .await
                .map_err(FollowRedirectError::RemoteError)?;

            if !response.status().is_redirection() {
                return Ok(response);
            }

            if redirect_count >= MAX_REDIRECTS {
                return Err(FollowRedirectError::TooManyRedirects);
            }

            let location = response
                .headers()
                .get(LOCATION)
                .ok_or(FollowRedirectError::MissingLocationHeader)?
                .to_str()
                .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;

            let redirect_url = Url::parse(location)
                .or_else(|_| current_url.join(location))
                .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;

            let next_uri: Uri = redirect_url
                .as_str()
                .parse()
                .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;

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
                .expect("failed to build redirect request"); // Safety: We have already made sure method and uri are valid.

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
