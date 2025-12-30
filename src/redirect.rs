//! Middleware for following HTTP redirects.

use http::{HeaderMap, Uri, Version};
use http_kit::{
    Endpoint, HttpError, Method,
    header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, HOST, LOCATION},
};
use url::Url;

use crate::{Body, Request, Response, StatusCode, client::Client};
use crate::auth::suppress_auth_header;
use http_kit::utils::Bytes;

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

/// Errors encountered while following HTTP redirects.
#[derive(Debug, thiserror::Error)]
pub enum FollowRedirectError<H: HttpError> {
    /// Failed to parse a redirect target as a URL.
    #[error("URL parse error: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// Upstream backend returned an error.
    #[error("Remote error: {0}")]
    RemoteError(H),

    /// Redirect limit exceeded.
    #[error("Too many redirects")]
    TooManyRedirects,

    /// Redirect response did not include a `Location` header.
    #[error("Missing Location header in redirect response")]
    MissingLocationHeader,

    /// Redirect target was not a valid `Location` header.
    #[error("Invalid Location header in redirect response")]
    InvalidLocationHeader,

    /// Failed to rebuild the request for redirect replay.
    #[error("Failed to rebuild request: {0}")]
    RequestBuildError(#[from] crate::Error),
}

impl<H: HttpError> HttpError for FollowRedirectError<H> {
    fn status(&self) -> StatusCode {
        match self {
            Self::RemoteError(err) => err.status(),
            Self::RequestBuildError(err) => err.status(),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// Convert FollowRedirectError to unified zenwave::Error
impl<H> From<FollowRedirectError<H>> for crate::Error
where
    H: HttpError + Into<Self>,
{
    fn from(err: FollowRedirectError<H>) -> Self {
        match err {
            FollowRedirectError::InvalidUrl(_) => {
                Self::InvalidUri("Invalid redirect URL".to_string())
            }
            FollowRedirectError::RemoteError(e) => e.into(),
            FollowRedirectError::TooManyRedirects => Self::TooManyRedirects { max: 10 },
            FollowRedirectError::MissingLocationHeader
            | FollowRedirectError::InvalidLocationHeader => Self::InvalidRedirectLocation,
            FollowRedirectError::RequestBuildError(err) => err,
        }
    }
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    type Error = FollowRedirectError<C::Error>;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        const MAX_REDIRECTS: u32 = 10;
        let snapshot = RequestSnapshot::from_request(request).await?;
        let initial_headers = request.headers().clone();
        let mut current_method = request.method().clone();
        let mut current_url = Url::parse(&request.uri().to_string())?;
        let mut redirect_count = 0;
        let mut auth_stripped = false;
        let mut current_headers = initial_headers.clone();

        loop {
            *request = snapshot.build_request(
                &current_method,
                &current_url,
                &current_headers,
                auth_stripped,
            )?;
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

            let next_method = match response.status() {
                StatusCode::SEE_OTHER => Method::GET,
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                    if current_method != Method::GET && current_method != Method::HEAD =>
                {
                    Method::GET
                }
                _ => current_method.clone(),
            };

            let mut headers = initial_headers.clone();
            headers.remove(HOST);
            let drop_body = next_method == Method::GET || next_method == Method::HEAD;
            if drop_body {
                headers.remove(CONTENT_LENGTH);
                headers.remove(http::header::CONTENT_TYPE);
            }
            if current_url.host_str() != redirect_url.host_str() {
                auth_stripped = true;
            }
            if auth_stripped {
                headers.remove(AUTHORIZATION);
                headers.remove(COOKIE);
            }

            current_headers = headers;
            current_url = redirect_url;
            current_method = next_method;
            redirect_count += 1;
        }
    }
}

#[derive(Clone)]
struct RequestSnapshot {
    version: Version,
    extensions: http::Extensions,
    body: Bytes,
}

impl RequestSnapshot {
    async fn from_request(request: &mut Request) -> Result<Self, crate::Error> {
        let version = request.version();
        let extensions = request.extensions().clone();
        let body = request
            .body_mut()
            .take()
            .map_err(|_| crate::Error::InvalidRequest("request body already consumed".to_string()))?
            .into_bytes()
            .await?;

        Ok(Self {
            version,
            extensions,
            body,
        })
    }

    fn build_request(
        &self,
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        suppress_auth: bool,
    ) -> Result<Request, crate::Error> {
        let body = if method == &Method::GET || method == &Method::HEAD {
            Body::empty()
        } else {
            Body::from(self.body.clone())
        };
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|_| crate::Error::InvalidRequest("invalid redirect URI".to_string()))?;
        let mut request = http::Request::builder()
            .method(method.clone())
            .uri(uri)
            .version(self.version)
            .body(body)
            .map_err(|err| crate::Error::InvalidRequest(err.to_string()))?;

        let mut merged_headers = headers.clone();
        if suppress_auth {
            merged_headers.remove(AUTHORIZATION);
            merged_headers.remove(COOKIE);
        }
        *request.headers_mut() = merged_headers;
        *request.extensions_mut() = self.extensions.clone();
        if suppress_auth {
            suppress_auth_header(&mut request);
        }
        Ok(request)
    }
}
