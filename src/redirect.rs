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

    /// Remove redirect middleware and recover the wrapped client.
    #[must_use]
    pub fn disable_redirect(self) -> C {
        self.client
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
}

impl<H: HttpError> HttpError for FollowRedirectError<H> {
    fn status(&self) -> StatusCode {
        match self {
            Self::RemoteError(err) => err.status(),
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
        }
    }
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    type Error = FollowRedirectError<C::Error>;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        const MAX_REDIRECTS: u32 = 10;
        let mut redirect_headers = request.headers().clone();
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

            if current_url.origin() != redirect_url.origin() {
                redirect_headers.remove(AUTHORIZATION);
                redirect_headers.remove(COOKIE);
            }

            let mut headers = redirect_headers.clone();
            headers.remove(HOST);
            headers.remove(CONTENT_LENGTH);
            *new_request.headers_mut() = headers;

            *request = new_request;
            current_url = redirect_url;
            current_method = next_method;
            redirect_count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        future::{Future, ready},
    };

    use http_kit::{Body, Endpoint, Request, Response, StatusCode, header};

    use super::FollowRedirect;

    struct RedirectBackend {
        responses: VecDeque<Response>,
        credential_presence: Vec<(bool, bool)>,
    }

    impl Endpoint for RedirectBackend {
        type Error = Infallible;

        fn respond(
            &mut self,
            request: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> {
            self.credential_presence.push((
                request.headers().contains_key(header::AUTHORIZATION),
                request.headers().contains_key(header::COOKIE),
            ));
            ready(Ok(self.responses.pop_front().expect(
                "redirect test backend must have a response for every request",
            )))
        }
    }

    impl crate::Client for RedirectBackend {}

    #[test]
    fn credentials_stay_removed_after_a_cross_origin_redirect() {
        let mut client = FollowRedirect::new(RedirectBackend {
            responses: VecDeque::from([
                redirect_response("http://media.waterui.dev:8080/intermediate"),
                redirect_response("http://media.waterui.dev:8080/final"),
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .expect("final redirect test response must build"),
            ]),
            credential_presence: Vec::new(),
        });
        let mut request = http::Request::builder()
            .uri("http://media.waterui.dev:80/start")
            .header(header::AUTHORIZATION, "Bearer waterui-test-token")
            .header(header::COOKIE, "waterui_session=test")
            .body(Body::empty())
            .expect("redirect test request must build");

        futures_executor::block_on(client.respond(&mut request))
            .expect("redirect chain must complete");

        assert_eq!(
            client.disable_redirect().credential_presence,
            [(true, true), (false, false), (false, false)]
        );
    }

    fn redirect_response(location: &'static str) -> Response {
        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, location)
            .body(Body::empty())
            .expect("redirect test response must build")
    }
}
