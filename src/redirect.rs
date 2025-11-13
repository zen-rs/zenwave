//! Middleware for following HTTP redirects.

use http_kit::{Endpoint, Method, ResultExt, header::LOCATION};

use crate::{Request, Response, Result, StatusCode, client::Client};

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
        // Store the original URI before it gets modified by the backend
        let original_uri = request.uri().clone();
        let original_method = request.method().clone();

        let mut current_response = self.client.respond(request).await?;
        let mut redirect_count = 0;

        // Follow redirects up to MAX_REDIRECTS times
        while current_response.status().is_redirection() && redirect_count < MAX_REDIRECTS {
            let location = current_response
                .headers()
                .get(LOCATION)
                .ok_or_else(|| http_kit::Error::msg("Missing Location header"))?
                .to_str()
                .status(StatusCode::BAD_REQUEST)?;

            // According to RFC 9110
            let method = match current_response.status() {
                StatusCode::MULTIPLE_CHOICES | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                    Method::GET
                }
                _ => original_method.clone(),
            };

            // Handle relative URLs by resolving against the original request URI
            let redirect_uri =
                if location.starts_with("http://") || location.starts_with("https://") {
                    location.to_string()
                } else {
                    // For relative URLs, use the same scheme and host as the original request
                    let base_uri = original_uri.to_string();

                    base_uri.find("://").map_or_else(
                        || location.to_string(),
                        |scheme_end| {
                            let after_scheme = scheme_end + 3;
                            let path_start =
                                base_uri[after_scheme..].find('/').map(|i| i + after_scheme);
                            let scheme_and_host = &base_uri[..path_start.unwrap_or(base_uri.len())];
                            if location.starts_with('/') {
                                format!("{scheme_and_host}{location}")
                            } else {
                                format!("{scheme_and_host}/{location}")
                            }
                        },
                    )
                };

            current_response = self.client.method(method, redirect_uri).await?;
            redirect_count += 1;
        }

        if redirect_count >= MAX_REDIRECTS {
            return Err(http_kit::Error::msg("Too many redirects"));
        }

        Ok(current_response)
    }
}
