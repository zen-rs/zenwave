//! Authentication middlewares for HTTP requests.
//!
//! Both middlewares only set `Authorization` when the request does not already
//! carry one, so a per-request credential always wins over a client-wide one.
//!
//! Credentials are encoded into a [`HeaderValue`] once, when the middleware is
//! constructed. Credentials that cannot appear in a header (for example a token
//! containing a newline) are rejected at that point rather than panicking on
//! every request, which is why [`BearerAuth::new`] and [`BasicAuth::new`] are
//! fallible.

use std::convert::Infallible;

use http_kit::{
    Endpoint, Middleware, Request, Response, header, header::HeaderValue,
    middleware::MiddlewareError,
};

use crate::Error;

/// Encode a bearer token into an `Authorization` header value.
pub(crate) fn bearer_header_value(token: &str) -> Result<HeaderValue, Error> {
    let mut value = String::with_capacity("Bearer ".len() + token.len());
    value.push_str("Bearer ");
    value.push_str(token);
    HeaderValue::from_maybe_shared(value)
        .map_err(|_| Error::InvalidRequest("bearer token is not a valid header value".to_string()))
}

/// Encode `username:password` into a `Basic` `Authorization` header value.
pub(crate) fn basic_header_value(
    username: &str,
    password: Option<&str>,
) -> Result<HeaderValue, Error> {
    use base64::Engine as _;

    let password = password.unwrap_or_default();
    let mut credentials = String::with_capacity(username.len() + 1 + password.len());
    credentials.push_str(username);
    credentials.push(':');
    credentials.push_str(password);

    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    let mut value = String::with_capacity("Basic ".len() + encoded.len());
    value.push_str("Basic ");
    value.push_str(&encoded);

    // Base64 output is always header-safe, so this only fails on a bug.
    HeaderValue::from_maybe_shared(value)
        .map_err(|_| Error::InvalidRequest("basic credentials are not encodable".to_string()))
}

/// Middleware for Bearer Token Authentication.
///
/// Adds an `Authorization: Bearer <token>` header to requests that do not
/// already carry an `Authorization` header.
#[derive(Debug, Clone)]
pub struct BearerAuth {
    value: HeaderValue,
}

impl BearerAuth {
    /// Create a new `BearerAuth` middleware with the given token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] when `token` contains characters that
    /// cannot appear in a header value, such as a newline.
    pub fn new(token: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            value: bearer_header_value(token.as_ref())?,
        })
    }
}

impl Middleware for BearerAuth {
    type Error = Infallible;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        if !request.headers().contains_key(header::AUTHORIZATION) {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, self.value.clone());
        }

        next.respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)
    }
}

/// Middleware for Basic Authentication.
///
/// Adds an `Authorization: Basic <base64-encoded-credentials>` header to
/// requests that do not already carry an `Authorization` header.
#[derive(Debug, Clone)]
pub struct BasicAuth {
    value: HeaderValue,
}

impl BasicAuth {
    /// Create a new `BasicAuth` middleware with the given username and optional password.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] when the encoded credentials cannot be
    /// represented as a header value.
    // `Option<impl AsRef<str>>` keeps `BasicAuth::new("user", Some("pass"))`
    // readable; taking it by reference would force callers to spell out `&Some`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        username: impl AsRef<str>,
        password: Option<impl AsRef<str>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            value: basic_header_value(username.as_ref(), password.as_ref().map(AsRef::as_ref))?,
        })
    }
}

impl Middleware for BasicAuth {
    type Error = Infallible;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        if !request.headers().contains_key(header::AUTHORIZATION) {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, self.value.clone());
        }

        next.respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::{basic_header_value as basic_value, bearer_header_value as bearer_value};

    #[test]
    fn bearer_rejects_tokens_that_cannot_be_header_values() {
        let error = bearer_value("token\nInjected: header")
            .expect_err("a token containing a newline must be rejected");
        assert!(matches!(error, crate::Error::InvalidRequest(_)));
    }

    #[test]
    fn bearer_prefixes_the_token() {
        let value = bearer_value("abc123").expect("plain tokens must encode");
        assert_eq!(value.to_str().expect("header is ascii"), "Bearer abc123");
    }

    #[test]
    fn basic_encodes_username_and_password() {
        let value = basic_value("testuser", Some("testpass")).expect("credentials must encode");
        // base64("testuser:testpass")
        assert_eq!(
            value.to_str().expect("header is ascii"),
            "Basic dGVzdHVzZXI6dGVzdHBhc3M="
        );
    }

    #[test]
    fn basic_without_password_still_appends_the_separator() {
        let value = basic_value("onlyuser", None).expect("credentials must encode");
        // base64("onlyuser:")
        assert_eq!(
            value.to_str().expect("header is ascii"),
            "Basic b25seXVzZXI6"
        );
    }

    #[test]
    fn basic_tolerates_credentials_with_control_characters() {
        // Base64 always produces header-safe output, so odd input must not fail.
        basic_value("user\n", Some("pass\r")).expect("base64 output is always header safe");
    }
}
