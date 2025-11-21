//! Authentication middlewares for HTTP requests.

use std::convert::Infallible;

use http_kit::{Endpoint, Middleware, Request, Response, header, middleware::MiddlewareError};

/// Middleware for Bearer Token Authentication.
/// Adds an `Authorization: Bearer <token>` header to requests.
#[derive(Debug, Clone)]
pub struct BearerAuth {
    token: String,
}

impl BearerAuth {
    /// Create a new `BearerAuth` middleware with the given token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl Middleware for BearerAuth {
    type Error = Infallible;
    async fn handle<E:Endpoint>(
            &mut self,
            request: &mut Request,
            mut next: E,
        ) -> Result<Response,http_kit::middleware::MiddlewareError<E::Error,Self::Error>> {
         // Only add auth header if one isn't already present
        if !request.headers().contains_key(header::AUTHORIZATION) {
            let auth_value = format!("Bearer {}", self.token);
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, auth_value.parse().unwrap());
        }

        Ok(next.respond(request).await.map_err(MiddlewareError::Endpoint)?)
    }
}

/// Middleware for Basic Authentication.
/// Adds an `Authorization: Basic <base64-encoded-credentials>` header to requests.
#[derive(Debug, Clone)]
pub struct BasicAuth {
    username: String,
    password: Option<String>,
}

impl BasicAuth {
    /// Create a new `BasicAuth` middleware with the given username and optional password.
    pub fn new(username: impl Into<String>, password: Option<impl Into<String>>) -> Self {
        Self {
            username: username.into(),
            password: password.map(std::convert::Into::into),
        }
    }
}

impl Middleware for BasicAuth {
    type Error = Infallible;
    async fn handle<E:Endpoint>(
            &mut self,
            request: &mut Request,
            mut next: E,
        ) -> Result<Response,http_kit::middleware::MiddlewareError<E::Error,Self::Error>> {
        // Only add auth header if one isn't already present
        if !request.headers().contains_key(header::AUTHORIZATION) {
            use base64::Engine;

            let credentials = match &self.password {
                Some(password) => format!("{}:{}", self.username, password),
                None => format!("{}:", self.username),
            };

            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
            let auth_value = format!("Basic {encoded}");

            request
                .headers_mut()
                .insert(header::AUTHORIZATION, auth_value.parse().unwrap());
        }

        Ok(next.respond(request).await.map_err(MiddlewareError::Endpoint)?)
    }
}
