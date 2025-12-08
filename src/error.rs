//! Unified error types for zenwave HTTP client.
//!
//! This module provides a single, unified error type [`Error`] that encompasses
//! all possible errors that can occur during HTTP operations. This includes:
//! - HTTP server errors (4xx/5xx responses)
//! - Network transport errors (connection failures, DNS errors, etc.)
//! - Request/response parsing errors
//! - Middleware-specific errors (timeout, redirect, authentication, etc.)
//!
//! The [`Error`] type implements [`http_kit::HttpError`] trait and provides
//! rich helper methods for error classification and handling.

use http_kit::{BodyError, Response, StatusCode};
use std::error::Error as StdError;
use thiserror::Error;

/// Unified error type for all zenwave operations.
#[derive(Debug, Error)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// HTTP server returned an error response (4xx/5xx status code).
    ///
    /// This represents a successful HTTP connection where the server returned
    /// an error status. The response body may contain additional error details
    /// that can be deserialized using [`Error::deserialize_http_error`].
    #[error("HTTP error {status}: {message}")]
    Http {
        /// HTTP status code
        status: StatusCode,
        /// Error message (extracted from response body or default message)
        message: String,
        /// Full HTTP error response details
        #[source]
        response: HttpErrorResponse,
    },

    /// Network transport layer error (connection failed, DNS resolution failed, etc.).
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn StdError + Send + Sync>),

    /// TLS/SSL error.
    #[error("TLS error: {0}")]
    Tls(#[source] Box<dyn StdError + Send + Sync>),

    /// Request timed out.
    #[error("request timed out")]
    Timeout,

    /// Too many redirects were followed.
    #[error("too many redirects (max {max})")]
    TooManyRedirects {
        /// Maximum number of redirects allowed
        max: u32,
    },

    /// Invalid redirect Location header.
    #[error("invalid redirect location")]
    InvalidRedirectLocation,

    /// URI parsing error.
    #[error("invalid URI: {0}")]
    InvalidUri(String),

    /// Request construction error (invalid headers, body, etc.).
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Response body parsing error (JSON, form, string, etc.).
    #[error("failed to parse response body: {0}")]
    BodyParse(#[from] BodyError),

    /// Cookie management error.
    #[error("cookie error: {0}")]
    Cookie(#[from] CookieErrorKind),

    /// `OAuth2` authentication error.
    #[error("OAuth2 error: {0}")]
    OAuth2(#[from] OAuth2ErrorKind),

    /// File download error.
    #[error("download error: {0}")]
    Download(#[from] DownloadErrorKind),

    /// WebSocket error.
    #[error("websocket error: {0}")]
    WebSocket(#[from] WebSocketErrorKind),

    /// I/O error (file operations, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other uncategorized error.
    #[error("other error: {0}")]
    Other(#[source] Box<dyn StdError + Send + Sync>),
}

/// HTTP error response details.
///
/// Contains the full HTTP response and cached body text for errors
/// returned by the server (4xx/5xx status codes).
#[derive(Debug)]
pub struct HttpErrorResponse {
    /// Complete HTTP response (including headers, body, etc.)
    pub response: Response,
    /// Response body as text (if available and UTF-8)
    pub body_text: Option<String>,
}

impl StdError for HttpErrorResponse {}

impl std::fmt::Display for HttpErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP response with status {}", self.response.status())
    }
}

/// Cookie-related errors.
#[derive(Debug, Error)]
pub enum CookieErrorKind {
    /// Failed to load cookies from disk.
    #[error("failed to load cookies from disk: {0}")]
    LoadFailed(#[source] std::io::Error),

    /// Failed to parse cookie data.
    #[error("failed to parse cookies: {0}")]
    ParseFailed(#[source] serde_json::Error),

    /// Failed to persist cookies to disk.
    #[error("failed to persist cookies: {0}")]
    PersistFailed(#[source] std::io::Error),

    /// Invalid cookie header.
    #[error("invalid cookie header")]
    InvalidHeader,
}

/// OAuth2-related errors.
#[derive(Debug, Error)]
pub enum OAuth2ErrorKind {
    /// Failed to fetch `OAuth2` token.
    #[error("failed to fetch token: {0}")]
    TokenFetchFailed(String),

    /// Token endpoint returned an error.
    #[error("token endpoint returned error: {status} - {message}")]
    TokenEndpointError {
        /// HTTP status code from token endpoint
        status: StatusCode,
        /// Error message
        message: String,
    },

    /// Invalid token response format.
    #[error("invalid token response: {0}")]
    InvalidTokenResponse(String),
}

/// Download-related errors.
#[derive(Debug, Error)]
pub enum DownloadErrorKind {
    /// Server returned an error status.
    #[error("upstream returned error: {0}")]
    UpstreamError(StatusCode),

    /// File system error during download.
    #[error("file system error: {0}")]
    FileSystem(#[source] std::io::Error),

    /// Failed to read response body.
    #[error("failed to read response body: {0}")]
    BodyRead(String),
}

/// WebSocket-related errors.
#[derive(Debug, Error)]
pub enum WebSocketErrorKind {
    /// Failed to encode payload.
    #[error("failed to encode payload: {0}")]
    EncodeFailed(#[source] serde_json::Error),

    /// Unsupported URI scheme.
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),

    /// WebSocket connection failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
}

impl Error {
    /// Check if this is a network transport error.
    pub const fn is_network_error(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Tls(_))
    }

    /// Check if this is a timeout error.
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout)
    }

    /// Check if this is a client error (4xx HTTP status).
    pub fn is_client_error(&self) -> bool {
        matches!(self, Self::Http { status, .. } if status.is_client_error())
    }

    /// Check if this is a server error (5xx HTTP status).
    pub fn is_server_error(&self) -> bool {
        matches!(self, Self::Http { status, .. } if status.is_server_error())
    }

    /// Check if this is a redirect-related error.
    pub const fn is_redirect_error(&self) -> bool {
        matches!(
            self,
            Self::TooManyRedirects { .. } | Self::InvalidRedirectLocation
        )
    }

    /// Check if this is a request construction error.
    pub const fn is_request_error(&self) -> bool {
        matches!(self, Self::InvalidRequest(_) | Self::InvalidUri(_))
    }

    /// Get the response body text (if this is an HTTP error).
    pub fn response_body(&self) -> Option<&str> {
        match self {
            Self::Http { response, .. } => response.body_text.as_deref(),
            _ => None,
        }
    }

    /// Get the full HTTP response (if this is an HTTP error).
    pub const fn response(&self) -> Option<&Response> {
        match self {
            Self::Http { response, .. } => Some(&response.response),
            _ => None,
        }
    }

    /// Attempt to deserialize the HTTP error response body as a specific type.
    ///
    /// This is useful for APIs that return structured error responses.
    ///
    /// # Example
    /// ```no_run
    /// use serde::Deserialize;
    /// use zenwave::Client;
    ///
    /// #[derive(Deserialize)]
    /// struct ApiError {
    ///     code: String,
    ///     message: String,
    /// }
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut client = zenwave::client();
    /// match client.get("https://api.example.com/data").await {
    ///     Err(e) => {
    ///         if let Some(api_err) = e.deserialize_http_error::<ApiError>() {
    ///             println!("API error: {} - {}", api_err.code, api_err.message);
    ///         }
    ///     }
    ///     Ok(resp) => { /* ... */ }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn deserialize_http_error<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        match self {
            Self::Http { response, .. } => response
                .body_text
                .as_ref()
                .and_then(|text| serde_json::from_str(text).ok()),
            _ => None,
        }
    }

    /// Get the error category/kind.
    ///
    /// Useful for logging and monitoring.
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::Http { .. } => ErrorKind::Http,
            Self::Transport(_) => ErrorKind::Transport,
            Self::Tls(_) => ErrorKind::Tls,
            Self::Timeout => ErrorKind::Timeout,
            Self::TooManyRedirects { .. } | Self::InvalidRedirectLocation => ErrorKind::Redirect,
            Self::InvalidUri(_) | Self::InvalidRequest(_) => ErrorKind::Request,
            Self::BodyParse(_) => ErrorKind::BodyParse,
            Self::Cookie(_) => ErrorKind::Cookie,
            Self::OAuth2(_) => ErrorKind::OAuth2,
            Self::Download(_) => ErrorKind::Download,
            Self::WebSocket(_) => ErrorKind::WebSocket,
            Self::Io(_) => ErrorKind::Io,
            Self::Other(_) => ErrorKind::Other,
        }
    }
}

/// Error category labels.
///
/// Used for classifying errors for logging, monitoring, and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// HTTP server error
    Http,
    /// Transport/network error
    Transport,
    /// TLS/SSL error
    Tls,
    /// Timeout error
    Timeout,
    /// Redirect error
    Redirect,
    /// Request construction error
    Request,
    /// Response body parsing error
    BodyParse,
    /// Cookie management error
    Cookie,
    /// `OAuth2` authentication error
    OAuth2,
    /// Download error
    Download,
    /// WebSocket error
    WebSocket,
    /// I/O error
    Io,
    /// Other/uncategorized error
    Other,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Transport => write!(f, "transport"),
            Self::Tls => write!(f, "tls"),
            Self::Timeout => write!(f, "timeout"),
            Self::Redirect => write!(f, "redirect"),
            Self::Request => write!(f, "request"),
            Self::BodyParse => write!(f, "body_parse"),
            Self::Cookie => write!(f, "cookie"),
            Self::OAuth2 => write!(f, "oauth2"),
            Self::Download => write!(f, "download"),
            Self::WebSocket => write!(f, "websocket"),
            Self::Io => write!(f, "io"),
            Self::Other => write!(f, "other"),
        }
    }
}

// Implement http_kit::HttpError trait for Error
impl http_kit::HttpError for Error {
    fn status(&self) -> StatusCode {
        match self {
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Http { status, .. }
            | Self::OAuth2(OAuth2ErrorKind::TokenEndpointError { status, .. })
            | Self::Download(DownloadErrorKind::UpstreamError(status)) => *status,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// Generic conversion from MiddlewareError to Error
impl<E, M> From<http_kit::middleware::MiddlewareError<E, M>> for Error
where
    E: Into<Self>,
    M: Into<Self>,
{
    fn from(err: http_kit::middleware::MiddlewareError<E, M>) -> Self {
        match err {
            http_kit::middleware::MiddlewareError::Endpoint(e) => e.into(),
            http_kit::middleware::MiddlewareError::Middleware(m) => m.into(),
        }
    }
}
