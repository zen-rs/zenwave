use std::{fmt, path::PathBuf};

use http::StatusCode;
use http_kit::{BodyError, HttpError as HttpKitError};
use thiserror::Error;

/// Convenient result alias using zenwave's error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Top-level error type surfaced by zenwave.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Download(#[from] DownloadError),
    #[error(transparent)]
    CookieStore(#[from] CookieStoreError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error(transparent)]
    Redirect(#[from] RedirectError),
    #[error(transparent)]
    WebBackend(#[from] WebBackendError),
    #[cfg(feature = "hyper-backend")]
    #[error(transparent)]
    HyperBackend(#[from] HyperBackendError),
    #[error(transparent)]
    Http(#[from] http_kit::Error),
}

impl Error {
    /// HTTP status associated with this error.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Client(err) => err.status(),
            Self::Download(err) => err.status(),
            Self::CookieStore(err) => err.status(),
            Self::Cache(err) => err.status(),
            Self::Redirect(err) => err.status(),
            Self::WebBackend(err) => err.status(),
            #[cfg(feature = "hyper-backend")]
            Self::HyperBackend(err) => err.status(),
            Self::Http(err) => err.status(),
        }
    }

    /// Convert this error into an `http_kit::Error`, preserving the HTTP status code.
    #[must_use]
    pub fn into_http_error(self) -> http_kit::Error {
        match self {
            Error::Client(inner) => {
                let status = inner.status();
                http_error_from(inner, status)
            }
            Error::Download(inner) => {
                let status = inner.status();
                http_error_from(inner, status)
            }
            Error::CookieStore(inner) => {
                let status = inner.status();
                http_error_from(inner, status)
            }
            Error::Cache(inner) => {
                let status = inner.status();
                http_error_from(inner, status)
            }
            Error::Redirect(inner) => {
                let status = inner.status();
                http_error_from(inner, status)
            }
            Error::WebBackend(inner) => {
                let status = inner.status();
                http_error_from(inner, status)
            }
            #[cfg(feature = "hyper-backend")]
            Error::HyperBackend(inner) => {
                let status = inner.status();
                http_error_from(inner, status)
            }
            Error::Http(inner) => inner,
        }
    }
}

impl HttpKitError for Error {
    fn status(&self) -> StatusCode {
        self.status()
    }
}

fn http_error_from<E>(err: E, status: StatusCode) -> http_kit::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    http_kit::Error::new(err, status)
}

/// Errors produced while reading or transforming response bodies through the client API.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("failed to read response body as string")]
    BodyToString { source: BodyError },
    #[error("failed to read response body as bytes")]
    BodyToBytes { source: BodyError },
    #[error("failed to serialize body as JSON")]
    JsonEncode {
        #[from]
        source: serde_json::Error,
    },
    #[error("failed to deserialize response body as JSON")]
    JsonDecode { source: BodyError },
    #[error("failed to deserialize response body as form data")]
    FormDecode { source: BodyError },
}

impl ClientError {
    const fn status(&self) -> StatusCode {
        match self {
            Self::BodyToString { .. } | Self::BodyToBytes { .. } | Self::JsonEncode { .. } => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::JsonDecode { .. } | Self::FormDecode { .. } => StatusCode::BAD_REQUEST,
        }
    }
}

/// Errors generated while downloading responses to disk.
#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("failed to read metadata for {path}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open {path} for download")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to seek {path} while resuming download")]
    Seek {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write downloaded data to {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to flush downloaded data to {path}")]
    Flush {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read the next chunk from the response body")]
    BodyChunk {
        #[from]
        source: BodyError,
    },
}

impl DownloadError {
    const fn status(&self) -> StatusCode {
        match self {
            Self::BodyChunk { .. } => StatusCode::BAD_GATEWAY,
            Self::Metadata { .. }
            | Self::Open { .. }
            | Self::Seek { .. }
            | Self::Write { .. }
            | Self::Flush { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Errors produced by the cookie store middleware.
#[derive(Debug, Error)]
pub enum CookieStoreError {
    #[error("failed to {operation} at {path}")]
    Persistence {
        path: PathBuf,
        operation: PersistenceOperation,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize cookies")]
    SnapshotSerialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to deserialize cookies")]
    SnapshotDeserialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to encode cookie header")]
    HeaderEncoding {
        #[from]
        source: http::header::InvalidHeaderValue,
    },
    #[error("failed to parse cookie header as UTF-8")]
    HeaderToStr {
        #[from]
        source: http::header::ToStrError,
    },
    #[error("failed to parse Set-Cookie header")]
    CookieParse {
        #[from]
        source: http_kit::cookie::ParseError,
    },
}

impl CookieStoreError {
    const fn status(&self) -> StatusCode {
        match self {
            Self::HeaderEncoding { .. }
            | Self::HeaderToStr { .. }
            | Self::CookieParse { .. } => StatusCode::BAD_REQUEST,
            Self::Persistence { .. }
            | Self::SnapshotSerialize { .. }
            | Self::SnapshotDeserialize { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Disk persistence operations performed by the cookie store.
#[derive(Debug, Clone, Copy)]
pub enum PersistenceOperation {
    Load,
    CreateDir,
    WriteTemp,
    Rename,
}

impl fmt::Display for PersistenceOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load => write!(f, "load persisted cookie store"),
            Self::CreateDir => write!(f, "create cookie store directory"),
            Self::WriteTemp => write!(f, "write cookie snapshot"),
            Self::Rename => write!(f, "finalize cookie snapshot"),
        }
    }
}

/// Errors generated while caching responses.
#[derive(Debug, Error)]
#[error("failed to buffer response body for caching")]
pub struct CacheError {
    #[from]
    source: BodyError,
}

impl CacheError {
    const fn status(&self) -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Errors related to HTTP redirect handling.
#[derive(Debug, Error)]
pub enum RedirectError {
    #[error("invalid request URI: {uri}")]
    InvalidRequestUri {
        uri: String,
        #[source]
        source: url::ParseError,
    },
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("redirect response missing Location header")]
    MissingLocation,
    #[error("failed to parse Location header as UTF-8")]
    LocationToStr {
        #[from]
        source: http::header::ToStrError,
    },
    #[error("invalid redirect location: {value}")]
    InvalidLocation {
        value: String,
        #[source]
        source: url::ParseError,
    },
    #[error("invalid redirect URI: {value}")]
    InvalidRedirectUri {
        value: String,
        #[source]
        source: http::uri::InvalidUri,
    },
}

impl RedirectError {
    const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

/// Errors surfaced by the WASM backend.
#[derive(Debug, Error)]
pub enum WebBackendError {
    #[error("failed to convert request header to string")]
    HeaderToStr {
        #[from]
        source: http::header::ToStrError,
    },
    #[error("failed to set request header: {message}")]
    HeaderSet { message: String },
    #[error("failed to construct browser request: {message}")]
    RequestConstruction { message: String },
    #[error("window.fetch reported an error: {message}")]
    Fetch { message: String },
    #[error("failed to cast JS value into a Response")]
    ResponseCast,
    #[error("failed to iterate response headers: {message}")]
    HeaderIteration { message: String },
    #[error("failed to cast header entry into an array")]
    HeaderPairCast,
    #[error("invalid response header name")]
    HeaderName {
        #[from]
        source: http::header::InvalidHeaderName,
    },
    #[error("invalid response header value")]
    HeaderValue {
        #[from]
        source: http::header::InvalidHeaderValue,
    },
    #[error("response header entry missing name or value")]
    HeaderFieldMissing,
    #[error("failed to read response body: {message}")]
    BodyRead { message: String },
}

impl WebBackendError {
    const fn status(&self) -> StatusCode {
        match self {
            Self::HeaderToStr { .. }
            | Self::HeaderSet { .. }
            | Self::RequestConstruction { .. }
            | Self::HeaderIteration { .. }
            | Self::HeaderPairCast
            | Self::HeaderName { .. }
            | Self::HeaderValue { .. }
            | Self::HeaderFieldMissing => StatusCode::BAD_REQUEST,
            Self::Fetch { .. } | Self::ResponseCast | Self::BodyRead { .. } => {
                StatusCode::BAD_GATEWAY
            }
        }
    }
}

/// Errors surfaced by the Hyper backend.
#[cfg(feature = "hyper-backend")]
#[derive(Debug, Error)]
#[error("hyper backend request failed")]
pub struct HyperBackendError {
    #[from]
    source: hyper::Error,
}

#[cfg(feature = "hyper-backend")]
impl HyperBackendError {
    const fn status(&self) -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
