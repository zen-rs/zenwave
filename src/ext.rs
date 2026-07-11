use http_kit::{
    BodyError,
    sse::SseStream,
    utils::{ByteStr, Bytes},
};

/// Extension trait for `Response` to add additional functionality.
pub trait ResponseExt {
    /// Consumes the response body and parses it as JSON into the specified type.
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be parsed as JSON.
    fn into_json<T: serde::de::DeserializeOwned>(
        self,
    ) -> impl Future<Output = Result<T, BodyError>> + Send;

    /// Consumes the response body and returns an SSE stream.
    fn into_sse(self) -> SseStream;

    /// Consumes the response body and returns it as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be converted to a string.
    fn into_string(self) -> impl Future<Output = Result<ByteStr, BodyError>> + Send;
    /// Consumes the response body and returns it as bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be converted to bytes.
    fn into_bytes(self) -> impl Future<Output = Result<Bytes, BodyError>> + Send;

    /// Consumes the response, returning it unchanged when the status is a
    /// success (2xx) and a rich [`crate::Error::Http`] otherwise.
    ///
    /// On error the body is read and captured as `body_text` (when valid
    /// UTF-8), mirroring what backend-level HTTP errors report — so server
    /// error messages surface in the returned error instead of being
    /// silently dropped.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Http`] when the status is not 2xx.
    fn error_for_status(self) -> impl Future<Output = Result<Self, crate::Error>> + Send
    where
        Self: Sized;
}

impl ResponseExt for crate::Response {
    async fn into_json<T: serde::de::DeserializeOwned>(self) -> Result<T, BodyError> {
        self.into_body().into_json().await
    }

    fn into_sse(self) -> SseStream {
        self.into_body().into_sse()
    }
    fn into_string(self) -> impl Future<Output = Result<ByteStr, BodyError>> + Send {
        self.into_body().into_string()
    }

    fn into_bytes(self) -> impl Future<Output = Result<Bytes, BodyError>> + Send {
        self.into_body().into_bytes()
    }

    async fn error_for_status(self) -> Result<Self, crate::Error> {
        let status = self.status();
        if status.is_success() {
            return Ok(self);
        }
        let (parts, body) = self.into_parts();
        let body_text = body.into_string().await.ok().map(|text| text.to_string());
        let message = body_text.clone().unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("Unknown error")
                .to_string()
        });
        Err(crate::Error::Http {
            status,
            message,
            response: Box::new(crate::error::HttpErrorResponse {
                response: Self::from_parts(parts, http_kit::Body::empty()),
                body_text,
            }),
        })
    }
}
