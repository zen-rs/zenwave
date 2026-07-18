use futures_util::StreamExt;
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

    /// Consumes the response body and returns at most `limit` bytes.
    ///
    /// Streaming stops as soon as the configured limit is exceeded, so an
    /// untrusted peer cannot force the client to buffer an unbounded response.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ResponseBodyTooLarge`] when the body exceeds
    /// `limit`, or a body parsing error when the response stream fails.
    fn into_bytes_with_limit(
        self,
        limit: usize,
    ) -> impl Future<Output = Result<Bytes, crate::Error>> + Send;

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

    async fn into_bytes_with_limit(self, limit: usize) -> Result<Bytes, crate::Error> {
        let mut body = self.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            let next_len = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(crate::Error::ResponseBodyTooLarge { limit })?;
            if next_len > limit {
                return Err(crate::Error::ResponseBodyTooLarge { limit });
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes.into())
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

#[cfg(test)]
mod tests {
    use super::ResponseExt;
    use futures_executor::block_on;
    use futures_util::stream;
    use http_kit::{Body, Response, utils::Bytes};

    #[test]
    fn bounded_response_accepts_body_at_limit() {
        let response = Response::new(Body::from("license"));
        let body = block_on(response.into_bytes_with_limit(7)).unwrap();
        assert_eq!(body.as_ref(), b"license");
    }

    #[test]
    fn bounded_response_rejects_stream_when_limit_is_exceeded() {
        let chunks = stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"license")),
            Ok(Bytes::from_static(b"-response")),
        ]);
        let response = Response::new(Body::from_stream(chunks));
        let error = block_on(response.into_bytes_with_limit(8)).unwrap_err();
        assert!(matches!(
            error,
            crate::Error::ResponseBodyTooLarge { limit: 8 }
        ));
    }
}
