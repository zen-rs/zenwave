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
}
