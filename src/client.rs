//! The [`Client`] trait and its request builder.
//!
//! [`Client`] layers middleware onto any [`Endpoint`], and its `get`/`post`/...
//! helpers hand back a [`RequestBuilder`] that is awaited to send the request.

use core::{fmt::Display, pin::Pin, time::Duration};
use std::marker::PhantomData;
use std::{fmt::Debug, future::Future};

#[cfg(not(target_arch = "wasm32"))]
use futures_io::AsyncRead;
use futures_util::{Stream, StreamExt};
use http::{HeaderName, HeaderValue, header};
use http_kit::{
    Endpoint, Method, Middleware, Request, Response, Uri,
    endpoint::WithMiddleware,
    sse::SseStream,
    utils::{ByteStr, Bytes},
};
use serde::de::DeserializeOwned;

#[cfg(not(target_arch = "wasm32"))]
mod download;
#[cfg(not(target_arch = "wasm32"))]
pub use download::{DownloadError, DownloadOptions, DownloadProgress, DownloadReport};

use crate::{
    auth::{BasicAuth, BearerAuth},
    cache::Cache,
    cookie::CookieStore,
    multipart::Multipart,
    redirect::FollowRedirect,
    retry::Retry,
    timeout::Timeout,
};

/// Builder for HTTP requests using a Client.
#[derive(Debug)]
pub struct RequestBuilder<'a, T: Client> {
    client: T,
    request: Request,
    _marker: PhantomData<&'a mut T>,
}

impl<'a, T: Client> IntoFuture for RequestBuilder<'a, T> {
    type Output = Result<Response, T::Error>;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut request = self.request;
            self.client.respond(&mut request).await
        })
    }
}

fn invalid_uri(error: impl Display) -> crate::Error {
    crate::Error::InvalidUri(error.to_string())
}

fn invalid_request(error: impl Display) -> crate::Error {
    crate::Error::InvalidRequest(error.to_string())
}

fn invalid_request_with_prefix(prefix: &str, error: impl Display) -> crate::Error {
    let error_text = error.to_string();
    let mut message = String::with_capacity(prefix.len() + error_text.len());
    message.push_str(prefix);
    message.push_str(error_text.as_str());
    crate::Error::InvalidRequest(message)
}

impl<T: Client> RequestBuilder<'_, T> {
    /// Set an `Authorization: Bearer <token>` header on this request.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRequest`] when `token` cannot appear in a
    /// header value, for example because it contains a newline.
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Result<Self, crate::Error> {
        let value = crate::auth::bearer_header_value(token.as_ref())?;
        self.request
            .headers_mut()
            .insert(header::AUTHORIZATION, value);
        Ok(self)
    }

    /// Set an `Authorization: Basic <credentials>` header on this request.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRequest`] when the encoded credentials
    /// cannot be represented as a header value.
    // `Option<impl AsRef<str>>` keeps `basic_auth("user", Some("pass"))` readable;
    // taking it by reference would force callers to spell out `&Some`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn basic_auth(
        mut self,
        username: impl AsRef<str>,
        password: Option<impl AsRef<str>>,
    ) -> Result<Self, crate::Error> {
        let value = crate::auth::basic_header_value(
            username.as_ref(),
            password.as_ref().map(std::convert::AsRef::as_ref),
        )?;
        self.request
            .headers_mut()
            .insert(header::AUTHORIZATION, value);
        Ok(self)
    }

    /// Insert or replace a request header.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRequest`] when the header name or value cannot be parsed.
    pub fn header(
        mut self,
        name: impl TryInto<HeaderName, Error: Display>,
        value: impl TryInto<HeaderValue, Error: Display>,
    ) -> Result<Self, crate::Error> {
        let header_name: HeaderName = name.try_into().map_err(invalid_request)?;
        let header_value: HeaderValue = value.try_into().map_err(invalid_request)?;
        self.request.headers_mut().insert(header_name, header_value);
        Ok(self)
    }

    /// Append URL-encoded query parameters to the request URI.
    ///
    /// Existing query parameters are kept, so this can be called more than once.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidUri`] when appending the parameters would
    /// produce a URI that cannot be parsed.
    pub fn query<I, K, V>(mut self, params: I) -> Result<Self, crate::Error>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in params {
            serializer.append_pair(key.as_ref(), value.as_ref());
        }
        let encoded = serializer.finish();
        if encoded.is_empty() {
            return Ok(self);
        }

        let uri = self.request.uri();
        let path = uri.path();
        let mut path_and_query = String::with_capacity(path.len() + encoded.len() + 1);
        path_and_query.push_str(path);
        match uri.query() {
            Some(existing) if !existing.is_empty() => {
                path_and_query.push('?');
                path_and_query.push_str(existing);
                path_and_query.push('&');
            }
            _ => path_and_query.push('?'),
        }
        path_and_query.push_str(&encoded);

        let mut parts = uri.clone().into_parts();
        parts.path_and_query = Some(path_and_query.parse().map_err(invalid_uri)?);
        *self.request.uri_mut() = Uri::from_parts(parts).map_err(invalid_uri)?;
        Ok(self)
    }

    /// Set a JSON-encoded body for the request.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRequest`] when the payload cannot be serialized to JSON.
    pub fn json_body<B: serde::Serialize>(mut self, body: &B) -> Result<Self, crate::Error> {
        let json = serde_json::to_string(body).map_err(|error| {
            invalid_request_with_prefix("failed to serialize JSON body: ", error)
        })?;

        *self.request.body_mut() = http_kit::Body::from(json);
        self.request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        Ok(self)
    }

    /// Set a URL-encoded form body for the request.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRequest`] when the payload cannot be
    /// serialized as `application/x-www-form-urlencoded`.
    pub fn form_body<B: serde::Serialize>(mut self, body: &B) -> Result<Self, crate::Error> {
        let encoded = http_kit::Body::from_form(body).map_err(|error| {
            invalid_request_with_prefix("failed to serialize form body: ", error)
        })?;

        *self.request.body_mut() = encoded;
        self.request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        Ok(self)
    }

    /// Set a `multipart/form-data` body, including the matching `Content-Type`.
    #[must_use]
    pub fn multipart_body(mut self, multipart: Multipart) -> Self {
        let (boundary, body) = multipart.encode();

        // The boundary is generated from a restricted alphabet, so it is always
        // a valid header value.
        let content_type =
            HeaderValue::from_maybe_shared(format!("multipart/form-data; boundary={boundary}"))
                .unwrap_or_else(|_| HeaderValue::from_static("multipart/form-data"));

        *self.request.body_mut() = http_kit::Body::from(body);
        self.request
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
        self
    }

    /// Set a raw byte body for the request.
    #[must_use]
    pub fn bytes_body(mut self, bytes: impl Into<Bytes>) -> Self {
        *self.request.body_mut() = http_kit::Body::from_bytes(bytes.into());
        self
    }

    /// Set a UTF-8 text body for the request.
    #[must_use]
    pub fn text_body(mut self, text: impl Into<ByteStr>) -> Self {
        *self.request.body_mut() = http_kit::Body::from_text(text.into());
        self
    }

    /// Provide an async reader as the request body.
    ///
    /// When `length` is known it is sent as `Content-Length`; otherwise the body
    /// is streamed with chunked transfer encoding.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn reader_body<R>(mut self, reader: R, length: Option<u64>) -> Self
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        use futures_util::io::AsyncReadExt;

        if let Some(len) = length
            && let Ok(value) = HeaderValue::from_str(&len.to_string())
        {
            self.request
                .headers_mut()
                .insert(header::CONTENT_LENGTH, value);
        }

        let stream = futures_util::stream::unfold(reader, |mut reader| async move {
            let mut buf = vec![0u8; READ_CHUNK_SIZE];
            match reader.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some((Ok::<_, std::io::Error>(Bytes::from(buf)), reader))
                }
                Err(e) => Some((Err(e), reader)),
            }
        });

        *self.request.body_mut() = http_kit::Body::from_stream(stream);
        self
    }

    /// Stream a file from disk as the request body without loading it into memory.
    ///
    /// # Errors
    ///
    /// Returns any file-system error encountered while opening the file or loading its metadata.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn file_body(
        self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, std::io::Error> {
        use async_fs::File;

        let file = File::open(path.as_ref()).await?;
        let metadata = file.metadata().await?;
        Ok(self.reader_body(file, Some(metadata.len())))
    }

    /// Attach a streaming body composed from arbitrary async chunks.
    #[must_use]
    pub fn stream_body<Chunk, ErrType, S>(mut self, stream: S) -> Self
    where
        Chunk: Into<Bytes> + Send + 'static,
        ErrType: Into<Box<dyn core::error::Error + Send + Sync>> + Send + Sync + 'static,
        S: Stream<Item = std::result::Result<Chunk, ErrType>> + Send + Sync + 'static,
    {
        let mapped = stream.map(|result| result.map_err(Into::into));
        *self.request.body_mut() = http_kit::Body::from_stream(mapped);
        self
    }

    /// Download the response body into the provided path, resuming partial files automatically.
    ///
    /// # Errors
    ///
    /// Returns a [`DownloadError`] when the request fails, the server rejects the
    /// range request, or the destination file cannot be written.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn download_to_path(
        self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<DownloadReport, DownloadError<T::Error>> {
        download::download_to_path(self, path, DownloadOptions::default(), |_| {}).await
    }

    /// Download the response body into a path using custom [`DownloadOptions`].
    ///
    /// # Errors
    ///
    /// Returns a [`DownloadError`] when the request fails, the server rejects the
    /// range request, or the destination file cannot be written.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn download_to_path_with(
        self,
        path: impl AsRef<std::path::Path>,
        options: DownloadOptions,
    ) -> Result<DownloadReport, DownloadError<T::Error>> {
        download::download_to_path(self, path, options, |_| {}).await
    }

    /// Download the response body into a path, reporting progress as it is written.
    ///
    /// `on_progress` is called after every chunk is written to disk.
    ///
    /// # Errors
    ///
    /// Returns a [`DownloadError`] when the request fails, the server rejects the
    /// range request, or the destination file cannot be written.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn download_to_path_with_progress(
        self,
        path: impl AsRef<std::path::Path>,
        options: DownloadOptions,
        on_progress: impl FnMut(DownloadProgress),
    ) -> Result<DownloadReport, DownloadError<T::Error>> {
        download::download_to_path(self, path, options, on_progress).await
    }
}

/// Buffer size used when streaming a reader or file as a request body.
#[cfg(not(target_arch = "wasm32"))]
const READ_CHUNK_SIZE: usize = 8192;

// Consuming helpers for any client whose error can be normalized into zenwave::Error.
impl<T: Client> RequestBuilder<'_, T>
where
    T::Error: Into<crate::Error>,
{
    /// Deserialize the response body as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response body is not valid JSON for `Res`.
    pub async fn json<Res: DeserializeOwned>(self) -> Result<Res, crate::Error> {
        let response = self.await.map_err(Into::into)?;
        let mut body = response.into_body();
        Ok(body.into_json().await?)
    }

    /// Read the response body as text.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response body cannot be decoded as text.
    pub async fn string(self) -> Result<ByteStr, crate::Error> {
        let response = self.await.map_err(Into::into)?;
        let body = response.into_body();
        Ok(body.into_string().await?)
    }

    /// Read the response body as raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response body stream errors.
    pub async fn bytes(self) -> Result<Bytes, crate::Error> {
        let response = self.await.map_err(Into::into)?;
        let body = response.into_body();
        Ok(body.into_bytes().await?)
    }

    /// Read the response body as raw bytes, failing if it exceeds `limit`.
    ///
    /// Use this instead of [`RequestBuilder::bytes`] for untrusted peers, which
    /// could otherwise make the client buffer an unbounded response.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ResponseBodyTooLarge`] when the body exceeds
    /// `limit`, or the request/parse error otherwise.
    pub async fn bytes_with_limit(self, limit: usize) -> Result<Bytes, crate::Error> {
        use crate::ResponseExt as _;

        let response = self.await.map_err(Into::into)?;
        response.into_bytes_with_limit(limit).await
    }

    /// Deserialize the response body as form data.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response body cannot be decoded into `Res`.
    pub async fn form<Res: DeserializeOwned>(self) -> Result<Res, crate::Error> {
        let response = self.await.map_err(Into::into)?;
        let mut body = response.into_body();
        Ok(body.into_form().await?)
    }

    /// Convert the response body into an SSE stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sse(self) -> Result<SseStream, crate::Error> {
        let response = self.await.map_err(Into::into)?;
        let body = response.into_body();
        Ok(body.into_sse())
    }
}

/// Trait representing an HTTP client with middleware support.
pub trait Client: Endpoint + Sized {
    /// Add middleware to the client.
    ///
    /// The concrete return type keeps the wrapped error type visible, so the
    /// consuming helpers such as [`RequestBuilder::json`] stay available on the
    /// resulting client.
    fn with<M: Middleware>(self, middleware: M) -> WithMiddleware<Self, M> {
        WithMiddleware::new(self, middleware)
    }

    /// Enable automatic redirect following, up to
    /// [`FollowRedirect::DEFAULT_MAX_REDIRECTS`] hops.
    fn follow_redirect(self) -> FollowRedirect<Self> {
        FollowRedirect::new(self)
    }

    /// Enable automatic retry of failed requests.
    fn retry(self, max_retries: usize) -> Retry<Self> {
        Retry::new(self, max_retries)
    }

    /// Enable HTTP caching middleware bounded to [`Cache::DEFAULT_CAPACITY`].
    fn enable_cache(self) -> WithMiddleware<Self, Cache> {
        WithMiddleware::new(self, Cache::new())
    }

    /// Enable HTTP caching middleware holding at most `capacity` responses.
    fn enable_cache_with_capacity(self, capacity: usize) -> WithMiddleware<Self, Cache> {
        WithMiddleware::new(self, Cache::with_capacity(capacity))
    }

    /// Enable cookie management.
    fn enable_cookie(self) -> WithMiddleware<Self, CookieStore> {
        WithMiddleware::new(self, CookieStore::default())
    }

    /// Enable cookie management with persistent backing storage (native targets only).
    #[cfg(not(target_arch = "wasm32"))]
    fn enable_persistent_cookie(self) -> WithMiddleware<Self, CookieStore> {
        WithMiddleware::new(self, CookieStore::persistent_default())
    }

    /// Enforce a timeout for individual requests issued by this client.
    fn timeout(self, duration: Duration) -> WithMiddleware<Self, Timeout> {
        WithMiddleware::new(self, Timeout::new(duration))
    }

    /// Add Bearer Token Authentication middleware.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRequest`] when `token` cannot appear in a
    /// header value.
    fn bearer_auth(
        self,
        token: impl AsRef<str>,
    ) -> Result<WithMiddleware<Self, BearerAuth>, crate::Error> {
        Ok(WithMiddleware::new(self, BearerAuth::new(token)?))
    }

    /// Add Basic Authentication middleware.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRequest`] when the encoded credentials
    /// cannot be represented as a header value.
    fn basic_auth(
        self,
        username: impl AsRef<str>,
        password: Option<impl AsRef<str>>,
    ) -> Result<WithMiddleware<Self, BasicAuth>, crate::Error> {
        Ok(WithMiddleware::new(
            self,
            BasicAuth::new(username, password)?,
        ))
    }

    /// Create a request with the specified method and URI.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidUri`] when `uri` cannot be parsed, or
    /// [`crate::Error::InvalidRequest`] when the request cannot be constructed.
    fn method<U>(
        &mut self,
        method: Method,
        uri: U,
    ) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        let uri = uri.try_into().map_err(invalid_uri)?;
        let request = http::Request::builder()
            .method(method)
            .uri(uri)
            .body(http_kit::Body::empty())
            .map_err(invalid_request)?;

        Ok(RequestBuilder {
            client: self,
            request,
            _marker: PhantomData,
        })
    }

    /// Create a GET request.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Client::method`].
    fn get<U>(&mut self, uri: U) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        self.method(Method::GET, uri)
    }

    /// Create a POST request.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Client::method`].
    fn post<U>(&mut self, uri: U) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        self.method(Method::POST, uri)
    }

    /// Create a PUT request.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Client::method`].
    fn put<U>(&mut self, uri: U) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        self.method(Method::PUT, uri)
    }

    /// Create a PATCH request.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Client::method`].
    fn patch<U>(&mut self, uri: U) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        self.method(Method::PATCH, uri)
    }

    /// Create a DELETE request.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Client::method`].
    fn delete<U>(&mut self, uri: U) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        self.method(Method::DELETE, uri)
    }

    /// Create a HEAD request.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Client::method`].
    fn head<U>(&mut self, uri: U) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        self.method(Method::HEAD, uri)
    }

    /// Create an OPTIONS request.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Client::method`].
    fn options<U>(&mut self, uri: U) -> Result<RequestBuilder<'_, &mut Self>, crate::Error>
    where
        U: TryInto<Uri>,
        U::Error: Display,
    {
        self.method(Method::OPTIONS, uri)
    }
}

impl<C: Client, M: Middleware> Client for WithMiddleware<C, M> {}

impl<T: Client> Client for &mut T {}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use async_fs as fs;
    use async_lock::Mutex;
    use futures_util::stream;
    use http::Response;
    use http_kit::StatusCode;
    use std::{convert::Infallible, sync::Arc};
    use tempfile::tempdir;

    #[test]
    fn download_to_path_resumes_existing_file() {
        let payload: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
        let dir = tempdir().unwrap();
        let path = dir.path().join("download.bin");
        async_io::block_on(async {
            fs::write(&path, &payload[..1024]).await.unwrap();

            let mut client = FakeBackend::with_payload(payload.clone());
            client
                .get("http://example.com/file.bin")
                .unwrap()
                .download_to_path(&path)
                .await
                .unwrap();

            let final_bytes = fs::read(&path).await.unwrap();
            assert_eq!(final_bytes, payload);
        });
    }

    #[test]
    fn download_to_path_restarts_when_range_is_not_supported() {
        let payload: Vec<u8> = (0..2048_u32).map(|i| (i % 199) as u8).collect();
        let dir = tempdir().unwrap();
        let path = dir.path().join("download.bin");
        async_io::block_on(async {
            fs::write(&path, &[1_u8, 2, 3, 4]).await.unwrap();

            let mut client = FakeBackend::without_range(payload.clone());
            client
                .get("http://example.com/file.bin")
                .unwrap()
                .download_to_path(&path)
                .await
                .unwrap();

            let final_bytes = fs::read(&path).await.unwrap();
            assert_eq!(final_bytes, payload);
        });
    }

    #[test]
    fn file_body_streams_files_without_buffering() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("upload.bin");
        let payload: Vec<u8> = (0..2048)
            .map(|i| u8::try_from(i % 256).expect("value fits in u8"))
            .collect();
        async_io::block_on(async {
            fs::write(&path, &payload).await.unwrap();

            let backend = RecordingBackend::default();
            let recorded = backend.recorded.clone();
            let mut client = backend;

            client
                .post("http://example.com/upload")
                .unwrap()
                .file_body(&path)
                .await
                .unwrap()
                .await
                .unwrap();

            let data = recorded.lock().await.clone();
            assert_eq!(data, payload);
        });
    }

    #[test]
    fn stream_body_uploads_chunks() {
        let backend = RecordingBackend::default();
        let recorded = backend.recorded.clone();
        let mut client = backend;

        async_io::block_on(async {
            let stream = stream::iter(vec![
                Ok::<_, std::io::Error>(Bytes::from_static(b"chunk-a")),
                Ok(Bytes::from_static(b"chunk-b")),
            ]);

            client
                .post("http://example.com/upload")
                .unwrap()
                .stream_body(stream)
                .await
                .unwrap();

            let data = recorded.lock().await.clone();
            assert_eq!(data, b"chunk-achunk-b");
        });
    }

    #[derive(Clone)]
    struct FakeBackend {
        payload: Arc<Vec<u8>>,
        honor_range: bool,
    }

    impl FakeBackend {
        fn with_payload(payload: Vec<u8>) -> Self {
            Self {
                payload: Arc::new(payload),
                honor_range: true,
            }
        }

        fn without_range(payload: Vec<u8>) -> Self {
            Self {
                payload: Arc::new(payload),
                honor_range: false,
            }
        }
    }

    impl Default for FakeBackend {
        fn default() -> Self {
            Self {
                payload: Arc::new(Vec::new()),
                honor_range: true,
            }
        }
    }

    impl Endpoint for FakeBackend {
        type Error = Infallible;
        fn respond(
            &mut self,
            request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Response<http_kit::Body>, Self::Error>>
        {
            let start = if self.honor_range {
                parse_range(request)
            } else {
                0
            };
            let start = start.min(self.payload.len());
            let data = self.payload[start..].to_vec();

            let mut response = Response::builder()
                .status(if start > 0 && self.honor_range {
                    StatusCode::PARTIAL_CONTENT
                } else {
                    StatusCode::OK
                })
                .body(http_kit::Body::from(data))
                .unwrap();

            if self.honor_range {
                response.headers_mut().insert(
                    http_kit::header::ACCEPT_RANGES,
                    http_kit::header::HeaderValue::from_static("bytes"),
                );
            }

            if start > 0 && self.honor_range {
                response.headers_mut().insert(
                    http_kit::header::CONTENT_RANGE,
                    format!(
                        "bytes {}-{}/{}",
                        start,
                        self.payload.len().saturating_sub(1),
                        self.payload.len()
                    )
                    .parse()
                    .unwrap(),
                );
            }

            std::future::ready(Ok(response))
        }
    }

    impl Client for FakeBackend {}

    #[derive(Clone, Default)]
    struct RecordingBackend {
        recorded: Arc<Mutex<Vec<u8>>>,
    }

    impl Endpoint for RecordingBackend {
        type Error = Infallible;
        async fn respond(
            &mut self,
            request: &mut Request,
        ) -> Result<Response<http_kit::Body>, Self::Error> {
            let body = request
                .body_mut()
                .take()
                .unwrap_or_else(|_| http_kit::Body::empty());
            let bytes = body.into_bytes().await.expect("failed to read body");
            *self.recorded.lock().await = bytes.to_vec();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(http_kit::Body::empty())
                .unwrap())
        }
    }

    impl Client for RecordingBackend {}

    fn parse_range(request: &Request) -> usize {
        request
            .headers()
            .get(http_kit::header::RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.strip_prefix("bytes="))
            .and_then(|range| range.split('-').next())
            .and_then(|start| start.trim().parse().ok())
            .unwrap_or(0)
    }
}
