#![allow(clippy::cast_sign_loss)]

use core::{pin::Pin, time::Duration};
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
pub use download::{DownloadError, DownloadOptions, DownloadReport};

use crate::{
    auth::{BasicAuth, BearerAuth},
    cache::Cache,
    cookie::CookieStore,
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

// ClientError has been removed - all errors now use zenwave::Error

impl<T: Client> RequestBuilder<'_, T> {
    pub fn bearer_auth(mut self, token: impl Into<String>) -> Self {
        let auth_value = format!("Bearer {}", token.into());
        self.request
            .headers_mut()
            .insert(http_kit::header::AUTHORIZATION, auth_value.parse().unwrap());
        self
    }

    pub fn basic_auth(
        mut self,
        username: impl Into<String>,
        password: Option<impl Into<String>>,
    ) -> Self {
        use base64::Engine;

        let credentials = match password {
            Some(p) => format!("{}:{}", username.into(), p.into()),
            None => format!("{}:", username.into()),
        };

        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        let auth_value = format!("Basic {encoded}");

        self.request
            .headers_mut()
            .insert(http_kit::header::AUTHORIZATION, auth_value.parse().unwrap());
        self
    }

    pub fn header(
        mut self,
        name: impl TryInto<HeaderName, Error: Debug>,
        value: impl TryInto<HeaderValue, Error: Debug>,
    ) -> Self {
        let header_name: http_kit::header::HeaderName = name.try_into().unwrap();
        let header_value: http_kit::header::HeaderValue = value.try_into().unwrap();
        self.request.headers_mut().insert(header_name, header_value);
        self
    }

    /// Set a JSON-encoded body for the request.
    ///
    /// # Panics
    ///
    /// Panics if the body cannot be serialized to JSON.
    pub fn json_body<B: serde::Serialize>(mut self, body: &B) -> Self {
        let json = serde_json::to_string(body).expect("failed to serialize JSON body");

        // Set the body directly
        *self.request.body_mut() = http_kit::Body::from(json);

        // Add content-type header
        let content_type = header::CONTENT_TYPE;
        let json_type = HeaderValue::from_static("application/json");
        self.request.headers_mut().insert(content_type, json_type);

        self
    }

    pub fn bytes_body(mut self, bytes: Vec<u8>) -> Self {
        *self.request.body_mut() = http_kit::Body::from(bytes);
        self
    }

    /// Provide an async reader as the request body.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn reader_body<R>(mut self, reader: R, length: Option<u64>) -> Self
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        use futures_util::io::AsyncReadExt;
        use http_kit::header;

        if let Some(len) = length
            && let Ok(value) = header::HeaderValue::from_str(&len.to_string())
        {
            self.request
                .headers_mut()
                .insert(header::CONTENT_LENGTH, value);
        }

        let stream = futures_util::stream::unfold(reader, |mut reader| async move {
            let mut buf = vec![0u8; 8192];
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
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn download_to_path(
        self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<DownloadReport, DownloadError<T::Error>> {
        download::download_to_path(self, path, DownloadOptions::default()).await
    }

    /// Download the response body into a path using custom [`DownloadOptions`].
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn download_to_path_with(
        self,
        path: impl AsRef<std::path::Path>,
        options: DownloadOptions,
    ) -> Result<DownloadReport, DownloadError<T::Error>> {
        download::download_to_path(self, path, options).await
    }
}

// Consuming methods when T::Error is already zenwave::Error
impl<T: Client<Error = crate::Error>> RequestBuilder<'_, T> {
    pub async fn json<Res: DeserializeOwned>(self) -> Result<Res, crate::Error> {
        let response = self.await?;
        let mut body = response.into_body();
        Ok(body.into_json().await?)
    }

    pub async fn string(self) -> Result<ByteStr, crate::Error> {
        let response = self.await?;
        let body = response.into_body();
        Ok(body.into_string().await?)
    }

    pub async fn bytes(self) -> Result<Bytes, crate::Error> {
        let response = self.await?;
        let body = response.into_body();
        Ok(body.into_bytes().await?)
    }

    pub async fn form<Res: DeserializeOwned>(self) -> Result<Res, crate::Error> {
        let response = self.await?;
        let mut body = response.into_body();
        Ok(body.into_form().await?)
    }

    pub async fn sse(self) -> Result<SseStream, crate::Error> {
        let response = self.await?;
        let body = response.into_body();
        Ok(body.into_sse())
    }
}

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
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let dir = tempdir().unwrap();
        let path = dir.path().join("download.bin");
        async_io::block_on(async {
            fs::write(&path, &payload[..1024]).await.unwrap();

            let mut client = FakeBackend::with_payload(payload.clone());
            client
                .get("http://example.com/file.bin")
                .download_to_path(&path)
                .await
                .unwrap();

            let final_bytes = fs::read(&path).await.unwrap();
            assert_eq!(final_bytes, payload);
        });
    }

    #[test]
    fn download_to_path_restarts_when_range_is_not_supported() {
        let payload: Vec<u8> = (0..2048).map(|i| (i % 199) as u8).collect();
        let dir = tempdir().unwrap();
        let path = dir.path().join("download.bin");
        async_io::block_on(async {
            fs::write(&path, &[1_u8, 2, 3, 4]).await.unwrap();

            let mut client = FakeBackend::without_range(payload.clone());
            client
                .get("http://example.com/file.bin")
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
        async fn respond(
            &mut self,
            request: &mut Request,
        ) -> Result<Response<http_kit::Body>, Self::Error> {
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

            Ok(response)
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

/// Trait representing an HTTP client with middleware support.
pub trait Client: Endpoint + Sized {
    /// Add middleware to the client.
    fn with(self, middleware: impl Middleware) -> impl Client {
        WithMiddleware::new(self, middleware)
    }

    /// Enable automatic redirect following.
    fn follow_redirect(self) -> impl Client {
        FollowRedirect::new(self)
    }

    /// Enable automatic retry of failed requests.
    fn retry(self, max_retries: usize) -> Retry<Self> {
        Retry::new(self, max_retries)
    }

    /// Enable HTTP caching middleware.
    fn enable_cache(self) -> impl Client {
        WithMiddleware::new(self, Cache::new())
    }

    /// Enable cookie management.
    fn enable_cookie(self) -> impl Client {
        WithMiddleware::new(self, CookieStore::default())
    }

    /// Enable cookie management with persistent backing storage (native targets only).
    #[cfg(not(target_arch = "wasm32"))]
    fn enable_persistent_cookie(self) -> impl Client {
        WithMiddleware::new(self, CookieStore::persistent_default())
    }

    /// Enforce a timeout for individual requests issued by this client.
    fn timeout(self, duration: Duration) -> impl Client {
        WithMiddleware::new(self, Timeout::new(duration))
    }

    /// Add Bearer Token Authentication middleware.
    fn bearer_auth(self, token: impl Into<String>) -> impl Client {
        WithMiddleware::new(self, BearerAuth::new(token))
    }

    /// Add Basic Authentication middleware.
    fn basic_auth(
        self,
        username: impl Into<String>,
        password: Option<impl Into<String>>,
    ) -> impl Client {
        WithMiddleware::new(self, BasicAuth::new(username, password))
    }

    /// Create a request with the specified method and URI.
    fn method<U>(&mut self, method: Method, uri: U) -> RequestBuilder<'_, &mut Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        let uri = uri.try_into().unwrap();
        let request = http::Request::builder()
            .method(method)
            .uri(uri)
            .body(http_kit::Body::empty())
            .unwrap();

        RequestBuilder {
            client: self,
            request,
            _marker: PhantomData,
        }
    }

    /// Create a GET request.
    fn get<U>(&mut self, uri: U) -> RequestBuilder<'_, &mut Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        self.method(Method::GET, uri)
    }

    /// Create a POST request.
    fn post<U>(&mut self, uri: U) -> RequestBuilder<'_, &mut Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        self.method(Method::POST, uri)
    }

    /// Create a PUT request.
    fn put<'a, U>(&mut self, uri: U) -> RequestBuilder<'_, &mut Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
        Self: 'a,
    {
        self.method(Method::PUT, uri)
    }

    /// Create a DELETE request.
    fn delete<U>(&mut self, uri: U) -> RequestBuilder<'_, &mut Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        self.method(Method::DELETE, uri)
    }
}

impl<C: Client, M: Middleware> Client for WithMiddleware<C, M> {}

impl<T: Client> Client for &mut T {}
