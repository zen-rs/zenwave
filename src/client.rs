use core::pin::Pin;
use std::{fmt::Debug, future::Future};

use http_kit::{
    Endpoint, Method, Middleware, Request, Response, Result, Uri,
    endpoint::WithMiddleware,
    sse::SseStream,
    utils::{ByteStr, Bytes},
};
use serde::de::DeserializeOwned;

use crate::{
    ClientBackend,
    auth::{BasicAuth, BearerAuth},
    cookie::CookieStore,
    redirect::FollowRedirect,
};

/// Builder for HTTP requests using a Client.
#[derive(Debug)]
pub struct RequestBuilder<'a, T: Client> {
    client: &'a mut T,
    request: Request,
}

impl<'a, T: Client> IntoFuture for RequestBuilder<'a, T> {
    type Output = Result<Response>;

    type IntoFuture = Pin<Box<dyn Future<Output = Result<Response>> + Send + Sync + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut request = self.request;
            self.client.respond(&mut request).await
        })
    }
}

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

    pub async fn json<Res: DeserializeOwned>(self) -> Result<Res> {
        let response = self.await?;
        let mut body = response.into_body();
        body.into_json()
            .await
            .map_err(|e| http_kit::Error::new(e, http_kit::StatusCode::BAD_REQUEST))
    }

    pub async fn string(self) -> Result<ByteStr> {
        let response = self.await?;
        let body = response.into_body();
        Ok(body.into_string().await?)
    }

    pub async fn bytes(self) -> Result<Bytes> {
        let response = self.await?;
        let body = response.into_body();
        Ok(body.into_bytes().await?)
    }

    pub async fn form<Res: DeserializeOwned>(self) -> Result<Res> {
        let response = self.await?;
        let mut body = response.into_body();
        body.into_form()
            .await
            .map_err(|e| http_kit::Error::new(e, http_kit::StatusCode::BAD_REQUEST))
    }

    pub async fn sse(self) -> Result<SseStream> {
        let response = self.await?;
        let body = response.into_body();
        Ok(body.into_sse())
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let header_name: http_kit::header::HeaderName = name.into().parse().unwrap();
        let header_value: http_kit::header::HeaderValue = value.into().parse().unwrap();
        self.request.headers_mut().insert(header_name, header_value);
        self
    }

    pub fn json_body<B: serde::Serialize>(mut self, body: &B) -> Result<Self> {
        let json = serde_json::to_string(body)
            .map_err(|e| anyhow::anyhow!("Failed to serialize JSON: {e}"))?;

        // Set the body directly
        *self.request.body_mut() = http_kit::Body::from(json);

        // Add content-type header
        let content_type: http_kit::header::HeaderName = "content-type".parse().unwrap();
        let json_type: http_kit::header::HeaderValue = "application/json".parse().unwrap();
        self.request.headers_mut().insert(content_type, json_type);

        Ok(self)
    }

    pub fn bytes_body(mut self, bytes: Vec<u8>) -> Self {
        *self.request.body_mut() = http_kit::Body::from(bytes);
        self
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

    /// Enable cookie management.
    fn enable_cookie(self) -> impl Client {
        WithMiddleware::new(self, CookieStore::default())
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
    fn method<U>(&mut self, method: Method, uri: U) -> RequestBuilder<'_, Self>
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
        }
    }

    /// Create a GET request.
    fn get<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        self.method(Method::GET, uri)
    }

    /// Create a POST request.
    fn post<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        self.method(Method::POST, uri)
    }

    /// Create a PUT request.
    fn put<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        self.method(Method::PUT, uri)
    }

    /// Create a DELETE request.
    fn delete<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        self.method(Method::DELETE, uri)
    }
}

impl<C: Client, M: Middleware> Client for WithMiddleware<C, M> {}

impl<T: ClientBackend> Client for T {}
