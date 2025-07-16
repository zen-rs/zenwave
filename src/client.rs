use core::pin::Pin;
use std::fmt::Debug;

use http_kit::{
    Endpoint, Method, Middleware, Request, Response, Result, Uri,
    endpoint::WithMiddleware,
    utils::{ByteStr, Bytes},
};
use serde::de::DeserializeOwned;

use crate::{ClientBackend, cookie_store::CookieStore, redirect::FollowRedirect};

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
    pub async fn json<Res: DeserializeOwned>(self) -> Result<Res> {
        let mut response = self.await?;
        response.into_json().await
    }

    pub async fn string(self) -> Result<ByteStr> {
        let mut response = self.await?;
        Ok(response.into_string().await?)
    }

    pub async fn bytes(self) -> Result<Bytes> {
        let mut response = self.await?;
        Ok(response.into_bytes().await?)
    }

    pub async fn form<Res: DeserializeOwned>(self) -> Result<Res> {
        let mut response = self.await?;
        response.into_form().await
    }
}

pub trait Client: Endpoint + Sized {
    fn with(self, middleware: impl Middleware) -> impl Client {
        WithMiddleware::new(self, middleware)
    }

    fn follow_redirect(self) -> impl Client {
        FollowRedirect::new(self)
    }

    fn enable_cookie(self) -> impl Client {
        WithMiddleware::new(self, CookieStore::default())
    }

    fn method<U>(&mut self, method: Method, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri> + Send + Sync,
        U::Error: Debug,
    {
        RequestBuilder {
            client: self,
            request: Request::new(method, uri),
        }
    }

    fn get<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri> + Send + Sync,
        U::Error: Debug,
    {
        self.method(Method::GET, uri)
    }

    fn post<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri> + Send + Sync,
        U::Error: Debug,
    {
        self.method(Method::POST, uri)
    }

    fn put<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri> + Send + Sync,
        U::Error: Debug,
    {
        self.method(Method::PUT, uri)
    }

    fn delete<U>(&mut self, uri: U) -> RequestBuilder<'_, Self>
    where
        U: TryInto<Uri> + Send + Sync,
        U::Error: Debug,
    {
        self.method(Method::DELETE, uri)
    }
}

impl<C: Client, M: Middleware> Client for WithMiddleware<C, M> {}

impl<T: ClientBackend> Client for T {}
