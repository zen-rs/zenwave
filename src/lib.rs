pub mod backend;
pub use backend::ClientBackend;
use backend::HyperBackend;

use bytes::Bytes;
use bytestr::ByteStr;
use cookie::{Cookie, CookieJar};
use http::{HeaderName, HeaderValue};
use http_kit::{header, Method, Request, Response, Uri};
use hyper::http;
use once_cell::sync::Lazy;
use std::fmt::Debug;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::RwLock;

type DefaultBackend = HyperBackend;

#[derive(Debug, Default)]
pub struct Client<B = DefaultBackend> {
    cookies: RwLock<CookieJar>,
    cookie_store: bool,
    backend: B,
}

impl<B: ClientBackend> Client<B> {
    pub fn cookie(self, cookie: Cookie<'static>) -> Self {
        self.set_cookie(cookie);
        self
    }

    pub fn enable_cookie_store(&mut self) {
        self.cookie_store = true;
    }

    pub fn disable_cookie_store(&mut self) {
        self.cookie_store = false;
    }

    fn set_cookie(&self, cookie: Cookie<'static>) {
        self.cookies.write().unwrap().add_original(cookie);
    }

    pub async fn send(&self, request: Request) -> http_kit::Result<Response> {
        RequestBuilder::new(request, self).await
    }
}

macro_rules! impl_client {
    ($(($name:ident,$method:tt)),*) => {
        impl <B:ClientBackend>Client<B>{
            $(
                pub fn $name<U>(&self, uri: U) -> RequestBuilder<B>
                where
                    U: TryInto<Uri>,
                    U::Error: Debug,
                {
                    RequestBuilder::new(Request::new(Method::$method, uri), self)
                }
            )*
        }

        $(
            #[doc = concat!("Send a `",stringify!($method),"` request.")]
            pub fn $name<U>(uri: U) -> RequestBuilder<'static, DefaultBackend>
            where
                U: TryInto<Uri>,
                U::Error: Debug,
            {
                DEFAULT_CLIENT.$name(uri)
            }
        )*
    };
}

impl_client![(get, GET), (post, POST), (put, PUT), (delete, DELETE)];

pub struct RequestBuilder<'a, B> {
    request: Request,
    client: &'a Client<B>,
}

impl<'a, B: ClientBackend> RequestBuilder<'a, B> {
    fn new(request: Request, client: &'a Client<B>) -> Self {
        Self { request, client }
    }

    fn insert_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.request.insert_header(name, value);
    }

    pub async fn bytes(self) -> http_kit::Result<Bytes> {
        let mut response = self.await?;
        Ok(response.take_body()?.into_bytes().await?)
    }

    pub async fn text(self) -> http_kit::Result<ByteStr> {
        let mut response = self.await?;
        Ok(response.take_body()?.into_string().await?)
    }

    pub async fn json<T: serde::de::DeserializeOwned>(self) -> http_kit::Result<T> {
        let mut response = self.await?;
        Ok(response.take_body()?.into_json().await?)
    }

    pub async fn form<T: serde::de::DeserializeOwned>(self) -> http_kit::Result<T> {
        let mut response = self.await?;
        Ok(response.take_body()?.into_form().await?)
    }

    pub fn header<V>(mut self, name: HeaderName, value: V) -> Self
    where
        V: TryInto<HeaderValue>,
        V::Error: Debug,
    {
        self.insert_header(name, value.try_into().unwrap());
        self
    }
}

pub struct ResponseFuture<'a> {
    future: Pin<Box<dyn 'a + Future<Output = http_kit::Result<Response>>>>,
}

impl<'a> Future for ResponseFuture<'a> {
    type Output = http_kit::Result<Response>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

impl<'a, B: ClientBackend> IntoFuture for RequestBuilder<'a, B> {
    type Output = http_kit::Result<Response>;

    type IntoFuture = ResponseFuture<'a>;

    fn into_future(mut self) -> Self::IntoFuture {
        ResponseFuture {
            future: Box::pin(async move {
                if self.client.cookie_store {
                    let cookies = self.client.cookies.read().unwrap();
                    let vec: Vec<String> =
                        cookies.iter().map(|v| v.encoded().to_string()).collect();
                    self.request.insert_header(
                        header::COOKIE,
                        HeaderValue::try_from(vec.join(";")).unwrap(),
                    );
                }

                let mut result = self.client.backend.call_endpoint(&mut self.request).await;
                if self.client.cookie_store {
                    result = result.map(|response| {
                        let mut cookies = self.client.cookies.write().unwrap();

                        for cookie in response.headers().get_all(header::SET_COOKIE) {
                            let cookie = String::from_utf8(cookie.as_bytes().to_vec()).unwrap();
                            cookies.add_original(Cookie::parse(cookie).unwrap());
                        }
                        response
                    });
                }
                result
            }),
        }
    }
}

impl Client<DefaultBackend> {
    pub fn new() -> Self {
        Self::default()
    }
}

static DEFAULT_CLIENT: Lazy<Client> = Lazy::new(|| Client::default());

#[cfg(test)]
mod test {
    use http_kit::Request;

    use crate::Client;

    #[tokio::test]
    async fn example() {
        let client = Client::new();
        let mut response = client
            .send(Request::get("http://example.com"))
            .await
            .unwrap();
        let string = response.take_body().unwrap().into_string().await.unwrap();
        println!("{}", string);
    }
}
