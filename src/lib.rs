pub mod backend;
pub use backend::ClientBackend;
use backend::HyperBackend;

use std::fmt::Debug;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::RwLock;
use std::task::{ready, Poll};

use cookie::{Cookie, CookieJar};
use http::HeaderValue;
use http_kit::{header, Method, Request, Response, Uri};
use hyper::http;
use once_cell::sync::Lazy;

type DefaultBackend = HyperBackend;

#[derive(Debug, Default)]
pub struct Client<B = DefaultBackend> {
    cookies: RwLock<CookieJar>,
    cookie_store: bool,
    backend: B,
}

impl<B: ClientBackend> Client<B> {
    pub fn cookie(&self, name: &str) -> Option<Cookie<'static>> {
        let cookies = self.cookies.read().unwrap();
        cookies.get(name).map(|v| v.clone())
    }

    pub fn enable_cookie_store(&mut self) {
        self.cookie_store = true;
    }

    pub fn disable_cookie_store(&mut self) {
        self.cookie_store = false;
    }

    pub fn set_cookie(&self, cookie: Cookie<'static>) {
        self.cookies.write().unwrap().add_original(cookie);
    }

    pub async fn send(&mut self, request: Request) -> http_kit::Result<Response> {
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

impl<'a, B> RequestBuilder<'a, B> {
    fn new(request: Request, client: &'a Client<B>) -> Self {
        Self { request, client }
    }
}

pub struct ResponseFuture<'a, B> {
    client: &'a Client<B>,
    request: Option<Request>,
    future: Option<Pin<Box<dyn 'a + Future<Output = http_kit::Result<Response>>>>>,
}

impl<'a, B: ClientBackend> Future for ResponseFuture<'a, B> {
    type Output = http_kit::Result<Response>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if let Some(mut request) = self.request.take() {
            if self.client.cookie_store {
                let cookies = self.client.cookies.read().unwrap();
                let vec: Vec<String> = cookies.iter().map(|v| v.encoded().to_string()).collect();
                request.insert_header(
                    header::COOKIE,
                    HeaderValue::try_from(vec.join(";")).unwrap(),
                );
            }

            self.future = Some(self.client.backend.call_endpoint(request));
        }

        if let Some(future) = self.future.as_mut() {
            let mut result = ready!(Pin::new(future).poll(cx));
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

            Poll::Ready(result)
        } else {
            panic!("Please do not poll this future after it finished.")
        }
    }
}

impl<'a, B: ClientBackend> IntoFuture for RequestBuilder<'a, B> {
    type Output = http_kit::Result<Response>;

    type IntoFuture = ResponseFuture<'a, B>;

    fn into_future(self) -> Self::IntoFuture {
        ResponseFuture {
            client: self.client,
            request: Some(self.request),
            future: None,
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
        let mut client = Client::new();
        let mut response = client
            .send(Request::get("http://example.com"))
            .await
            .unwrap();
        let string = response.take_body().unwrap().into_string().await.unwrap();
        println!("{}", string);
    }
}
