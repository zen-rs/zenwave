use std::fmt::Debug;

use http_kit::{
    Endpoint, Method, Middleware, Request, Response, Result, Uri, endpoint::WithMiddleware,
};

use crate::{ClientBackend, cookie_store::CookieStore, redirect::FollowRedirect};

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

    fn method<U>(
        &mut self,
        method: Method,
        uri: U,
    ) -> impl Future<Output = Result<Response>> + Send + Sync
    where
        U: TryInto<Uri> + Send + Sync,
        U::Error: Debug,
    {
        async {
            let mut request = Request::new(method, uri);
            self.respond(&mut request).await
        }
    }
}

impl<C: Client, M: Middleware> Client for WithMiddleware<C, M> {}

impl<T: ClientBackend> Client for T {}
