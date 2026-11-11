//! The default client and the one-shot request functions built on it: every
//! item here needs a [`DefaultBackend`], which a build with `native-backend`
//! and no driver runtime does not have.

use crate::{
    Client, Endpoint, Error, Method, Request, Response, Transport, Uri, backend::DefaultBackend,
    clock::Clocked, redirect,
};

/// The default Zenwave client.
///
/// This wraps the platform backend with redirect following enabled so
/// `zenwave::client()` behaves like a modern HTTP client out of the box.
#[derive(Debug)]
pub struct DefaultClient {
    inner: redirect::FollowRedirect<DefaultBackend>,
}

impl DefaultClient {
    /// A client over `transport` with redirect following enabled.
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self {
            inner: DefaultBackend::new(transport).follow_redirect(),
        }
    }

    /// Remove redirect middleware and recover the raw backend.
    #[must_use]
    pub fn disable_redirect(self) -> DefaultBackend {
        self.inner.disable_redirect()
    }

    /// The bare platform backend over `transport`, without redirect middleware.
    // Not every backend's constructor is `const` (URLSession sessions are
    // opened lazily into a map), so this stays a plain fn on every target.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn raw(transport: Transport) -> DefaultBackend {
        DefaultBackend::new(transport)
    }
}

impl Default for DefaultClient {
    /// The system transport: OS proxy settings and OS root certificates.
    fn default() -> Self {
        Self::new(Transport::system())
    }
}

impl Endpoint for DefaultClient {
    type Error = Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.inner.respond(request).await.map_err(Into::into)
    }
}

http_kit::impl_send_endpoint!(DefaultClient);

impl Client for DefaultClient {}

impl Clocked for DefaultClient {
    type Clock = <DefaultBackend as Clocked>::Clock;

    fn clock(&self) -> Self::Clock {
        self.inner.clock()
    }
}

/// The default client over the system transport: the operating system's
/// proxy settings and root certificates, redirects followed.
#[must_use]
pub fn client() -> DefaultClient {
    DefaultClient::default()
}

/// The default client over a transport of your own: explicit proxy rules,
/// extra root certificates. See [`Transport::builder`].
#[must_use]
pub fn client_with(transport: Transport) -> DefaultClient {
    DefaultClient::new(transport)
}

/// Send a GET request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn get<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::GET, uri)?.await
}

/// Send a POST request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn post<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::POST, uri)?.await
}

/// Send a PUT request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn put<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::PUT, uri)?.await
}

/// Send a DELETE request to the specified URI using the default client backend.
///
/// # Errors
/// If the request fails, an error is returned.
pub async fn delete<U>(uri: U) -> Result<Response, Error>
where
    U: TryInto<Uri>,
    U::Error: core::fmt::Display,
{
    let mut client = client();
    client.method(Method::DELETE, uri)?.await
}
