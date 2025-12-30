//! Middleware for retrying failed HTTP requests.

use core::time::Duration;
#[cfg(target_arch = "wasm32")]
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use http_kit::{Endpoint, Request, Response};
use http_kit::utils::Bytes;
use http::HeaderMap;
use http::Version;

use crate::client::Client;

/// Middleware that retries failed requests.
///
/// This middleware automatically retries requests that fail with a transport error
/// (e.g., connection timeout, DNS error). It does *not* retry requests that receive
/// a valid HTTP response, even if the status code indicates an error (e.g., 500 or 503).
///
/// # Warning
///
/// This middleware buffers the request body in memory so it can be replayed on retries.
/// For large streaming bodies, this can be expensive or undesirable; consider disabling
/// retries or ensuring requests are small/replayable when using this middleware.
#[derive(Debug, Clone)]
pub struct Retry<C: Client> {
    client: C,
    max_retries: usize,
    min_delay: Duration,
    max_delay: Duration,
}

#[cfg(target_arch = "wasm32")]
struct SingleThreaded<T>(T);

// wasm targets are single-threaded, so it is safe to mark the wrapper as Send.
#[cfg(target_arch = "wasm32")]
unsafe impl<T> Send for SingleThreaded<T> {}

#[cfg(target_arch = "wasm32")]
impl<T: Future> Future for SingleThreaded<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: SingleThreaded<T> is a newtype wrapper; we never move the inner future.
        let this = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut this.0).poll(cx) }
    }
}

impl<C: Client> Retry<C> {
    /// Create a new `Retry` middleware.
    pub const fn new(client: C, max_retries: usize) -> Self {
        Self {
            client,
            max_retries,
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
        }
    }

    /// Set the minimum delay between retries.
    #[must_use]
    pub const fn min_delay(mut self, delay: Duration) -> Self {
        self.min_delay = delay;
        self
    }

    /// Set the maximum delay between retries.
    #[must_use]
    pub const fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }
}

impl<C> Client for Retry<C>
where
    C: Client,
    C::Error: Into<crate::Error>,
{
}

impl<C> Endpoint for Retry<C>
where
    C: Client,
    C::Error: Into<crate::Error>,
{
    type Error = crate::Error;

    #[allow(clippy::cast_possible_truncation)]
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let snapshot = RequestSnapshot::from_request(request).await?;
        let mut attempts = 0;
        loop {
            *request = snapshot.build_request()?;
            match self.client.respond(request).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    attempts += 1;
                    if attempts > self.max_retries {
                        return Err(err.into());
                    }

                    // Simple exponential backoff
                    let delay =
                        (self.min_delay * 2u32.pow((attempts - 1) as u32)).min(self.max_delay);

                    #[cfg(not(target_arch = "wasm32"))]
                    async_io::Timer::after(delay).await;

                    #[cfg(target_arch = "wasm32")]
                    SingleThreaded(gloo_timers::future::TimeoutFuture::new(
                        delay.as_millis() as u32
                    ))
                    .await;
                }
            }
        }
    }
}

#[derive(Clone)]
struct RequestSnapshot {
    method: http::Method,
    uri: http::Uri,
    version: Version,
    headers: HeaderMap,
    extensions: http::Extensions,
    body: Bytes,
}

impl RequestSnapshot {
    async fn from_request(request: &mut Request) -> Result<Self, crate::Error> {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let version = request.version();
        let headers = request.headers().clone();
        let extensions = request.extensions().clone();
        let body = request
            .body_mut()
            .take()
            .map_err(|_| crate::Error::InvalidRequest("request body already consumed".to_string()))?
            .into_bytes()
            .await?;

        Ok(Self {
            method,
            uri,
            version,
            headers,
            extensions,
            body,
        })
    }

    fn build_request(&self) -> Result<Request, crate::Error> {
        let mut request = http::Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone())
            .version(self.version)
            .body(http_kit::Body::from(self.body.clone()))
            .map_err(|err| crate::Error::InvalidRequest(err.to_string()))?;
        *request.headers_mut() = self.headers.clone();
        *request.extensions_mut() = self.extensions.clone();
        Ok(request)
    }
}
