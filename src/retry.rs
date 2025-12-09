//! Middleware for retrying failed HTTP requests.

use core::time::Duration;
#[cfg(target_arch = "wasm32")]
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use http_kit::{Endpoint, Request, Response};

use crate::client::Client;

/// Middleware that retries failed requests.
///
/// This middleware automatically retries requests that fail with a transport error
/// (e.g., connection timeout, DNS error). It does *not* retry requests that receive
/// a valid HTTP response, even if the status code indicates an error (e.g., 500 or 503).
///
/// # Warning
///
/// This middleware retries requests by calling the inner client's `respond` method multiple times.
/// If the request body is a stream that is consumed by the inner client (e.g., during a partial upload),
/// subsequent retries may send an empty or incomplete body. This is safe for requests with empty bodies
/// (like GET) or buffered bodies that can be replayed.
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

impl<C: Client> Client for Retry<C> {}

impl<C: Client> Endpoint for Retry<C> {
    type Error = C::Error;

    #[allow(clippy::cast_possible_truncation)]
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let mut attempts = 0;
        loop {
            match self.client.respond(request).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    attempts += 1;
                    if attempts > self.max_retries {
                        return Err(err);
                    }

                    // Simple exponential backoff
                    let delay =
                        (self.min_delay * 2u32.pow((attempts - 1) as u32)).min(self.max_delay);

                    #[cfg(not(target_arch = "wasm32"))]
                    async_io::Timer::after(delay).await;

                    #[cfg(target_arch = "wasm32")]
                    SingleThreaded(gloo_timers::future::TimeoutFuture::new(
                        delay.as_millis() as u32,
                    ))
                    .await;
                }
            }
        }
    }
}
