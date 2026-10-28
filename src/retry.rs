//! Middleware for retrying failed HTTP requests.

use core::time::Duration;
use http_kit::{Endpoint, Request, Response};

use crate::client::Client;
#[cfg(target_arch = "wasm32")]
use crate::single_threaded::SingleThreaded;

/// Middleware that retries failed requests.
///
/// This middleware automatically retries requests that fail with a transient
/// error — a transport failure, a timeout or an I/O error, classified by
/// [`crate::Error::is_transient`]. Any other error (a malformed request, a
/// refused credential, an HTTP error status) cannot succeed on a second
/// attempt and is returned after the first one.
///
/// Every attempt sends the original request. A backend takes the request out
/// of the `&mut Request` it is handed, so a copy is taken before each attempt
/// and restored for the next one. A request whose body can be read only once
/// (a reader or a stream) cannot be copied and is attempted once: its error is
/// returned as is.
#[derive(Debug, Clone)]
pub struct Retry<C>
where
    C: Client,
    C::Error: Into<crate::Error>,
{
    client: C,
    max_retries: usize,
    min_delay: Duration,
    max_delay: Duration,
}

impl<C: Client> Retry<C>
where
    C::Error: Into<crate::Error>,
{
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

impl<C: Client> Client for Retry<C> where C::Error: Into<crate::Error> {}

impl<C: Client> Endpoint for Retry<C>
where
    C::Error: Into<crate::Error>,
{
    type Error = crate::Error;

    #[allow(clippy::cast_possible_truncation)]
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let mut attempts = 0;
        loop {
            let replay = (attempts < self.max_retries)
                .then(|| replayable(request))
                .flatten();
            match self.client.respond(request).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    let err = err.into();
                    if !err.is_transient() {
                        return Err(err);
                    }
                    let Some(replay) = replay else {
                        return Err(err);
                    };
                    attempts += 1;
                    tracing::debug!(attempt = attempts, uri = %replay.uri(), "retrying request");

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

                    *request = replay;
                }
            }
        }
    }
}

/// A copy of `request` for the next attempt, or `None` when its body can be
/// read only once.
fn replayable(request: &Request) -> Option<Request> {
    let mut copy = Request::new(request.body().try_clone()?);
    *copy.method_mut() = request.method().clone();
    *copy.uri_mut() = request.uri().clone();
    *copy.version_mut() = request.version();
    *copy.headers_mut() = request.headers().clone();
    *copy.extensions_mut() = request.extensions().clone();
    Some(copy)
}
