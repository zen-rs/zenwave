//! Middleware for retrying failed HTTP requests.

use core::time::Duration;
use http_kit::{Endpoint, Request, Response, utils::Bytes};

use crate::client::Client;

/// Middleware that retries failed requests with exponential backoff.
///
/// Only transport-level failures are retried: a request that produced a valid
/// HTTP response is returned as-is, even when the status indicates an error.
///
/// # Request bodies
///
/// Retrying means sending the request again, so the body has to be replayable.
/// A body whose length is known is buffered once and replayed on every attempt.
/// A streaming body of unknown length cannot be rewound, so such a request is
/// attempted exactly once and its error returned unchanged rather than being
/// retried with a truncated body. Bodies larger than
/// [`Retry::max_replay_size`] are treated the same way.
#[derive(Debug, Clone)]
pub struct Retry<C: Client> {
    client: C,
    max_retries: usize,
    min_delay: Duration,
    max_delay: Duration,
    max_replay_size: usize,
}

impl<C: Client> Retry<C> {
    /// Largest request body buffered for replay by default (1 MiB).
    pub const DEFAULT_MAX_REPLAY_SIZE: usize = 1 << 20;

    /// Create a new `Retry` middleware allowing `max_retries` extra attempts.
    pub const fn new(client: C, max_retries: usize) -> Self {
        Self {
            client,
            max_retries,
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            max_replay_size: Self::DEFAULT_MAX_REPLAY_SIZE,
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

    /// Set the largest request body buffered so it can be replayed on a retry.
    ///
    /// Requests with a larger body are attempted only once.
    #[must_use]
    pub const fn max_replay_size(mut self, bytes: usize) -> Self {
        self.max_replay_size = bytes;
        self
    }

    /// Backoff delay before attempt number `attempt` (1 is the first retry).
    ///
    /// The doubling is saturating, so a large `max_retries` cannot overflow.
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2_u32.saturating_pow(attempt.saturating_sub(1));
        self.min_delay.saturating_mul(factor).min(self.max_delay)
    }
}

impl<C: Client> Client for Retry<C> {}

/// Sleep for `delay` on whichever target we are built for.
async fn sleep(delay: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    async_io::Timer::after(delay).await;

    #[cfg(target_arch = "wasm32")]
    {
        let millis = delay.as_millis().try_into().unwrap_or(u32::MAX);
        crate::timeout::SingleThreaded::new(gloo_timers::future::TimeoutFuture::new(millis)).await;
    }
}

impl<C: Client> Endpoint for Retry<C> {
    type Error = C::Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        // Buffer the body up front when it is small enough to resend; otherwise
        // this request gets a single attempt.
        let replay = match request.body().len() {
            // A body already frozen or unreadable yields no buffer, so this
            // request simply gets a single attempt.
            Some(len) if len <= self.max_replay_size => match request.body_mut().take() {
                Ok(body) => body.into_bytes().await.ok(),
                Err(_) => None,
            },
            _ => None,
        };

        if let Some(bytes) = &replay {
            *request.body_mut() = http_kit::Body::from_bytes(bytes.clone());
        }

        let mut attempts: u32 = 0;
        loop {
            match self.client.respond(request).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    let exhausted = usize::try_from(attempts)
                        .is_ok_and(|attempted| attempted >= self.max_retries);
                    // Without a buffered body a retry would send a truncated
                    // request, so report the original failure instead.
                    let Some(bytes) = replay.as_ref().filter(|_| !exhausted) else {
                        return Err(err);
                    };

                    attempts = attempts.saturating_add(1);
                    sleep(self.backoff(attempts)).await;
                    restore_body(request, bytes);
                }
            }
        }
    }
}

/// Reset `request` to the buffered body so the next attempt sends it again.
fn restore_body(request: &mut Request, bytes: &Bytes) {
    *request.body_mut() = http_kit::Body::from_bytes(bytes.clone());
}

#[cfg(test)]
mod tests {
    use super::Retry;
    use core::time::Duration;

    /// Backoff needs a client only to satisfy the type parameter.
    fn backoff_for(attempt: u32, max_retries: usize) -> Duration {
        struct Never;
        impl http_kit::Endpoint for Never {
            type Error = std::convert::Infallible;
            async fn respond(
                &mut self,
                _request: &mut http_kit::Request,
            ) -> Result<http_kit::Response, Self::Error> {
                unreachable!("backoff tests never dispatch a request")
            }
        }
        impl crate::Client for Never {}

        Retry::new(Never, max_retries)
            .min_delay(Duration::from_millis(100))
            .max_delay(Duration::from_secs(5))
            .backoff(attempt)
    }

    #[test]
    fn backoff_doubles_until_it_reaches_the_ceiling() {
        assert_eq!(backoff_for(1, 10), Duration::from_millis(100));
        assert_eq!(backoff_for(2, 10), Duration::from_millis(200));
        assert_eq!(backoff_for(3, 10), Duration::from_millis(400));
        assert_eq!(backoff_for(4, 10), Duration::from_millis(800));
        assert_eq!(backoff_for(6, 10), Duration::from_millis(3200));
        // Capped at max_delay from here on.
        assert_eq!(backoff_for(7, 10), Duration::from_secs(5));
    }

    #[test]
    fn backoff_saturates_instead_of_overflowing() {
        // 2^63 would overflow both the shift and the Duration multiply.
        assert_eq!(backoff_for(64, 100), Duration::from_secs(5));
        assert_eq!(backoff_for(u32::MAX, usize::MAX), Duration::from_secs(5));
    }
}
