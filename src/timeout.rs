//! Timeout middleware on a [`Clock`].
//!
//! This middleware cancels in-flight requests when the configured duration
//! elapses and surfaces a `504 Gateway Timeout` error. The sleep comes from
//! the clock it is built with, which a [`Clocked`](crate::clock::Clocked)
//! client supplies itself ([`Client::timeout`](crate::Client::timeout)).

use core::time::Duration;

use futures_util::{future::Either, pin_mut};
use http_kit::{
    Endpoint, HttpError, Middleware, Request, Response, SendEndpoint, SendMiddleware, StatusCode,
    middleware::MiddlewareError,
};
use thiserror::Error;

use crate::clock::Clock;

/// Middleware that fails requests exceeding the configured duration.
#[derive(Debug, Clone, Copy)]
pub struct Timeout<K> {
    clock: K,
    duration: Duration,
}

impl<K: Clock> Timeout<K> {
    /// Construct a timeout middleware that limits requests to `duration` on
    /// `clock`.
    #[must_use]
    pub const fn new(clock: K, duration: Duration) -> Self {
        Self { clock, duration }
    }
}

/// Error returned when a request exceeds the configured timeout.
#[derive(Debug, Error)]
#[error("request timed out")]
pub struct TimeoutError;

impl HttpError for TimeoutError {
    fn status(&self) -> StatusCode {
        StatusCode::GATEWAY_TIMEOUT
    }
}

// Convert TimeoutError to unified zenwave::Error
impl From<TimeoutError> for crate::Error {
    fn from(_: TimeoutError) -> Self {
        Self::Timeout(crate::TimedOut::Request)
    }
}

impl<K: Clock> SendMiddleware for Timeout<K> {
    fn handle_send<E: SendEndpoint>(
        &mut self,
        request: &mut Request,
        next: E,
    ) -> impl Future<Output = Result<Response, MiddlewareError<E::Error, Self::Error>>> + Send {
        self.handle(request, http_kit::endpoint::SendNext::new(next))
    }
}

impl<K: Clock> Middleware for Timeout<K> {
    type Error = TimeoutError;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, http_kit::middleware::MiddlewareError<E::Error, Self::Error>> {
        let response_future = next.respond(request);
        // The sleep's output is discarded: `select` reports which side
        // finished first.
        let timeout_future = self.clock.sleep(self.duration);

        pin_mut!(response_future);
        pin_mut!(timeout_future);

        match futures_util::future::select(response_future, timeout_future).await {
            Either::Left((result, _)) => Ok(result.map_err(MiddlewareError::Endpoint)?),
            Either::Right(_) => Err(MiddlewareError::Middleware(TimeoutError)),
        }
    }
}

#[cfg(all(test, reactor))]
mod tests {
    use super::*;
    use crate::clock::AsyncIoClock;
    use async_io::Timer;
    use http_kit::{Body, HttpError, Method};
    use std::{convert::Infallible, time::Duration};

    fn request() -> Request {
        http::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap()
    }

    #[derive(Debug, Clone)]
    struct SlowEndpoint {
        delay: Duration,
        status: StatusCode,
    }

    impl Endpoint for SlowEndpoint {
        type Error = Infallible;
        async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
            Timer::after(self.delay).await;
            let response = http::Response::builder()
                .status(self.status)
                .body(Body::empty())
                .unwrap();
            Ok(response)
        }
    }

    #[test]
    fn completes_before_timeout() {
        let mut middleware = Timeout::new(AsyncIoClock, Duration::from_millis(50));
        let backend = SlowEndpoint {
            delay: Duration::from_millis(10),
            status: StatusCode::OK,
        };
        let mut req = request();

        let response = async_io::block_on(async {
            middleware
                .handle(&mut req, backend)
                .await
                .expect("request should finish before timeout")
        });

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn errors_after_timeout_expires() {
        // Both sides are timers and `select` prefers a ready response, so the
        // backend stays far behind the timeout even when the reactor's first
        // wake-up is late (a simulator on a busy CI runner).
        let mut middleware = Timeout::new(AsyncIoClock, Duration::from_millis(5));
        let backend = SlowEndpoint {
            delay: Duration::from_secs(5),
            status: StatusCode::OK,
        };
        let mut req = request();

        let err = async_io::block_on(async {
            middleware
                .handle(&mut req, backend)
                .await
                .expect_err("timeout should fire first")
        });

        assert_eq!(err.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(err.to_string().contains("timed out"));
    }
}
