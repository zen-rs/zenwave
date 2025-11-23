//! Timeout middleware backed by the native-executor timer.
//!
//! This middleware cancels in-flight requests when the configured duration
//! elapses and surfaces a `504 Gateway Timeout` error. It uses
//! `native-executor`'s high precision timers so it works uniformly across
//! Apple, Android, Web, and other targets (via the built-in polyfill).

use core::time::Duration;

use futures_util::{future::Either, pin_mut};
use http_kit::{
    Endpoint, HttpError, Middleware, Request, Response, StatusCode, middleware::MiddlewareError,
};
use native_executor::timer::Timer;
use thiserror::Error;

/// Middleware that fails requests exceeding the configured duration.
#[derive(Debug, Clone, Copy)]
pub struct Timeout {
    duration: Duration,
}

impl Timeout {
    /// Construct a timeout middleware that limits requests to `duration`.
    #[must_use]
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }
}

/// Error returned when a request exceeds the configured timeout.
#[derive(Debug, Error)]
#[error("request timed out")]
pub struct TimeoutError;

impl HttpError for TimeoutError {
    fn status(&self) -> Option<StatusCode> {
        Some(StatusCode::GATEWAY_TIMEOUT)
    }
}

impl Middleware for Timeout {
    type Error = TimeoutError;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, http_kit::middleware::MiddlewareError<E::Error, Self::Error>> {
        let response_future = next.respond(request);
        let timeout_future = Timer::after(self.duration);

        pin_mut!(response_future);
        pin_mut!(timeout_future);

        match futures_util::future::select(response_future, timeout_future).await {
            Either::Left((result, _)) => Ok(result.map_err(MiddlewareError::Endpoint)?),
            Either::Right(((), _)) => Err(MiddlewareError::Middleware(TimeoutError)),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
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
            tokio::time::sleep(self.delay).await;
            let response = http::Response::builder()
                .status(self.status)
                .body(Body::empty())
                .unwrap();
            Ok(response)
        }
    }

    #[tokio::test]
    async fn completes_before_timeout() {
        let mut middleware = Timeout::new(Duration::from_millis(50));
        let backend = SlowEndpoint {
            delay: Duration::from_millis(10),
            status: StatusCode::OK,
        };
        let mut req = request();

        let response = middleware
            .handle(&mut req, backend)
            .await
            .expect("request should finish before timeout");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn errors_after_timeout_expires() {
        let mut middleware = Timeout::new(Duration::from_millis(5));
        let backend = SlowEndpoint {
            delay: Duration::from_millis(50),
            status: StatusCode::OK,
        };
        let mut req = request();

        let err = middleware
            .handle(&mut req, backend)
            .await
            .expect_err("timeout should fire first");

        assert_eq!(err.status(), Some(StatusCode::GATEWAY_TIMEOUT));
        assert!(err.to_string().contains("timed out"));
    }
}
