//! Timeout middleware backed by a runtime-agnostic timer.
//!
//! This middleware cancels in-flight requests when the configured duration
//! elapses and surfaces a `504 Gateway Timeout` error. It relies on
//! `async-io`'s timers so it works uniformly across targets without pulling
//! in a dedicated async runtime.

use core::time::Duration;
#[cfg(target_arch = "wasm32")]
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(not(target_arch = "wasm32"))]
use async_io::Timer;
use futures_util::{future::Either, pin_mut};
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::TimeoutFuture;
use http_kit::{
    Endpoint, HttpError, Middleware, Request, Response, StatusCode, middleware::MiddlewareError,
};
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

// Convert TimeoutError to unified zenwave::Error
impl From<TimeoutError> for crate::Error {
    fn from(_: TimeoutError) -> Self {
        Self::Timeout
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
        let timeout_future = timeout_future(self.duration);

        pin_mut!(response_future);
        pin_mut!(timeout_future);

        match futures_util::future::select(response_future, timeout_future).await {
            Either::Left((result, _)) => Ok(result.map_err(MiddlewareError::Endpoint)?),
            Either::Right((_, _)) => Err(MiddlewareError::Middleware(TimeoutError)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn timeout_future(duration: Duration) -> SingleThreaded<TimeoutFuture> {
    // gloo expects milliseconds as u32; saturate to avoid overflow for long durations.
    let millis = duration.as_millis().try_into().unwrap_or(u32::MAX);
    SingleThreaded(TimeoutFuture::new(millis))
}

#[cfg(not(target_arch = "wasm32"))]
fn timeout_future(duration: Duration) -> Timer {
    Timer::after(duration)
}

#[cfg(target_arch = "wasm32")]
struct SingleThreaded<T>(T);

#[cfg(target_arch = "wasm32")]
unsafe impl<T> Send for SingleThreaded<T> {}
#[cfg(target_arch = "wasm32")]
unsafe impl<T> Sync for SingleThreaded<T> {}

#[cfg(target_arch = "wasm32")]
impl<T: Future> Future for SingleThreaded<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: SingleThreaded is a newtype wrapper; we never move the inner future.
        let inner = unsafe { self.map_unchecked_mut(|this| &mut this.0) };
        inner.poll(cx)
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
        let mut middleware = Timeout::new(Duration::from_millis(50));
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
        let mut middleware = Timeout::new(Duration::from_millis(5));
        let backend = SlowEndpoint {
            delay: Duration::from_millis(50),
            status: StatusCode::OK,
        };
        let mut req = request();

        let err = async_io::block_on(async {
            middleware
                .handle(&mut req, backend)
                .await
                .expect_err("timeout should fire first")
        });

        assert_eq!(err.status(), Some(StatusCode::GATEWAY_TIMEOUT));
        assert!(err.to_string().contains("timed out"));
    }
}
