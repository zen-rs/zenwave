//! Opting a client into treating an error status as an error.
//!
//! Every backend returns the response it received, whatever its status, with
//! its body still streaming: a reverse proxy forwards an upstream's `502` as
//! it came, and an SDK reads a `404` as "absent", without either having to
//! take the response back out of an error. A caller that wants a 4xx or 5xx
//! to fail the request adds [`ErrorForStatus`] to its client, or calls
//! [`ResponseExt::error_for_status`] on one response.

use http_kit::{Endpoint, Middleware, Request, Response, middleware::MiddlewareError};

use crate::ResponseExt as _;

/// Middleware turning a 4xx or 5xx response into [`crate::Error::Http`].
///
/// The error's body is read whole, as [`ResponseExt::error_for_status`]
/// reads it; any other status passes through untouched. Placed beneath
/// [`crate::redirect::FollowRedirect`] it sees each hop, above it only the
/// final response; redirects are not error statuses either way.
///
/// [`ResponseExt::error_for_status`]: crate::ResponseExt::error_for_status
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorForStatus;

http_kit::impl_send_middleware!(ErrorForStatus);

impl Middleware for ErrorForStatus {
    type Error = crate::Error;

    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        let response = next
            .respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)?;
        response
            .error_for_status()
            .await
            .map_err(MiddlewareError::Middleware)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use futures_executor::block_on;
    use http_kit::{Body, Method, StatusCode};

    use super::*;

    /// A reason in Chinese, Japanese and Korean.
    const REASON: &str = "库存不足。在庫切れです。재고가 없습니다.";

    /// Answers every request with `status` and [`REASON`] as the body.
    struct Answer(StatusCode);

    impl Endpoint for Answer {
        type Error = Infallible;

        fn respond(
            &mut self,
            _request: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> {
            std::future::ready(Ok(http::Response::builder()
                .status(self.0)
                .body(Body::from(REASON))
                .expect("a status and a body form a response")))
        }
    }

    fn handle(status: StatusCode) -> Result<Response, MiddlewareError<Infallible, crate::Error>> {
        let mut request = http::Request::builder()
            .method(Method::GET)
            .uri("http://example.com/stock")
            .body(Body::empty())
            .expect("a GET forms a request");
        block_on(ErrorForStatus.handle(&mut request, Answer(status)))
    }

    #[test]
    fn client_and_server_errors_become_http_errors_holding_their_body() {
        for status in [StatusCode::NOT_FOUND, StatusCode::BAD_GATEWAY] {
            let Err(MiddlewareError::Middleware(error)) = handle(status) else {
                panic!("{status} must become an error");
            };
            let crate::Error::Http {
                status: reported,
                message,
                response,
            } = error
            else {
                panic!("{status} must become Error::Http");
            };
            assert_eq!(reported, status);
            assert_eq!(message, REASON);
            assert_eq!(response.body_text.as_deref(), Some(REASON));
            assert_eq!(response.response.status(), status);
            let body =
                block_on(response.response.into_body().into_string()).expect("the held body reads");
            assert_eq!(body.as_str(), REASON);
        }
    }

    #[test]
    fn other_statuses_pass_through_with_their_body() {
        for status in [
            StatusCode::SWITCHING_PROTOCOLS,
            StatusCode::OK,
            StatusCode::NO_CONTENT,
            StatusCode::NOT_MODIFIED,
            StatusCode::TEMPORARY_REDIRECT,
        ] {
            let response = handle(status)
                .unwrap_or_else(|error| panic!("{status} must pass through, got {error:?}"));
            assert_eq!(response.status(), status);
            let body = block_on(response.into_body().into_string()).expect("the body reads");
            assert_eq!(body.as_str(), REASON);
        }
    }
}
