//! Middleware for following HTTP redirects.

use http::Uri;
use http_kit::{
    Endpoint, HttpError, Method,
    header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, HOST, LOCATION},
};
use url::Url;

use crate::{Body, Request, Response, StatusCode, client::Client};

/// Middleware that follows HTTP redirects.
///
/// `303 See Other` always becomes a `GET`, and `301`/`302` become `GET` for
/// anything that was not already a `GET` or `HEAD`, matching what browsers do.
/// `307`/`308` keep both the method and the body.
///
/// Because a redirected body has to be replayed, a body of known length is
/// buffered up front (up to [`FollowRedirect::max_replay_size`]) so a `307`/`308`
/// hop can resend it. A streaming body cannot be rewound, so redirecting one
/// fails with [`FollowRedirectError::UnreplayableBody`] instead of silently
/// sending an empty body.
///
/// `Authorization` and `Cookie` headers are dropped as soon as the redirect
/// chain leaves the original origin.
#[derive(Debug, Clone)]
pub struct FollowRedirect<C: Client> {
    client: C,
    max_redirects: u32,
    max_replay_size: usize,
}

impl<C: Client> Client for FollowRedirect<C> {}

impl<C: Client> FollowRedirect<C> {
    /// Redirect hops allowed by [`FollowRedirect::new`].
    pub const DEFAULT_MAX_REDIRECTS: u32 = 10;

    /// Largest request body buffered so a `307`/`308` can resend it (1 MiB).
    pub const DEFAULT_MAX_REPLAY_SIZE: usize = 1 << 20;

    /// Create a new `FollowRedirect` middleware wrapping the given client.
    ///
    /// Follows up to [`FollowRedirect::DEFAULT_MAX_REDIRECTS`] hops.
    pub const fn new(client: C) -> Self {
        Self {
            client,
            max_redirects: Self::DEFAULT_MAX_REDIRECTS,
            max_replay_size: Self::DEFAULT_MAX_REPLAY_SIZE,
        }
    }

    /// Set the largest request body buffered for a `307`/`308` replay.
    ///
    /// Redirecting a larger body fails rather than truncating it.
    #[must_use]
    pub const fn max_replay_size(mut self, bytes: usize) -> Self {
        self.max_replay_size = bytes;
        self
    }

    /// Limit how many redirects are followed before giving up.
    ///
    /// A limit of zero rejects the first redirect instead of following it.
    #[must_use]
    pub const fn max_redirects(mut self, max_redirects: u32) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Redirect hops this middleware will follow.
    #[must_use]
    pub const fn redirect_limit(&self) -> u32 {
        self.max_redirects
    }

    /// Remove redirect middleware and recover the wrapped client.
    #[must_use]
    pub fn disable_redirect(self) -> C {
        self.client
    }
}

/// Errors encountered while following HTTP redirects.
#[derive(Debug, thiserror::Error)]
pub enum FollowRedirectError<H: HttpError> {
    /// Failed to parse a redirect target as a URL.
    #[error("URL parse error: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// Upstream backend returned an error.
    #[error("Remote error: {0}")]
    RemoteError(H),

    /// Redirect limit exceeded.
    #[error("too many redirects (max {max})")]
    TooManyRedirects {
        /// Redirect limit that was reached.
        max: u32,
    },

    /// Redirect response did not include a `Location` header.
    #[error("Missing Location header in redirect response")]
    MissingLocationHeader,

    /// Redirect target was not a valid `Location` header.
    #[error("Invalid Location header in redirect response")]
    InvalidLocationHeader,

    /// A `307`/`308` redirect required resending a body that cannot be replayed.
    #[error("cannot replay a streaming request body across a {status} redirect")]
    UnreplayableBody {
        /// Redirect status that required the body to be resent.
        status: StatusCode,
    },
}

impl<H: HttpError> HttpError for FollowRedirectError<H> {
    fn status(&self) -> StatusCode {
        match self {
            Self::RemoteError(err) => err.status(),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// Convert FollowRedirectError to unified zenwave::Error
impl<H> From<FollowRedirectError<H>> for crate::Error
where
    H: HttpError + Into<Self>,
{
    fn from(err: FollowRedirectError<H>) -> Self {
        match err {
            FollowRedirectError::InvalidUrl(_) => {
                Self::InvalidUri("Invalid redirect URL".to_string())
            }
            FollowRedirectError::RemoteError(e) => e.into(),
            FollowRedirectError::TooManyRedirects { max } => Self::TooManyRedirects { max },
            FollowRedirectError::MissingLocationHeader
            | FollowRedirectError::InvalidLocationHeader => Self::InvalidRedirectLocation,
            FollowRedirectError::UnreplayableBody { status } => Self::InvalidRequest(format!(
                "cannot replay a streaming request body across a {status} redirect"
            )),
        }
    }
}

/// Method to use for the next hop, per RFC 9110 §15.4.
fn redirect_method(status: StatusCode, current: &Method) -> Method {
    match status {
        StatusCode::SEE_OTHER => Method::GET,
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
            if current != Method::GET && current != Method::HEAD =>
        {
            Method::GET
        }
        _ => current.clone(),
    }
}

/// Whether `status` requires the original body to be resent unchanged.
const fn preserves_body(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT
    )
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    type Error = FollowRedirectError<C::Error>;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        // Parsing the URI is only needed to resolve a relative `Location`, so it
        // is deferred until the first redirect actually arrives.
        let mut current_url: Option<Url> = None;
        let mut redirect_count = 0;

        // The backend consumes the body, so anything a 307/308 might need to
        // resend has to be captured before the first attempt. Buffering a body
        // that is already in memory only clones a refcounted handle.
        let replay = match request.body().len() {
            Some(len) if len <= self.max_replay_size => match request.body_mut().take() {
                Ok(body) => body.into_bytes().await.ok(),
                Err(_) => None,
            },
            _ => None,
        };
        if let Some(bytes) = &replay {
            *request.body_mut() = Body::from_bytes(bytes.clone());
        }

        loop {
            let response = self
                .client
                .respond(request)
                .await
                .map_err(FollowRedirectError::RemoteError)?;

            let status = response.status();
            if !status.is_redirection() {
                return Ok(response);
            }

            if redirect_count >= self.max_redirects {
                return Err(FollowRedirectError::TooManyRedirects {
                    max: self.max_redirects,
                });
            }

            let location = response
                .headers()
                .get(LOCATION)
                .ok_or(FollowRedirectError::MissingLocationHeader)?
                .to_str()
                .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;

            let base = match current_url {
                Some(url) => url,
                None => Url::parse(&request.uri().to_string())?,
            };
            let redirect_url = Url::parse(location)
                .or_else(|_| base.join(location))
                .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;
            let next_uri: Uri = redirect_url
                .as_str()
                .parse()
                .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;

            let next_method = redirect_method(status, request.method());

            // 307/308 must resend the original body; every other redirect drops it.
            let next_body = if preserves_body(status) {
                let bytes = replay
                    .as_ref()
                    .ok_or(FollowRedirectError::UnreplayableBody { status })?;
                Body::from_bytes(bytes.clone())
            } else {
                Body::empty()
            };

            let mut headers = std::mem::take(request.headers_mut());
            if base.origin() != redirect_url.origin() {
                headers.remove(AUTHORIZATION);
                headers.remove(COOKIE);
            }
            headers.remove(HOST);
            // The new body may differ in size; let the backend recompute it.
            headers.remove(CONTENT_LENGTH);

            let mut next_request = http::Request::builder()
                .method(next_method)
                .uri(next_uri)
                .body(next_body)
                .expect("method and uri were already validated");
            *next_request.headers_mut() = headers;

            *request = next_request;
            current_url = Some(redirect_url);
            redirect_count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        future::{Future, ready},
    };

    use http_kit::{Body, Endpoint, Method, Request, Response, StatusCode, header};

    use super::{FollowRedirect, FollowRedirectError, preserves_body, redirect_method};

    /// Backend that replays canned responses and records what it was asked to send.
    struct RedirectBackend {
        responses: VecDeque<Response>,
        credential_presence: Vec<(bool, bool)>,
        requests: Vec<(Method, String)>,
    }

    impl RedirectBackend {
        fn new(responses: impl IntoIterator<Item = Response>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                credential_presence: Vec::new(),
                requests: Vec::new(),
            }
        }
    }

    impl Endpoint for RedirectBackend {
        type Error = Infallible;

        fn respond(
            &mut self,
            request: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> {
            self.credential_presence.push((
                request.headers().contains_key(header::AUTHORIZATION),
                request.headers().contains_key(header::COOKIE),
            ));
            self.requests
                .push((request.method().clone(), request.uri().to_string()));
            ready(Ok(self.responses.pop_front().expect(
                "redirect test backend must have a response for every request",
            )))
        }
    }

    impl crate::Client for RedirectBackend {}

    /// Backend that records the body bytes it received for every request.
    struct BodyRecordingBackend {
        responses: VecDeque<Response>,
        bodies: Vec<String>,
        methods: Vec<Method>,
    }

    impl Endpoint for BodyRecordingBackend {
        type Error = Infallible;

        async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
            self.methods.push(request.method().clone());
            let body = request.body_mut().take().unwrap_or_else(|_| Body::empty());
            let bytes = body.into_bytes().await.expect("test body must read");
            self.bodies
                .push(String::from_utf8_lossy(bytes.as_ref()).into_owned());
            Ok(self
                .responses
                .pop_front()
                .expect("test backend must have a response for every request"))
        }
    }

    impl crate::Client for BodyRecordingBackend {}

    fn redirect_response(status: StatusCode, location: &str) -> Response {
        http::Response::builder()
            .status(status)
            .header(header::LOCATION, location)
            .body(Body::empty())
            .expect("redirect test response must build")
    }

    fn ok_response() -> Response {
        http::Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .expect("test response must build")
    }

    #[test]
    fn credentials_stay_removed_after_a_cross_origin_redirect() {
        let mut client = FollowRedirect::new(RedirectBackend::new([
            redirect_response(
                StatusCode::FOUND,
                "http://media.waterui.dev:8080/intermediate",
            ),
            redirect_response(StatusCode::FOUND, "http://media.waterui.dev:8080/final"),
            ok_response(),
        ]));
        let mut request = http::Request::builder()
            .uri("http://media.waterui.dev:80/start")
            .header(header::AUTHORIZATION, "Bearer waterui-test-token")
            .header(header::COOKIE, "waterui_session=test")
            .body(Body::empty())
            .expect("redirect test request must build");

        futures_executor::block_on(client.respond(&mut request))
            .expect("redirect chain must complete");

        assert_eq!(
            client.disable_redirect().credential_presence,
            [(true, true), (false, false), (false, false)]
        );
    }

    #[test]
    fn a_307_redirect_resends_the_original_method_and_body() {
        let mut client = FollowRedirect::new(BodyRecordingBackend {
            responses: VecDeque::from([
                redirect_response(StatusCode::TEMPORARY_REDIRECT, "/next"),
                ok_response(),
            ]),
            bodies: Vec::new(),
            methods: Vec::new(),
        });
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/start")
            .body(Body::from("important-payload"))
            .expect("test request must build");

        futures_executor::block_on(client.respond(&mut request))
            .expect("redirect chain must complete");

        let backend = client.disable_redirect();
        assert_eq!(backend.methods, [Method::POST, Method::POST]);
        assert_eq!(backend.bodies, ["important-payload", "important-payload"]);
    }

    #[test]
    fn a_308_redirect_resends_the_original_method_and_body() {
        let mut client = FollowRedirect::new(BodyRecordingBackend {
            responses: VecDeque::from([
                redirect_response(StatusCode::PERMANENT_REDIRECT, "/moved"),
                ok_response(),
            ]),
            bodies: Vec::new(),
            methods: Vec::new(),
        });
        let mut request = http::Request::builder()
            .method(Method::PUT)
            .uri("https://example.com/start")
            .body(Body::from("keep-me"))
            .expect("test request must build");

        futures_executor::block_on(client.respond(&mut request))
            .expect("redirect chain must complete");

        let backend = client.disable_redirect();
        assert_eq!(backend.methods, [Method::PUT, Method::PUT]);
        assert_eq!(backend.bodies, ["keep-me", "keep-me"]);
    }

    #[test]
    fn a_303_redirect_drops_the_body_and_switches_to_get() {
        let mut client = FollowRedirect::new(BodyRecordingBackend {
            responses: VecDeque::from([
                redirect_response(StatusCode::SEE_OTHER, "/result"),
                ok_response(),
            ]),
            bodies: Vec::new(),
            methods: Vec::new(),
        });
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/submit")
            .body(Body::from("form-data"))
            .expect("test request must build");

        futures_executor::block_on(client.respond(&mut request))
            .expect("redirect chain must complete");

        let backend = client.disable_redirect();
        assert_eq!(backend.methods, [Method::POST, Method::GET]);
        assert_eq!(backend.bodies, ["form-data", ""]);
    }

    #[test]
    fn a_307_redirect_rejects_a_body_it_cannot_replay() {
        let stream = futures_util::stream::iter([Ok::<_, std::io::Error>(
            http_kit::utils::Bytes::from_static(b"streamed"),
        )]);
        let mut client = FollowRedirect::new(BodyRecordingBackend {
            responses: VecDeque::from([redirect_response(StatusCode::TEMPORARY_REDIRECT, "/next")]),
            bodies: Vec::new(),
            methods: Vec::new(),
        });
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .body(Body::from_stream(stream))
            .expect("test request must build");

        let error = futures_executor::block_on(client.respond(&mut request))
            .expect_err("an unrewindable body must not be silently dropped");
        assert!(matches!(
            error,
            FollowRedirectError::UnreplayableBody {
                status: StatusCode::TEMPORARY_REDIRECT
            }
        ));
    }

    #[test]
    fn the_redirect_limit_is_configurable_and_reported() {
        let mut client = FollowRedirect::new(RedirectBackend::new([
            redirect_response(StatusCode::FOUND, "/one"),
            redirect_response(StatusCode::FOUND, "/two"),
        ]))
        .max_redirects(1);
        assert_eq!(client.redirect_limit(), 1);

        let mut request = http::Request::builder()
            .uri("https://example.com/start")
            .body(Body::empty())
            .expect("test request must build");

        let error = futures_executor::block_on(client.respond(&mut request))
            .expect_err("the second redirect must exceed a limit of one");
        assert!(matches!(
            error,
            FollowRedirectError::TooManyRedirects { max: 1 }
        ));
    }

    #[test]
    fn a_zero_limit_refuses_the_first_redirect() {
        let mut client = FollowRedirect::new(RedirectBackend::new([redirect_response(
            StatusCode::FOUND,
            "/one",
        )]))
        .max_redirects(0);
        let mut request = http::Request::builder()
            .uri("https://example.com/start")
            .body(Body::empty())
            .expect("test request must build");

        let error = futures_executor::block_on(client.respond(&mut request))
            .expect_err("a zero limit must reject the first redirect");
        assert!(matches!(
            error,
            FollowRedirectError::TooManyRedirects { max: 0 }
        ));
    }

    #[test]
    fn a_relative_location_resolves_against_the_previous_hop() {
        let mut client = FollowRedirect::new(RedirectBackend::new([
            redirect_response(StatusCode::FOUND, "/deep/first"),
            redirect_response(StatusCode::FOUND, "second"),
            ok_response(),
        ]));
        let mut request = http::Request::builder()
            .uri("https://example.com/start/path")
            .body(Body::empty())
            .expect("test request must build");

        futures_executor::block_on(client.respond(&mut request))
            .expect("redirect chain must complete");

        let uris: Vec<String> = client
            .disable_redirect()
            .requests
            .into_iter()
            .map(|(_, uri)| uri)
            .collect();
        assert_eq!(
            uris,
            [
                "https://example.com/start/path",
                "https://example.com/deep/first",
                // Resolved against the previous hop, not the original request.
                "https://example.com/deep/second",
            ]
        );
    }

    #[test]
    fn redirect_method_follows_rfc_9110() {
        assert_eq!(
            redirect_method(StatusCode::SEE_OTHER, &Method::POST),
            Method::GET
        );
        assert_eq!(
            redirect_method(StatusCode::SEE_OTHER, &Method::GET),
            Method::GET
        );
        assert_eq!(
            redirect_method(StatusCode::FOUND, &Method::POST),
            Method::GET
        );
        assert_eq!(
            redirect_method(StatusCode::FOUND, &Method::HEAD),
            Method::HEAD
        );
        assert_eq!(
            redirect_method(StatusCode::MOVED_PERMANENTLY, &Method::DELETE),
            Method::GET
        );
        assert_eq!(
            redirect_method(StatusCode::TEMPORARY_REDIRECT, &Method::POST),
            Method::POST
        );
        assert_eq!(
            redirect_method(StatusCode::PERMANENT_REDIRECT, &Method::PATCH),
            Method::PATCH
        );
    }

    #[test]
    fn only_307_and_308_preserve_the_body() {
        assert!(preserves_body(StatusCode::TEMPORARY_REDIRECT));
        assert!(preserves_body(StatusCode::PERMANENT_REDIRECT));
        assert!(!preserves_body(StatusCode::FOUND));
        assert!(!preserves_body(StatusCode::MOVED_PERMANENTLY));
        assert!(!preserves_body(StatusCode::SEE_OTHER));
    }
}
