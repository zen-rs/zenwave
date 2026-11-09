//! Middleware for following HTTP redirects.

use http::{HeaderMap, Uri};
use http_kit::{
    Endpoint, HttpError, Method,
    header::{
        AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION,
        TRANSFER_ENCODING,
    },
};
use url::Url;

use crate::cookie::{RequestCookieJar, cookie_header, store_response_cookies};
use crate::{Body, Request, Response, StatusCode, client::Client};

/// Middleware that follows HTTP redirects.
///
/// A `301`/`302` converts a `POST` — and only a `POST` — into a bodyless `GET`, a `303`
/// converts any method other than `GET`/`HEAD` the same way, and a `307`/`308` re-sends the
/// request unchanged, body included, when the body is replayable; a redirect whose body cannot
/// be replayed is returned to the caller rather than followed with an emptied one. Payload
/// headers are dropped together with a dropped body, and `Authorization`/`Cookie` are stripped
/// on a cross-origin hop.
///
/// Credential middleware belongs *outside* this one — `client.bearer_auth(t)` composes the
/// bearer middleware around `FollowRedirect`, so the credential is applied before a hop and the
/// cross-origin strip removes it. Wrapping the other way would let the inner middleware
/// re-attach it on every hop.
#[derive(Debug, Clone)]
pub struct FollowRedirect<C: Client> {
    client: C,
}

impl<C: Client> Client for FollowRedirect<C> {}

impl<C: Client> FollowRedirect<C> {
    /// Create a new `FollowRedirect` middleware wrapping the given client.
    pub const fn new(client: C) -> Self {
        Self { client }
    }

    /// Remove redirect middleware and recover the wrapped client.
    #[must_use]
    pub fn disable_redirect(self) -> C {
        self.client
    }

    /// The absolute URL a redirect response points at, resolved against the URL that
    /// produced it; `Err` when `Location` is missing or does not resolve.
    fn redirect_target(
        current_url: &Url,
        response: &Response,
    ) -> Result<Url, FollowRedirectError<C::Error>> {
        let location = response
            .headers()
            .get(LOCATION)
            .ok_or(FollowRedirectError::MissingLocationHeader)?
            .to_str()
            .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;
        Url::parse(location)
            .or_else(|_| current_url.join(location))
            .map_err(|_| FollowRedirectError::InvalidLocationHeader)
    }

    /// Builds the request for the next hop of a redirect chain and advances `state` to it.
    ///
    /// `Ok(None)` means the redirect must be handed back to the caller untouched: the hop
    /// would preserve a body that cannot be replayed.
    fn next_hop(
        request: &mut Request,
        response: &Response,
        state: &mut RedirectState,
    ) -> Result<Option<Request>, FollowRedirectError<C::Error>> {
        let redirect_url = Self::redirect_target(&state.url, response)?;

        let next_uri: Uri = redirect_url
            .as_str()
            .parse()
            .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;

        // RFC 9110 §15.4 as the clients implement it: a 303 is always a plain retrieval —
        // `GET` unless the method already is `GET` or `HEAD`, and the body never rides
        // along — a 301/302 does so only when the method was `POST`, and a 307/308
        // preserves method and body.
        let status = response.status();
        let (next_method, keeps_body) = match status {
            StatusCode::SEE_OTHER => (
                if state.method == Method::GET || state.method == Method::HEAD {
                    state.method.clone()
                } else {
                    Method::GET
                },
                false,
            ),
            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if state.method == Method::POST => {
                (Method::GET, false)
            }
            _ => (state.method.clone(), true),
        };

        let next_body = if keeps_body {
            match state.body.as_ref().and_then(Body::try_clone) {
                Some(body) => body,
                // A body that cannot be replayed cannot be redirected safely — hand the
                // redirect back to the caller rather than send an empty one.
                None if state.had_body => return Ok(None),
                None => Body::empty(),
            }
        } else {
            // The body is gone for the rest of the chain — and the headers that
            // described it with it.
            state.body = None;
            state.had_body = false;
            state.headers.remove(CONTENT_LENGTH);
            state.headers.remove(CONTENT_TYPE);
            state.headers.remove(CONTENT_ENCODING);
            state.headers.remove(TRANSFER_ENCODING);
            Body::empty()
        };

        let mut new_request = http::Request::builder()
            .method(next_method.clone())
            .uri(next_uri)
            .body(next_body)
            .expect("failed to build redirect request"); // Safety: We have already made sure method and uri are valid.

        if state.url.origin() != redirect_url.origin() {
            state.headers.remove(AUTHORIZATION);
            state.headers.remove(COOKIE);
        }

        // A response that redirects is a hop: its `Set-Cookie` headers
        // belong to this hop's URL.
        if let Some(jar) = request.extensions_mut().get_mut::<RequestCookieJar>() {
            jar.changed |= store_response_cookies(&mut jar.store, response.headers(), &state.url);
        }

        let mut headers = state.headers.clone();
        headers.remove(HOST);

        // A hop keeps the request's extensions — the jar moves with them, and the next
        // `Cookie` header comes from it for the new URL — replacing the carried-over one,
        // including the value just stripped on a cross-origin hop.
        *new_request.extensions_mut() = request.extensions().clone();
        if let Some(jar) = new_request.extensions_mut().get_mut::<RequestCookieJar>() {
            match cookie_header(&jar.store, &redirect_url) {
                Some(cookie) => {
                    headers.insert(COOKIE, cookie);
                }
                None => {
                    headers.remove(COOKIE);
                }
            }
        }

        *new_request.headers_mut() = headers;
        state.method = next_method;
        state.url = redirect_url;
        Ok(Some(new_request))
    }
}

/// State carried between the hops of one redirect chain.
#[derive(Debug)]
struct RedirectState {
    /// The header set each hop is built from: credentials are stripped on cross-origin hops
    /// and payload headers leave once a hop drops the body.
    headers: HeaderMap,
    /// Method of the request that produced the latest response.
    method: Method,
    /// URL of the request that produced the latest response.
    url: Url,
    /// Replayable snapshot of the current body, `None` once consumed or dropped.
    body: Option<Body>,
    /// Whether the current, not-yet-replayed request carried a body at all.
    had_body: bool,
    /// Hops taken so far.
    count: u32,
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
    #[error("Too many redirects")]
    TooManyRedirects,

    /// Redirect response did not include a `Location` header.
    #[error("Missing Location header in redirect response")]
    MissingLocationHeader,

    /// Redirect target was not a valid `Location` header.
    #[error("Invalid Location header in redirect response")]
    InvalidLocationHeader,
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
            FollowRedirectError::TooManyRedirects => Self::TooManyRedirects { max: 10 },
            FollowRedirectError::MissingLocationHeader
            | FollowRedirectError::InvalidLocationHeader => Self::InvalidRedirectLocation,
        }
    }
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    type Error = FollowRedirectError<C::Error>;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        const MAX_REDIRECTS: u32 = 10;
        // The body snapshot is taken with `try_clone` — replayable only for an in-memory
        // body — before the inner client can consume it.
        let mut state = RedirectState {
            headers: request.headers().clone(),
            method: request.method().clone(),
            url: Url::parse(&request.uri().to_string())?,
            body: request.body().try_clone(),
            had_body: request.body().is_empty() != Some(true),
            count: 0,
        };

        loop {
            let response = self
                .client
                .respond(request)
                .await
                .map_err(FollowRedirectError::RemoteError)?;

            // `request` holds whatever the endpoint left behind — the jar,
            // when the chain carries one, rides along in its extensions.
            if let Some(jar) = request.extensions_mut().get_mut::<RequestCookieJar>() {
                jar.response_url = Some(state.url.clone());
            }

            if !matches!(
                response.status(),
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            ) {
                return Ok(response);
            }

            if state.count >= MAX_REDIRECTS {
                return Err(FollowRedirectError::TooManyRedirects);
            }
            state.count += 1;

            match Self::next_hop(request, &response, &mut state)? {
                Some(next_request) => *request = next_request,
                None => return Ok(response),
            }
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

    use http_kit::{Body, Endpoint, Request, Response, StatusCode, header};

    use super::FollowRedirect;

    struct RedirectBackend {
        responses: VecDeque<Response>,
        credential_presence: Vec<(bool, bool)>,
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
            ready(Ok(self.responses.pop_front().expect(
                "redirect test backend must have a response for every request",
            )))
        }
    }

    impl crate::Client for RedirectBackend {}

    #[test]
    fn credentials_stay_removed_after_a_cross_origin_redirect() {
        let mut client = FollowRedirect::new(RedirectBackend {
            responses: VecDeque::from([
                redirect_response("http://media.waterui.dev:8080/intermediate"),
                redirect_response("http://media.waterui.dev:8080/final"),
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .expect("final redirect test response must build"),
            ]),
            credential_presence: Vec::new(),
        });
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

    fn redirect_response(location: &'static str) -> Response {
        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, location)
            .body(Body::empty())
            .expect("redirect test response must build")
    }
}
