//! Middleware for following HTTP redirects.

use alloc::{string::String, vec::Vec};

use http::{HeaderMap, Uri};
use http_kit::{
    Endpoint, HttpError, Method, SendEndpoint,
    header::{
        AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION,
        TRANSFER_ENCODING,
    },
};

use crate::clock::Clocked;
#[cfg(has_cookie)]
use crate::cookie::{RequestCookieJar, cookie_header, parse_uri, store_response_cookies};
use crate::{Body, Request, Response, StatusCode, client::Client};

/// Final redirect state attached to a response by [`FollowRedirect`] so
/// callers (such as multi-range downloads) can pin subsequent requests to the
/// resolved URI and know whether credentials were stripped across origins.
#[cfg_attr(not(has_std), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct RedirectOutcome {
    /// Final URI that produced the response.
    pub(crate) effective_uri: Uri,
    /// Whether any hop crossed origins and stripped `Authorization` / `Cookie`.
    pub(crate) stripped_credentials: bool,
}

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

impl<C: Clocked> Clocked for FollowRedirect<C> {
    type Clock = C::Clock;

    fn clock(&self) -> C::Clock {
        self.client.clock()
    }
}

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

    /// The absolute URI a redirect response points at, resolved against `current_uri`
    /// per RFC 3986 §5.2; `Err` when `Location` is missing or does not resolve.
    fn redirect_target(
        current_uri: &Uri,
        response: &Response,
    ) -> Result<Uri, FollowRedirectError<C::Error>> {
        let location = response
            .headers()
            .get(LOCATION)
            .ok_or(FollowRedirectError::MissingLocationHeader)?
            .to_str()
            .map_err(|_| FollowRedirectError::InvalidLocationHeader)?;
        resolve_redirect_uri(current_uri, location)
            .ok_or(FollowRedirectError::InvalidLocationHeader)
    }

    /// Builds the request for the next hop of a redirect chain and advances `state` to it.
    ///
    /// `Ok(None)` means the redirect must be handed back to the caller untouched: the hop
    /// would preserve a body that cannot be replayed.
    #[cfg_attr(not(has_cookie), allow(clippy::needless_pass_by_ref_mut))]
    fn next_hop(
        request: &mut Request,
        response: &Response,
        state: &mut RedirectState,
    ) -> Result<Option<Request>, FollowRedirectError<C::Error>> {
        if state.uri.scheme().is_none() || state.uri.authority().is_none() {
            return Err(FollowRedirectError::InvalidUri);
        }
        let next_uri = Self::redirect_target(&state.uri, response)?;

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
            .uri(next_uri.clone())
            .body(next_body)
            .expect("failed to build redirect request");

        if !same_origin(&state.uri, &next_uri) {
            state.headers.remove(AUTHORIZATION);
            state.headers.remove(COOKIE);
            state.stripped_credentials = true;
        }

        // A response that redirects is a hop: its `Set-Cookie` headers
        // belong to this hop's URL.
        #[cfg(has_cookie)]
        if let Some(jar) = request.extensions_mut().get_mut::<RequestCookieJar>()
            && let Some(hop_url) = parse_uri(&state.uri)
        {
            for value in response.headers().get_all(http_kit::header::SET_COOKIE) {
                jar.hop_set_cookies.push((hop_url.clone(), value.clone()));
            }
            jar.changed |= store_response_cookies(&mut jar.store, response.headers(), &hop_url);
        }

        let mut headers = state.headers.clone();
        headers.remove(HOST);

        // A hop keeps the request's extensions — the jar moves with them, and the next
        // `Cookie` header comes from it for the new URL — replacing the carried-over one,
        // including the value just stripped on a cross-origin hop.
        *new_request.extensions_mut() = request.extensions().clone();
        #[cfg(has_cookie)]
        if let Some(jar) = new_request.extensions_mut().get_mut::<RequestCookieJar>() {
            match parse_uri(&next_uri).and_then(|url| cookie_header(&jar.store, &url)) {
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
        state.uri = next_uri;
        Ok(Some(new_request))
    }
}

/// Resolves `location` against `base` per RFC 3986 §5.2 and strips any `#fragment`
/// per RFC 9110 §7.1.2.
fn resolve_redirect_uri(base: &Uri, location: &str) -> Option<Uri> {
    let base_scheme = base.scheme_str()?;
    let base_authority = base.authority()?.as_str();
    let loc = location.split('#').next().unwrap_or("");

    if let Some(rest) = loc.strip_prefix("//") {
        let (authority, tail) = split_authority_and_tail(rest)?;
        let pq = normalize_tail(tail);
        return build_uri(base_scheme, authority, &pq);
    }

    if let Some((scheme, after_colon)) = split_scheme(loc) {
        let rest = after_colon.strip_prefix("//")?;
        let (authority, tail) = split_authority_and_tail(rest)?;
        let pq = normalize_tail(tail);
        return build_uri(scheme, authority, &pq);
    }

    if loc.is_empty() {
        let pq = base
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        return build_uri(base_scheme, base_authority, pq);
    }

    if loc.starts_with('?') {
        let base_path = non_empty_path(base.path());
        let mut pq = String::with_capacity(base_path.len() + loc.len());
        pq.push_str(base_path);
        pq.push_str(loc);
        return build_uri(base_scheme, base_authority, &pq);
    }

    let (rel_path, query) = match loc.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (loc, None),
    };

    let merged = if rel_path.starts_with('/') {
        remove_dot_segments(rel_path)
    } else {
        let base_path = base.path();
        let dir = base_path.rfind('/').map_or("/", |idx| &base_path[..=idx]);
        let mut raw = String::with_capacity(dir.len() + rel_path.len());
        raw.push_str(dir);
        raw.push_str(rel_path);
        remove_dot_segments(&raw)
    };

    let pq = match query {
        Some(q) => {
            let mut s = String::with_capacity(merged.len() + 1 + q.len());
            s.push_str(&merged);
            s.push('?');
            s.push_str(q);
            s
        }
        None => merged,
    };
    build_uri(base_scheme, base_authority, &pq)
}

const fn non_empty_path(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

fn split_authority_and_tail(rest: &str) -> Option<(&str, &str)> {
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return None;
    }
    Some((authority, &rest[end..]))
}

fn normalize_tail(tail: &str) -> String {
    if tail.is_empty() {
        return String::from("/");
    }
    if tail.starts_with('?') {
        let mut s = String::with_capacity(1 + tail.len());
        s.push('/');
        s.push_str(tail);
        return s;
    }
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let clean = remove_dot_segments(path);
    match query {
        Some(q) => {
            let mut s = String::with_capacity(clean.len() + 1 + q.len());
            s.push_str(&clean);
            s.push('?');
            s.push_str(q);
            s
        }
        None => clean,
    }
}

/// Splits an RFC 3986 scheme prefix (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"`)
/// when `:` appears before any `/` or `?`.
fn split_scheme(input: &str) -> Option<(&str, &str)> {
    let colon = input.find(':')?;
    if input[..colon].contains(['/', '?']) {
        return None;
    }
    let scheme = &input[..colon];
    let mut bytes = scheme.bytes();
    if !bytes.next()?.is_ascii_alphabetic() {
        return None;
    }
    if !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) {
        return None;
    }
    Some((scheme, &input[colon + 1..]))
}

/// RFC 3986 §5.2.4 `remove_dot_segments`.
fn remove_dot_segments(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    let mut trailing_slash = path.ends_with('/');
    for seg in path.split('/') {
        match seg {
            "" | "." => {
                if seg == "." {
                    trailing_slash = true;
                }
            }
            ".." => {
                stack.pop();
                trailing_slash = true;
            }
            other => {
                stack.push(other);
                trailing_slash = path.ends_with('/');
            }
        }
    }
    let mut out = String::with_capacity(path.len().max(1));
    for seg in &stack {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() || (trailing_slash && !out.ends_with('/')) {
        out.push('/');
    }
    out
}

fn build_uri(scheme: &str, authority: &str, path_and_query: &str) -> Option<Uri> {
    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .ok()
}

pub(crate) fn same_origin(left: &Uri, right: &Uri) -> bool {
    let (Some(ls), Some(rs)) = (left.scheme_str(), right.scheme_str()) else {
        return false;
    };
    if !ls.eq_ignore_ascii_case(rs) {
        return false;
    }
    let (Some(lh), Some(rh)) = (left.host(), right.host()) else {
        return false;
    };
    if !lh.eq_ignore_ascii_case(rh) {
        return false;
    }
    match (effective_port(left), effective_port(right)) {
        (Some(lp), Some(rp)) => lp == rp,
        _ => false,
    }
}

fn effective_port(uri: &Uri) -> Option<u16> {
    if let Some(port) = uri.port_u16() {
        return Some(port);
    }
    match uri.scheme_str()? {
        s if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("ws") => Some(80),
        s if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") => Some(443),
        _ => None,
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
    /// URI of the request that produced the latest response.
    uri: Uri,
    /// Replayable snapshot of the current body, `None` once consumed or dropped.
    body: Option<Body>,
    /// Whether the current, not-yet-replayed request carried a body at all.
    had_body: bool,
    /// Hops taken so far.
    count: u32,
    /// Whether any hop crossed origins and stripped credentials.
    stripped_credentials: bool,
}

/// Errors encountered while following HTTP redirects.
#[derive(Debug, thiserror::Error)]
pub enum FollowRedirectError<H: HttpError> {
    /// Request URI lacked a scheme or authority needed to resolve a redirect.
    #[error("request URI cannot be used as a redirect base")]
    InvalidUri,
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
            FollowRedirectError::InvalidUri => {
                Self::InvalidUri(String::from("request URI lacks scheme or authority"))
            }
            FollowRedirectError::RemoteError(e) => e.into(),
            FollowRedirectError::TooManyRedirects => Self::TooManyRedirects { max: 10 },
            FollowRedirectError::MissingLocationHeader
            | FollowRedirectError::InvalidLocationHeader => Self::InvalidRedirectLocation,
        }
    }
}

impl<C: Client> SendEndpoint for FollowRedirect<C> {
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
        self.respond(request)
    }
}

impl<C: Client> Endpoint for FollowRedirect<C> {
    type Error = FollowRedirectError<C::Error>;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        const MAX_REDIRECTS: u32 = 10;
        // `Uri::clone` is an atomic refcount bump over `Bytes` (zero heap allocation),
        // and `Body::try_clone` is skipped altogether for empty bodies.
        let had_body = request.body().is_empty() != Some(true);
        let mut state = RedirectState {
            headers: request.headers().clone(),
            method: request.method().clone(),
            uri: request.uri().clone(),
            body: if had_body {
                request.body().try_clone()
            } else {
                None
            },
            had_body,
            count: 0,
            stripped_credentials: false,
        };

        loop {
            let mut response = self
                .client
                .respond_send(request)
                .await
                .map_err(FollowRedirectError::RemoteError)?;

            // `request` holds whatever the endpoint left behind — the jar,
            // when the chain carries one, rides along in its extensions.
            #[cfg(has_cookie)]
            if state.count > 0
                && let Some(jar) = request.extensions_mut().get_mut::<RequestCookieJar>()
            {
                jar.response_url = parse_uri(&state.uri);
            }

            if !matches!(
                response.status(),
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            ) {
                response.extensions_mut().insert(RedirectOutcome {
                    effective_uri: state.uri,
                    stripped_credentials: state.stripped_credentials,
                });
                return Ok(response);
            }

            if state.count >= MAX_REDIRECTS {
                return Err(FollowRedirectError::TooManyRedirects);
            }
            state.count += 1;

            if let Some(next_request) = Self::next_hop(request, &response, &mut state)? {
                *request = next_request;
            } else {
                response.extensions_mut().insert(RedirectOutcome {
                    effective_uri: state.uri,
                    stripped_credentials: state.stripped_credentials,
                });
                return Ok(response);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::{
        collections::VecDeque,
        convert::Infallible,
        future::{Future, ready},
    };

    use http::Uri;
    use http_kit::{Body, Endpoint, Request, Response, StatusCode, header};

    use super::{FollowRedirect, resolve_redirect_uri, same_origin};

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

    http_kit::impl_send_endpoint!(RedirectBackend);

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

    #[test]
    fn rfc3986_relative_resolution_and_origin_matching() {
        let base: Uri = "https://example.com/a/b/c?old=1".parse().unwrap();
        assert_eq!(
            resolve_redirect_uri(&base, "../d/./e?new=2#frag").unwrap(),
            "https://example.com/a/d/e?new=2"
        );
        assert_eq!(
            resolve_redirect_uri(&base, "//cdn.example.net/x").unwrap(),
            "https://cdn.example.net/x"
        );
        assert_eq!(
            resolve_redirect_uri(&base, "?only=query").unwrap(),
            "https://example.com/a/b/c?only=query"
        );
        assert_eq!(
            resolve_redirect_uri(&base, "https://other.example?q=1").unwrap(),
            "https://other.example/?q=1"
        );

        let default_https: Uri = "https://example.com/x".parse().unwrap();
        let explicit_443: Uri = "https://EXAMPLE.COM:443/y".parse().unwrap();
        let other_port: Uri = "https://example.com:8443/y".parse().unwrap();
        assert!(same_origin(&default_https, &explicit_443));
        assert!(!same_origin(&default_https, &other_port));
    }

    fn redirect_response(location: &'static str) -> Response {
        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, location)
            .body(Body::empty())
            .expect("redirect test response must build")
    }
}
