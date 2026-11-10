//! The request and response handling the hyper and native backends share:
//! what origin a request belongs to, how an HTTP/1.1 request is shaped for
//! the path its connection took, and how a received response is logged.

use std::mem::replace;

use http::{HeaderValue, header, uri::Scheme};
use http_kit::{Body, Method, Request, Response};
use tracing::debug;

use crate::{
    Error,
    transport::route::{Origin, Via},
};

/// Takes the request out of the endpoint's slot. Extensions are caller
/// context, not wire data: they stay on the slot so middleware (the cookie
/// jar, for one) finds them again once `respond` returns.
pub fn take_request(slot: &mut Request) -> http::Request<Body> {
    let mut placeholder = http::Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())
        .expect("a GET to `/` is a valid request");
    std::mem::swap(placeholder.extensions_mut(), slot.extensions_mut());
    replace(slot, placeholder)
}

/// A copy of `request` for a replay on a fresh connection, or `None` when
/// the body cannot be sent twice — `http_kit::Body::try_clone` yields a
/// body only for buffered bytes (or an empty one); a reader, stream, or
/// frozen body is not replayed.
#[cfg(any(feature = "http2", native_backend))]
pub fn replayable_request(request: &http::Request<Body>) -> Option<http::Request<Body>> {
    let mut replay = http::Request::new(request.body().try_clone()?);
    *replay.method_mut() = request.method().clone();
    *replay.uri_mut() = request.uri().clone();
    *replay.version_mut() = request.version();
    *replay.headers_mut() = request.headers().clone();
    *replay.extensions_mut() = request.extensions().clone();
    Some(replay)
}

/// The request's authority as a pool origin.
///
/// # Errors
///
/// The URI has no host, or a scheme other than `http` and `https`.
pub fn request_origin(uri: &http::Uri) -> Result<Origin, Error> {
    let host = uri
        .host()
        .ok_or_else(|| Error::InvalidUri(uri.to_string()))?;
    let scheme = match uri.scheme_str().unwrap_or("http") {
        "https" => Scheme::HTTPS,
        "http" => Scheme::HTTP,
        other => return Err(Error::InvalidUri(other.to_string())),
    };
    Ok(Origin {
        host: host.to_owned(),
        port: uri
            .port_u16()
            .unwrap_or(if scheme == Scheme::HTTPS { 443 } else { 80 }),
        scheme,
    })
}

/// Shapes an h1 request for the path its connection took: origin-form and a
/// `Host` header for direct connections, absolute-form plus the proxy's
/// `Proxy-Authorization` through a forward proxy.
///
/// # Errors
///
/// The request's path does not form an origin-form target.
pub fn shape_h1_request(request: &mut http::Request<Body>, via: &Via) -> Result<(), Error> {
    if request.headers().get(header::HOST).is_none()
        && let Some(authority) = request.uri().authority()
        && let Ok(value) = HeaderValue::from_str(authority.as_str())
    {
        request.headers_mut().insert(header::HOST, value);
    }
    match via {
        Via::Direct => {
            let origin_form = request
                .uri()
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            *request.uri_mut() = origin_form
                .parse()
                .map_err(|err| Error::InvalidUri(format!("{origin_form}: {err}")))?;
        }
        Via::HttpProxy { authorization } => {
            // Absolute-form request line: the proxy needs the full URI.
            if let Some(authorization) = authorization {
                request
                    .headers_mut()
                    .insert(header::PROXY_AUTHORIZATION, authorization.clone());
            }
        }
    }
    Ok(())
}

/// Logs the head of a response the backend is about to return. Its status
/// is the caller's to judge: a backend hands back what it received, and
/// [`crate::ErrorForStatus`] is the layer that turns an error status into
/// an error.
pub fn received(response: &Response) {
    debug!(
        status = %response.status(),
        headers = ?response.headers(),
        "received response"
    );
}
