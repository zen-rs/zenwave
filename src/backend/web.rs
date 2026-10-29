use core::{fmt, future::Future};

use http_kit::{BodyError, Endpoint, HttpError, StatusCode, utils::StreamExt};
use std::error::Error as StdError;
use std::io;
use wasm_bindgen_futures::JsFuture;
use web_sys::wasm_bindgen::{JsCast, JsValue};

use crate::single_threaded::SingleThreaded;
use crate::{Client, Transport, error::HttpErrorResponse};
/// HTTP client backend for browser environments using `fetch`.
pub struct WebBackend {
    scope: SingleThreaded<FetchScope>,
    transport: Transport,
}

/// `globalThis` and the `fetch` it owns.
///
/// A page has a `Window`, a web worker a `WorkerGlobalScope`, and a
/// Cloudflare Worker a global whose constructor is not exposed at all, so
/// no `instanceof` test names every runtime. What every one of them has is
/// a `fetch` property on `globalThis`; the backend takes that function once
/// and calls it with `globalThis` as `this`, which is how the platform
/// itself dispatches `fetch(request)`.
struct FetchScope {
    global: JsValue,
    fetch: web_sys::js_sys::Function,
}

impl FetchScope {
    /// The scope this code is running in, or `None` when `globalThis` has
    /// no `fetch` at all (a bare JS shell, for instance).
    fn current() -> Option<Self> {
        let global: JsValue = web_sys::js_sys::global().into();
        let fetch = web_sys::js_sys::Reflect::get(&global, &JsValue::from_str("fetch")).ok()?;
        let fetch = fetch.dyn_into::<web_sys::js_sys::Function>().ok()?;
        Some(Self { global, fetch })
    }

    fn fetch_with_request(
        &self,
        request: &web_sys::Request,
    ) -> Result<web_sys::js_sys::Promise, JsValue> {
        self.fetch
            .call1(&self.global, request)
            .map(web_sys::js_sys::Promise::from)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("{source}")]
    Transport {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
        status: StatusCode,
    },
    #[error("remote error: {status}")]
    Remote {
        status: StatusCode,
        body: Option<String>,
        // Boxed: a full `Response` dwarfs the rest of the enum and would make
        // every `Result<_, WebError>` carry it inline (`result_large_err`).
        raw_response: Box<http_kit::Response>,
    },
}

impl WebError {
    fn new(status: StatusCode, error: impl StdError + Send + Sync + 'static) -> Self {
        Self::Transport {
            source: Box::new(error),
            status,
        }
    }

    fn remote(status: StatusCode, body: Option<String>, raw_response: http_kit::Response) -> Self {
        Self::Remote {
            status,
            body,
            raw_response: Box::new(raw_response),
        }
    }
}

impl HttpError for WebError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Transport { status, .. } | Self::Remote { status, .. } => *status,
        }
    }
}

// Convert WebError to unified zenwave::Error
impl From<WebError> for crate::Error {
    fn from(err: WebError) -> Self {
        match err {
            WebError::Transport { source, .. } => Self::Transport(source),
            WebError::Remote {
                status,
                body,
                raw_response,
            } => Self::Http {
                status,
                message: body.clone().unwrap_or_else(|| {
                    status
                        .canonical_reason()
                        .unwrap_or("Unknown error")
                        .to_string()
                }),
                response: Box::new(HttpErrorResponse {
                    response: *raw_response,
                    body_text: body,
                }),
            },
        }
    }
}

impl fmt::Debug for WebBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `scope` is a handle to the JS global; it has nothing to print.
        f.debug_struct("WebBackend")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl WebBackend {
    /// Construct a new `WebBackend` bound to the global scope's `fetch`.
    ///
    /// The browser owns proxying and trust, so `transport` carries no settings
    /// here; taking it keeps the constructor shape shared with the native
    /// backends.
    ///
    /// # Panics
    ///
    /// Panics when `globalThis` is neither a `Window` nor a
    /// `WorkerGlobalScope`, because there is then no `fetch` to speak through.
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        let scope = FetchScope::current().expect(
            "globalThis is neither a Window nor a WorkerGlobalScope, so there is no `fetch`",
        );

        Self {
            scope: SingleThreaded(scope),
            transport,
        }
    }
}

impl Default for WebBackend {
    fn default() -> Self {
        Self::new(Transport::system())
    }
}

impl Endpoint for WebBackend {
    type Error = crate::Error;
    async fn respond(
        &mut self,
        request: &mut http_kit::Request,
    ) -> Result<http_kit::Response, Self::Error> {
        fetch(&self.scope, request).await.map_err(Into::into)
    }
}

fn fetch(
    scope: &FetchScope,
    request: &mut http_kit::Request,
) -> impl Future<Output = Result<http_kit::Response, WebError>> + Send {
    SingleThreaded(async move {
        let request_init = request_init(request).await?;
        let fetch_request = fetch_request(request, &request_init)?;
        let response = send(scope, &fetch_request).await?;
        let status = StatusCode::from_u16(response.status())
            .map_err(|e| WebError::new(StatusCode::BAD_GATEWAY, e))?;
        let headers = response_headers(&response)?;
        let body = response_body(&response);

        let is_error = status.is_client_error() || status.is_server_error();
        let mut response: http::Response<http_kit::Body> = http::Response::new(body);
        *response.headers_mut() = headers;
        *response.status_mut() = status;

        if is_error {
            let body = response
                .body_mut()
                .as_str()
                .await
                .ok()
                .map(ToOwned::to_owned);
            return Err(WebError::remote(status, body, response));
        }
        Ok(response)
    })
}

/// The `RequestInit` carrying the method, the buffered body and the headers.
///
/// The request body is handed to `fetch` as bytes, never as a
/// `ReadableStream`. A streamed request body is a Chromium-only feature that
/// also needs HTTP/2 and `duplex: "half"`; Firefox and Safari reject it, and
/// a Cloudflare Worker never pulls a stream driven from Rust, so the request
/// sat pending until the runtime cancelled the invocation. Buffering costs
/// one copy of the body and works everywhere `fetch` does.
async fn request_init(request: &mut http_kit::Request) -> Result<web_sys::RequestInit, WebError> {
    let request_init = web_sys::RequestInit::new();
    request_init.set_method(request.method().as_str());
    let headers = web_sys::Headers::new().unwrap();

    let body = std::mem::replace(request.body_mut(), http_kit::Body::empty());
    let bytes = body
        .into_bytes()
        .await
        .map_err(|e| WebError::new(StatusCode::BAD_REQUEST, e))?;
    if !bytes.is_empty() {
        let body_value: JsValue = js_sys::Uint8Array::from(bytes.as_ref()).into();
        request_init.set_body(&body_value);
    }

    for (name, value) in request.headers() {
        let value = value
            .to_str()
            .map_err(|e| WebError::new(StatusCode::BAD_REQUEST, e))?;
        headers
            .set(name.as_str(), value)
            .map_err(|err| bad_request(&err))?;
    }
    request_init.set_headers(headers.as_ref());
    Ok(request_init)
}

fn fetch_request(
    request: &http_kit::Request,
    request_init: &web_sys::RequestInit,
) -> Result<web_sys::Request, WebError> {
    let uri = request.uri().to_string();
    web_sys::Request::new_with_str_and_init(uri.as_str(), request_init)
        .map_err(|err| bad_request(&err))
}

async fn send(
    scope: &FetchScope,
    fetch_request: &web_sys::Request,
) -> Result<web_sys::Response, WebError> {
    let promise = scope
        .fetch_with_request(fetch_request)
        .map_err(|err| bad_gateway(&err))?;
    let response = SingleThreaded(JsFuture::from(promise))
        .await
        .map_err(|err| bad_gateway(&err))?;
    response.dyn_into().map_err(|_| {
        WebError::new(
            StatusCode::BAD_GATEWAY,
            transport_error("Failed to cast to Response"),
        )
    })
}

fn response_headers(response: &web_sys::Response) -> Result<http_kit::header::HeaderMap, WebError> {
    let mut headers = http_kit::header::HeaderMap::new();
    for pair in response.headers().entries() {
        let entry: js_sys::Array =
            pair.map_err(|err| bad_gateway(&err))?
                .dyn_into()
                .map_err(|_| {
                    WebError::new(
                        StatusCode::BAD_GATEWAY,
                        transport_error("Failed to cast header entry to Array"),
                    )
                })?;
        let name = entry.get(0).as_string().ok_or_else(|| {
            WebError::new(
                StatusCode::BAD_GATEWAY,
                transport_error("Failed to read header name"),
            )
        })?;
        let value = entry.get(1).as_string().ok_or_else(|| {
            WebError::new(
                StatusCode::BAD_GATEWAY,
                transport_error("Failed to read header value"),
            )
        })?;
        headers.insert(
            http_kit::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| WebError::new(StatusCode::BAD_GATEWAY, e))?,
            http_kit::header::HeaderValue::from_str(&value)
                .map_err(|e| WebError::new(StatusCode::BAD_GATEWAY, e))?,
        );
    }
    Ok(headers)
}

fn response_body(response: &web_sys::Response) -> http_kit::Body {
    response.body().map_or_else(http_kit::Body::empty, |body| {
        let stream = wasm_streams::ReadableStream::from_raw(body).into_stream();
        let stream = stream.map(|result| {
            result
                .map(|chunk| {
                    let uint8_array = js_sys::Uint8Array::new(&chunk);
                    let mut vec = vec![0; uint8_array.length() as usize];
                    uint8_array.copy_to(&mut vec[..]);
                    vec.into_boxed_slice()
                })
                .map_err(|e| {
                    BodyError::Other(Box::new(io::Error::other(format!(
                        "Failed to read body: {e:?}"
                    ))))
                })
        });
        http_kit::Body::from_stream(SingleThreaded(stream))
    })
}

fn format_js_value(value: &JsValue) -> String {
    value.as_string().unwrap_or_else(|| format!("{value:?}"))
}

fn bad_request(err: &JsValue) -> WebError {
    WebError::new(
        StatusCode::BAD_REQUEST,
        transport_error(format_js_value(err)),
    )
}

fn bad_gateway(err: &JsValue) -> WebError {
    WebError::new(
        StatusCode::BAD_GATEWAY,
        transport_error(format_js_value(err)),
    )
}

fn transport_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

impl Client for WebBackend {}
