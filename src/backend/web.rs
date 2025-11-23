use core::{
    fmt,
    future::Future,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::anyhow;
use http_kit::{
    Endpoint, HttpError, StatusCode,
    utils::{Stream, StreamExt},
};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Window,
    wasm_bindgen::{JsCast, JsValue},
};

use super::ClientBackend;
/// HTTP client backend for browser environments using `fetch`.
pub struct WebBackend {
    window: SingleThreaded<Window>,
}

#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct WebError {
    #[source]
    source: anyhow::Error,
    status: StatusCode,
}

impl WebError {
    fn new(status: StatusCode, error: impl Into<anyhow::Error>) -> Self {
        Self {
            source: error.into(),
            status,
        }
    }
}

impl HttpError for WebError {
    fn status(&self) -> Option<StatusCode> {
        Some(self.status)
    }
}

impl fmt::Debug for WebBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebBackend").finish()
    }
}

// Browser is not multi-threaded, so we can safely implement `Send` and `Sync`
// since the WebBackend will only be used on the main thread
struct SingleThreaded<T>(pub T);

impl<T: Stream> Stream for SingleThreaded<T> {
    type Item = T::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // SAFETY: SingleThreaded<T> is a newtype wrapper, and we do not move T out.
        let this = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut this.0).poll_next(cx) }
    }
}

unsafe impl<T> Send for SingleThreaded<T> {}
unsafe impl<T> Sync for SingleThreaded<T> {}

impl<T> Deref for SingleThreaded<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Future> Future for SingleThreaded<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: SingleThreaded<T> is a newtype wrapper, and we do not move T out.
        let this = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut this.0).poll(cx) }
    }
}

impl WebBackend {
    /// Construct a new `WebBackend` bound to the global `window`.
    pub fn new() -> Self {
        let window = web_sys::window().expect("No global `window` exists");

        Self {
            window: SingleThreaded(window),
        }
    }
}

impl Default for WebBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Endpoint for WebBackend {
    type Error = WebError;
    async fn respond(
        &mut self,
        request: &mut http_kit::Request,
    ) -> Result<http_kit::Response, WebError> {
        fetch(&self.window, request).await
    }
}

fn fetch(
    window: &Window,
    request: &mut http_kit::Request,
) -> impl Future<Output = Result<http_kit::Response, WebError>> + Send {
    SingleThreaded(async move {
        let request_init = web_sys::RequestInit::new();
        request_init.set_method(request.method().as_str());
        let headers = web_sys::Headers::new().unwrap();
        let body = std::mem::replace(request.body_mut(), http_kit::Body::empty());
        let has_body = body.is_empty().map(|empty| !empty).unwrap_or(true);

        if has_body {
            let body_stream = body.map(|result| {
                result
                    .map(|chunk| {
                        let chunk: Box<[u8]> = chunk.to_vec().into_boxed_slice();
                        JsValue::from(chunk)
                    })
                    .map_err(|e| JsValue::from_str(&format!("{e:?}")))
            });
            let body_value = wasm_streams::ReadableStream::from_stream(body_stream).into_raw();
            request_init.set_body(body_value.dyn_ref().unwrap());
        }

        for (name, value) in request.headers().iter() {
            let value = value
                .to_str()
                .map_err(|e| WebError::new(StatusCode::BAD_REQUEST, e))?;
            headers
                .set(name.as_str(), value)
                .map_err(|err| WebError::new(StatusCode::BAD_REQUEST, anyhow!(err)))?;
        }
        request_init.set_headers(headers.as_ref());

        let uri = request.uri().to_string();
        let fetch_request = web_sys::Request::new_with_str_and_init(uri.as_str(), &request_init)
            .map_err(|err| WebError::new(StatusCode::BAD_REQUEST, anyhow!(err)))?;

        let promise = window.fetch_with_request(&fetch_request);
        let fut = SingleThreaded(JsFuture::from(promise));
        let response = fut
            .await
            .map_err(|e| WebError::new(StatusCode::BAD_GATEWAY, anyhow!(e)))?;
        let response: web_sys::Response = response.dyn_into().map_err(|_| {
            WebError::new(
                StatusCode::BAD_GATEWAY,
                anyhow!("Failed to cast to Response"),
            )
        })?;

        let status = StatusCode::from_u16(response.status() as u16)
            .map_err(|e| WebError::new(StatusCode::BAD_GATEWAY, e))?;
        let mut headers = http_kit::header::HeaderMap::new();
        for pair in response.headers().entries() {
            let pair = pair.map_err(|err| WebError::new(StatusCode::BAD_GATEWAY, anyhow!(err)))?;
            let entry: js_sys::Array = pair.dyn_into().map_err(|_| {
                WebError::new(
                    StatusCode::BAD_GATEWAY,
                    anyhow!("Failed to cast header entry to Array"),
                )
            })?;
            let name = entry.get(0).as_string().ok_or_else(|| {
                WebError::new(
                    StatusCode::BAD_GATEWAY,
                    anyhow!("Failed to read header name"),
                )
            })?;
            let value = entry.get(1).as_string().ok_or_else(|| {
                WebError::new(
                    StatusCode::BAD_GATEWAY,
                    anyhow!("Failed to read header value"),
                )
            })?;
            headers.insert(
                http_kit::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| WebError::new(StatusCode::BAD_GATEWAY, e))?,
                http_kit::header::HeaderValue::from_str(&value)
                    .map_err(|e| WebError::new(StatusCode::BAD_GATEWAY, e))?,
            );
        }

        let body = response
            .body()
            .map(|body| {
                let stream = wasm_streams::ReadableStream::from_raw(body).into_stream();

                let stream = stream.map(|result| {
                    result
                        .map(|chunk| {
                            let uint8_array = js_sys::Uint8Array::new(&chunk);
                            let mut vec = vec![0; uint8_array.length() as usize];
                            uint8_array.copy_to(&mut vec[..]);
                            let chunk: Box<[u8]> = vec.into_boxed_slice();
                            chunk
                        })
                        .map_err(|e| anyhow!("Failed to read body: {e:?}"))
                });
                http_kit::Body::from_stream(SingleThreaded(stream))
            })
            .unwrap_or_else(http_kit::Body::empty);

        let mut response: http::Response<http_kit::Body> = http::Response::new(body);

        *response.headers_mut() = headers;
        *response.status_mut() = status;
        Ok(response)
    })
}

impl ClientBackend for WebBackend {}
