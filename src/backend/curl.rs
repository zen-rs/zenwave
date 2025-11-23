use std::{mem::replace, str};

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use curl::easy::{Easy2, Handler, List, ProxyType, ReadError, WriteError};
use http::{
    HeaderMap, Method,
    header::{HeaderName, HeaderValue},
};
use http_kit::{Body, Endpoint, HttpError, Request, Response, StatusCode};
use hyper_util::client::proxy::matcher;
use thiserror::Error;
use tokio::task;

use crate::{ClientBackend, Proxy};

/// HTTP backend implemented with libcurl.
#[derive(Debug, Clone, Default)]
pub struct CurlBackend {
    proxy: Option<Proxy>,
}

#[derive(Debug, Error)]
pub enum CurlError {
    #[error("bad request: {0}")]
    BadRequest(#[source] anyhow::Error),
    #[error("bad gateway: {0}")]
    BadGateway(#[source] anyhow::Error),
}

impl HttpError for CurlError {
    fn status(&self) -> Option<StatusCode> {
        Some(match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
        })
    }
}

impl CurlError {
    fn bad_request(error: impl Into<anyhow::Error>) -> Self {
        Self::BadRequest(error.into())
    }

    fn bad_gateway(error: impl Into<anyhow::Error>) -> Self {
        Self::BadGateway(error.into())
    }
}

impl CurlBackend {
    /// Create a new backend without proxy configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a backend configured to use the supplied proxy matcher.
    #[must_use]
    pub const fn with_proxy(proxy: Proxy) -> Self {
        Self { proxy: Some(proxy) }
    }

    /// Replace the proxy matcher.
    #[must_use]
    pub fn proxy(self, proxy: Proxy) -> Self {
        Self::with_proxy(proxy)
    }
}

impl ClientBackend for CurlBackend {}

impl Endpoint for CurlBackend {
    type Error = CurlError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .expect("building dummy request failed");
        let request = replace(request, dummy_request);
        execute(request, self.proxy.clone()).await
    }
}

async fn execute(request: Request, proxy: Option<Proxy>) -> Result<Response, CurlError> {
    let (parts, body) = request.into_parts();
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        let value_str = value.to_str().map_err(CurlError::bad_request)?;
        headers.push((name.as_str().to_string(), value_str.to_string()));
    }

    let body_bytes = body
        .into_bytes()
        .await
        .map_err(CurlError::bad_request)?
        .to_vec();

    let proxy = proxy
        .as_ref()
        .and_then(|cfg| cfg.intercept(&parts.uri))
        .map(|intercept| resolve_proxy(&intercept).map_err(CurlError::bad_request))
        .transpose()?;

    let prepared = PreparedRequest {
        method: parts.method.as_str().to_owned(),
        url: parts.uri.to_string(),
        headers,
        body: body_bytes,
        proxy,
    };

    let response = task::spawn_blocking(move || perform(prepared))
        .await
        .map_err(CurlError::bad_gateway)??;

    Ok(response)
}

fn perform(request: PreparedRequest) -> Result<Response, CurlError> {
    let handler = CurlHandler::new(request.body);
    let upload_len = handler.request_body_len();

    let mut easy = Easy2::new(handler);
    easy.url(&request.url).map_err(map_curl_error)?;
    easy.custom_request(&request.method)
        .map_err(map_curl_error)?;

    if upload_len > 0 {
        easy.upload(true).map_err(map_curl_error)?;
        easy.in_filesize(upload_len as u64)
            .map_err(map_curl_error)?;
    }

    let header_list = if request.headers.is_empty() {
        None
    } else {
        let mut list = List::new();
        for (name, value) in &request.headers {
            list.append(&format!("{name}: {value}"))
                .map_err(map_curl_error)?;
        }
        Some(easy.http_headers(list).map_err(map_curl_error)?)
    };

    if let Some(proxy) = &request.proxy {
        apply_proxy(&mut easy, proxy).map_err(map_curl_error)?;
    }

    easy.perform().map_err(map_curl_error)?;

    // Keep the header list alive until this point.
    let _ = header_list;

    let handler = easy.get_mut();
    let response = handler.take_response().map_err(CurlError::bad_gateway)?;

    let mut http_response = http::Response::new(Body::from(response.body));
    *http_response.status_mut() = response.status;
    *http_response.headers_mut() = response.headers;

    Ok(http_response)
}

fn map_curl_error(error: curl::Error) -> CurlError {
    CurlError::bad_gateway(error)
}

#[derive(Debug)]
struct PreparedRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    proxy: Option<ResolvedProxy>,
}
#[derive(Debug)]
struct ResolvedProxy {
    endpoint: String,
    kind: ProxyType,
    credentials: Option<String>,
}

fn apply_proxy(
    handler: &mut Easy2<CurlHandler>,
    proxy: &ResolvedProxy,
) -> std::result::Result<(), curl::Error> {
    handler.proxy(&proxy.endpoint)?;
    handler.proxy_type(proxy.kind)?;
    if let Some(creds) = &proxy.credentials {
        let (username, password) = creds
            .split_once(':')
            .map_or((creds.as_str(), ""), |(user, pass)| (user, pass));
        handler.proxy_username(username)?;
        handler.proxy_password(password)?;
    }
    Ok(())
}

fn resolve_proxy(intercept: &matcher::Intercept) -> anyhow::Result<ResolvedProxy> {
    let scheme = intercept
        .uri()
        .scheme_str()
        .unwrap_or("http")
        .to_ascii_lowercase();
    let authority = intercept
        .uri()
        .authority()
        .context("proxy URI missing authority")?
        .as_str();
    let endpoint = format!("{scheme}://{authority}");

    let (kind, credentials) = match scheme.as_str() {
        "http" => (
            ProxyType::Http,
            intercept
                .basic_auth()
                .and_then(decode_basic_auth)
                .map(|(user, pass)| format!("{user}:{pass}")),
        ),
        "https" => (
            ProxyType::Http,
            intercept
                .basic_auth()
                .and_then(decode_basic_auth)
                .map(|(user, pass)| format!("{user}:{pass}")),
        ),
        "socks4" => (
            ProxyType::Socks4,
            intercept
                .raw_auth()
                .map(|(user, pass)| format!("{user}:{pass}")),
        ),
        "socks4a" => (
            ProxyType::Socks4a,
            intercept
                .raw_auth()
                .map(|(user, pass)| format!("{user}:{pass}")),
        ),
        "socks5" => (
            ProxyType::Socks5,
            intercept
                .raw_auth()
                .map(|(user, pass)| format!("{user}:{pass}")),
        ),
        "socks5h" => (
            ProxyType::Socks5Hostname,
            intercept
                .raw_auth()
                .map(|(user, pass)| format!("{user}:{pass}")),
        ),
        other => return Err(anyhow!("unsupported proxy scheme `{other}`")),
    };

    Ok(ResolvedProxy {
        endpoint,
        kind,
        credentials,
    })
}

fn decode_basic_auth(value: &HeaderValue) -> Option<(String, String)> {
    let text = value.to_str().ok()?;
    let encoded = text.strip_prefix("Basic ")?;
    let decoded = BASE64_STANDARD.decode(encoded).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let mut parts = creds.splitn(2, ':');
    let user = parts.next()?.to_string();
    let pass = parts.next().unwrap_or("").to_string();
    Some((user, pass))
}

#[derive(Debug)]
struct CurlHandler {
    request_body: Option<Vec<u8>>,
    offset: usize,
    response_body: Vec<u8>,
    headers: HeaderMap,
    status: Option<StatusCode>,
}

impl CurlHandler {
    fn new(body: Vec<u8>) -> Self {
        let request_body = if body.is_empty() { None } else { Some(body) };
        Self {
            request_body,
            offset: 0,
            response_body: Vec::new(),
            headers: HeaderMap::new(),
            status: None,
        }
    }

    fn request_body_len(&self) -> usize {
        self.request_body.as_ref().map_or(0, Vec::len)
    }

    fn take_response(&mut self) -> anyhow::Result<SessionResponse> {
        let status = self
            .status
            .ok_or_else(|| anyhow!("curl response missing HTTP status line"))?;
        Ok(SessionResponse {
            status,
            headers: std::mem::take(&mut self.headers),
            body: std::mem::take(&mut self.response_body),
        })
    }

    fn parse_header_line(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }

        if let Some(rest) = line.strip_prefix("HTTP/")
            && let Some(code) = rest.split_whitespace().nth(1)
            && let Ok(value) = code.parse::<u16>()
            && let Ok(status) = StatusCode::from_u16(value)
        {
            self.status = Some(status);
            self.headers.clear();
            return;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.is_empty() {
                return;
            }

            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                self.headers.append(header_name, header_value);
            }
        }
    }
}

impl Handler for CurlHandler {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.response_body.extend_from_slice(data);
        Ok(data.len())
    }

    fn header(&mut self, data: &[u8]) -> bool {
        if let Ok(line) = str::from_utf8(data) {
            self.parse_header_line(line.trim());
        }
        true
    }

    fn read(&mut self, data: &mut [u8]) -> Result<usize, ReadError> {
        if let Some(body) = &self.request_body {
            if self.offset >= body.len() {
                return Ok(0);
            }
            let remaining = &body[self.offset..];
            let len = remaining.len().min(data.len());
            data[..len].copy_from_slice(&remaining[..len]);
            self.offset += len;
            Ok(len)
        } else {
            Ok(0)
        }
    }
}

#[derive(Debug)]
struct SessionResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}
