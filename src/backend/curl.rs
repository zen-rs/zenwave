use std::{mem::replace, str};

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use blocking::unblock;
use curl::easy::{Easy2, Handler, List, ProxyType, ReadError, WriteError};
use http::{
    HeaderMap, Method,
    header::{HeaderName, HeaderValue},
};
use http_kit::{Body, Endpoint, HttpError, Request, Response, StatusCode};
use thiserror::Error;

use crate::{Client, Transport, error::HttpErrorResponse, transport::proxy::Intercept};

/// HTTP backend implemented with libcurl.
#[derive(Debug, Clone)]
pub struct CurlBackend {
    transport: Transport,
}

#[derive(Debug, Error)]
pub enum CurlError {
    #[error("bad request: {0}")]
    BadRequest(#[source] anyhow::Error),
    #[error("bad gateway: {0}")]
    BadGateway(#[source] anyhow::Error),
    #[error("TLS failure: {0}")]
    Tls(#[source] curl::Error),
    #[error("remote error: {status}")]
    Remote {
        status: StatusCode,
        body: Option<String>,
        raw_response: Box<Response>,
    },
}

impl HttpError for CurlError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::BadGateway(_) | Self::Tls(_) => StatusCode::BAD_GATEWAY,
            Self::Remote { status, .. } => *status,
        }
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

// Convert CurlError to unified zenwave::Error
impl From<CurlError> for crate::Error {
    fn from(err: CurlError) -> Self {
        match err {
            CurlError::BadRequest(e) => Self::InvalidRequest(e.to_string()),
            CurlError::BadGateway(e) => {
                let io_err = std::io::Error::other(e);
                Self::Transport(Box::new(io_err))
            }
            CurlError::Tls(e) => Self::tls(e),
            CurlError::Remote {
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

impl CurlBackend {
    /// Create a backend that follows `transport` for proxy rules and trust.
    #[must_use]
    pub const fn new(transport: Transport) -> Self {
        Self { transport }
    }
}

impl Default for CurlBackend {
    fn default() -> Self {
        Self::new(Transport::system())
    }
}

impl Client for CurlBackend {}

impl Endpoint for CurlBackend {
    type Error = crate::Error;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .expect("building dummy request failed");
        let request = replace(request, dummy_request);
        execute(request, &self.transport).await.map_err(Into::into)
    }
}

async fn execute(request: Request, transport: &Transport) -> Result<Response, CurlError> {
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

    let proxy = transport
        .proxy()
        .intercept(&parts.uri)
        .map(|intercept| resolve_proxy(&intercept).map_err(CurlError::bad_request))
        .transpose()?;

    let prepared = PreparedRequest {
        method: parts.method.as_str().to_owned(),
        url: parts.uri.to_string(),
        headers,
        body: body_bytes,
        proxy,
        ca_bundle: transport.ca_bundle().map(<[u8]>::to_vec),
    };

    let response = unblock(move || perform(prepared)).await?;

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

    // The matcher is the only source of proxy rules: an empty CURLOPT_PROXY
    // stops libcurl from consulting `http_proxy` and friends on its own.
    match &request.proxy {
        Some(proxy) => apply_proxy(&mut easy, proxy).map_err(map_curl_error)?,
        None => easy.proxy("").map_err(map_curl_error)?,
    }
    if let Some(bundle) = &request.ca_bundle {
        easy.ssl_cainfo_blob(bundle).map_err(map_curl_error)?;
    }

    easy.perform().map_err(map_curl_error)?;

    // Keep the header list alive until this point.
    let _ = header_list;

    let handler = easy.get_mut();
    let response = handler.take_response().map_err(CurlError::bad_gateway)?;

    let SessionResponse {
        status,
        headers,
        body,
    } = response;

    let is_error = status.is_client_error() || status.is_server_error();
    let error_body = if is_error {
        String::from_utf8(body.clone()).ok()
    } else {
        None
    };

    let mut http_response = http::Response::new(Body::from(body));
    *http_response.status_mut() = status;
    *http_response.headers_mut() = headers;

    if is_error {
        return Err(CurlError::Remote {
            status,
            body: error_body,
            raw_response: Box::new(http_response),
        });
    }

    Ok(http_response)
}

/// Sort a libcurl failure into zenwave's error taxonomy: handshake and
/// certificate problems are TLS errors, everything else is transport.
fn map_curl_error(error: curl::Error) -> CurlError {
    let is_tls = error.is_ssl_connect_error()
        || error.is_peer_failed_verification()
        || error.is_ssl_certproblem()
        || error.is_ssl_cipher()
        || error.is_ssl_cacert()
        || error.is_ssl_cacert_badfile()
        || error.is_ssl_crl_badfile()
        || error.is_ssl_issuer_error()
        || error.is_use_ssl_failed()
        || error.is_ssl_engine_notfound()
        || error.is_ssl_engine_setfailed()
        || error.is_ssl_engine_initfailed();
    if is_tls {
        CurlError::Tls(error)
    } else {
        CurlError::bad_gateway(error)
    }
}

#[derive(Debug)]
struct PreparedRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    proxy: Option<ResolvedProxy>,
    ca_bundle: Option<Vec<u8>>,
}
#[derive(Debug)]
struct ResolvedProxy {
    endpoint: String,
    kind: ProxyType,
    credentials: Option<(String, String)>,
}

fn apply_proxy(
    handler: &mut Easy2<CurlHandler>,
    proxy: &ResolvedProxy,
) -> std::result::Result<(), curl::Error> {
    handler.proxy(&proxy.endpoint)?;
    handler.proxy_type(proxy.kind)?;
    // The matcher already applied `no_proxy`; an empty CURLOPT_NOPROXY keeps
    // libcurl from second-guessing it with the `no_proxy` environment variable.
    handler.noproxy("")?;
    if let Some((username, password)) = &proxy.credentials {
        handler.proxy_username(username)?;
        handler.proxy_password(password)?;
    }
    Ok(())
}

fn resolve_proxy(intercept: &Intercept) -> anyhow::Result<ResolvedProxy> {
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

    let kind = match scheme.as_str() {
        "http" | "https" => ProxyType::Http,
        "socks4" => ProxyType::Socks4,
        "socks4a" => ProxyType::Socks4a,
        "socks5" => ProxyType::Socks5,
        "socks5h" => ProxyType::Socks5Hostname,
        other => return Err(anyhow!("unsupported proxy scheme `{other}`")),
    };
    let credentials = match kind {
        ProxyType::Http => intercept.basic_auth().and_then(decode_basic_auth),
        _ => intercept
            .raw_auth()
            .map(|(user, pass)| (user.to_owned(), pass.to_owned())),
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
