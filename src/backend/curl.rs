use std::{mem::replace, str};

use anyhow::anyhow;
use curl::easy::{Easy2, Handler, List, ReadError, WriteError};
use http::{
    HeaderMap, Method,
    header::{HeaderName, HeaderValue},
};
use http_kit::{Body, Endpoint, Request, Response, Result, StatusCode};
use tokio::task;

use crate::ClientBackend;

/// HTTP backend implemented with libcurl.
#[derive(Debug, Default)]
pub struct CurlBackend;

impl ClientBackend for CurlBackend {}

impl Endpoint for CurlBackend {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        let dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .expect("building dummy request failed");
        let mut request = replace(request, dummy_request);
        execute(request).await
    }
}

async fn execute(request: Request) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (name, value) in parts.headers.iter() {
        let value_str = value
            .to_str()
            .map_err(|e| http_kit::Error::new(e, StatusCode::BAD_REQUEST))?;
        headers.push((name.as_str().to_string(), value_str.to_string()));
    }

    let body_bytes = body
        .into_bytes()
        .await
        .map_err(|e| http_kit::Error::new(e, StatusCode::BAD_REQUEST))?
        .to_vec();

    let prepared = PreparedRequest {
        method: parts.method.as_str().to_owned(),
        url: parts.uri.to_string(),
        headers,
        body: body_bytes,
    };

    task::spawn_blocking(move || perform(prepared))
        .await
        .map_err(|e| http_kit::Error::new(e, StatusCode::BAD_GATEWAY))??
}

fn perform(request: PreparedRequest) -> Result<Response> {
    let mut handler = CurlHandler::new(request.body);
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

    let mut header_list = None;
    if !request.headers.is_empty() {
        let mut list = List::new();
        for (name, value) in &request.headers {
            list.append(&format!("{name}: {value}"))
                .map_err(map_curl_error)?;
        }
        header_list = Some(easy.http_headers(list).map_err(map_curl_error)?);
    }

    easy.perform().map_err(map_curl_error)?;

    // Keep the header list alive until this point.
    drop(header_list);

    let handler = easy.into_inner();
    let response = handler
        .into_response()
        .map_err(|e| http_kit::Error::new(e, StatusCode::BAD_GATEWAY))?;

    let mut http_response = http::Response::new(Body::from(response.body));
    *http_response.status_mut() = response.status;
    *http_response.headers_mut() = response.headers;

    Ok(http_response)
}

fn map_curl_error(error: curl::Error) -> http_kit::Error {
    http_kit::Error::new(error, StatusCode::BAD_GATEWAY)
}

#[derive(Debug)]
struct PreparedRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
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

    fn into_response(self) -> anyhow::Result<SessionResponse> {
        let status = self
            .status
            .ok_or_else(|| anyhow!("curl response missing HTTP status line"))?;
        Ok(SessionResponse {
            status,
            headers: self.headers,
            body: self.response_body,
        })
    }

    fn parse_header_line(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }

        if let Some(rest) = line.strip_prefix("HTTP/") {
            if let Some(code) = rest.split_whitespace().nth(1) {
                if let Ok(value) = code.parse::<u16>() {
                    if let Ok(status) = StatusCode::from_u16(value) {
                        self.status = Some(status);
                        self.headers.clear();
                    }
                }
            }
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
