#[cfg(unix_socket)]
use std::path::{Path, PathBuf};
use std::{io, mem::replace, str, time::Duration};

use blocking::unblock;
use curl::easy::{Easy2, Handler, List, ProxyType, ReadError, SslOpt, WriteError};
use http::{
    HeaderMap, Method,
    header::{HeaderName, HeaderValue},
};
use http_kit::{Body, Endpoint, Request, Response, StatusCode};

use crate::{
    Attempt, Cause, Client, ConfigError, ConnectFailure, ConnectPhase, Error, ExchangeFailure, Hop,
    ResolveError, TcpFailure, TimedOut, TlsError, TlsFailure, Transport,
    clock::{AsyncIoClock, Clocked},
    transport::proxy::{self, Intercept},
};

/// HTTP backend implemented with libcurl.
#[derive(Debug, Clone)]
pub struct CurlBackend {
    transport: Transport,
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

http_kit::impl_send_endpoint!(CurlBackend);

impl Client for CurlBackend {}

impl Clocked for CurlBackend {
    type Clock = AsyncIoClock;

    fn clock(&self) -> AsyncIoClock {
        AsyncIoClock
    }
}

impl Endpoint for CurlBackend {
    type Error = crate::Error;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        crate::timeouts::refuse(request)?;
        let mut dummy_request = http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .expect("building dummy request failed");
        // Extensions are caller context, not wire data: they stay on the
        // request slot handed to the endpoint so middleware (e.g. the
        // cookie jar) finds them again once `respond` returns.
        std::mem::swap(dummy_request.extensions_mut(), request.extensions_mut());
        let request = replace(request, dummy_request);
        execute(request, &self.transport).await
    }
}

async fn execute(request: Request, transport: &Transport) -> Result<Response, Error> {
    let (parts, body) = request.into_parts();
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        let value_str = value
            .to_str()
            .map_err(|error| Error::InvalidRequest(error.to_string()))?;
        headers.push((name.as_str().to_string(), value_str.to_string()));
    }

    let body_bytes = body
        .into_bytes()
        .await
        .map_err(|error| Error::InvalidRequest(error.to_string()))?
        .to_vec();

    let matched_proxy = || {
        transport
            .proxy()
            .intercept(&parts.uri)
            .map(|intercept| resolve_proxy(&intercept))
            .transpose()
    };
    // No proxy can reach a local socket: a transport carrying one skips the
    // matcher entirely, matching `curl --unix-socket`.
    #[cfg(unix_socket)]
    let unix_socket = transport.unix_socket().map(Path::to_path_buf);
    #[cfg(unix_socket)]
    let proxy = if unix_socket.is_some() {
        None
    } else {
        matched_proxy()?
    };
    #[cfg(not(unix_socket))]
    let proxy = matched_proxy()?;

    let https = parts.uri.scheme_str() == Some("https");
    let prepared = PreparedRequest {
        method: parts.method.as_str().to_owned(),
        url: parts.uri.to_string(),
        host: parts.uri.host().unwrap_or_default().to_owned(),
        port: parts.uri.port_u16().unwrap_or(if https { 443 } else { 80 }),
        https,
        headers,
        body: body_bytes,
        proxy,
        #[cfg(unix_socket)]
        unix_socket,
        ca_bundle: transport.ca_bundle().map(<[u8]>::to_vec),
    };

    let response = unblock(move || perform(prepared)).await?;

    Ok(response)
}

fn perform(mut request: PreparedRequest) -> Result<Response, Error> {
    let handler = CurlHandler::new(std::mem::take(&mut request.body));
    let upload_len = handler.request_body_len();

    // An option libcurl refuses is a request it cannot be given.
    let refused = |error: curl::Error| Error::InvalidRequest(error.to_string());

    let mut easy = Easy2::new(handler);
    easy.url(&request.url).map_err(refused)?;
    easy.custom_request(&request.method).map_err(refused)?;
    #[cfg(unix_socket)]
    if let Some(path) = &request.unix_socket {
        easy.unix_socket_path(Some(path)).map_err(refused)?;
    }

    if upload_len > 0 {
        easy.upload(true).map_err(refused)?;
        easy.in_filesize(upload_len as u64).map_err(refused)?;
    }

    let header_list = if request.headers.is_empty() {
        None
    } else {
        let mut list = List::new();
        for (name, value) in &request.headers {
            list.append(&format!("{name}: {value}")).map_err(refused)?;
        }
        Some(easy.http_headers(list).map_err(refused)?)
    };

    // The matcher is the only source of proxy rules: an empty CURLOPT_PROXY
    // stops libcurl from consulting `http_proxy` and friends on its own.
    match &request.proxy {
        Some(proxy) => apply_proxy(&mut easy, proxy)
            .map_err(|error| Error::Config(ConfigError::Tls(Cause::Curl(error))))?,
        None => easy.proxy("").map_err(refused)?,
    }
    if let Some(bundle) = &request.ca_bundle {
        easy.ssl_cainfo_blob(bundle)
            .map_err(|error| Error::trust_store(Cause::Curl(error)))?;
    }
    // Revocation is checked when the information is reachable and skipped
    // when it is not (no distribution point, offline responder), which is how
    // the platform verifiers behind the rustls and native-tls engines behave.
    // Only Schannel interprets this flag; the other TLS libraries ignore it.
    easy.ssl_options(SslOpt::new().revoke_best_effort(true))
        .map_err(|error| Error::tls_config(Cause::Curl(error)))?;

    if let Err(error) = easy.perform() {
        return Err(classify(&easy, &request, error));
    }

    // Keep the header list alive until this point.
    let _ = header_list;

    let handler = easy.get_mut();
    let response = handler.take_response()?;

    let SessionResponse {
        status,
        headers,
        body,
    } = response;

    let mut http_response = http::Response::new(Body::from(body));
    *http_response.status_mut() = status;
    *http_response.headers_mut() = headers;
    Ok(http_response)
}

/// Sort a failed `perform` into zenwave's error taxonomy. libcurl reports
/// one code for the whole transfer, so the phase it failed in comes from its
/// timings: each of name lookup, TCP connect and TLS handshake stays at zero
/// until it completes.
fn classify(easy: &Easy2<CurlHandler>, request: &PreparedRequest, error: curl::Error) -> Error {
    let origin = |failure| Error::connect(Hop::Origin, &request.host, request.port, failure);
    // libcurl does not say which hop refused: with a proxy configured, a
    // connect failure is the proxy's.
    let (hop, host, port) = request.proxy.as_ref().map_or(
        (Hop::Origin, request.host.as_str(), request.port),
        |proxy| (Hop::Proxy, proxy.host.as_str(), proxy.port),
    );
    let connect = |hop, host: &str, port, failure| Error::connect(hop, host, port, failure);
    let reached = |timing: Result<Duration, curl::Error>| timing.is_ok_and(|time| !time.is_zero());
    let tls = |failure| {
        origin(ConnectFailure::Tls(TlsError::new(
            failure,
            Cause::Curl(error.clone()),
        )))
    };

    if error.is_couldnt_resolve_host() {
        return origin(ConnectFailure::Resolve(ResolveError::Lookup(Cause::Curl(
            error,
        ))));
    }
    if error.is_couldnt_resolve_proxy() {
        let (host, port) = request
            .proxy
            .as_ref()
            .map_or((request.host.as_str(), request.port), |proxy| {
                (proxy.host.as_str(), proxy.port)
            });
        return connect(
            Hop::Proxy,
            host,
            port,
            ConnectFailure::Resolve(ResolveError::Lookup(Cause::Curl(error))),
        );
    }
    if error.is_couldnt_connect() {
        return connect(
            hop,
            host,
            port,
            ConnectFailure::Tcp(TcpFailure::new(vec![Attempt::new(
                None,
                io::Error::other(error),
            )])),
        );
    }
    if error.is_operation_timedout() {
        return Error::Timeout(if !reached(easy.namelookup_time()) {
            TimedOut::Connect {
                during: ConnectPhase::Resolve,
            }
        } else if !reached(easy.connect_time()) {
            TimedOut::Connect {
                during: ConnectPhase::Tcp,
            }
        } else if request.https && !reached(easy.appconnect_time()) {
            TimedOut::Connect {
                during: ConnectPhase::Tls,
            }
        } else {
            TimedOut::ResponseHead
        });
    }
    if error.is_peer_failed_verification() || error.is_ssl_cacert() || error.is_ssl_issuer_error() {
        return tls(TlsFailure::Certificate);
    }
    if error.is_ssl_connect_error()
        || error.is_ssl_certproblem()
        || error.is_ssl_cipher()
        || error.is_use_ssl_failed()
    {
        return tls(TlsFailure::Protocol);
    }
    if error.is_ssl_cacert_badfile() || error.is_ssl_crl_badfile() {
        return Error::trust_store(Cause::Curl(error));
    }
    if error.is_ssl_engine_notfound()
        || error.is_ssl_engine_setfailed()
        || error.is_ssl_engine_initfailed()
    {
        return Error::tls_config(Cause::Curl(error));
    }
    let failure = if error.is_got_nothing() || error.is_recv_error() || error.is_send_error() {
        ExchangeFailure::Terminated
    } else if error.is_partial_file() {
        ExchangeFailure::Incomplete
    } else {
        ExchangeFailure::Io
    };
    Error::exchange(failure, Cause::Curl(error))
}

#[derive(Debug)]
struct PreparedRequest {
    method: String,
    url: String,
    /// The URL's host and port, and whether it is `https`: where a failure
    /// to connect is reported.
    host: String,
    port: u16,
    https: bool,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    proxy: Option<ResolvedProxy>,
    #[cfg(unix_socket)]
    unix_socket: Option<PathBuf>,
    ca_bundle: Option<Vec<u8>>,
}
#[derive(Debug)]
struct ResolvedProxy {
    endpoint: String,
    /// The proxy's host and port, for the errors that name it.
    host: String,
    port: u16,
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

fn resolve_proxy(intercept: &Intercept) -> Result<ResolvedProxy, Error> {
    let scheme = intercept
        .uri()
        .scheme_str()
        .unwrap_or("http")
        .to_ascii_lowercase();
    let authority = intercept
        .uri()
        .authority()
        .ok_or(Error::Config(ConfigError::ProxyHost))?;
    let endpoint = format!("{scheme}://{}", authority.as_str());

    let (kind, default_port) = match scheme.as_str() {
        "http" => (ProxyType::Http, 80),
        "https" => (ProxyType::Http, 443),
        "socks4" => (ProxyType::Socks4, 1080),
        "socks4a" => (ProxyType::Socks4a, 1080),
        "socks5" => (ProxyType::Socks5, 1080),
        "socks5h" => (ProxyType::Socks5Hostname, 1080),
        other => return Err(Error::Config(ConfigError::ProxyScheme(other.to_owned()))),
    };
    let credentials = proxy::credentials(intercept);

    Ok(ResolvedProxy {
        endpoint,
        host: authority.host().to_owned(),
        port: authority.port_u16().unwrap_or(default_port),
        kind,
        credentials,
    })
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

    fn take_response(&mut self) -> Result<SessionResponse, Error> {
        let status = self.status.ok_or_else(|| {
            Error::exchange(
                ExchangeFailure::Protocol,
                Cause::Detail("curl response missing HTTP status line".to_owned()),
            )
        })?;
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
