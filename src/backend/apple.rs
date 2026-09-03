//! `URLSession` backend.
//!
//! One `NSURLSession` per proxy decision. With [`Proxy::system`] a single
//! session lets the OS route every request (System Settings, PAC scripts
//! included). With explicit rules the transport's matcher decides per request
//! and each distinct outcome, direct or one proxy endpoint, gets its own
//! lazily built session whose `connectionProxyDictionary` pins that outcome.
//! Proxy credentials and extra root certificates are supplied through the
//! session delegate's authentication-challenge handler.
//!
//! [`Proxy::system`]: crate::Proxy::system
#![allow(unsafe_code)]
#![allow(unexpected_cfgs)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    fmt::Write as _,
    mem::replace,
    os::raw::c_char,
    ptr,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{Error, anyhow};
use block::{Block, ConcreteBlock};
use core_foundation::base::TCFType;
use futures_channel::oneshot;
use http::{
    HeaderMap, Uri,
    header::{HeaderName, HeaderValue, PROXY_AUTHORIZATION},
};
use http_kit::{Body, Endpoint, HttpError, Request, Response, StatusCode};
use objc::{
    class,
    declare::ClassDecl,
    msg_send,
    rc::{StrongPtr, autoreleasepool},
    runtime::{BOOL, Class, NO, Object, Sel, YES},
    sel, sel_impl,
};
use rustls_pki_types::CertificateDer;
use security_framework::{certificate::SecCertificate, trust::SecTrust};

use crate::{
    Client, Transport,
    error::{HttpErrorResponse, ProxyErrorKind},
    transport::proxy::{self, Intercept, Source},
};

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}

/// HTTP backend backed by Apple's `URLSession`.
pub struct AppleBackend {
    transport: Transport,
    sessions: HashMap<SessionKey, Session>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppleError {
    #[error("bad request: {0}")]
    BadRequest(#[source] anyhow::Error),
    #[error("bad gateway: {0}")]
    BadGateway(#[source] anyhow::Error),
    #[error("TLS failure: {0}")]
    Tls(#[source] anyhow::Error),
    #[error(transparent)]
    Proxy(#[from] ProxyErrorKind),
    #[error("remote error: {status}")]
    Remote {
        status: StatusCode,
        body: Option<String>,
        raw_response: Box<Response>,
    },
}

impl AppleError {
    fn bad_request(error: impl Into<anyhow::Error>) -> Self {
        Self::BadRequest(error.into())
    }

    fn bad_gateway(error: impl Into<anyhow::Error>) -> Self {
        Self::BadGateway(error.into())
    }
}

impl HttpError for AppleError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::Proxy(_) => StatusCode::BAD_REQUEST,
            Self::BadGateway(_) | Self::Tls(_) => StatusCode::BAD_GATEWAY,
            Self::Remote { status, .. } => *status,
        }
    }
}

impl From<AppleError> for crate::Error {
    fn from(err: AppleError) -> Self {
        match err {
            AppleError::BadRequest(e) => Self::InvalidRequest(e.to_string()),
            AppleError::BadGateway(e) => {
                let io_err = std::io::Error::other(e);
                Self::Transport(Box::new(io_err))
            }
            AppleError::Tls(e) => Self::tls(e),
            AppleError::Proxy(kind) => Self::Proxy(kind),
            AppleError::Remote {
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

/// A session plus the delegate state its tasks report through.
#[derive(Clone)]
struct SessionHandle {
    session: *mut Object,
    state: Arc<DelegateState>,
}

unsafe impl Send for SessionHandle {}
unsafe impl Sync for SessionHandle {}

impl SessionHandle {
    const fn as_ptr(&self) -> *mut Object {
        self.session
    }
}

#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for AppleBackend {}
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Sync for AppleBackend {}

impl AppleBackend {
    /// Create a backend that follows `transport` for proxy rules and trust.
    ///
    /// Sessions are opened lazily, on the first request that needs them.
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            sessions: HashMap::new(),
        }
    }

    /// The session whose proxy configuration matches `destination`, and the
    /// header the request itself must carry to get through.
    fn route_for(&mut self, destination: &Uri) -> Result<Route, AppleError> {
        let rules = self.transport.proxy();
        let key = match rules.source() {
            Source::System => SessionKey::System,
            Source::Explicit => rules
                .intercept(destination)
                .map_or(Ok(SessionKey::Direct), |intercept| {
                    ProxyEndpoint::new(&intercept).map(SessionKey::Proxied)
                })?,
        };
        let proxy_authorization = key.preemptive_authorization(destination);
        let session = if let Some(session) = self.sessions.get(&key) {
            session.handle()
        } else {
            let session = Session::open(&key, self.transport.extra_roots())?;
            let handle = session.handle();
            self.sessions.insert(key, session);
            handle
        };
        Ok(Route {
            session,
            proxy_authorization,
        })
    }
}

/// Where one request goes.
struct Route {
    session: SessionHandle,
    proxy_authorization: Option<HeaderValue>,
}

impl Default for AppleBackend {
    fn default() -> Self {
        Self::new(Transport::system())
    }
}

impl Endpoint for AppleBackend {
    type Error = crate::Error;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let route = self.route_for(request.uri())?;
        if let Some(authorization) = route.proxy_authorization {
            request
                .headers_mut()
                .insert(PROXY_AUTHORIZATION, authorization);
        }
        send_with_url_session(route.session, request)
            .await
            .map_err(Into::into)
    }
}

impl core::fmt::Debug for AppleBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppleBackend")
            .field("transport", &self.transport)
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl Client for AppleBackend {}

/// What a session is configured for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SessionKey {
    /// `Proxy::system()`: `URLSession` applies the OS configuration itself.
    System,
    /// Explicit rules with no match: connect directly.
    Direct,
    /// Explicit rules matched this proxy.
    Proxied(ProxyEndpoint),
}

impl SessionKey {
    /// Credentials answered to a proxy challenge (`CONNECT` tunnels).
    fn proxy_credentials(&self) -> Option<(String, String)> {
        match self {
            Self::Proxied(endpoint) => endpoint.credentials.clone(),
            Self::System | Self::Direct => None,
        }
    }

    /// `URLSession` treats a 407 to a plaintext request forwarded through an
    /// HTTP proxy as the final response instead of a challenge, so those
    /// requests carry `Proxy-Authorization` from the start, exactly as the
    /// hyper backend does.
    fn preemptive_authorization(&self, destination: &Uri) -> Option<HeaderValue> {
        match self {
            Self::Proxied(endpoint)
                if endpoint.scheme == ProxyScheme::Http
                    && destination.scheme_str() != Some("https") =>
            {
                endpoint.basic_auth.clone()
            }
            Self::Proxied(_) | Self::System | Self::Direct => None,
        }
    }
}

/// A proxy the matcher selected, in the terms `connectionProxyDictionary` uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProxyEndpoint {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    credentials: Option<(String, String)>,
    /// The `Basic` header value for HTTP proxies.
    basic_auth: Option<HeaderValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ProxyScheme {
    /// An HTTP proxy, used for plaintext destinations and as a `CONNECT`
    /// tunnel for TLS ones.
    Http,
    /// SOCKS5; `CFNetwork` decides where the hostname is resolved, so
    /// `socks5` and `socks5h` behave alike here.
    Socks,
}

impl ProxyEndpoint {
    fn new(intercept: &Intercept) -> Result<Self, AppleError> {
        let uri = intercept.uri();
        let scheme_name = uri.scheme_str().unwrap_or("http");
        let (scheme, default_port) = match scheme_name {
            "http" => (ProxyScheme::Http, 80),
            "socks5" | "socks5h" => (ProxyScheme::Socks, 1080),
            other => return Err(ProxyErrorKind::UnsupportedScheme(other.to_owned()).into()),
        };
        let host = uri.host().ok_or(ProxyErrorKind::MissingHost)?.to_owned();
        Ok(Self {
            scheme,
            host,
            port: uri.port_u16().unwrap_or(default_port),
            credentials: proxy::credentials(intercept),
            basic_auth: intercept.basic_auth().cloned(),
        })
    }

    /// The `connectionProxyDictionary` pinning this endpoint for every scheme.
    ///
    /// Keys are the string values of `kCFNetworkProxies*` from
    /// `CFProxySupport.h`; the HTTPS and SOCKS symbols are not exported on
    /// iOS although `CFNetwork` honours the keys there.
    unsafe fn dictionary(&self) -> Result<*mut Object, AppleError> {
        let dictionary: *mut Object = msg_send![class!(NSMutableDictionary), new];
        let entries: &[(&str, &str, &str)] = match self.scheme {
            ProxyScheme::Http => &[
                ("HTTPEnable", "HTTPProxy", "HTTPPort"),
                ("HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
            ],
            ProxyScheme::Socks => &[("SOCKSEnable", "SOCKSProxy", "SOCKSPort")],
        };
        for (enable, host, port) in entries {
            let yes: *mut Object = msg_send![class!(NSNumber), numberWithInteger: 1isize];
            let port_number: *mut Object =
                msg_send![class!(NSNumber), numberWithUnsignedShort: self.port];
            let _: () = msg_send![dictionary, setObject: yes forKey: str_to_nsstring(enable)?];
            let _: () = msg_send![
                dictionary,
                setObject: str_to_nsstring(&self.host)?
                forKey: str_to_nsstring(host)?
            ];
            let _: () =
                msg_send![dictionary, setObject: port_number forKey: str_to_nsstring(port)?];
        }
        // SOCKS never challenges: credentials travel in the dictionary, under
        // the `kCFStreamPropertySOCKSUser` / `kCFStreamPropertySOCKSPassword` keys.
        if self.scheme == ProxyScheme::Socks
            && let Some((user, password)) = &self.credentials
        {
            let _: () = msg_send![
                dictionary,
                setObject: str_to_nsstring(user)?
                forKey: str_to_nsstring("kCFStreamPropertySOCKSUser")?
            ];
            let _: () = msg_send![
                dictionary,
                setObject: str_to_nsstring(password)?
                forKey: str_to_nsstring("kCFStreamPropertySOCKSPassword")?
            ];
        }
        Ok(dictionary)
    }
}

/// One `NSURLSession` with its delegate and delegate queue.
struct Session {
    inner: StrongPtr,
    state: Arc<DelegateState>,
    _delegate: StrongPtr,
    _queue: StrongPtr,
}

impl Session {
    fn open(key: &SessionKey, extra_roots: &[CertificateDer<'static>]) -> Result<Self, AppleError> {
        let anchors = extra_roots
            .iter()
            .map(|der| SecCertificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppleError::Tls(error.into()))?;
        let state = Arc::new(DelegateState {
            proxy_credentials: key.proxy_credentials(),
            anchors,
            rejected_tunnels: Mutex::new(HashMap::new()),
        });

        autoreleasepool(|| unsafe {
            let config: StrongPtr = StrongPtr::retain(msg_send![
                class!(NSURLSessionConfiguration),
                ephemeralSessionConfiguration
            ]);
            let nil: *mut Object = ptr::null_mut();
            let _: () = msg_send![*config, setURLCache: nil];
            let _: () = msg_send![*config, setHTTPCookieStorage: nil];
            let _: () = msg_send![*config, setHTTPCookieAcceptPolicy: 0isize];
            let _: () = msg_send![*config, setHTTPShouldSetCookies: NO];
            match key {
                SessionKey::System => {}
                SessionKey::Direct => {
                    // An empty dictionary disables every proxy.
                    let empty: *mut Object = msg_send![class!(NSDictionary), dictionary];
                    let _: () = msg_send![*config, setConnectionProxyDictionary: empty];
                }
                SessionKey::Proxied(endpoint) => {
                    let dictionary = endpoint.dictionary()?;
                    let _: () = msg_send![*config, setConnectionProxyDictionary: dictionary];
                }
            }

            let delegate = StrongPtr::new(msg_send![session_delegate_class(), new]);
            (**delegate).set_ivar(
                STATE_IVAR,
                Arc::into_raw(Arc::clone(&state))
                    .cast::<c_void>()
                    .cast_mut(),
            );
            let queue = StrongPtr::new(msg_send![class!(NSOperationQueue), new]);
            let _: () = msg_send![*queue, setMaxConcurrentOperationCount: 1isize];

            let session: *mut Object = msg_send![
                class!(NSURLSession),
                sessionWithConfiguration: *config
                delegate: *delegate
                delegateQueue: *queue
            ];

            Ok(Self {
                inner: StrongPtr::retain(session),
                state,
                _delegate: delegate,
                _queue: queue,
            })
        })
    }

    fn handle(&self) -> SessionHandle {
        SessionHandle {
            session: *self.inner,
            state: Arc::clone(&self.state),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            let _: () = msg_send![*self.inner, invalidateAndCancel];
        }
    }
}

#[derive(Debug)]
struct SessionResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

type CompletionSender = Arc<Mutex<Option<oneshot::Sender<Result<SessionResponse, AppleError>>>>>;

async fn send_with_url_session(
    handle: SessionHandle,
    request: &mut Request,
) -> Result<Response, AppleError> {
    let method = request.method().as_str().to_owned();
    let uri = request.uri().to_string();

    let mut collected_headers = Vec::new();
    for (name, value) in request.headers() {
        let value_str = value.to_str().map_err(AppleError::bad_request)?;
        collected_headers.push((name.as_str().to_string(), value_str.to_string()));
    }

    let body_bytes = {
        let body = replace(request.body_mut(), Body::empty());
        body.into_bytes()
            .await
            .map_err(AppleError::bad_request)?
            .to_vec()
    };
    let body = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes)
    };

    let (tx, rx) = oneshot::channel();
    let sender = Arc::new(Mutex::new(Some(tx)));

    start_task(
        &handle,
        &method,
        &uri,
        &collected_headers,
        body.as_deref(),
        sender,
    )?;

    let response = rx
        .await
        .map_err(|_| AppleError::bad_gateway(anyhow!("URLSession task cancelled")))??;

    let SessionResponse {
        status,
        headers,
        body,
    } = response;

    let mut http_response = http::Response::new(Body::from(body));
    *http_response.status_mut() = status;
    *http_response.headers_mut() = headers;

    if status.is_client_error() || status.is_server_error() {
        let body = http_response
            .body_mut()
            .as_str()
            .await
            .ok()
            .map(std::borrow::ToOwned::to_owned);
        return Err(AppleError::Remote {
            status,
            body,
            raw_response: Box::new(http_response),
        });
    }

    Ok(http_response)
}

fn start_task(
    handle: &SessionHandle,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    sender: CompletionSender,
) -> Result<(), AppleError> {
    autoreleasepool(|| unsafe {
        let session = handle.as_ptr();
        let request = build_request(method, url, headers, body)?;

        // The block exists before the task does; the identifier is filled in
        // below, before `resume`, so the completion always finds it.
        let task_id = Arc::new(OnceLock::new());
        let completion = ConcreteBlock::new({
            let task_id = Arc::clone(&task_id);
            let state = Arc::clone(&handle.state);
            move |data: *mut Object, response: *mut Object, error: *mut Object| {
                autoreleasepool(|| {
                    let id = *task_id
                        .get()
                        .expect("task identifier recorded before resume");
                    let result = handle_completion(data, response, error, &state, id);
                    let tx = sender.lock().expect("mutex poisoned").take();
                    if let Some(tx) = tx {
                        let _ = tx.send(result);
                    }
                });
            }
        })
        .copy();

        let task: *mut Object =
            msg_send![session, dataTaskWithRequest: request completionHandler: &*completion];
        if task.is_null() {
            return Err(AppleError::bad_gateway(anyhow!(
                "Failed to create URLSession data task"
            )));
        }
        let id: usize = msg_send![task, taskIdentifier];
        task_id
            .set(id)
            .expect("task identifier is recorded exactly once");

        let _: () = msg_send![task, resume];
        Ok(())
    })
}

unsafe fn build_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<*mut Object, AppleError> {
    let ns_url = str_to_nsurl(url)?;
    let request: *mut Object = msg_send![class!(NSMutableURLRequest), requestWithURL: ns_url];
    if request.is_null() {
        return Err(AppleError::bad_gateway(anyhow!(
            "Failed to create NSMutableURLRequest"
        )));
    }

    let method_string = str_to_nsstring(method)?;
    let _: () = msg_send![request, setHTTPMethod: method_string];

    for (name, value) in headers {
        let header_name = str_to_nsstring(name)?;
        let header_value = str_to_nsstring(value)?;
        let _: () = msg_send![request, setValue: header_value forHTTPHeaderField: header_name];
    }

    if let Some(body) = body
        && !body.is_empty()
    {
        let data = bytes_to_nsdata(body);
        let _: () = msg_send![request, setHTTPBody: data];
    }
    let _: () = msg_send![request, setHTTPShouldHandleCookies: NO];

    Ok(request)
}

fn handle_completion(
    data: *mut Object,
    response: *mut Object,
    error: *mut Object,
    state: &DelegateState,
    task_id: usize,
) -> Result<SessionResponse, AppleError> {
    unsafe {
        if !error.is_null() {
            return Err(classify_nserror(error, state, task_id));
        }

        if response.is_null() {
            return Err(AppleError::bad_gateway(anyhow!(
                "URLSession returned an empty response"
            )));
        }

        let status = http_status(response)?
            .ok_or_else(|| AppleError::bad_gateway(anyhow!("URLSession response is not HTTP")))?;

        let headers = headers_from_response(response);

        let body = if data.is_null() {
            Vec::new()
        } else {
            nsdata_to_vec(data)
        };

        Ok(SessionResponse {
            status,
            headers,
            body,
        })
    }
}

/// The status of an `NSURLResponse`, `None` when it is not an HTTP response.
unsafe fn http_status(response: *mut Object) -> Result<Option<StatusCode>, AppleError> {
    if response.is_null() {
        return Ok(None);
    }
    let is_http: BOOL = msg_send![response, isKindOfClass: class!(NSHTTPURLResponse)];
    if is_http != YES {
        return Ok(None);
    }
    let status_code: i64 = msg_send![response, statusCode];
    let status = u16::try_from(status_code).map_err(|e| AppleError::bad_gateway(anyhow!(e)))?;
    StatusCode::from_u16(status)
        .map(Some)
        .map_err(AppleError::bad_gateway)
}

/// `NSURLErrorDomain` codes for TLS handshake and certificate failures
/// (`NSURLErrorSecureConnectionFailed` through `NSURLErrorClientCertificateRequired`).
const NSURL_TLS_ERROR_CODES: std::ops::RangeInclusive<isize> = -1206..=-1200;
/// `NSURLErrorCancelled`: what a task reports after the delegate cancelled
/// its authentication challenge.
const NSURL_ERROR_CANCELLED: isize = -999;

/// Sort an `NSError` into zenwave's taxonomy: a cancellation the delegate
/// caused by refusing a proxy challenge is that proxy's rejection, certificate
/// and handshake failures are TLS errors, everything else is transport.
unsafe fn classify_nserror(
    error: *mut Object,
    state: &DelegateState,
    task_id: usize,
) -> AppleError {
    let domain: *mut Object = msg_send![error, domain];
    let code: isize = msg_send![error, code];
    let domain = nsobject_to_string(domain).unwrap_or_default();
    let message = error_to_anyhow(error);
    if domain != "NSURLErrorDomain" {
        return AppleError::bad_gateway(message.context(format!("{domain} {code}")));
    }
    if code == NSURL_ERROR_CANCELLED
        && let Some(status) = state.take_rejected_tunnel(task_id)
    {
        return AppleError::Proxy(ProxyErrorKind::TunnelRejected(status));
    }
    if NSURL_TLS_ERROR_CODES.contains(&code) {
        AppleError::Tls(message)
    } else {
        AppleError::bad_gateway(message.context(format!("{domain} {code}")))
    }
}

unsafe fn str_to_nsurl(url: &str) -> Result<*mut Object, AppleError> {
    let string = str_to_nsstring(url)?;
    let ns_url: *mut Object = msg_send![class!(NSURL), URLWithString: string];
    if ns_url.is_null() {
        Err(AppleError::bad_request(anyhow!(
            "Invalid URL for URLSession"
        )))
    } else {
        Ok(ns_url)
    }
}

unsafe fn str_to_nsstring(value: &str) -> Result<*mut Object, AppleError> {
    let c_string = CString::new(value).map_err(AppleError::bad_request)?;
    let ns_string: *mut Object =
        msg_send![class!(NSString), stringWithUTF8String: c_string.as_ptr()];
    if ns_string.is_null() {
        Err(AppleError::bad_request(anyhow!(
            "Failed to create NSString"
        )))
    } else {
        Ok(ns_string)
    }
}

unsafe fn bytes_to_nsdata(bytes: &[u8]) -> *mut Object {
    msg_send![
        class!(NSData),
        dataWithBytes: bytes.as_ptr().cast::<c_void>()
        length: bytes.len()
    ]
}

unsafe fn headers_from_response(response: *mut Object) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let dictionary: *mut Object = msg_send![response, allHeaderFields];
    if dictionary.is_null() {
        return headers;
    }

    let enumerator: *mut Object = msg_send![dictionary, keyEnumerator];
    loop {
        let key: *mut Object = msg_send![enumerator, nextObject];
        if key.is_null() {
            break;
        }
        let value: *mut Object = msg_send![dictionary, objectForKey: key];
        if let (Some(name), Some(raw_value)) = (nsobject_to_string(key), nsobject_to_string(value))
            && let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&raw_value),
            )
        {
            headers.append(header_name, header_value);
        }
    }

    headers
}

unsafe fn nsdata_to_vec(data: *mut Object) -> Vec<u8> {
    let length: usize = msg_send![data, length];
    let bytes: *const c_void = msg_send![data, bytes];
    if bytes.is_null() || length == 0 {
        Vec::new()
    } else {
        let slice = core::slice::from_raw_parts(bytes.cast::<u8>(), length);
        slice.to_vec()
    }
}

unsafe fn nsobject_to_string(obj: *mut Object) -> Option<String> {
    if obj.is_null() {
        return None;
    }

    let can_utf8: BOOL = msg_send![obj, respondsToSelector: sel!(UTF8String)];
    let description: *mut Object = if can_utf8 == YES {
        obj
    } else {
        msg_send![obj, description]
    };

    let c_str: *const c_char = msg_send![description, UTF8String];
    if c_str.is_null() {
        return None;
    }
    let c_str = CStr::from_ptr(c_str);
    Some(c_str.to_string_lossy().into_owned())
}

/// The error's description, followed by the chain of underlying errors with
/// their domains and codes, so a TLS or proxy failure names its real cause.
unsafe fn error_to_anyhow(error: *mut Object) -> Error {
    let description: *mut Object = msg_send![error, localizedDescription];
    let mut message =
        nsobject_to_string(description).unwrap_or_else(|| "URLSession error".to_owned());
    let mut current = error;
    loop {
        let user_info: *mut Object = msg_send![current, userInfo];
        if user_info.is_null() {
            break;
        }
        let Ok(key) = str_to_nsstring("NSUnderlyingError") else {
            break;
        };
        let underlying: *mut Object = msg_send![user_info, objectForKey: key];
        if underlying.is_null() {
            break;
        }
        let domain: *mut Object = msg_send![underlying, domain];
        let code: isize = msg_send![underlying, code];
        let detail: *mut Object = msg_send![underlying, localizedDescription];
        let _ = write!(
            message,
            " (caused by {} {code}: {})",
            nsobject_to_string(domain).unwrap_or_default(),
            nsobject_to_string(detail).unwrap_or_default()
        );
        current = underlying;
    }
    anyhow!(message)
}

/// What the delegate needs to answer authentication challenges.
struct DelegateState {
    /// Sent once when the proxy asks for them; a second challenge means they
    /// were refused and the task is failed.
    proxy_credentials: Option<(String, String)>,
    /// Trusted in addition to the system anchors.
    anchors: Vec<SecCertificate>,
    /// Proxy verdicts for tasks whose challenge the delegate cancelled, by
    /// task identifier, until the completion handler collects them.
    rejected_tunnels: Mutex<HashMap<usize, StatusCode>>,
}

impl DelegateState {
    fn record_rejected_tunnel(&self, task_id: usize, status: StatusCode) {
        self.rejected_tunnels
            .lock()
            .expect("rejected tunnels")
            .insert(task_id, status);
    }

    fn take_rejected_tunnel(&self, task_id: usize) -> Option<StatusCode> {
        self.rejected_tunnels
            .lock()
            .expect("rejected tunnels")
            .remove(&task_id)
    }
}

/// Instance variable holding an `Arc<DelegateState>` raw pointer.
const STATE_IVAR: &str = "zenwaveState";

/// `NSURLSessionAuthChallengeDisposition`.
const USE_CREDENTIAL: isize = 0;
const PERFORM_DEFAULT_HANDLING: isize = 1;
const CANCEL_AUTHENTICATION_CHALLENGE: isize = 2;

/// `NSURLCredentialPersistenceNone`.
const PERSISTENCE_NONE: isize = 0;

fn session_delegate_class() -> *const Class {
    #[derive(Clone, Copy)]
    struct ClassHandle(*const Class);

    unsafe impl Send for ClassHandle {}
    unsafe impl Sync for ClassHandle {}

    static CLASS: OnceLock<ClassHandle> = OnceLock::new();
    CLASS
        .get_or_init(|| unsafe {
            let superclass = class!(NSObject);
            let mut decl = ClassDecl::new("ZenwaveURLSessionDelegate", superclass)
                .expect("failed to declare delegate class");
            decl.add_ivar::<*mut c_void>(STATE_IVAR);
            decl.add_method(
                sel!(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:),
                redirect_handler
                    as extern "C" fn(
                        &Object,
                        Sel,
                        *mut Object,
                        *mut Object,
                        *mut Object,
                        *mut Object,
                        *mut Object,
                    ),
            );
            decl.add_method(
                sel!(URLSession:task:didReceiveChallenge:completionHandler:),
                challenge_handler
                    as extern "C" fn(
                        &Object,
                        Sel,
                        *mut Object,
                        *mut Object,
                        *mut Object,
                        *mut Object,
                    ),
            );
            decl.add_method(sel!(dealloc), dealloc as extern "C" fn(&Object, Sel));
            ClassHandle(decl.register())
        })
        .0
}

extern "C" fn redirect_handler(
    _this: &Object,
    _cmd: Sel,
    _session: *mut Object,
    _task: *mut Object,
    _response: *mut Object,
    _new_request: *mut Object,
    completion_handler: *mut Object,
) {
    unsafe {
        if completion_handler.is_null() {
            return;
        }
        let handler = &*completion_handler.cast::<Block<(*mut Object,), ()>>();
        handler.call((ptr::null_mut(),));
    }
}

extern "C" fn challenge_handler(
    this: &Object,
    _cmd: Sel,
    _session: *mut Object,
    task: *mut Object,
    challenge: *mut Object,
    completion_handler: *mut Object,
) {
    unsafe {
        if completion_handler.is_null() {
            return;
        }
        let handler = &*completion_handler.cast::<Block<(isize, *mut Object), ()>>();
        let state: *mut c_void = *this.get_ivar(STATE_IVAR);
        // The credential is autoreleased, so the handler runs inside the pool.
        autoreleasepool(|| {
            let (disposition, credential) = state
                .cast::<DelegateState>()
                .as_ref()
                .map_or((PERFORM_DEFAULT_HANDLING, ptr::null_mut()), |state| {
                    answer_challenge(state, task, challenge)
                });
            handler.call((disposition, credential));
        });
    }
}

/// Decide a challenge: extra anchors for server trust, stored credentials for
/// the proxy, the system's own handling for everything else.
unsafe fn answer_challenge(
    state: &DelegateState,
    task: *mut Object,
    challenge: *mut Object,
) -> (isize, *mut Object) {
    let space: *mut Object = msg_send![challenge, protectionSpace];
    let method: *mut Object = msg_send![space, authenticationMethod];
    if nsobject_to_string(method).as_deref() == Some("NSURLAuthenticationMethodServerTrust") {
        if state.anchors.is_empty() {
            return (PERFORM_DEFAULT_HANDLING, ptr::null_mut());
        }
        let trust_ref: *mut c_void = msg_send![space, serverTrust];
        if trust_ref.is_null() {
            return (PERFORM_DEFAULT_HANDLING, ptr::null_mut());
        }
        let mut trust = SecTrust::wrap_under_get_rule(trust_ref.cast());
        let accepted = trust.set_anchor_certificates(&state.anchors).is_ok()
            && trust.set_trust_anchor_certificates_only(false).is_ok()
            && trust.evaluate_with_error().is_ok();
        if accepted {
            let credential: *mut Object =
                msg_send![class!(NSURLCredential), credentialForTrust: trust_ref];
            return (USE_CREDENTIAL, credential);
        }
        // Not trusted with the extra anchors either: let the system evaluate
        // and fail the task with its own, precise certificate error.
        return (PERFORM_DEFAULT_HANDLING, ptr::null_mut());
    }

    let is_proxy: BOOL = msg_send![space, isProxy];
    if is_proxy == YES {
        let previous_failures: isize = msg_send![challenge, previousFailureCount];
        if previous_failures == 0
            && let Some((user, password)) = &state.proxy_credentials
            && let (Ok(user), Ok(password)) = (str_to_nsstring(user), str_to_nsstring(password))
        {
            let credential: *mut Object = msg_send![
                class!(NSURLCredential),
                credentialWithUser: user
                password: password
                persistence: PERSISTENCE_NONE
            ];
            return (USE_CREDENTIAL, credential);
        }
        // Nothing (more) to offer. Default handling would keep the task alive
        // until its timeout, so cancel now and keep the proxy's verdict for
        // the completion handler.
        let failure: *mut Object = msg_send![challenge, failureResponse];
        let status = http_status(failure)
            .ok()
            .flatten()
            .unwrap_or(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        let task_id: usize = msg_send![task, taskIdentifier];
        state.record_rejected_tunnel(task_id, status);
        return (CANCEL_AUTHENTICATION_CHALLENGE, ptr::null_mut());
    }
    (PERFORM_DEFAULT_HANDLING, ptr::null_mut())
}

extern "C" fn dealloc(this: &Object, _cmd: Sel) {
    unsafe {
        let state: *mut c_void = *this.get_ivar(STATE_IVAR);
        if !state.is_null() {
            drop(Arc::from_raw(state.cast_const().cast::<DelegateState>()));
        }
        let _: () = msg_send![super(this, class!(NSObject)), dealloc];
    }
}

#[cfg(test)]
mod tests {
    use super::AppleBackend;
    use crate::{Proxy, Transport};

    #[test]
    fn one_session_per_proxy_decision() {
        let rules = Proxy::builder()
            .all("http://127.0.0.1:1")
            .no_proxy("localhost")
            .build();
        let transport = Transport::builder()
            .proxy(rules)
            .build()
            .expect("transport builds");
        let mut backend = AppleBackend::new(transport);

        let proxied = |path: &str| format!("https://github.com/zen-rs/{path}").parse().unwrap();
        let first = backend.route_for(&proxied("zenwave")).unwrap().session;
        let second = backend.route_for(&proxied("http-kit")).unwrap().session;
        assert_eq!(first.as_ptr(), second.as_ptr(), "same proxy, same session");

        let direct = backend
            .route_for(&"http://localhost:8080/".parse().unwrap())
            .unwrap()
            .session;
        assert_ne!(
            first.as_ptr(),
            direct.as_ptr(),
            "direct traffic gets its own session"
        );
        assert_eq!(backend.sessions.len(), 2);
    }

    #[test]
    fn system_rules_share_one_session() {
        let mut backend = AppleBackend::default();
        let a = backend
            .route_for(&"https://github.com/".parse().unwrap())
            .unwrap()
            .session;
        let b = backend
            .route_for(&"http://localhost:8080/".parse().unwrap())
            .unwrap()
            .session;
        assert_eq!(a.as_ptr(), b.as_ptr());
        assert_eq!(backend.sessions.len(), 1);
    }

    #[test]
    fn plaintext_requests_through_an_http_proxy_carry_credentials() {
        let rules = Proxy::builder()
            .all("http://alice:s3cret@127.0.0.1:1")
            .build();
        let transport = Transport::builder()
            .proxy(rules)
            .build()
            .expect("transport builds");
        let mut backend = AppleBackend::new(transport);

        let plaintext = backend
            .route_for(&"http://github.com/".parse().unwrap())
            .unwrap();
        assert_eq!(
            plaintext
                .proxy_authorization
                .as_ref()
                .and_then(|value| value.to_str().ok()),
            Some("Basic YWxpY2U6czNjcmV0")
        );
        let tunnelled = backend
            .route_for(&"https://github.com/".parse().unwrap())
            .unwrap();
        assert!(
            tunnelled.proxy_authorization.is_none(),
            "CONNECT is authenticated by the delegate"
        );
    }
}
