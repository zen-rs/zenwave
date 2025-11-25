#![allow(unsafe_code)]
#![allow(unexpected_cfgs)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use std::{
    ffi::{CStr, CString},
    mem::replace,
    os::raw::c_char,
    ptr,
    sync::{Arc, Mutex, OnceLock},
};

use crate::ClientBackend;
use anyhow::{Error, anyhow};
use block::{Block, ConcreteBlock};
use futures_channel::oneshot;
use http::{
    HeaderMap,
    header::{HeaderName, HeaderValue},
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

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}

/// HTTP backend backed by Apple's `URLSession`.
pub struct AppleBackend {
    session: StrongPtr,
    _delegate: StrongPtr,
    _queue: StrongPtr,
    handle: SessionHandle,
}

#[derive(Debug, thiserror::Error)]
pub enum AppleError {
    #[error("bad request: {0}")]
    BadRequest(#[source] anyhow::Error),
    #[error("bad gateway: {0}")]
    BadGateway(#[source] anyhow::Error),
    #[error("remote error: {status}")]
    Remote {
        status: StatusCode,
        body: Option<String>,
        raw_response: Response,
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
    fn status(&self) -> Option<StatusCode> {
        Some(match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::Remote { status, .. } => *status,
        })
    }
}

#[derive(Clone, Copy)]
struct SessionHandle(*mut Object);

unsafe impl Send for SessionHandle {}
unsafe impl Sync for SessionHandle {}

impl SessionHandle {
    const fn as_ptr(self) -> *mut Object {
        self.0
    }
}

#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for AppleBackend {}
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Sync for AppleBackend {}

impl AppleBackend {
    /// Create a new backend backed by an ephemeral `URLSession`.
    #[must_use]
    pub fn new() -> Self {
        unsafe {
            let config: StrongPtr = StrongPtr::retain(msg_send![
                class!(NSURLSessionConfiguration),
                ephemeralSessionConfiguration
            ]);
            let nil: *mut Object = ptr::null_mut();
            let _: () = msg_send![*config, setURLCache: nil];
            let _: () = msg_send![*config, setHTTPCookieStorage: nil];
            let _: () = msg_send![*config, setHTTPCookieAcceptPolicy: 0isize];
            let _: () = msg_send![*config, setHTTPShouldSetCookies: NO];

            let delegate_class = session_delegate_class();
            let delegate = StrongPtr::new(msg_send![delegate_class, new]);
            let queue = StrongPtr::new(msg_send![class!(NSOperationQueue), new]);
            let _: () = msg_send![*queue, setMaxConcurrentOperationCount: 1isize];

            let session: *mut Object = msg_send![
                class!(NSURLSession),
                sessionWithConfiguration: *config
                delegate: *delegate
                delegateQueue: *queue
            ];

            Self {
                session: StrongPtr::retain(session),
                _delegate: delegate,
                _queue: queue,
                handle: SessionHandle(session),
            }
        }
    }
}

impl Default for AppleBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AppleBackend {
    fn drop(&mut self) {
        unsafe {
            let _: () = msg_send![*self.session, invalidateAndCancel];
        }
    }
}

impl Endpoint for AppleBackend {
    type Error = AppleError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let handle = self.handle;
        send_with_url_session(handle, request).await
    }
}

impl core::fmt::Debug for AppleBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppleBackend").finish()
    }
}

impl ClientBackend for AppleBackend {}

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
        handle,
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
            .map(|text| text.to_owned());
        return Err(AppleError::Remote {
            status,
            body,
            raw_response: http_response,
        });
    }

    Ok(http_response)
}

fn start_task(
    handle: SessionHandle,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    sender: CompletionSender,
) -> Result<(), AppleError> {
    autoreleasepool(|| unsafe {
        let session = handle.as_ptr();
        let request = build_request(method, url, headers, body)?;

        let completion = ConcreteBlock::new(
            move |data: *mut Object, response: *mut Object, error: *mut Object| {
                autoreleasepool(|| {
                    let result = handle_completion(data, response, error);
                    let tx = sender.lock().expect("mutex poisoned").take();
                    if let Some(tx) = tx {
                        let _ = tx.send(result);
                    }
                });
            },
        )
        .copy();

        let task: *mut Object =
            msg_send![session, dataTaskWithRequest: request completionHandler: &*completion];
        if task.is_null() {
            return Err(AppleError::bad_gateway(anyhow!(
                "Failed to create URLSession data task"
            )));
        }

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
) -> Result<SessionResponse, AppleError> {
    unsafe {
        if !error.is_null() {
            return Err(AppleError::bad_gateway(error_to_anyhow(error)));
        }

        if response.is_null() {
            return Err(AppleError::bad_gateway(anyhow!(
                "URLSession returned an empty response"
            )));
        }

        let http_response_class = class!(NSHTTPURLResponse);
        let is_http: BOOL = msg_send![response, isKindOfClass: http_response_class];
        if is_http != YES {
            return Err(AppleError::bad_gateway(anyhow!(
                "URLSession response is not HTTP"
            )));
        }

        let status_code: i64 = msg_send![response, statusCode];
        let status = u16::try_from(status_code).map_err(|e| AppleError::bad_gateway(anyhow!(e)))?;
        let status = StatusCode::from_u16(status).map_err(AppleError::bad_gateway)?;

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

unsafe fn error_to_anyhow(error: *mut Object) -> Error {
    let description: *mut Object = msg_send![error, localizedDescription];
    nsobject_to_string(description)
        .map_or_else(|| anyhow!("URLSession error"), |message| anyhow!(message))
}

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
