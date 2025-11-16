#![allow(unsafe_code)]
#![allow(unexpected_cfgs)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use std::{
    ffi::{CStr, CString},
    mem::replace,
    os::raw::c_char,
    ptr,
    sync::{Arc, Mutex, Once},
};

use crate::ClientBackend;
use anyhow::{Error, anyhow};
use block::{Block, ConcreteBlock};
use futures_channel::oneshot;
use http::{
    HeaderMap,
    header::{HeaderName, HeaderValue},
};
use http_kit::{Body, Endpoint, Request, Response, Result, StatusCode};
use objc::{
    class,
    declare::ClassDecl,
    msg_send,
    rc::autoreleasepool,
    runtime::{BOOL, Class, Object, Sel, YES},
    sel, sel_impl,
};

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}

/// HTTP backend backed by Apple's `URLSession`.
#[derive(Debug)]
pub struct AppleBackend {
    _marker: (),
}

struct OwnedSession {
    session: *mut Object,
    delegate: *mut Object,
    queue: *mut Object,
}

unsafe impl Send for OwnedSession {}
unsafe impl Sync for OwnedSession {}

impl OwnedSession {
    unsafe fn new() -> Self {
        let config: *mut Object = msg_send![
            class!(NSURLSessionConfiguration),
            defaultSessionConfiguration
        ];
        let _: () = msg_send![config, setHTTPShouldSetCookies: false];
        let _: () = msg_send![config, setHTTPCookieStorage: ptr::null_mut::<Object>()];

        let delegate = create_delegate();
        let queue: *mut Object = msg_send![class!(NSOperationQueue), new];
        let _: () = msg_send![queue, setMaxConcurrentOperationCount: 1_isize];

        let session: *mut Object = msg_send![
            class!(NSURLSession),
            sessionWithConfiguration: config
            delegate: delegate
            delegateQueue: queue
        ];
        let _: () = msg_send![config, release];

        Self {
            session,
            delegate,
            queue,
        }
    }

    const fn session_ptr(&self) -> *mut Object {
        self.session
    }
}

impl Drop for OwnedSession {
    fn drop(&mut self) {
        unsafe {
            let _: () = msg_send![self.session, finishTasksAndInvalidate];
            let _: () = msg_send![self.session, release];
            let _: () = msg_send![self.delegate, release];
            let _: () = msg_send![self.queue, release];
        }
    }
}

unsafe impl Send for AppleBackend {}
unsafe impl Sync for AppleBackend {}

impl AppleBackend {
    /// Create a new backend backed by `[NSURLSession sharedSession]`.
    #[must_use]
    pub fn new() -> Self {
        Self { _marker: () }
    }
}

impl Default for AppleBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AppleBackend {
    fn drop(&mut self) {}
}

impl Endpoint for AppleBackend {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        let session = unsafe { OwnedSession::new() };
        send_with_url_session(&session, request).await
    }
}

impl ClientBackend for AppleBackend {}

#[derive(Debug)]
struct SessionResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

type CompletionSender = Arc<Mutex<Option<oneshot::Sender<Result<SessionResponse>>>>>;

async fn send_with_url_session(session: &OwnedSession, request: &mut Request) -> Result<Response> {
    let method = request.method().as_str().to_owned();
    let uri = request.uri().to_string();

    let mut collected_headers = Vec::new();
    for (name, value) in request.headers().iter() {
        let value_str = value
            .to_str()
            .map_err(|e| http_kit::Error::new(e, StatusCode::BAD_REQUEST))?;
        collected_headers.push((name.as_str().to_string(), value_str.to_string()));
    }

    let body_bytes = {
        let body = replace(request.body_mut(), Body::empty());
        body.into_bytes()
            .await
            .map_err(|e| http_kit::Error::new(e, StatusCode::BAD_REQUEST))?
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
        session,
        &method,
        &uri,
        &collected_headers,
        body.as_deref(),
        sender,
    )?;

    let response = rx.await.map_err(|_| {
        http_kit::Error::new(
            anyhow!("URLSession task cancelled"),
            StatusCode::BAD_GATEWAY,
        )
    })??;

    let mut http_response = http::Response::new(Body::from(response.body));
    *http_response.status_mut() = response.status;
    *http_response.headers_mut() = response.headers;

    Ok(http_response)
}

fn start_task(
    session: &OwnedSession,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    sender: CompletionSender,
) -> Result<()> {
    autoreleasepool(|| unsafe {
        let session_ptr = session.session_ptr();
        let request = build_request(method, url, headers, body)?;

        let completion = ConcreteBlock::new(
            move |data: *mut Object, response: *mut Object, error: *mut Object| {
                let result = handle_completion(data, response, error);
                if let Some(tx) = sender.lock().expect("mutex poisoned").take() {
                    let _ = tx.send(result);
                }
            },
        )
        .copy();

        let task: *mut Object =
            msg_send![session_ptr, dataTaskWithRequest: request completionHandler: &*completion];
        if task.is_null() {
            return Err(http_kit::Error::new(
                anyhow!("Failed to create URLSession data task"),
                StatusCode::BAD_GATEWAY,
            ));
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
) -> Result<*mut Object> {
    let ns_url = str_to_nsurl(url)?;
    let request: *mut Object = msg_send![class!(NSMutableURLRequest), requestWithURL: ns_url];
    if request.is_null() {
        return Err(http_kit::Error::new(
            anyhow!("Failed to create NSMutableURLRequest"),
            StatusCode::BAD_GATEWAY,
        ));
    }

    let method_string = str_to_nsstring(method)?;
    let _: () = msg_send![request, setHTTPMethod: method_string];

    for (name, value) in headers {
        let header_name = str_to_nsstring(name)?;
        let header_value = str_to_nsstring(value)?;
        let _: () = msg_send![request, setValue: header_value forHTTPHeaderField: header_name];
    }

    if let Some(body) = body {
        if !body.is_empty() {
            let data = bytes_to_nsdata(body);
            let _: () = msg_send![request, setHTTPBody: data];
        }
    }

    Ok(request)
}

fn handle_completion(
    data: *mut Object,
    response: *mut Object,
    error: *mut Object,
) -> Result<SessionResponse> {
    unsafe {
        if !error.is_null() {
            return Err(http_kit::Error::new(
                error_to_anyhow(error),
                StatusCode::BAD_GATEWAY,
            ));
        }

        if response.is_null() {
            return Err(http_kit::Error::new(
                anyhow!("URLSession returned an empty response"),
                StatusCode::BAD_GATEWAY,
            ));
        }

        let http_response_class = class!(NSHTTPURLResponse);
        let is_http: BOOL = msg_send![response, isKindOfClass: http_response_class];
        if is_http != YES {
            return Err(http_kit::Error::new(
                anyhow!("URLSession response is not HTTP"),
                StatusCode::BAD_GATEWAY,
            ));
        }

        let status_code: i64 = msg_send![response, statusCode];
        let status = StatusCode::from_u16(status_code as u16)
            .map_err(|e| http_kit::Error::new(e, StatusCode::BAD_GATEWAY))?;

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

unsafe fn str_to_nsurl(url: &str) -> Result<*mut Object> {
    let string = str_to_nsstring(url)?;
    let ns_url: *mut Object = msg_send![class!(NSURL), URLWithString: string];
    if ns_url.is_null() {
        Err(http_kit::Error::new(
            anyhow!("Invalid URL for URLSession"),
            StatusCode::BAD_REQUEST,
        ))
    } else {
        Ok(ns_url)
    }
}

unsafe fn str_to_nsstring(value: &str) -> Result<*mut Object> {
    let c_string =
        CString::new(value).map_err(|e| http_kit::Error::new(e, StatusCode::BAD_REQUEST))?;
    let ns_string: *mut Object =
        msg_send![class!(NSString), stringWithUTF8String: c_string.as_ptr()];
    if ns_string.is_null() {
        Err(http_kit::Error::new(
            anyhow!("Failed to create NSString"),
            StatusCode::BAD_REQUEST,
        ))
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
        {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&raw_value),
            ) {
                headers.append(header_name, header_value);
            }
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
    if let Some(message) = nsobject_to_string(description) {
        anyhow!(message)
    } else {
        anyhow!("URLSession error")
    }
}

fn create_delegate() -> *mut Object {
    static INIT: Once = Once::new();
    static mut DELEGATE: *mut Object = std::ptr::null_mut();
    INIT.call_once(|| unsafe {
        let cls = delegate_class();
        let delegate: *mut Object = msg_send![cls, new];
        let _: () = msg_send![delegate, retain];
        DELEGATE = delegate;
    });
    unsafe { DELEGATE }
}

fn delegate_class() -> *const Class {
    static INIT: Once = Once::new();
    static mut CLASS_PTR: *const Class = std::ptr::null();
    INIT.call_once(|| unsafe {
        let superclass = class!(NSObject);
        let mut decl =
            ClassDecl::new("ZenwaveURLSessionDelegate", superclass).expect("delegate creation");
        decl.add_method(
            sel!(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:),
            handle_redirect
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
        CLASS_PTR = decl.register();
    });

    unsafe { CLASS_PTR }
}

extern "C" fn handle_redirect(
    _this: &Object,
    _cmd: Sel,
    _session: *mut Object,
    _task: *mut Object,
    _response: *mut Object,
    request: *mut Object,
    completion_handler: *mut Object,
) {
    unsafe {
        if completion_handler.is_null() {
            return;
        }
        let block = &*(completion_handler as *mut Block<(*mut Object,), ()>);
        block.call((request,));
    }
}
