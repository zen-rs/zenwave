#![allow(missing_docs)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::{StreamExt as _, stream};
use serde_json::Value;
use zenwave::{
    Body, BodyError, BodyFrame, Client as _, ConnectFailure, Endpoint, Error, Method, Request,
    Response, ResponseExt, StatusCode, TimedOut, Transport, backend::WasiBackend, clock::Clocked,
    get, header,
};

wasip3::cli::command::export!(Smoke);

struct Smoke;

impl wasip3::exports::cli::run::Guest for Smoke {
    async fn run() -> Result<(), ()> {
        run_all().await;
        Ok(())
    }
}

fn base_url() -> String {
    std::env::var("ZENWAVE_TEST_BASE_URL")
        .expect("ZENWAVE_TEST_BASE_URL must be set")
        .trim_end_matches('/')
        .to_owned()
}

fn uri(path: &str) -> String {
    format!("{}/{}", base_url(), path.trim_start_matches('/'))
}

async fn run_all() {
    test_basic_get().await;
    test_post_json_cjk().await;
    test_streaming_request_and_response().await;
    test_response_trailers().await;
    test_request_trailers().await;
    test_host_header_normalization().await;
    test_middleware_chain().await;
    test_retry_over_wasi_clock().await;
    test_timeouts_and_connect_errors().await;
    test_invalid_inputs().await;
}

async fn test_basic_get() {
    let resp = get(uri("/get")).await.expect("GET /get succeeds");
    assert_eq!(resp.status(), StatusCode::OK);
    let json: Value = resp.into_body().into_json().await.expect("GET JSON parses");
    assert_eq!(json.get("origin").and_then(Value::as_str), Some("httpbin"));

    let resp = get(uri("/json")).await.expect("GET /json succeeds");
    assert_eq!(resp.status(), StatusCode::OK);
    let json: Value = resp.into_body().into_json().await.expect("/json parses");
    assert_eq!(
        json.pointer("/slideshow/author").and_then(Value::as_str),
        Some("zenwave")
    );
}

async fn test_post_json_cjk() {
    let mut client = zenwave::client();
    let payload = serde_json::json!({
        "greeting": "你好 こんにちは 안녕하세요",
        "backend": "wasip3",
    });

    let resp = client
        .post(uri("/post"))
        .expect("valid POST URI")
        .header("x-zenwave-test", "wasi-p3")
        .expect("valid header")
        .json_body(&payload)
        .expect("JSON encodes")
        .await
        .expect("POST /post succeeds");
    assert_eq!(resp.status(), StatusCode::OK);

    let echoed: Value = resp
        .into_body()
        .into_json()
        .await
        .expect("echo JSON parses");
    assert_eq!(echoed.get("json"), Some(&payload));
    assert_eq!(
        echoed
            .pointer("/headers/x-zenwave-test")
            .and_then(Value::as_str),
        Some("wasi-p3")
    );
}

async fn test_streaming_request_and_response() {
    let mut client = zenwave::client();
    let chunks = vec![
        Ok::<_, std::io::Error>(zenwave::utils::Bytes::from_static(b"chunk-one-")),
        Ok(zenwave::utils::Bytes::from_static(b"chunk-two-")),
        Ok(zenwave::utils::Bytes::from_static(b"chunk-three")),
    ];
    let resp = client
        .post(uri("/post"))
        .expect("valid POST URI")
        .header(header::CONTENT_TYPE, "text/plain")
        .expect("valid header")
        .stream_body(stream::iter(chunks))
        .await
        .expect("streaming POST succeeds");
    assert_eq!(resp.status(), StatusCode::OK);
    let echoed: Value = resp
        .into_body()
        .into_json()
        .await
        .expect("stream echo parses");
    assert_eq!(
        echoed.get("data").and_then(Value::as_str),
        Some("chunk-one-chunk-two-chunk-three")
    );

    let resp = get(uri("/stream")).await.expect("GET /stream succeeds");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp
        .into_body()
        .into_bytes()
        .await
        .expect("256 KiB stream reads");
    assert_eq!(bytes.len(), 256 * 1024);
    assert!(bytes.iter().all(|&b| b == 0xA5));
}

async fn test_response_trailers() {
    let mut client = zenwave::client();
    let resp = client
        .get(uri("/trailers"))
        .expect("valid URI")
        // RFC 9112 §7.1.2 / hyper HTTP/1.1 server: trailing fields are only emitted
        // on the wire when the request advertises `TE: trailers`.
        .header(header::TE, "trailers")
        .expect("valid TE header")
        .await
        .expect("GET /trailers succeeds");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut data = Vec::new();
    let mut trailers = None;
    let mut body = resp.into_body();
    while let Some(frame) = body.next().await {
        match frame.expect("frame succeeds") {
            BodyFrame::Data(chunk) => {
                assert!(trailers.is_none(), "no data after trailers");
                data.extend_from_slice(&chunk);
            }
            BodyFrame::Trailers(map) => {
                trailers = Some(map);
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    assert_eq!(data, b"trailing payload");
    let trailers = trailers.expect("response trailers arrive");
    assert_eq!(
        trailers
            .get("x-checksum")
            .and_then(|value| value.to_str().ok()),
        Some("sha256-ok")
    );
}

async fn test_request_trailers() {
    let mut trailer_map = header::HeaderMap::new();
    trailer_map.insert(
        "x-req-checksum",
        header::HeaderValue::from_static("req-sha256-ok"),
    );
    let body = Body::from_frames(stream::iter([
        Ok::<_, BodyError>(BodyFrame::Data(zenwave::utils::Bytes::from_static(
            b"body-with-trailer",
        ))),
        Ok(BodyFrame::Trailers(trailer_map)),
    ]));

    let mut req = Request::new(body);
    *req.method_mut() = Method::POST;
    *req.uri_mut() = uri("/post").parse().expect("valid URI");
    req.headers_mut().insert(
        header::TRAILER,
        header::HeaderValue::from_static("x-req-checksum"),
    );

    let mut client = zenwave::client();
    let resp = client
        .respond(&mut req)
        .await
        .expect("POST /post with request trailers succeeds");
    assert_eq!(resp.status(), StatusCode::OK);

    let echoed: Value = resp
        .into_body()
        .into_json()
        .await
        .expect("echo JSON parses");
    assert_eq!(
        echoed.get("data").and_then(Value::as_str),
        Some("body-with-trailer")
    );
    assert_eq!(
        echoed
            .pointer("/trailers/x-req-checksum")
            .and_then(Value::as_str),
        Some("req-sha256-ok")
    );
}

async fn test_host_header_normalization() {
    let target = uri("/get");
    let parsed: zenwave::Uri = target.parse().expect("valid URI");
    let authority = parsed.authority().expect("authority").as_str().to_owned();

    let mut client = zenwave::client();
    let resp = client
        .get(&target)
        .expect("valid URI")
        .header(header::HOST, &authority)
        .expect("valid Host header")
        .await
        .expect("matching Host header is normalized");
    assert_eq!(resp.status(), StatusCode::OK);

    let mismatch = client
        .get(&target)
        .expect("valid URI")
        .header(header::HOST, "wrong-host.example")
        .expect("valid Host header")
        .await
        .expect_err("mismatched Host header must fail");
    assert!(
        matches!(mismatch, Error::InvalidRequest(_)),
        "expected InvalidRequest, got: {mismatch}"
    );
}

async fn test_middleware_chain() {
    // FollowRedirect (default on zenwave::client())
    let resp = get(uri("/redirect/2"))
        .await
        .expect("redirect chain succeeds");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().into_string().await.expect("body reads"),
        "redirect complete"
    );

    // CookieStore + public-suffix
    let mut cookie_client = zenwave::client().enable_cookie();
    let set_resp = cookie_client
        .get(uri("/cookies/set/session/abc"))
        .expect("URI")
        .await
        .expect("set cookie succeeds");
    assert_eq!(set_resp.status(), StatusCode::OK);

    let ps_resp = cookie_client
        .get(uri("/cookies/set/pub/blocked?domain=co.uk"))
        .expect("URI")
        .await
        .expect("public-suffix cookie request succeeds");
    assert_eq!(ps_resp.status(), StatusCode::OK);

    let cookies_resp = cookie_client
        .get(uri("/cookies"))
        .expect("URI")
        .await
        .expect("GET /cookies succeeds");
    let cookie_text = cookies_resp
        .into_body()
        .into_string()
        .await
        .expect("cookies body");
    assert!(
        cookie_text.contains("session=abc"),
        "expected session=abc in `{cookie_text}`"
    );
    assert!(
        !cookie_text.contains("pub=blocked"),
        "public suffix cookie leaked in `{cookie_text}`"
    );

    // BearerAuth
    let mut auth_client = zenwave::client().bearer_auth("secret-token");
    let auth_resp = auth_client
        .get(uri("/bearer"))
        .expect("URI")
        .await
        .expect("bearer auth succeeds");
    assert_eq!(auth_resp.status(), StatusCode::OK);
    assert_eq!(
        auth_resp.into_body().into_string().await.expect("body"),
        "authorized"
    );

    // ErrorForStatus
    let raw_404 = get(uri("/status/404"))
        .await
        .expect("404 is Ok on default client");
    assert_eq!(raw_404.status(), StatusCode::NOT_FOUND);
    let err_404 = raw_404
        .error_for_status()
        .await
        .expect_err("ResponseExt::error_for_status turns 404 into Error::Http");
    assert!(matches!(
        err_404,
        Error::Http {
            status: StatusCode::NOT_FOUND,
            ..
        }
    ));

    let err_client = zenwave::client()
        .error_for_status()
        .get(uri("/status/404"))
        .expect("URI")
        .await
        .expect_err("ErrorForStatus middleware turns 404 into Error::Http");
    let err_client: Error = err_client.into();
    assert!(matches!(
        err_client,
        Error::Http {
            status: StatusCode::NOT_FOUND,
            ..
        }
    ));

    // Timeout middleware (driven by WasiClock)
    let timeout_err = zenwave::client()
        .timeout(Duration::from_millis(80))
        .get(uri("/delay-ms/500"))
        .expect("URI")
        .await
        .expect_err("Timeout middleware must fire");
    let timeout_err: Error = timeout_err.into();
    assert!(
        matches!(timeout_err, Error::Timeout(TimedOut::Request)),
        "expected TimedOut::Request, got: {timeout_err}"
    );
}

#[derive(Clone)]
struct FlakyOnce {
    attempts: Arc<AtomicUsize>,
    inner: WasiBackend,
}

impl Endpoint for FlakyOnce {
    type Error = Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(Error::Timeout(TimedOut::ResponseHead));
        }
        self.inner.respond(request).await
    }
}

zenwave::impl_send_endpoint!(FlakyOnce);

impl zenwave::Client for FlakyOnce {}

impl Clocked for FlakyOnce {
    type Clock = <WasiBackend as Clocked>::Clock;

    fn clock(&self) -> Self::Clock {
        self.inner.clock()
    }
}

async fn test_retry_over_wasi_clock() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut client = FlakyOnce {
        attempts: Arc::clone(&attempts),
        inner: WasiBackend::default(),
    }
    .retry(1);

    let resp = client
        .get(uri("/get"))
        .expect("URI")
        .await
        .expect("retry succeeds on second attempt");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

async fn test_timeouts_and_connect_errors() {
    // 1. response_head_timeout via Transport
    let head_transport = Transport::builder()
        .response_head_timeout(Duration::from_millis(80))
        .build()
        .expect("transport builds");
    let head_err = zenwave::client_with(head_transport)
        .get(uri("/delay-ms/500"))
        .expect("URI")
        .await
        .expect_err("response_head_timeout must fire");
    assert!(
        matches!(head_err, Error::Timeout(TimedOut::ResponseHead)),
        "expected TimedOut::ResponseHead, got: {head_err}"
    );

    // 2. per-request response_head_timeout override
    let req_head_err = zenwave::client()
        .get(uri("/delay-ms/500"))
        .expect("URI")
        .response_head_timeout(Duration::from_millis(80))
        .await
        .expect_err("per-request response_head_timeout must fire");
    assert!(
        matches!(req_head_err, Error::Timeout(TimedOut::ResponseHead)),
        "expected TimedOut::ResponseHead, got: {req_head_err}"
    );

    // 3. body_idle_timeout on /stream/stalled
    let idle_transport = Transport::builder()
        .body_idle_timeout(Duration::from_millis(80))
        .build()
        .expect("transport builds");
    let stalled_resp = zenwave::client_with(idle_transport)
        .get(uri("/stream/stalled"))
        .expect("URI")
        .await
        .expect("initial head arrives before stall");
    assert_eq!(stalled_resp.status(), StatusCode::OK);
    let body_err = stalled_resp
        .into_body()
        .into_bytes()
        .await
        .expect_err("stalled body must time out");
    let idle_err: Error = body_err.into();
    assert!(
        matches!(idle_err, Error::Timeout(TimedOut::BodyIdle)),
        "expected TimedOut::BodyIdle, got: {idle_err}"
    );

    // 4. Connection refused on closed port
    let closed_port = std::env::var("ZENWAVE_CLOSED_PORT").expect("ZENWAVE_CLOSED_PORT");
    let refused_err = get(format!("http://127.0.0.1:{closed_port}/get"))
        .await
        .expect_err("closed port must fail");
    assert!(
        matches!(
            &refused_err,
            Error::Connect(conn) if matches!(conn.failure, ConnectFailure::Tcp(_))
        ),
        "expected ConnectFailure::Tcp, got: {refused_err}"
    );
    assert!(refused_err.is_transient());
}

async fn test_invalid_inputs() {
    let ftp_err = get("ftp://example.com")
        .await
        .expect_err("non-HTTP scheme must fail");
    assert!(
        matches!(ftp_err, Error::InvalidUri(_)),
        "expected InvalidUri, got: {ftp_err}"
    );

    let mut client = zenwave::client();
    assert!(client.get("").is_err());

    let mut raw = WasiBackend::default();
    let mut req = Request::new(Body::empty());
    *req.uri_mut() = uri("/get").parse().expect("URI");
    req.headers_mut().insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_static("not-a-number"),
    );
    let cl_err = raw
        .respond(&mut req)
        .await
        .expect_err("invalid Content-Length must fail");
    assert!(matches!(cl_err, Error::InvalidRequest(_)));
}
