//! Shared test utilities for running against a local httpbin-like server.
//!
//! The real httpbin/httpbingo services are flaky or rate-limited in CI, so we
//! run a lightweight local replacement that implements just the endpoints the
//! test suite needs. On wasm targets we fall back to the real service unless
//! `ZENWAVE_TEST_BASE_URL` is provided.

// The production `futures-io` → `hyper::rt` adapter, shared with the test
// server rather than duplicated.
#[cfg(not(target_arch = "wasm32"))]
#[path = "../../src/transport/hyper_io.rs"]
mod hyper_io;

#[cfg(not(target_arch = "wasm32"))]
pub mod proxy;

/// A hostname for the TLS fixture that no resolver knows: only the test
/// proxies map it to the loopback server. Proxy tests reach the fixture
/// through this name because `CFNetwork` never proxies a literal loopback
/// address, and every backend must hand the name to the proxy unresolved.
#[allow(dead_code)]
pub const FIXTURE_HOST: &str = "zenwave-fixture.test";

/// Resolve a destination the way the test proxies do: the fixture hostname is
/// the loopback server, anything else goes to the system resolver.
#[allow(dead_code)]
pub fn resolve_for_proxy(host: &str, port: u16) -> (String, u16) {
    if host == FIXTURE_HOST {
        ("127.0.0.1".to_owned(), port)
    } else {
        (host.to_owned(), port)
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub mod socks5;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
mod local {
    use std::{
        convert::Infallible,
        fmt::Write as _,
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use async_io::Async;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use futures_util::{StreamExt as _, stream};
    use http_body_util::{BodyExt as _, Full, StreamBody, combinators::BoxBody};
    use hyper::{
        body::{Bytes, Frame, Incoming},
        service::service_fn,
    };
    use once_cell::sync::OnceCell;
    use url::Url;

    use super::hyper_io::HyperIo;

    /// A parsed request, everything the router needs of it.
    struct TestRequest {
        /// The request target, origin-form (`/path?query`).
        target: String,
        headers: Vec<(String, String)>,
    }

    /// The response a route produces; hyper serializes and frames it.
    struct TestResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: TestBody,
    }

    /// How a route's body reaches the wire.
    enum TestBody {
        /// The whole body, framed with `Content-Length`.
        Full(Vec<u8>),
        /// One chunk, then a body that never ends: the connection can only
        /// finish when the client abandons it, which is what a test of an
        /// abandoned body needs — the bytes it did not read cannot be
        /// drained, whatever the kernel and hyper buffer.
        Stalled(Vec<u8>),
    }

    impl From<TestBody> for BoxBody<Bytes, Infallible> {
        fn from(body: TestBody) -> Self {
            match body {
                TestBody::Full(bytes) => Self::new(Full::new(Bytes::from(bytes))),
                TestBody::Stalled(first) => Self::new(StreamBody::new(
                    stream::once(async move { Ok(Frame::data(Bytes::from(first))) })
                        .chain(stream::pending()),
                )),
            }
        }
    }

    impl TestResponse {
        fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
            self.headers.push((name.to_owned(), value.into()));
            self
        }
    }

    impl From<TestResponse> for hyper::Response<BoxBody<Bytes, Infallible>> {
        fn from(response: TestResponse) -> Self {
            let mut builder = hyper::Response::builder().status(response.status);
            for (name, value) in &response.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            builder
                .body(response.body.into())
                .expect("response must build")
        }
    }

    #[derive(Debug)]
    pub struct TestServer {
        base: String,
        /// Connections the accept loop has taken; a pooled client reusing a
        /// connection does not add to it.
        accepted: Arc<AtomicUsize>,
        // Keep the thread alive for the duration of the tests.
        _thread: thread::JoinHandle<()>,
    }

    /// Return the base URL for the local test server, falling back to an env var
    /// override so the tests can target another server if needed.
    pub fn httpbin_base() -> String {
        if let Ok(base) = std::env::var("ZENWAVE_TEST_BASE_URL") {
            return base.trim_end_matches('/').to_string();
        }
        test_server().base.clone()
    }

    /// Build a full URL against the local test server.
    pub fn httpbin_uri(path: &str) -> String {
        format!("{}/{}", httpbin_base(), path.trim_start_matches('/'))
    }

    pub fn test_server() -> &'static TestServer {
        static INSTANCE: OnceCell<TestServer> = OnceCell::new();
        INSTANCE.get_or_init(TestServer::start)
    }

    impl TestServer {
        /// A dedicated server instance: the shared `test_server()` is used by
        /// tests running in parallel, so accepts on it cannot be attributed
        /// to one test.
        pub fn standalone() -> Self {
            Self::start()
        }

        /// Build a full URL against this server instance.
        pub fn uri(&self, path: &str) -> String {
            format!("{}/{}", self.base, path.trim_start_matches('/'))
        }

        /// Connections accepted so far. Requests served on a pooled
        /// connection do not move it.
        pub fn accepted(&self) -> usize {
            self.accepted.load(Ordering::Relaxed)
        }

        fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("start test server");
            let base = format!("http://{}", listener.local_addr().expect("server address"));
            let accepted = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&accepted);
            let thread = thread::spawn(move || run_server(&listener, &counter));

            Self {
                base,
                accepted,
                _thread: thread,
            }
        }
    }

    /// One thread per connection. A pooled client keeps a connection open for
    /// its whole keep-alive lifetime, so dispatching connections through a
    /// bounded worker pool can strand a task; dedicating a thread per
    /// connection cannot.
    fn run_server(listener: &TcpListener, accepted: &AtomicUsize) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            accepted.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || {
                let io = HyperIo(Async::new(stream).expect("async socket wrapper"));
                let conn = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service_fn(route));
                let _ = async_io::block_on(conn);
            });
        }
    }

    /// Route one request: drain the body so the connection stays aligned for
    /// keep-alive reuse, then produce the response.
    async fn route(
        request: hyper::Request<Incoming>,
    ) -> Result<hyper::Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let (parts, body) = request.into_parts();
        let _ = body.collect().await;
        let request = TestRequest {
            target: parts
                .uri
                .path_and_query()
                .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
        };
        Ok(handle_request(&request).into())
    }

    fn handle_request(request: &TestRequest) -> TestResponse {
        // The request target only provides the path/query, so prefix with a
        // dummy scheme/host.
        let url = Url::parse(&format!("http://localhost{}", request.target)).unwrap();
        let mut path = url.path().to_string();
        // Some clients send absolute-form URLs; strip the leading host portion.
        if let Some(rest) = path.strip_prefix("//") {
            if let Some(pos) = rest.find('/') {
                path = rest[pos..].to_string();
            } else {
                path = "/".to_string();
            }
        }
        let query = url
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();

        match path.as_str() {
            "/bearer" => {
                if let Some(auth) = header_value(&request.headers, "authorization")
                    && auth.to_ascii_lowercase().starts_with("bearer ")
                {
                    return text_response(200, "authorized");
                }
                text_response(401, "unauthorized")
            }
            "/headers" => {
                let mut body = String::from("headers:\n");
                for (name, value) in &request.headers {
                    writeln!(&mut body, "{name}: {value}").unwrap();
                }
                if let Some(auth) = header_value(&request.headers, "authorization") {
                    writeln!(&mut body, "Authorization: {auth}").unwrap();
                }
                if let Some(custom) = header_value(&request.headers, "x-test") {
                    writeln!(&mut body, "X-Test: {custom}").unwrap();
                }
                text_response(200, body)
            }
            "/cookies" => {
                let cookie_header = header_value(&request.headers, "cookie").unwrap_or_default();
                text_response(200, format!("cookies: {cookie_header}"))
            }
            "/json" => json_response(
                200,
                r#"{"slideshow":{"title":"httpbin local","author":"zenwave"}}"#,
            ),
            "/user-agent" => {
                let ua = header_value(&request.headers, "user-agent")
                    .unwrap_or_else(|| "zenwave-test-agent".to_string());
                text_response(200, format!("user-agent: {ua}"))
            }
            "/get" => json_response(
                200,
                r#"{"url":"http://httpbin.local/get","origin":"httpbin"}"#,
            ),
            "/post" | "/put" | "/delete" | "/patch" => {
                json_response(200, r#"{"result":"ok","server":"httpbin-local"}"#)
            }
            "/gzip" => bytes_response(200, b"gzip response"),
            // A body that arrives in several reads.
            "/stream" => bytes_response(200, vec![0xA5; 256 * 1024]),
            // A body that never completes; see `TestBody::Stalled`.
            "/stream/stalled" => TestResponse {
                status: 200,
                headers: vec![],
                body: TestBody::Stalled(vec![0x5A; 16 * 1024]),
            },
            "/delay/1" => {
                // Small delay to emulate a slow endpoint.
                thread::sleep(Duration::from_millis(10));
                text_response(200, "delayed")
            }
            "/html" => text_response(200, "<html><body>not json</body></html>"),
            _ => {
                if let Some(stripped) = path.strip_prefix("/basic-auth/") {
                    return handle_basic_auth(request, stripped);
                }
                if let Some(stripped) = path.strip_prefix("/cookies/set/") {
                    return handle_set_cookie(stripped);
                }
                if let Some(stripped) = path.strip_prefix("/status/") {
                    return handle_status(stripped);
                }
                if let Some(stripped) = path.strip_prefix("/base64/") {
                    return handle_base64(stripped);
                }
                if path.starts_with("/redirect/") {
                    return handle_redirect(path.as_str());
                }
                if path == "/redirect-to" {
                    return handle_redirect_to(&query);
                }
                text_response(404, format!("no route for {path}"))
            }
        }
    }

    fn handle_basic_auth(request: &TestRequest, path: &str) -> TestResponse {
        let mut parts = path.split('/');
        let user = parts.next().unwrap_or_default();
        let pass = parts.next().unwrap_or_default();
        let expected = format!("Basic {}", BASE64.encode(format!("{user}:{pass}")));

        if let Some(auth) = header_value(&request.headers, "authorization")
            && auth == expected
        {
            return text_response(200, "authenticated");
        }
        text_response(401, "unauthorized")
    }

    fn handle_set_cookie(path: &str) -> TestResponse {
        let mut parts = path.split('/');
        let name = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        text_response(200, "cookie set").with_header("Set-Cookie", format!("{name}={value}"))
    }

    fn handle_status(code: &str) -> TestResponse {
        let status = code.parse::<u16>().unwrap_or(400);
        if status == 204 {
            return TestResponse {
                status,
                headers: vec![],
                body: TestBody::Full(Vec::new()),
            };
        }
        text_response(status, format!("status {status}"))
    }

    fn handle_base64(data: &str) -> TestResponse {
        BASE64.decode(data).map_or_else(
            |_| text_response(400, "invalid base64"),
            |bytes| bytes_response(200, bytes),
        )
    }

    fn handle_redirect(path: &str) -> TestResponse {
        let steps = path
            .trim_start_matches("/redirect/")
            .parse::<i32>()
            .unwrap_or(0);
        if steps <= 0 {
            return text_response(200, "redirect complete");
        }

        let next = format!("/redirect/{}", steps - 1);
        redirect_response(&next)
    }

    fn handle_redirect_to(query: &[(String, String)]) -> TestResponse {
        let target = query
            .iter()
            .find(|(key, _)| key == "url")
            .map_or("/", |(_, value)| value.as_str());
        redirect_response(target)
    }

    fn redirect_response(location: &str) -> TestResponse {
        text_response(302, "redirect").with_header("Location", location)
    }

    fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }

    fn json_response(status: u16, body: &str) -> TestResponse {
        TestResponse {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: TestBody::Full(body.as_bytes().to_vec()),
        }
    }

    fn text_response(status: u16, body: impl Into<String>) -> TestResponse {
        TestResponse {
            status,
            headers: vec![(
                "Content-Type".to_owned(),
                "text/plain; charset=UTF-8".to_owned(),
            )],
            body: TestBody::Full(body.into().into_bytes()),
        }
    }

    fn bytes_response(status: u16, body: impl Into<Vec<u8>>) -> TestResponse {
        TestResponse {
            status,
            headers: vec![],
            body: TestBody::Full(body.into()),
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod local {
    /// On wasm, use an override if provided, otherwise fall back to httpbingo.org which supports CORS.
    pub fn httpbin_base() -> String {
        if let Some(base) = option_env!("ZENWAVE_TEST_BASE_URL") {
            return base.trim_end_matches('/').to_string();
        }

        std::env::var("ZENWAVE_TEST_BASE_URL")
            .unwrap_or_else(|_| "https://httpbingo.org".to_string())
    }

    pub fn httpbin_uri(path: &str) -> String {
        format!("{}/{}", httpbin_base(), path.trim_start_matches('/'))
    }
}

#[allow(unused_imports)]
pub use local::*;
