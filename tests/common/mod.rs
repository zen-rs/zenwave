//! Shared test utilities for running against a local httpbin-like server.
//!
//! The real httpbin/httpbingo services are flaky or rate-limited in CI, so we
//! run a lightweight local replacement that implements just the endpoints the
//! test suite needs. On wasm targets we fall back to the real service unless
//! `ZENWAVE_TEST_BASE_URL` is provided.

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
        fmt::Write as _,
        io::{Read as _, Write as _},
        net::{TcpListener, TcpStream},
        thread,
        time::Duration,
    };

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use once_cell::sync::OnceCell;
    use url::Url;

    /// A parsed request, everything the router needs of it.
    struct TestRequest {
        method: String,
        /// The raw request target: origin-form or absolute-form.
        target: String,
        headers: Vec<(String, String)>,
        /// `Connection: close`, or HTTP/1.0 without an explicit keep-alive.
        close: bool,
    }

    /// The response a route produces, serialized by [`serve_connection`].
    struct TestResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl TestResponse {
        fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
            self.headers.push((name.to_owned(), value.into()));
            self
        }
    }

    #[derive(Debug)]
    pub struct TestServer {
        base: String,
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
        fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("start test server");
            let base = format!("http://{}", listener.local_addr().expect("server address"));
            let thread = thread::spawn(move || run_server(&listener));

            Self {
                base,
                _thread: thread,
            }
        }
    }

    /// One thread per connection. A pooled client pins a reader for the
    /// connection's whole keep-alive lifetime, so dispatching connections
    /// through a bounded worker pool can strand a task; dedicating a thread
    /// per connection cannot.
    fn run_server(listener: &TcpListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || serve_connection(stream));
        }
    }

    fn serve_connection(mut stream: TcpStream) {
        // Bytes read past the head belong to the body or the next request.
        let mut pending = Vec::new();
        while let Some(request) = read_request(&mut stream, &mut pending) {
            let response = handle_request(&request);
            if write_response(&mut stream, &request, &response).is_err() || request.close {
                return;
            }
        }
    }

    /// Pull bytes from `stream` until `buffer` contains `needle`; returns the
    /// offset one past it.
    fn fill_until(stream: &mut TcpStream, buffer: &mut Vec<u8>, needle: &[u8]) -> Option<usize> {
        loop {
            if let Some(pos) = buffer
                .windows(needle.len())
                .position(|window| window == needle)
            {
                return Some(pos + needle.len());
            }
            let mut chunk = [0_u8; 8192];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    /// Consume exactly `n` bytes off `buffer` then `stream`.
    fn drain(stream: &mut TcpStream, buffer: &mut Vec<u8>, mut n: usize) -> Option<()> {
        while n > 0 {
            if buffer.is_empty() {
                let mut chunk = [0_u8; 8192];
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return None,
                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                }
            }
            let take = n.min(buffer.len());
            buffer.drain(..take);
            n -= take;
        }
        Some(())
    }

    /// Consume the next CRLF-terminated line off `buffer` then `stream`.
    fn read_line(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
        let end = fill_until(stream, buffer, b"\r\n")?;
        let line = buffer[..end - 2].to_vec();
        buffer.drain(..end);
        Some(line)
    }

    /// Read one request: head, then its body. `None` on EOF or a malformed
    /// request — the connection is closed either way.
    fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<TestRequest> {
        let head_len = fill_until(stream, buffer, b"\r\n\r\n")?;
        let (method, target, http10, headers) = {
            let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
            let mut parsed = httparse::Request::new(&mut parsed_headers);
            let Ok(httparse::Status::Complete(_)) = parsed.parse(&buffer[..head_len]) else {
                return None;
            };
            (
                parsed.method.unwrap_or_default().to_owned(),
                parsed.path.unwrap_or_default().to_owned(),
                parsed.version == Some(0),
                parsed
                    .headers
                    .iter()
                    .map(|header| {
                        (
                            header.name.to_owned(),
                            String::from_utf8_lossy(header.value).into_owned(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        buffer.drain(..head_len);
        let header = |name: &str| header_value(&headers, name);

        if header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").ok()?;
        }

        // Consume the body so the next request on this connection parses.
        if let Some(length) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            drain(stream, buffer, length)?;
        } else if header("transfer-encoding").is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        }) {
            loop {
                let size = usize::from_str_radix(
                    std::str::from_utf8(&read_line(stream, buffer)?)
                        .ok()?
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim(),
                    16,
                )
                .ok()?;
                if size == 0 {
                    // Trailers, through the blank line.
                    while !read_line(stream, buffer)?.is_empty() {}
                    break;
                }
                drain(stream, buffer, size + 2)?; // chunk data + CRLF
            }
        }

        let connection = header("connection").unwrap_or_default();
        let close = connection.eq_ignore_ascii_case("close")
            || (http10 && !connection.eq_ignore_ascii_case("keep-alive"));
        Some(TestRequest {
            method,
            target,
            headers,
            close,
        })
    }

    fn write_response(
        stream: &mut TcpStream,
        request: &TestRequest,
        response: &TestResponse,
    ) -> std::io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\n",
            response.status,
            reason_phrase(response.status)
        );
        for (name, value) in &response.headers {
            let _ = write!(head, "{name}: {value}\r\n");
        }
        // 1xx/204/304 carry no body; HEAD sends the headers only.
        let bodyless = matches!(response.status, 100..=199 | 204 | 304);
        if !bodyless {
            let _ = write!(head, "content-length: {}\r\n", response.body.len());
        }
        if request.close {
            head.push_str("connection: close\r\n");
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        if !bodyless && request.method != "HEAD" {
            stream.write_all(&response.body)?;
        }
        stream.flush()
    }

    const fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            418 => "I'm a Teapot",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Status",
        }
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
                body: Vec::new(),
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
            body: body.as_bytes().to_vec(),
        }
    }

    fn text_response(status: u16, body: impl Into<String>) -> TestResponse {
        TestResponse {
            status,
            headers: vec![(
                "Content-Type".to_owned(),
                "text/plain; charset=UTF-8".to_owned(),
            )],
            body: body.into().into_bytes(),
        }
    }

    fn bytes_response(status: u16, body: impl Into<Vec<u8>>) -> TestResponse {
        TestResponse {
            status,
            headers: vec![],
            body: body.into(),
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
