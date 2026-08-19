//! Shared test utilities for running against a local httpbin-like server.
//!
//! The real httpbin/httpbingo services are flaky or rate-limited in CI, so we
//! run a lightweight local replacement that implements just the endpoints the
//! test suite needs. On wasm targets we fall back to the real service unless
//! `ZENWAVE_TEST_BASE_URL` is provided.

#[cfg(not(target_arch = "wasm32"))]
mod local {
    use std::{fmt::Write, io::Cursor, sync::OnceLock, thread, time::Duration};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use tiny_http::{Header, ListenAddr, Request, Response, Server, StatusCode};
    use url::Url;

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
        static INSTANCE: OnceLock<TestServer> = OnceLock::new();
        INSTANCE.get_or_init(TestServer::start)
    }

    impl TestServer {
        fn start() -> Self {
            let server = Server::http("127.0.0.1:0").expect("start test server");
            let addr: ListenAddr = server.server_addr();
            let base = format!("http://{addr}");
            let thread = thread::spawn(move || run_server(&server));

            Self {
                base,
                _thread: thread,
            }
        }
    }

    fn run_server(server: &Server) {
        for mut request in server.incoming_requests() {
            let response = handle_request(&mut request);
            let _ = request.respond(response);
        }
    }

    /// Read the whole request body, which the echo routes reflect back.
    fn read_body(request: &mut Request) -> Vec<u8> {
        let mut body = Vec::new();
        let _ = request.as_reader().read_to_end(&mut body);
        body
    }

    #[allow(clippy::too_many_lines)] // A flat router reads better than nested dispatch.
    fn handle_request(request: &mut Request) -> Response<Cursor<Vec<u8>>> {
        // tiny_http only provides the path/query, so prefix with a dummy scheme/host.
        let url = Url::parse(&format!("http://localhost{}", request.url())).unwrap();
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
                if let Some(auth) = header_value(request, "authorization")
                    && auth.to_ascii_lowercase().starts_with("bearer ")
                {
                    return text_response(StatusCode(200), "authorized");
                }
                text_response(StatusCode(401), "unauthorized")
            }
            "/headers" => {
                let mut body = String::from("headers:\n");
                for header in request.headers() {
                    let name = header.field.to_string();
                    let value = String::from_utf8_lossy(header.value.as_ref());
                    writeln!(&mut body, "{name}: {value}").unwrap();
                }
                if let Some(auth) = header_value(request, "authorization") {
                    writeln!(&mut body, "Authorization: {auth}").unwrap();
                }
                if let Some(custom) = header_value(request, "x-test") {
                    writeln!(&mut body, "X-Test: {custom}").unwrap();
                }
                text_response(StatusCode(200), body)
            }
            "/cookies" => {
                let cookie_header = header_value(request, "cookie").unwrap_or_default();
                text_response(StatusCode(200), format!("cookies: {cookie_header}"))
            }
            "/json" => json_response(
                StatusCode(200),
                r#"{"slideshow":{"title":"httpbin local","author":"zenwave"}}"#,
            ),
            "/user-agent" => {
                let ua = header_value(request, "user-agent")
                    .unwrap_or_else(|| "zenwave-test-agent".to_string());
                text_response(StatusCode(200), format!("user-agent: {ua}"))
            }
            "/get" => json_response(
                StatusCode(200),
                r#"{"url":"http://httpbin.local/get","origin":"httpbin"}"#,
            ),
            "/post" | "/put" | "/delete" | "/patch" => json_response(
                StatusCode(200),
                r#"{"result":"ok","server":"httpbin-local"}"#,
            ),
            // Reflects the method, headers of interest, and body so tests can
            // assert on what was actually sent.
            "/echo" => {
                let method = request.method().as_str().to_string();
                let content_type = header_value(request, "content-type").unwrap_or_default();
                let query = url.query().unwrap_or_default().to_string();
                let body = read_body(request);
                let mut payload =
                    format!("method={method}\ncontent-type={content_type}\nquery={query}\nbody=");
                payload.push_str(&String::from_utf8_lossy(&body));
                text_response(StatusCode(200), payload)
            }
            "/delay/1" => {
                // Small delay to emulate a slow endpoint.
                thread::sleep(Duration::from_millis(10));
                text_response(StatusCode(200), "delayed")
            }
            "/html" => text_response(StatusCode(200), "<html><body>not json</body></html>"),
            // A structured error body, for `Error::deserialize_http_error`.
            "/error-json" => json_response(
                StatusCode(422),
                r#"{"code":"invalid_field","message":"name is required"}"#,
            ),
            // Fixed-size payload for streaming and limit tests.
            "/bytes/4096" => bytes_response(StatusCode(200), vec![0xAB_u8; 4096]),
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
                // Method- and body-preserving redirects (307/308).
                if let Some(code) = path.strip_prefix("/redirect-keep/") {
                    let status = code.parse::<u16>().unwrap_or(307);
                    let location = Header::from_bytes("Location", "/echo").unwrap();
                    return text_response(StatusCode(status), "keep-method redirect")
                        .with_header(location);
                }
                // Fails with a connection-less 503 the first N times, then succeeds.
                if let Some(count) = path.strip_prefix("/flaky/") {
                    return handle_flaky(count);
                }
                if path == "/redirect-to" {
                    return handle_redirect_to(&query);
                }
                text_response(StatusCode(404), format!("no route for {path}"))
            }
        }
    }

    fn handle_basic_auth(request: &Request, path: &str) -> Response<Cursor<Vec<u8>>> {
        let mut parts = path.split('/');
        let user = parts.next().unwrap_or_default();
        let pass = parts.next().unwrap_or_default();
        let expected = format!("Basic {}", BASE64.encode(format!("{user}:{pass}")));

        if let Some(auth) = header_value(request, "authorization")
            && auth == expected
        {
            return text_response(StatusCode(200), "authenticated");
        }
        text_response(StatusCode(401), "unauthorized")
    }

    fn handle_set_cookie(path: &str) -> Response<Cursor<Vec<u8>>> {
        let mut parts = path.split('/');
        let name = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        // Real httpbin scopes these to the site root; without an explicit Path a
        // client following RFC 6265 would confine the cookie to /cookies/set/....
        let header = Header::from_bytes("Set-Cookie", format!("{name}={value}; Path=/")).unwrap();
        text_response(StatusCode(200), "cookie set").with_header(header)
    }

    fn handle_status(code: &str) -> Response<Cursor<Vec<u8>>> {
        let status = code.parse::<u16>().unwrap_or(400);
        if status == 204 {
            return Response::new(
                StatusCode(status),
                vec![],
                Cursor::new(Vec::new()),
                None,
                None,
            );
        }
        text_response(StatusCode(status), format!("status {status}"))
    }

    fn handle_base64(data: &str) -> Response<Cursor<Vec<u8>>> {
        BASE64.decode(data).map_or_else(
            |_| text_response(StatusCode(400), "invalid base64"),
            |bytes| bytes_response(StatusCode(200), bytes),
        )
    }

    /// Answer `503` until the named counter has been hit `count` times.
    fn handle_flaky(count: &str) -> Response<Cursor<Vec<u8>>> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static HITS: AtomicUsize = AtomicUsize::new(0);

        let threshold = count.parse::<usize>().unwrap_or(1);
        let seen = HITS.fetch_add(1, Ordering::SeqCst);
        if seen < threshold {
            return text_response(StatusCode(503), "try again");
        }
        text_response(StatusCode(200), format!("ok after {seen} failures"))
    }

    fn handle_redirect(path: &str) -> Response<Cursor<Vec<u8>>> {
        let steps = path
            .trim_start_matches("/redirect/")
            .parse::<i32>()
            .unwrap_or(0);
        if steps <= 0 {
            return text_response(StatusCode(200), "redirect complete");
        }

        let next = format!("/redirect/{}", steps - 1);
        redirect_response(&next)
    }

    fn handle_redirect_to(query: &[(String, String)]) -> Response<Cursor<Vec<u8>>> {
        let target = query
            .iter()
            .find(|(key, _)| key == "url")
            .map_or("/", |(_, value)| value.as_str());
        redirect_response(target)
    }

    fn redirect_response(location: &str) -> Response<Cursor<Vec<u8>>> {
        let location_header = Header::from_bytes("Location", location).unwrap();
        Response::from_string("redirect")
            .with_status_code(StatusCode(302))
            .with_header(location_header)
    }

    fn header_value(request: &Request, name: &str) -> Option<String> {
        request
            .headers()
            .iter()
            .find(|header| header.field.to_string().eq_ignore_ascii_case(name))
            .map(|header| String::from_utf8_lossy(header.value.as_ref()).into_owned())
    }

    fn json_response(status: StatusCode, body: &str) -> Response<Cursor<Vec<u8>>> {
        let content_type = Header::from_bytes("Content-Type", "application/json").unwrap();
        Response::from_string(body.to_string())
            .with_status_code(status)
            .with_header(content_type)
    }

    fn text_response(status: StatusCode, body: impl Into<String>) -> Response<Cursor<Vec<u8>>> {
        Response::from_string(body.into()).with_status_code(status)
    }

    fn bytes_response(status: StatusCode, body: impl Into<Vec<u8>>) -> Response<Cursor<Vec<u8>>> {
        Response::from_data(body.into()).with_status_code(status)
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

pub use local::*;
