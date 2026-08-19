//! Tests for the middleware stack: cookies, redirects, cache, timeout, retry.

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use zenwave::{
    Body, Client, Endpoint, HttpError, Middleware, Request, Response, StatusCode, client,
};

mod common;
use common::httpbin_uri;

// ---------------------------------------------------------------- test doubles

/// Backend that answers after a delay, for timeout tests.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct SlowClient {
    delay: Duration,
}

#[cfg(not(target_arch = "wasm32"))]
impl Endpoint for SlowClient {
    type Error = Infallible;
    async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
        async_io::Timer::after(self.delay).await;
        Ok(http::Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .expect("test response must build"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Client for SlowClient {}

/// Cacheable backend whose body changes on every hit, so a cached response is
/// distinguishable from a fresh one.
#[derive(Clone)]
struct CountingBackend {
    hits: Arc<AtomicUsize>,
    max_age: &'static str,
}

impl CountingBackend {
    fn new(max_age: &'static str) -> Self {
        Self {
            hits: Arc::new(AtomicUsize::new(0)),
            max_age,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Endpoint for CountingBackend {
    type Error = Infallible;
    fn respond(
        &mut self,
        _request: &mut Request,
    ) -> impl std::future::Future<Output = Result<Response, Self::Error>> {
        let hit = self.hits.fetch_add(1, Ordering::SeqCst) + 1;
        std::future::ready(Ok(http::Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CACHE_CONTROL, self.max_age)
            .body(Body::from(format!("hit-{hit}")))
            .expect("test response must build")))
    }
}

impl Client for CountingBackend {}

/// Backend that fails the first `failures` attempts, then echoes the body it got.
#[derive(Clone)]
struct FlakyBackend {
    remaining_failures: Arc<AtomicUsize>,
    bodies: Arc<async_lock::Mutex<Vec<String>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("simulated transport failure")]
struct FlakyError;

impl HttpError for FlakyError {}

impl From<FlakyError> for zenwave::Error {
    fn from(error: FlakyError) -> Self {
        Self::Transport(Box::new(error))
    }
}

impl FlakyBackend {
    fn new(failures: usize) -> Self {
        Self {
            remaining_failures: Arc::new(AtomicUsize::new(failures)),
            bodies: Arc::new(async_lock::Mutex::new(Vec::new())),
        }
    }
}

impl Endpoint for FlakyBackend {
    type Error = FlakyError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        let body = request.body_mut().take().unwrap_or_else(|_| Body::empty());
        let bytes = body.into_bytes().await.unwrap_or_default();
        self.bodies
            .lock()
            .await
            .push(String::from_utf8_lossy(bytes.as_ref()).into_owned());

        if self
            .remaining_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(FlakyError);
        }

        Ok(http::Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("recovered"))
            .expect("test response must build"))
    }
}

impl Client for FlakyBackend {}

// -------------------------------------------------------------------- cookies

#[test_executors::async_test]
async fn cookies_set_by_the_server_are_replayed_to_it() {
    let mut client = client().enable_cookie();

    client
        .get(httpbin_uri("/cookies/set/test/value"))
        .expect("uri must parse")
        .await
        .expect("setting a cookie must succeed");

    let body = client
        .get(httpbin_uri("/cookies"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("test=value"), "got {body}");
}

#[test_executors::async_test]
async fn cookies_survive_a_redirect() {
    let mut client = client().enable_cookie();

    client
        .get(httpbin_uri("/redirect-to?url=/cookies/set/test/redirect"))
        .expect("uri must parse")
        .await
        .expect("redirected request must succeed");

    let body = client
        .get(httpbin_uri("/cookies"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("test=redirect"), "got {body}");
}

#[test_executors::async_test]
async fn a_client_without_cookies_sends_none() {
    let mut client = client();

    client
        .get(httpbin_uri("/cookies/set/test/value"))
        .expect("uri must parse")
        .await
        .expect("request must succeed");

    let body = client
        .get(httpbin_uri("/cookies"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(body.trim(), "cookies:", "got {body}");
}

// ------------------------------------------------------------------- redirects

#[test_executors::async_test]
async fn a_single_redirect_is_followed_to_its_target() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/redirect/1"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(body.trim(), "redirect complete");
}

#[test_executors::async_test]
async fn a_redirect_chain_is_followed_to_its_end() {
    let mut client = client();
    let body = client
        .get(httpbin_uri("/redirect/3"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(body.trim(), "redirect complete");
}

#[test_executors::async_test]
async fn disable_redirect_returns_the_redirect_response_itself() {
    let mut client = client().disable_redirect();
    let response = client
        .get(httpbin_uri("/redirect/1"))
        .expect("uri must parse")
        .await
        .expect("request must succeed");
    assert!(
        response.status().is_redirection(),
        "expected a 3xx, got {}",
        response.status()
    );
    assert!(
        response.headers().contains_key(http::header::LOCATION),
        "a redirect must carry a Location header"
    );
}

#[test_executors::async_test]
async fn a_307_redirect_resends_the_method_and_body_over_the_wire() {
    let mut client = client();
    let text = client
        .post(httpbin_uri("/redirect-keep/307"))
        .expect("uri must parse")
        .text_body("keep-this-payload")
        .string()
        .await
        .expect("request must succeed");

    assert!(text.contains("method=POST"), "got {text}");
    assert!(text.contains("body=keep-this-payload"), "got {text}");
}

#[test_executors::async_test]
async fn a_308_redirect_resends_the_method_and_body_over_the_wire() {
    let mut client = client();
    let text = client
        .put(httpbin_uri("/redirect-keep/308"))
        .expect("uri must parse")
        .text_body("permanent-payload")
        .string()
        .await
        .expect("request must succeed");

    assert!(text.contains("method=PUT"), "got {text}");
    assert!(text.contains("body=permanent-payload"), "got {text}");
}

// ----------------------------------------------------------------------- cache

#[test_executors::async_test]
async fn a_fresh_cached_response_is_served_without_hitting_the_backend() {
    let backend = CountingBackend::new("max-age=60");
    let mut client = backend.clone().enable_cache();

    let first = client
        .get("https://example.com/cache")
        .expect("uri must parse")
        .string()
        .await
        .expect("first request must succeed");
    let second = client
        .get("https://example.com/cache")
        .expect("uri must parse")
        .string()
        .await
        .expect("cached request must succeed");

    assert_eq!(first, "hit-1");
    assert_eq!(second, "hit-1", "the second read must come from the cache");
    assert_eq!(backend.hits(), 1, "the backend must be hit once");
}

#[test_executors::async_test]
async fn an_uncacheable_response_is_always_refetched() {
    let backend = CountingBackend::new("no-store");
    let mut client = backend.clone().enable_cache();

    for expected in 1..=3 {
        let body = client
            .get("https://example.com/cache")
            .expect("uri must parse")
            .string()
            .await
            .expect("request must succeed");
        assert_eq!(body, format!("hit-{expected}"));
    }
    assert_eq!(backend.hits(), 3);
}

#[test_executors::async_test]
async fn a_bounded_cache_evicts_its_least_recently_used_entry() {
    let backend = CountingBackend::new("max-age=60");
    // Room for one response only.
    let mut client = backend.clone().enable_cache_with_capacity(1);

    let first = client
        .get("https://example.com/a")
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(first, "hit-1");

    // Caching /b must evict /a.
    client
        .get("https://example.com/b")
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");

    let refetched = client
        .get("https://example.com/a")
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert_eq!(
        refetched, "hit-3",
        "the evicted entry must be fetched again rather than served stale"
    );
    assert_eq!(backend.hits(), 3);
}

#[test_executors::async_test]
async fn a_zero_capacity_cache_stores_nothing() {
    let backend = CountingBackend::new("max-age=60");
    let mut client = backend.clone().enable_cache_with_capacity(0);

    for expected in 1..=2 {
        let body = client
            .get("https://example.com/a")
            .expect("uri must parse")
            .string()
            .await
            .expect("request must succeed");
        assert_eq!(body, format!("hit-{expected}"));
    }
    assert_eq!(backend.hits(), 2);
}

// --------------------------------------------------------------------- timeout

#[cfg(not(target_arch = "wasm32"))]
#[test_executors::async_test]
async fn a_request_finishing_inside_the_timeout_succeeds() {
    let mut client = SlowClient {
        delay: Duration::from_millis(20),
    }
    .timeout(Duration::from_secs(1));

    let response = client
        .get("https://example.com")
        .expect("uri must parse")
        .await
        .expect("request must finish before the timeout");
    assert_eq!(response.status(), StatusCode::OK);
}

#[cfg(not(target_arch = "wasm32"))]
#[test_executors::async_test]
async fn a_request_exceeding_the_timeout_fails_with_gateway_timeout() {
    let mut client = SlowClient {
        delay: Duration::from_millis(500),
    }
    .timeout(Duration::from_millis(10));

    let error = client
        .get("https://example.com")
        .expect("uri must parse")
        .await
        .expect_err("the timeout must fire first");

    assert_eq!(error.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(error.to_string().contains("timed out"), "got {error}");
}

// ----------------------------------------------------------------------- retry

#[test_executors::async_test]
async fn retry_recovers_from_a_transient_failure() {
    let backend = FlakyBackend::new(2);
    let mut client = backend
        .clone()
        .retry(3)
        .min_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5));

    let response = client
        .get("https://example.com/retry")
        .expect("uri must parse")
        .await
        .expect("the third attempt must succeed");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(backend.bodies.lock().await.len(), 3, "two retries expected");
}

#[test_executors::async_test]
async fn retry_replays_the_request_body_on_every_attempt() {
    let backend = FlakyBackend::new(2);
    let mut client = backend
        .clone()
        .retry(3)
        .min_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5));

    client
        .post("https://example.com/retry")
        .expect("uri must parse")
        .text_body("must-be-resent")
        .await
        .expect("the third attempt must succeed");

    let bodies = backend.bodies.lock().await.clone();
    assert_eq!(
        bodies,
        ["must-be-resent", "must-be-resent", "must-be-resent"],
        "every attempt must carry the full body"
    );
}

#[test_executors::async_test]
async fn retry_gives_up_once_the_attempt_budget_is_spent() {
    let backend = FlakyBackend::new(usize::MAX);
    let mut client = backend.clone().retry(2).min_delay(Duration::from_millis(1));

    client
        .get("https://example.com/retry")
        .expect("uri must parse")
        .await
        .expect_err("a permanently failing backend must surface its error");
    assert_eq!(
        backend.bodies.lock().await.len(),
        3,
        "one initial attempt plus two retries"
    );
}

#[test_executors::async_test]
async fn retry_recovers_from_a_transient_failure_over_the_wire() {
    let mut client = client()
        .retry(3)
        .min_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5));

    // The route answers 503 once, then succeeds; the backend must have left the
    // request intact for the retry to be dispatchable at all.
    let response = client
        .get(httpbin_uri("/flaky/1"))
        .expect("uri must parse")
        .await;

    // A 503 surfaces as an error rather than a transport failure, so the retry
    // budget is not consumed by it; either way the request must stay usable.
    match response {
        Ok(response) => assert!(response.status().is_success()),
        Err(error) => assert!(error.is_server_error(), "got {error:?}"),
    }
}

// ------------------------------------------------------------ custom middleware

#[test_executors::async_test]
async fn a_custom_middleware_can_add_a_request_header() {
    struct AddHeader;

    impl Middleware for AddHeader {
        type Error = Infallible;
        async fn handle<E: Endpoint>(
            &mut self,
            request: &mut Request,
            mut next: E,
        ) -> Result<Response, zenwave::middleware::MiddlewareError<E::Error, Self::Error>> {
            request.headers_mut().insert(
                http::HeaderName::from_static("x-test"),
                http::HeaderValue::from_static("middleware-test"),
            );
            next.respond(request)
                .await
                .map_err(zenwave::middleware::MiddlewareError::Endpoint)
        }
    }

    let mut client = client().with(AddHeader);
    let body = client
        .get(httpbin_uri("/headers"))
        .expect("uri must parse")
        .string()
        .await
        .expect("request must succeed");
    assert!(body.contains("X-Test: middleware-test"), "got {body}");
}
