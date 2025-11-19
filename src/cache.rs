//! HTTP caching middleware that honors basic Cache-Control and validator headers.

use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime},
};

use http::{HeaderMap, HeaderValue, Method, Response as HttpResponse, StatusCode, header};
use httpdate::parse_http_date;

use http_kit::{ResultExt, utils::Bytes};
use http_kit::{Endpoint, Middleware, Request, Response, Result};

/// Middleware implementing an in-memory HTTP cache.
///
/// The cache honors the core HTTP caching directives (`Cache-Control`, `Expires`, `ETag`,
/// `Last-Modified`) so it can serve fresh responses locally and transparently revalidate stale
/// entries using conditional requests.
#[derive(Debug, Default)]
pub struct Cache {
    entries: HashMap<String, CachedResponse>,
}

impl Cache {
    /// Create an empty in-memory cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn cache_key(request: &Request) -> Option<String> {
        if *request.method() != Method::GET {
            return None;
        }
        Some(request.uri().to_string())
    }
}

impl Middleware for Cache {
    async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
        let Some(key) = Self::cache_key(request) else {
            return next.respond(request).await;
        };

        let request_cc = CacheControl::from_header_map(request.headers());
        if request_cc.no_store {
            self.entries.remove(&key);
            return next.respond(request).await;
        }

        let now = Instant::now();
        if let Some(entry) = self.entries.get(&key)
            && !request_cc.no_cache
            && !entry.must_revalidate
            && entry.is_fresh(now)
        {
            return Ok(entry.to_response(now));
        }

        let mut cached_entry = None;
        if let Some(entry) = self.entries.get(&key) {
            let entry_requires_revalidation = entry.must_revalidate || !entry.is_fresh(now);
            let needs_revalidation = request_cc.no_cache || entry_requires_revalidation;
            if needs_revalidation && entry.can_revalidate() {
                let owned_entry = self.entries.remove(&key).unwrap();
                owned_entry.apply_conditional_headers(request.headers_mut());
                cached_entry = Some(owned_entry);
            } else if entry_requires_revalidation && !entry.can_revalidate() {
                self.entries.remove(&key);
            }
        }

        let response = next.respond(request).await?;
        if response.status() == StatusCode::NOT_MODIFIED {
            if let Some(mut entry) = cached_entry {
                entry.update_from_304(&response, now);
                let response = entry.to_response(now);
                self.entries.insert(key, entry);
                return Ok(response);
            }

            // No cached entry to reconcile against (should not happen) - treat as network miss.
            return Ok(response);
        }

        let response_cc = CacheControl::from_header_map(response.headers());
        let auth_present = request.headers().contains_key(header::AUTHORIZATION);
        let allow_shared = !auth_present || response_cc.public;

        if allow_shared && !response_cc.no_store {
            let (response, entry) =
                CachedResponse::from_response(response, response_cc, now, request_cc.no_cache)
                    .await?;
            if let Some(entry) = entry {
                let result = entry.to_response(now);
                self.entries.insert(key, entry);
                return Ok(result);
            }
            return Ok(response);
        }

        Ok(response)
    }
}

#[derive(Debug, Clone)]
struct CachedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    stored_at: Instant,
    freshness: Option<Duration>,
    must_revalidate: bool,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
}

impl CachedResponse {
    async fn from_response(
        response: Response,
        directives: CacheControl,
        now: Instant,
        request_no_cache: bool,
    ) -> Result<(Response, Option<Self>)> {
        let (mut parts, body) = response.into_parts();
        let etag = parts.headers.get(header::ETAG).cloned();
        let last_modified = parts.headers.get(header::LAST_MODIFIED).cloned();
        let status = parts.status;
        let headers_snapshot = parts.headers.clone();

        let mut freshness = directives.max_age.map(Duration::from_secs);
        if freshness.is_none()
            && let Some(duration) = expires_in(&parts.headers)
        {
            freshness = Some(duration);
        }

        let must_revalidate = directives.no_cache || directives.must_revalidate || request_no_cache;

        let should_store = freshness.is_some() || must_revalidate;
        if !should_store {
            let response = HttpResponse::from_parts(parts, body);
            return Ok((response, None));
        }

        let bytes = body.into_bytes().await.status(StatusCode::SERVICE_UNAVAILABLE)?;
        parts.headers.remove(header::AGE);
        let response = HttpResponse::from_parts(parts, http_kit::Body::from(bytes.clone()));

        Ok((
            response,
            Some(Self {
                status,
                headers: headers_snapshot,
                body: bytes,
                stored_at: now,
                freshness,
                must_revalidate,
                etag,
                last_modified,
            }),
        ))
    }

    fn is_fresh(&self, now: Instant) -> bool {
        self.freshness
            .is_some_and(|fresh| now.duration_since(self.stored_at) < fresh)
    }

    const fn can_revalidate(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }

    fn apply_conditional_headers(&self, headers: &mut HeaderMap) {
        if let Some(etag) = &self.etag {
            headers.insert(header::IF_NONE_MATCH, etag.clone());
        }
        if let Some(last_modified) = &self.last_modified {
            headers.insert(header::IF_MODIFIED_SINCE, last_modified.clone());
        }
    }

    fn update_from_304(&mut self, response: &Response, now: Instant) {
        self.stored_at = now;
        for name in &[
            header::CACHE_CONTROL,
            header::ETAG,
            header::EXPIRES,
            header::DATE,
            header::LAST_MODIFIED,
        ] {
            if let Some(value) = response.headers().get(name) {
                self.headers.insert(name.clone(), value.clone());
            }
        }
        let cc = CacheControl::from_header_map(response.headers());
        if let Some(max_age) = cc.max_age {
            self.freshness = Some(Duration::from_secs(max_age));
        }
        if cc.no_cache || cc.must_revalidate {
            self.must_revalidate = true;
        }
        if cc.max_age.is_none()
            && let Some(duration) = expires_in(&self.headers)
        {
            self.freshness = Some(duration);
        }
    }

    fn to_response(&self, now: Instant) -> Response {
        let mut headers = self.headers.clone();
        headers.insert(
            header::AGE,
            HeaderValue::from_str(&now.duration_since(self.stored_at).as_secs().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        );

        let mut builder = HttpResponse::builder().status(self.status);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        builder
            .body(http_kit::Body::from(self.body.clone()))
            .expect("failed to build cached response")
    }
}

#[derive(Debug, Default, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct CacheControl {
    no_cache: bool,
    no_store: bool,
    max_age: Option<u64>,
    must_revalidate: bool,
    public: bool,
}

impl CacheControl {
    fn from_header_map(headers: &HeaderMap) -> Self {
        headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .fold(Self::default(), |mut acc, value| {
                if let Ok(text) = value.to_str() {
                    for directive in text.split(',') {
                        let directive = directive.trim();
                        let lower = directive.to_ascii_lowercase();
                        match lower.as_str() {
                            "no-cache" => acc.no_cache = true,
                            "no-store" => acc.no_store = true,
                            "must-revalidate" => acc.must_revalidate = true,
                            "public" => acc.public = true,
                            _ => {
                                if let Some(rest) = lower.strip_prefix("max-age=")
                                    && let Ok(value) = rest.parse::<u64>()
                                {
                                    acc.max_age = Some(value);
                                }
                            }
                        }
                    }
                }
                acc
            })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use http::Request as HttpRequest;
    use http_kit::{Body, Method};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn serves_cached_response_until_expiration() {
        let backend = CountingEndpoint::new("hello", &[("cache-control", "max-age=60")]);
        let mut cache = Cache::new();
        let mut request = new_request();
        let mut endpoint = backend.clone();

        let response = cache.handle(&mut request, &mut endpoint).await.unwrap();
        assert_eq!(body_text(response).await, "hello");
        assert_eq!(backend.calls(), 1);

        let mut request = new_request();
        let mut endpoint = backend.clone();
        let response = cache.handle(&mut request, &mut endpoint).await.unwrap();
        assert_eq!(body_text(response).await, "hello");
        assert_eq!(backend.calls(), 1);
    }

    #[tokio::test]
    async fn respects_no_store() {
        let backend = CountingEndpoint::new("world", &[("cache-control", "no-store")]);
        let mut cache = Cache::new();

        for _ in 0..2 {
            let mut request = new_request();
            let mut endpoint = backend.clone();
            let response = cache.handle(&mut request, &mut endpoint).await.unwrap();
            assert_eq!(body_text(response).await, "world");
        }
        assert_eq!(backend.calls(), 2);
    }

    #[tokio::test]
    async fn revalidates_using_etag() {
        let backend = ConditionalEndpoint::new();
        let mut cache = Cache::new();

        let mut request = new_request();
        let mut endpoint = backend.clone();
        let response = cache.handle(&mut request, &mut endpoint).await.unwrap();
        assert_eq!(body_text(response).await, "fresh");
        assert_eq!(backend.calls(), 1);

        let mut request = new_request();
        let mut endpoint = backend.clone();
        let response = cache.handle(&mut request, &mut endpoint).await.unwrap();
        assert_eq!(body_text(response).await, "fresh");
        assert_eq!(backend.calls(), 2);
        assert_eq!(backend.conditional_requests(), 1);
    }

    fn new_request() -> Request {
        HttpRequest::builder()
            .method(Method::GET)
            .uri("http://example.com/data")
            .body(Body::empty())
            .unwrap()
    }

    async fn body_text(response: Response) -> String {
        response
            .into_body()
            .into_string()
            .await
            .unwrap()
            .to_string()
    }

    #[derive(Clone)]
    struct CountingEndpoint {
        calls: Arc<AtomicUsize>,
        body: &'static str,
        headers: Vec<(&'static str, &'static str)>,
    }

    impl CountingEndpoint {
        fn new(body: &'static str, headers: &[(&'static str, &'static str)]) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                body,
                headers: headers.to_vec(),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Endpoint for CountingEndpoint {
        async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut builder = HttpResponse::builder().status(StatusCode::OK);
            for (name, value) in &self.headers {
                builder = builder.header(*name, *value);
            }
            Ok(builder.body(Body::from(self.body)).unwrap())
        }
    }

    #[derive(Clone)]
    struct ConditionalEndpoint {
        calls: Arc<AtomicUsize>,
        conditional: Arc<AtomicUsize>,
    }

    impl ConditionalEndpoint {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                conditional: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn conditional_requests(&self) -> usize {
            self.conditional.load(Ordering::SeqCst)
        }
    }

    impl Endpoint for ConditionalEndpoint {
        async fn respond(&mut self, request: &mut Request) -> Result<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if request.headers().contains_key(header::IF_NONE_MATCH) {
                self.conditional.fetch_add(1, Ordering::SeqCst);
                return Ok(HttpResponse::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, "\"v1\"")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::empty())
                    .unwrap());
            }
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, "\"v1\"")
                .header(header::CACHE_CONTROL, "no-cache")
                .body(Body::from("fresh"))
                .unwrap())
        }
    }
}

fn expires_in(headers: &HeaderMap) -> Option<Duration> {
    let expires = headers.get(header::EXPIRES)?;
    let text = expires.to_str().ok()?;
    let timestamp = parse_http_date(text).ok()?;
    let duration = timestamp.duration_since(SystemTime::now()).ok()?;
    if duration.is_zero() {
        None
    } else {
        Some(duration)
    }
}
