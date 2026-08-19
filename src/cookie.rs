//! Middleware for managing cookies in HTTP requests and responses.
//!
//! Cookies are stored per origin and only replayed to requests they actually
//! apply to, following RFC 6265: a cookie is sent when its domain, path, and
//! `Secure` flag all match the outgoing request, and expired cookies are
//! dropped rather than sent.

use crate::header;
use crate::{Endpoint, Middleware, Request, Response};
use http_kit::HttpError;
use http_kit::cookie::Cookie;
use http_kit::header::HeaderValue;
use http_kit::middleware::MiddlewareError;
use std::collections::HashMap;

#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use {
    async_fs,
    async_lock::Mutex as AsyncMutex,
    serde_json,
    std::{
        io::ErrorKind,
        path::{Path, PathBuf},
        sync::{Arc, LazyLock},
    },
};

use time::OffsetDateTime;

/// Identity of a stored cookie: name plus the scope it was set for.
///
/// RFC 6265 treats cookies with the same name but a different domain or path as
/// distinct, so all three form the key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CookieKey {
    name: String,
    domain: String,
    path: String,
}

/// A cookie together with the scope it may be replayed to.
#[derive(Debug, Clone)]
struct StoredCookie {
    name: String,
    value: String,
    /// Domain the cookie applies to, lowercased and without a leading dot.
    domain: String,
    /// Path prefix the cookie applies to.
    path: String,
    /// Whether the cookie came with an explicit `Domain` attribute, which makes
    /// it apply to subdomains too.
    host_only: bool,
    secure: bool,
    expires: Option<OffsetDateTime>,
}

impl StoredCookie {
    fn key(&self) -> CookieKey {
        CookieKey {
            name: self.name.clone(),
            domain: self.domain.clone(),
            path: self.path.clone(),
        }
    }

    /// Whether this cookie is past its expiry at `now`.
    fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires.is_some_and(|expires| expires <= now)
    }

    /// Whether this cookie should be sent to `request_host`/`request_path`.
    fn matches(&self, request_host: &str, request_path: &str, request_is_secure: bool) -> bool {
        if self.secure && !request_is_secure {
            return false;
        }
        domain_matches(request_host, &self.domain, self.host_only)
            && path_matches(request_path, &self.path)
    }
}

/// RFC 6265 §5.1.3 domain matching.
///
/// A host-only cookie matches its host exactly. Otherwise the request host may
/// also be a subdomain of the cookie domain.
fn domain_matches(request_host: &str, cookie_domain: &str, host_only: bool) -> bool {
    if request_host == cookie_domain {
        return true;
    }
    if host_only {
        return false;
    }
    // Only a real subdomain matches: "evilexample.com" must not match "example.com".
    request_host
        .strip_suffix(cookie_domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

/// RFC 6265 §5.1.4 path matching.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if cookie_path == "/" || request_path == cookie_path {
        return true;
    }
    request_path
        .strip_prefix(cookie_path)
        .is_some_and(|rest| rest.starts_with('/') || cookie_path.ends_with('/'))
}

/// Default path for a cookie set by `request_path`, per RFC 6265 §5.1.4.
fn default_path(request_path: &str) -> String {
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => request_path[..index].to_string(),
    }
}

/// Scope of an outgoing request, used to select and store cookies.
struct RequestScope {
    host: String,
    path: String,
    is_secure: bool,
}

impl RequestScope {
    /// Derive the scope from a request URI, if it names a host.
    fn from_request(request: &Request) -> Option<Self> {
        let uri = request.uri();
        let host = uri.host()?.trim_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let path = uri.path();
        let scheme = uri.scheme_str().unwrap_or("http");
        // Loopback counts as a secure context, as browsers do, so local
        // development still sees `Secure` cookies.
        let is_secure = scheme.eq_ignore_ascii_case("https")
            || scheme.eq_ignore_ascii_case("wss")
            || is_loopback(&host);
        Some(Self {
            host,
            path: if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            },
            is_secure,
        })
    }
}

/// Whether `host` names the local machine.
fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Middleware for managing cookies in HTTP requests and responses.
#[derive(Debug, Default)]
pub struct CookieStore {
    cookies: HashMap<CookieKey, StoredCookie>,
    #[cfg(not(target_arch = "wasm32"))]
    persistence: Option<Persistence>,
}

/// Errors encountered while handling HTTP cookies.
#[derive(Debug, thiserror::Error)]
pub enum CookieError {
    /// Failed to read persisted cookies from disk.
    #[error("Failed to load cookies from disk: {0}")]
    FailToLoadCookiesFromDisk(std::io::Error),

    /// Failed to decode persisted cookie data.
    #[error("Failed to parse cookies from disk: {0}")]
    FailToParseCookiesFromDisk(serde_json::Error),

    /// Failed to write cookies to the persistence layer.
    #[error("Failed to persist cookies to disk: {0}")]
    FailToPersistCookiesToDisk(std::io::Error),

    /// Encountered an invalid cookie header value.
    #[error("Invalid cookie header")]
    InvalidCookieHeader,
}

impl HttpError for CookieError {}

// Convert CookieError to unified zenwave::Error
impl From<CookieError> for crate::Error {
    fn from(err: CookieError) -> Self {
        use crate::error::CookieErrorKind;

        let kind = match err {
            CookieError::FailToLoadCookiesFromDisk(e) => CookieErrorKind::LoadFailed(e),
            CookieError::FailToParseCookiesFromDisk(e) => CookieErrorKind::ParseFailed(e),
            CookieError::FailToPersistCookiesToDisk(e) => CookieErrorKind::PersistFailed(e),
            CookieError::InvalidCookieHeader => CookieErrorKind::InvalidHeader,
        };

        Self::Cookie(kind)
    }
}

impl CookieStore {
    /// Create an empty, in-memory cookie store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable persistent storage using the default path for the current crate.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn persistent_default() -> Self {
        default_cookie_path().map_or_else(Self::default, Self::persistent_with_path)
    }

    /// Enable persistent storage using the provided path.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn persistent_with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            cookies: HashMap::new(),
            persistence: Some(Persistence {
                path: path.into(),
                initialized: false,
            }),
        }
    }

    /// Number of cookies currently held, including any not yet expired.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Whether the store holds no cookies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Record a `Set-Cookie` value received from `scope`.
    ///
    /// Cookies scoped to a domain the responding host may not speak for are
    /// rejected, and a cookie whose expiry has already passed removes any
    /// stored counterpart instead of being kept.
    fn store(&mut self, cookie: &Cookie<'_>, scope: &RequestScope, now: OffsetDateTime) -> bool {
        let (domain, host_only) = match cookie.domain() {
            Some(domain) => {
                let domain = domain.trim_matches('.').to_ascii_lowercase();
                // Reject a cookie set for an unrelated domain.
                if domain.is_empty() || !domain_matches(&scope.host, &domain, false) {
                    return false;
                }
                (domain, false)
            }
            None => (scope.host.clone(), true),
        };

        let stored = StoredCookie {
            name: cookie.name().to_string(),
            value: cookie.value().to_string(),
            domain,
            path: cookie
                .path()
                .map_or_else(|| default_path(&scope.path), str::to_string),
            host_only,
            secure: cookie.secure().unwrap_or(false),
            expires: cookie.expires_datetime(),
        };

        let key = stored.key();
        if stored.is_expired(now) {
            // An expiry in the past is how servers delete a cookie.
            return self.cookies.remove(&key).is_some();
        }
        self.cookies.insert(key, stored);
        true
    }

    /// Build the `Cookie` header for `scope`, dropping expired cookies.
    fn cookie_header(&mut self, scope: &RequestScope, now: OffsetDateTime) -> Option<String> {
        self.cookies.retain(|_, cookie| !cookie.is_expired(now));

        let mut matching: Vec<&StoredCookie> = self
            .cookies
            .values()
            .filter(|cookie| cookie.matches(&scope.host, &scope.path, scope.is_secure))
            .collect();
        if matching.is_empty() {
            return None;
        }

        // RFC 6265 §5.4: longer paths first; the rest is sorted for a stable header.
        matching.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then_with(|| a.name.cmp(&b.name))
        });

        let mut header = String::new();
        for cookie in matching {
            if !header.is_empty() {
                header.push_str("; ");
            }
            header.push_str(&cookie.name);
            header.push('=');
            header.push_str(&cookie.value);
        }
        Some(header)
    }

    async fn prepare(&mut self) -> Result<(), CookieError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(path) = self
                .persistence
                .as_ref()
                .filter(|p| !p.initialized)
                .map(|p| p.path.clone())
            {
                self.load_from_disk(&path).await?;
                if let Some(persistence) = self
                    .persistence
                    .as_mut()
                    .filter(|persist| persist.path == path)
                {
                    persistence.initialized = true;
                }
            }
        }
        Ok(())
    }

    #[allow(unused_variables)]
    async fn finalize(&self, updated: bool) -> Result<(), CookieError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if updated && let Some(persistence) = &self.persistence {
                self.persist_to_path(&persistence.path).await?;
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_from_disk(&mut self, path: &Path) -> Result<(), CookieError> {
        let lock = file_mutex(path).await;
        let _guard = lock.lock().await;

        let data = match async_fs::read(path).await {
            Ok(data) => data,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => return Err(CookieError::FailToLoadCookiesFromDisk(err)),
        };

        if !data.is_empty() {
            let cookies: Vec<PersistedCookie> =
                serde_json::from_slice(&data).map_err(CookieError::FailToParseCookiesFromDisk)?;
            for stored in cookies {
                let stored = stored.into_stored();
                self.cookies.insert(stored.key(), stored);
            }
        }

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn persist_to_path(&self, path: &Path) -> Result<(), CookieError> {
        let lock = file_mutex(path).await;
        let _guard = lock.lock().await;

        let snapshot: Vec<PersistedCookie> =
            self.cookies.values().map(PersistedCookie::from).collect();
        // Serializing plain strings and timestamps cannot fail.
        let data = serde_json::to_vec(&snapshot).expect("cookie snapshot must serialize");

        if let Some(parent) = path.parent() {
            async_fs::create_dir_all(parent)
                .await
                .map_err(CookieError::FailToPersistCookiesToDisk)?;
        }

        let tmp = path.with_extension("tmp");
        async_fs::write(&tmp, &data)
            .await
            .map_err(CookieError::FailToPersistCookiesToDisk)?;
        async_fs::rename(&tmp, path)
            .await
            .map_err(CookieError::FailToPersistCookiesToDisk)?;

        Ok(())
    }
}

impl Middleware for CookieStore {
    type Error = CookieError;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, http_kit::middleware::MiddlewareError<E::Error, Self::Error>> {
        self.prepare().await.map_err(MiddlewareError::Middleware)?;

        let scope = RequestScope::from_request(request);
        let now = OffsetDateTime::now_utc();

        // A request with no host (or an explicit `Cookie` set by the caller) is
        // passed through untouched.
        if let Some(scope) = &scope
            && !request.headers().contains_key(header::COOKIE)
            && let Some(header) = self.cookie_header(scope, now)
        {
            let value = HeaderValue::from_maybe_shared(header)
                .map_err(|_| MiddlewareError::Middleware(CookieError::InvalidCookieHeader))?;
            request.headers_mut().insert(header::COOKIE, value);
        }

        let res = next
            .respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)?;

        let mut updated = false;
        if let Some(scope) = &scope {
            for set_cookie in res.headers().get_all(header::SET_COOKIE) {
                // A single malformed `Set-Cookie` should not fail the response.
                let Ok(text) = set_cookie.to_str() else {
                    continue;
                };
                let Ok(cookie) = text.parse::<Cookie>() else {
                    continue;
                };
                updated |= self.store(&cookie, scope, now);
            }
        }

        self.finalize(updated)
            .await
            .map_err(MiddlewareError::Middleware)?;
        Ok(res)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct Persistence {
    path: PathBuf,
    initialized: bool,
}

#[cfg(not(target_arch = "wasm32"))]
fn default_cookie_path() -> Option<PathBuf> {
    let dir = dirs::data_local_dir()?;
    let crate_name = env!("CARGO_PKG_NAME");
    Some(dir.join(format!("zenwave_cookie_store_{crate_name}.json")))
}

/// On-disk form of a stored cookie.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize, Deserialize)]
struct PersistedCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    #[serde(default)]
    host_only: bool,
    secure: bool,
    expires: Option<i64>,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<&StoredCookie> for PersistedCookie {
    fn from(cookie: &StoredCookie) -> Self {
        Self {
            name: cookie.name.clone(),
            value: cookie.value.clone(),
            domain: cookie.domain.clone(),
            path: cookie.path.clone(),
            host_only: cookie.host_only,
            secure: cookie.secure,
            expires: cookie.expires.map(OffsetDateTime::unix_timestamp),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PersistedCookie {
    fn into_stored(self) -> StoredCookie {
        StoredCookie {
            name: self.name,
            value: self.value,
            domain: self.domain,
            path: self.path,
            host_only: self.host_only,
            secure: self.secure,
            expires: self
                .expires
                .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok()),
        }
    }
}

/// Per-path locks so two stores sharing a file cannot interleave writes.
#[cfg(not(target_arch = "wasm32"))]
static COOKIE_FILE_LOCKS: LazyLock<AsyncMutex<HashMap<PathBuf, Arc<AsyncMutex<()>>>>> =
    LazyLock::new(|| AsyncMutex::new(HashMap::new()));

#[cfg(not(target_arch = "wasm32"))]
async fn file_mutex(path: &Path) -> Arc<AsyncMutex<()>> {
    let mut map = COOKIE_FILE_LOCKS.lock().await;
    // Drop locks no store is holding any more so the map cannot grow forever.
    map.retain(|_, lock| Arc::strong_count(lock) > 1);
    map.entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use http::{Request as HttpRequest, Response as HttpResponse, StatusCode};
    use http_kit::Body;
    use tempfile::tempdir;

    /// Endpoint that answers with a fixed set of `Set-Cookie` headers.
    struct SetCookieEndpoint(Vec<&'static str>);

    impl Endpoint for SetCookieEndpoint {
        type Error = Infallible;
        fn respond(
            &mut self,
            _request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Response, Self::Error>> {
            let mut builder = HttpResponse::builder().status(StatusCode::OK);
            for value in &self.0 {
                builder = builder.header(header::SET_COOKIE, *value);
            }
            std::future::ready(Ok(builder
                .body(Body::empty())
                .expect("test response must build")))
        }
    }

    /// Endpoint that records the `Cookie` header it was handed.
    #[derive(Default)]
    struct RecordingEndpoint {
        last_cookie: Option<String>,
    }

    impl Endpoint for RecordingEndpoint {
        type Error = Infallible;
        fn respond(
            &mut self,
            request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Response, Self::Error>> {
            self.last_cookie = request
                .headers()
                .get(header::COOKIE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);

            std::future::ready(Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .expect("test response must build")))
        }
    }

    fn request(uri: &str) -> Request {
        HttpRequest::builder()
            .method(http_kit::Method::GET)
            .uri(uri)
            .body(Body::empty())
            .expect("test request must build")
    }

    /// Run `store` against `uri` and return the `Cookie` header it produced.
    fn cookie_sent_to(store: &mut CookieStore, uri: &str) -> Option<String> {
        async_io::block_on(async {
            let mut endpoint = RecordingEndpoint::default();
            let mut req = request(uri);
            store
                .handle(&mut req, &mut endpoint)
                .await
                .expect("cookie middleware must not fail");
            endpoint.last_cookie
        })
    }

    /// Let `store` observe the given `Set-Cookie` headers from `uri`.
    fn receive_cookies(store: &mut CookieStore, uri: &str, set_cookie: Vec<&'static str>) {
        async_io::block_on(async {
            let mut req = request(uri);
            store
                .handle(&mut req, &mut SetCookieEndpoint(set_cookie))
                .await
                .expect("cookie middleware must not fail");
        });
    }

    #[test]
    fn cookies_are_not_sent_to_an_unrelated_domain() {
        let mut store = CookieStore::new();
        receive_cookies(
            &mut store,
            "https://bank.example/login",
            vec!["sid=secret; Path=/"],
        );

        assert_eq!(
            cookie_sent_to(&mut store, "https://bank.example/account").as_deref(),
            Some("sid=secret")
        );
        assert_eq!(cookie_sent_to(&mut store, "https://evil.test/steal"), None);
    }

    #[test]
    fn a_host_only_cookie_is_not_sent_to_subdomains() {
        let mut store = CookieStore::new();
        receive_cookies(&mut store, "https://example.com/", vec!["a=1"]);

        assert_eq!(
            cookie_sent_to(&mut store, "https://example.com/").as_deref(),
            Some("a=1")
        );
        assert_eq!(cookie_sent_to(&mut store, "https://api.example.com/"), None);
    }

    #[test]
    fn a_domain_cookie_is_sent_to_subdomains() {
        let mut store = CookieStore::new();
        receive_cookies(
            &mut store,
            "https://example.com/",
            vec!["a=1; Domain=example.com"],
        );

        assert_eq!(
            cookie_sent_to(&mut store, "https://api.example.com/").as_deref(),
            Some("a=1")
        );
        // A domain that merely ends with the cookie domain must not match.
        assert_eq!(cookie_sent_to(&mut store, "https://notexample.com/"), None);
    }

    #[test]
    fn a_cookie_for_an_unrelated_domain_is_rejected() {
        let mut store = CookieStore::new();
        receive_cookies(
            &mut store,
            "https://evil.test/",
            vec!["sid=forged; Domain=bank.example"],
        );

        assert!(store.is_empty(), "a cross-domain cookie must be rejected");
        assert_eq!(cookie_sent_to(&mut store, "https://bank.example/"), None);
    }

    #[test]
    fn a_secure_cookie_is_withheld_from_plaintext_requests() {
        let mut store = CookieStore::new();
        receive_cookies(
            &mut store,
            "https://example.com/",
            vec!["sid=secret; Secure; Domain=example.com"],
        );

        assert_eq!(
            cookie_sent_to(&mut store, "https://example.com/").as_deref(),
            Some("sid=secret")
        );
        assert_eq!(cookie_sent_to(&mut store, "http://example.com/"), None);
    }

    #[test]
    fn cookies_are_scoped_to_their_path() {
        let mut store = CookieStore::new();
        receive_cookies(
            &mut store,
            "https://example.com/app/page",
            vec!["scoped=1; Path=/app", "root=1; Path=/"],
        );

        let deep = cookie_sent_to(&mut store, "https://example.com/app/inner")
            .expect("both cookies apply under /app");
        assert!(deep.contains("scoped=1"), "got {deep}");
        assert!(deep.contains("root=1"), "got {deep}");

        assert_eq!(
            cookie_sent_to(&mut store, "https://example.com/other").as_deref(),
            Some("root=1")
        );
    }

    #[test]
    fn longer_paths_are_sent_first() {
        let mut store = CookieStore::new();
        receive_cookies(
            &mut store,
            "https://example.com/app/page",
            vec!["a=root; Path=/", "a=deep; Path=/app"],
        );

        let header =
            cookie_sent_to(&mut store, "https://example.com/app/page").expect("both cookies apply");
        assert_eq!(header, "a=deep; a=root");
    }

    #[test]
    fn an_expired_cookie_is_dropped_rather_than_sent() {
        let mut store = CookieStore::new();
        receive_cookies(
            &mut store,
            "https://example.com/",
            vec!["stale=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
        );

        assert!(
            store.is_empty(),
            "an already-expired cookie must not be kept"
        );
        assert_eq!(cookie_sent_to(&mut store, "https://example.com/"), None);
    }

    #[test]
    fn a_past_expiry_deletes_a_stored_cookie() {
        let mut store = CookieStore::new();
        receive_cookies(&mut store, "https://example.com/", vec!["sid=live"]);
        assert_eq!(store.len(), 1);

        receive_cookies(
            &mut store,
            "https://example.com/",
            vec!["sid=live; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
        );
        assert!(store.is_empty(), "a past expiry must delete the cookie");
    }

    #[test]
    fn no_cookie_header_is_sent_when_nothing_matches() {
        let mut store = CookieStore::new();
        assert_eq!(cookie_sent_to(&mut store, "https://example.com/"), None);
    }

    #[test]
    fn a_caller_supplied_cookie_header_is_left_alone() {
        let mut store = CookieStore::new();
        receive_cookies(&mut store, "https://example.com/", vec!["stored=1"]);

        let sent = async_io::block_on(async {
            let mut endpoint = RecordingEndpoint::default();
            let mut req = request("https://example.com/");
            req.headers_mut()
                .insert(header::COOKIE, HeaderValue::from_static("manual=yes"));
            store
                .handle(&mut req, &mut endpoint)
                .await
                .expect("cookie middleware must not fail");
            endpoint.last_cookie
        });
        assert_eq!(sent.as_deref(), Some("manual=yes"));
    }

    #[test]
    fn same_name_cookies_on_different_domains_do_not_collide() {
        let mut store = CookieStore::new();
        receive_cookies(&mut store, "https://one.test/", vec!["sid=first"]);
        receive_cookies(&mut store, "https://two.test/", vec!["sid=second"]);

        assert_eq!(store.len(), 2);
        assert_eq!(
            cookie_sent_to(&mut store, "https://one.test/").as_deref(),
            Some("sid=first")
        );
        assert_eq!(
            cookie_sent_to(&mut store, "https://two.test/").as_deref(),
            Some("sid=second")
        );
    }

    #[test]
    fn a_malformed_set_cookie_does_not_fail_the_response() {
        let mut store = CookieStore::new();
        receive_cookies(&mut store, "https://example.com/", vec!["=", "good=1"]);

        assert_eq!(
            cookie_sent_to(&mut store, "https://example.com/").as_deref(),
            Some("good=1")
        );
    }

    #[test]
    fn persistent_store_roundtrip() {
        let dir = tempdir().expect("tempdir must be creatable");
        let path = dir.path().join("cookies.json");

        let mut store = CookieStore::persistent_with_path(path.clone());
        receive_cookies(
            &mut store,
            "https://example.com/",
            vec!["session=abc; Path=/", "theme=dark; Path=/"],
        );

        let mut restored = CookieStore::persistent_with_path(path);
        let header = cookie_sent_to(&mut restored, "https://example.com/")
            .expect("persisted cookies must be restored");
        assert!(header.contains("session=abc"), "got {header}");
        assert!(header.contains("theme=dark"), "got {header}");
    }

    #[test]
    fn persistence_preserves_cookie_scope() {
        let dir = tempdir().expect("tempdir must be creatable");
        let path = dir.path().join("cookies.json");

        let mut store = CookieStore::persistent_with_path(path.clone());
        receive_cookies(&mut store, "https://example.com/", vec!["host=only"]);

        // A host-only cookie must stay host-only after a round trip.
        let mut restored = CookieStore::persistent_with_path(path);
        assert_eq!(
            cookie_sent_to(&mut restored, "https://api.example.com/"),
            None
        );
        assert_eq!(
            cookie_sent_to(&mut restored, "https://example.com/").as_deref(),
            Some("host=only")
        );
    }

    #[test]
    fn domain_matching_rejects_suffix_lookalikes() {
        assert!(domain_matches("example.com", "example.com", true));
        assert!(!domain_matches("api.example.com", "example.com", true));
        assert!(domain_matches("api.example.com", "example.com", false));
        assert!(!domain_matches("notexample.com", "example.com", false));
        assert!(!domain_matches(
            "example.com.evil.test",
            "example.com",
            false
        ));
    }

    #[test]
    fn path_matching_requires_a_segment_boundary() {
        assert!(path_matches("/anything", "/"));
        assert!(path_matches("/app", "/app"));
        assert!(path_matches("/app/inner", "/app"));
        assert!(!path_matches("/application", "/app"));
        assert!(!path_matches("/other", "/app"));
    }

    #[test]
    fn default_path_drops_the_last_segment() {
        assert_eq!(default_path("/app/page"), "/app");
        assert_eq!(default_path("/page"), "/");
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path(""), "/");
    }
}
