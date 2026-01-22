//! Middleware for managing cookies in HTTP requests and responses.

use crate::header;
use crate::{Endpoint, Middleware, Request, Response};
use http_kit::HttpError;
use http_kit::cookie::Cookie;
use http_kit::header::HeaderValue;
use http_kit::middleware::MiddlewareError;
#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use {
    async_fs,
    async_lock::Mutex as AsyncMutex,
    serde_json,
    std::{
        collections::HashMap,
        convert::TryFrom,
        io::ErrorKind,
        path::{Path, PathBuf},
        sync::{Arc, LazyLock},
    },
};

use time::OffsetDateTime;

/// Middleware for managing cookies in HTTP requests and responses.
#[derive(Debug)]
pub struct CookieStore {
    store: Vec<StoredCookie>,
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

impl Default for CookieStore {
    fn default() -> Self {
        Self {
            store: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            persistence: None,
        }
    }
}

impl CookieStore {
    /// Enable persistent storage using the default path for the current crate.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn persistent_default() -> Self {
        default_cookie_path().map_or_else(Self::default, Self::persistent_with_path)
    }

    /// Enable persistent storage using the provided path.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn persistent_with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            store: Vec::new(),
            persistence: Some(Persistence::new(path.into())),
        }
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
            let now = OffsetDateTime::now_utc();
            for stored in cookies {
                if let Some(cookie) = stored.into_cookie(now) {
                    self.store.push(cookie);
                }
            }
        }

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn persist_to_path(&self, path: &Path) -> Result<(), CookieError> {
        let lock = file_mutex(path).await;
        let _guard = lock.lock().await;

        let snapshot: Vec<PersistedCookie> = self
            .store
            .iter()
            .filter_map(PersistedCookie::from_cookie)
            .collect();
        let data = serde_json::to_vec(&snapshot).expect("failed to serialize cookies to JSON"); // Safety: Serialization should not fail.

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

        if !request.headers().contains_key(header::COOKIE) {
            let now = OffsetDateTime::now_utc();
            self.store.retain(|cookie| !cookie.is_expired(now));
            if let Some(header_value) = build_cookie_header(&self.store, request, now)
                .map_err(|_| MiddlewareError::Middleware(CookieError::InvalidCookieHeader))?
            {
                request.headers_mut().insert(header::COOKIE, header_value);
            }
        }

        let res = next
            .respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)?;

        let mut updated = false;
        let now = OffsetDateTime::now_utc();
        for set_cookie in res.headers().get_all(header::SET_COOKIE) {
            let set_cookie = set_cookie
                .to_str()
                .map_err(|_| MiddlewareError::Middleware(CookieError::InvalidCookieHeader))?;
            let cookie = set_cookie
                .parse::<Cookie>()
                .map_err(|_| MiddlewareError::Middleware(CookieError::InvalidCookieHeader))?;
            if apply_set_cookie(&mut self.store, request, cookie, now)
                .map_err(|_| MiddlewareError::Middleware(CookieError::InvalidCookieHeader))?
            {
                updated = true;
            }
        }
        self.finalize(updated)
            .await
            .map_err(MiddlewareError::Middleware)?;
        Ok(res)
    }
}

#[derive(Debug, Clone)]
struct StoredCookie {
    cookie: Cookie<'static>,
    domain: String,
    path: String,
    host_only: bool,
    expires_at: Option<OffsetDateTime>,
    secure: bool,
    http_only: bool,
}

impl StoredCookie {
    fn name(&self) -> &str {
        self.cookie.name()
    }

    fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|expiry| expiry <= now)
    }

    fn matches(&self, host: &str, path: &str, is_secure: bool) -> bool {
        if self.secure && !is_secure {
            return false;
        }

        if self.host_only {
            if host != self.domain {
                return false;
            }
        } else if !domain_matches(host, &self.domain) {
            return false;
        }

        path_matches(&self.path, path)
    }
}

fn apply_set_cookie(
    store: &mut Vec<StoredCookie>,
    request: &Request,
    cookie: Cookie<'static>,
    now: OffsetDateTime,
) -> Result<bool, CookieError> {
    let Some(host) = request.uri().host() else {
        return Ok(false);
    };
    let host = host.to_ascii_lowercase();
    let scheme = request.uri().scheme_str().unwrap_or("http");
    let is_secure_request = scheme.eq_ignore_ascii_case("https");

    let secure = cookie.secure().unwrap_or(false);
    if secure && !is_secure_request {
        return Ok(false);
    }

    let domain_attr = cookie.domain().map(|domain| domain.to_ascii_lowercase());
    if let Some(domain) = domain_attr.as_ref()
        && !domain_matches(&host, domain)
    {
        return Ok(false);
    }

    let host_only = domain_attr.is_none();
    let domain = domain_attr.unwrap_or_else(|| host.clone());

    let mut path = cookie
        .path()
        .map(str::to_string)
        .unwrap_or_else(|| default_path(request.uri().path()));
    if !path.starts_with('/') {
        path.insert(0, '/');
    }

    let expires_at = compute_expiration(&cookie, now);
    if expires_at.is_some_and(|expiry| expiry <= now) {
        remove_cookie(store, cookie.name(), &domain, &path, host_only);
        return Ok(true);
    }

    let http_only = cookie.http_only().unwrap_or(false);
    let stored = StoredCookie {
        cookie: cookie.into_owned(),
        domain,
        path,
        host_only,
        expires_at,
        secure,
        http_only,
    };

    remove_cookie(store, stored.name(), &stored.domain, &stored.path, stored.host_only);
    store.push(stored);
    Ok(true)
}

fn remove_cookie(store: &mut Vec<StoredCookie>, name: &str, domain: &str, path: &str, host_only: bool) {
    store.retain(|stored| {
        !(stored.name() == name
            && stored.domain == domain
            && stored.path == path
            && stored.host_only == host_only)
    });
}

fn build_cookie_header(
    store: &[StoredCookie],
    request: &Request,
    now: OffsetDateTime,
) -> Result<Option<HeaderValue>, CookieError> {
    let Some(host) = request.uri().host() else {
        return Ok(None);
    };
    let host = host.to_ascii_lowercase();
    let scheme = request.uri().scheme_str().unwrap_or("http");
    let is_secure_request = scheme.eq_ignore_ascii_case("https");
    let path = request.uri().path();

    let mut cookies = store
        .iter()
        .filter(|cookie| !cookie.is_expired(now))
        .filter(|cookie| cookie.matches(&host, path, is_secure_request))
        .collect::<Vec<_>>();

    if cookies.is_empty() {
        return Ok(None);
    }

    cookies.sort_by_key(|cookie| std::cmp::Reverse(cookie.path.len()));
    let value = cookies
        .into_iter()
        .map(|cookie| cookie.cookie.stripped().to_string())
        .collect::<Vec<_>>()
        .join("; ");

    if value.is_empty() {
        return Ok(None);
    }

    let header = HeaderValue::from_str(&value).map_err(|_| CookieError::InvalidCookieHeader)?;
    Ok(Some(header))
}

fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }

    if let Some(idx) = request_path.rfind('/') {
        if idx == 0 {
            return "/".to_string();
        }
        return request_path[..idx].to_string();
    }

    "/".to_string()
}

fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path == "/" {
        return true;
    }

    if !request_path.starts_with(cookie_path) {
        return false;
    }

    if cookie_path.ends_with('/') {
        return true;
    }

    request_path.len() == cookie_path.len()
        || request_path[cookie_path.len()..].starts_with('/')
}

fn domain_matches(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    host.ends_with(&format!(".{domain}"))
}

fn compute_expiration(cookie: &Cookie<'static>, now: OffsetDateTime) -> Option<OffsetDateTime> {
    if let Some(max_age) = cookie.max_age() {
        if max_age.is_positive() {
            return Some(now + max_age);
        }
        return Some(now);
    }

    cookie.expires_datetime()
}


#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct Persistence {
    path: PathBuf,
    initialized: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl Persistence {
    #[allow(clippy::missing_const_for_fn)]
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            initialized: false,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn default_cookie_path() -> Option<PathBuf> {
    let dir = dirs::data_local_dir()?;
    let crate_name = env!("CARGO_PKG_NAME");
    Some(dir.join(format!("zenwave_cookie_store_{crate_name}.json")))
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize, Deserialize)]
struct PersistedCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    host_only: bool,
    secure: bool,
    http_only: bool,
    expires: Option<i128>,
}

#[cfg(not(target_arch = "wasm32"))]
impl PersistedCookie {
    fn from_cookie(cookie: &StoredCookie) -> Option<Self> {
        let expires = cookie
            .expires_at
            .and_then(|dt| i64::try_from(dt.unix_timestamp()).ok())
            .map(i128::from);

        Some(Self {
            name: cookie.cookie.name().to_string(),
            value: cookie.cookie.value().to_string(),
            domain: cookie.domain.clone(),
            path: cookie.path.clone(),
            host_only: cookie.host_only,
            secure: cookie.secure,
            http_only: cookie.http_only,
            expires,
        })
    }

    fn into_cookie(self, now: OffsetDateTime) -> Option<StoredCookie> {
        let mut builder = Cookie::build((self.name, self.value))
            .path(self.path.clone())
            .secure(self.secure)
            .http_only(self.http_only);
        if !self.host_only {
            builder = builder.domain(self.domain.clone());
        }

        let expires_at = if let Some(timestamp) = self.expires
            && let Ok(secs) = i64::try_from(timestamp)
            && let Ok(datetime) = OffsetDateTime::from_unix_timestamp(secs)
        {
            builder = builder.expires(datetime);
            Some(datetime)
        } else {
            None
        };

        if expires_at.is_some_and(|expiry| expiry <= now) {
            return None;
        }

        Some(StoredCookie {
            cookie: builder.build(),
            domain: self.domain,
            path: self.path,
            host_only: self.host_only,
            expires_at,
            secure: self.secure,
            http_only: self.http_only,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
static COOKIE_FILE_LOCKS: LazyLock<AsyncMutex<HashMap<PathBuf, Arc<AsyncMutex<()>>>>> =
    LazyLock::new(|| AsyncMutex::new(HashMap::new()));

#[cfg(not(target_arch = "wasm32"))]
async fn file_mutex(path: &Path) -> Arc<AsyncMutex<()>> {
    let mut map = COOKIE_FILE_LOCKS.lock().await;
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

    #[test]
    fn persistent_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cookies.json");

        async_io::block_on(async {
            let mut store = CookieStore::persistent_with_path(path.clone());
            let mut request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://example.com")
                .body(Body::empty())
                .unwrap();

            let mut endpoint = SetCookieEndpoint;
            store.handle(&mut request, &mut endpoint).await.unwrap();

            let mut restored = CookieStore::persistent_with_path(path.clone());
            let mut echo = RecordingEndpoint::default();
            let mut request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://example.com")
                .body(Body::empty())
                .unwrap();
            restored.handle(&mut request, &mut echo).await.unwrap();

            let header = echo.last_cookie().expect("cookie header missing");
            assert!(header.contains("session=abc"));
            assert!(header.contains("theme=dark"));
        });
    }

    #[test]
    fn filters_cookie_domain_path_and_secure() {
        async_io::block_on(async {
            let mut store = CookieStore::default();
            let now = OffsetDateTime::now_utc();
            let base_request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://example.com/account/login")
                .body(Body::empty())
                .unwrap();

            apply_set_cookie(
                &mut store.store,
                &base_request,
                "id=one; Path=/account".parse().unwrap(),
                now,
            )
            .unwrap();
            apply_set_cookie(
                &mut store.store,
                &base_request,
                "secure=ok; Path=/; Secure".parse().unwrap(),
                now,
            )
            .unwrap();
            apply_set_cookie(
                &mut store.store,
                &base_request,
                "domain=wide; Domain=example.com; Path=/".parse().unwrap(),
                now,
            )
            .unwrap();

            let request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://example.com/account/profile")
                .body(Body::empty())
                .unwrap();
            let header = build_cookie_header(&store.store, &request, now)
                .unwrap()
                .expect("cookie header missing")
                .to_str()
                .unwrap()
                .to_string();
            assert!(header.contains("id=one"));
            assert!(header.contains("secure=ok"));
            assert!(header.contains("domain=wide"));

            let request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("http://example.com/account")
                .body(Body::empty())
                .unwrap();
            let header = build_cookie_header(&store.store, &request, now)
                .unwrap()
                .expect("cookie header missing")
                .to_str()
                .unwrap()
                .to_string();
            assert!(header.contains("id=one"));
            assert!(!header.contains("secure=ok"));

            let request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://sub.example.com/account")
                .body(Body::empty())
                .unwrap();
            let header = build_cookie_header(&store.store, &request, now)
                .unwrap()
                .expect("cookie header missing")
                .to_str()
                .unwrap()
                .to_string();
            assert!(!header.contains("id=one"));
            assert!(header.contains("domain=wide"));
        });
    }

    struct SetCookieEndpoint;

    impl Endpoint for SetCookieEndpoint {
        type Error = Infallible;
        async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .header(header::SET_COOKIE, "session=abc; Path=/")
                .header(header::SET_COOKIE, "theme=dark; Path=/")
                .body(Body::empty())
                .unwrap())
        }
    }

    #[derive(Default)]
    struct RecordingEndpoint {
        last_cookie: Option<String>,
    }

    impl RecordingEndpoint {
        fn last_cookie(&self) -> Option<String> {
            self.last_cookie.clone()
        }
    }

    impl Endpoint for RecordingEndpoint {
        type Error = Infallible;
        async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
            self.last_cookie = request
                .headers()
                .get(header::COOKIE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);

            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        }
    }
}
