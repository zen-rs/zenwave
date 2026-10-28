//! Middleware for managing cookies in HTTP requests and responses.

use crate::header;
use crate::{Endpoint, Middleware, Request, Response};
use cookie_store::{CookieStore as Store, RawCookie};
use http::HeaderMap;
use http_kit::HttpError;
use http_kit::header::HeaderValue;
use http_kit::middleware::MiddlewareError;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
use {
    async_fs,
    async_lock::Mutex as AsyncMutex,
    std::{
        collections::HashMap,
        io::ErrorKind,
        path::{Path, PathBuf},
        sync::{Arc, LazyLock},
    },
};

/// Middleware for managing cookies in HTTP requests and responses.
#[derive(Debug, Default)]
pub struct CookieStore {
    store: Store,
    #[cfg(not(target_arch = "wasm32"))]
    persistence: Option<Persistence>,
}

/// The jar [`CookieStore`] lends to the chain through `request.extensions`
/// while it waits on `next`.
///
/// `FollowRedirect` reads it on each hop: it stores the hop response's
/// `Set-Cookie` headers against the hop's URL and builds the next hop's
/// `Cookie` header from it. `CookieStore` takes the jar back out of
/// `extensions` before `handle` returns — on the error path too — so
/// exactly one place owns it at a time. `Clone` exists only because
/// `http::Extensions` requires it; the jar is moved, never copied, and a
/// `Clone` made by `Extensions::clone` (e.g. `Retry`'s replay snapshot)
/// only ever replaces the request it came from.
#[derive(Debug, Default, Clone)]
pub(crate) struct RequestCookieJar {
    /// The jar, owned by the request until `CookieStore` takes it back.
    pub(crate) store: Store,
    /// The URL the chain's last response came from — the final redirect
    /// hop — or `None` when the request URL never changed. `CookieStore`
    /// stores the returned response's `Set-Cookie` headers against it.
    pub(crate) response_url: Option<Url>,
    /// Set when the store changed while lent out: the jar needs
    /// persisting even when the response carries no `Set-Cookie`.
    pub(crate) changed: bool,
}

/// The `Cookie` header value `store` sends with a request to `url`, or
/// `None` when no stored cookie matches it.
pub(crate) fn cookie_header(store: &Store, url: &Url) -> Option<HeaderValue> {
    let value = store
        .get_request_values(url)
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    if value.is_empty() {
        return None;
    }
    HeaderValue::from_str(&value).ok()
}

/// Parse `headers`' `Set-Cookie` values into `store` as received from
/// `url`, returning whether the store changed. A malformed `Set-Cookie` is
/// skipped rather than failing the request or dropping the valid ones.
pub(crate) fn store_response_cookies(store: &mut Store, headers: &HeaderMap, url: &Url) -> bool {
    let mut changed = false;
    for header in headers.get_all(header::SET_COOKIE) {
        let Ok(value) = header.to_str() else {
            continue;
        };
        match RawCookie::parse(value.to_owned()) {
            Ok(cookie) => changed |= store.insert_raw(&cookie, url).is_ok(),
            Err(error) => {
                tracing::debug!(%error, value, "skipping malformed Set-Cookie header");
            }
        }
    }
    changed
}

/// Errors encountered while handling HTTP cookies.
#[derive(Debug, thiserror::Error)]
pub enum CookieError {
    /// Failed to read persisted cookies from disk.
    #[error("Failed to load cookies from disk: {0}")]
    FailToLoadCookiesFromDisk(std::io::Error),

    /// Failed to decode persisted cookie data.
    #[error("Failed to parse cookies from disk: {0}")]
    FailToParseCookiesFromDisk(cookie_store::Error),

    /// Failed to write cookies to the persistence layer.
    #[error("Failed to persist cookies to disk: {0}")]
    FailToPersistCookiesToDisk(cookie_store::Error),
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
        };

        Self::Cookie(kind)
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
            store: Store::default(),
            persistence: Some(Persistence::new(path.into())),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn prepare(&mut self) -> Result<(), CookieError> {
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
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn finalize(&self, updated: bool) -> Result<(), CookieError> {
        if updated && let Some(persistence) = &self.persistence {
            self.persist_to_path(&persistence.path).await?;
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
            self.store = cookie_store::serde::json::load_all(&data[..])
                .map_err(CookieError::FailToParseCookiesFromDisk)?;
        }

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn persist_to_path(&self, path: &Path) -> Result<(), CookieError> {
        let lock = file_mutex(path).await;
        let _guard = lock.lock().await;

        let mut data = Vec::new();
        // Everything in the jar is written, session cookies included — a
        // reload reproduces the jar exactly.
        cookie_store::serde::json::save_incl_expired_and_nonpersistent(&self.store, &mut data)
            .map_err(CookieError::FailToPersistCookiesToDisk)?;

        if let Some(parent) = path.parent() {
            async_fs::create_dir_all(parent)
                .await
                .map_err(|e| CookieError::FailToPersistCookiesToDisk(e.into()))?;
        }

        let tmp = path.with_extension("tmp");
        async_fs::write(&tmp, &data)
            .await
            .map_err(|e| CookieError::FailToPersistCookiesToDisk(e.into()))?;
        async_fs::rename(&tmp, path)
            .await
            .map_err(|e| CookieError::FailToPersistCookiesToDisk(e.into()))?;

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
        // Persistence exists only on native targets; on wasm32 there is
        // nothing to prepare or finalize.
        #[cfg(not(target_arch = "wasm32"))]
        self.prepare().await.map_err(MiddlewareError::Middleware)?;

        let request_url = Url::parse(&request.uri().to_string()).ok();
        if let Some(url) = &request_url
            && let Some(cookie) = cookie_header(&self.store, url)
        {
            request.headers_mut().insert(header::COOKIE, cookie);
        }

        // Lend the jar to the chain: `FollowRedirect` finds it in the
        // request's extensions and handles cookies per hop. It is taken
        // back below on both paths — `next` erroring must not strand it.
        request.extensions_mut().insert(RequestCookieJar {
            store: std::mem::take(&mut self.store),
            response_url: None,
            changed: false,
        });

        let result = next.respond(request).await;

        let mut jar = request
            .extensions_mut()
            .remove::<RequestCookieJar>()
            .expect("an endpoint below CookieStore dropped the request's extensions");
        self.store = std::mem::take(&mut jar.store);

        match result {
            Ok(response) => {
                if let Some(url) = jar.response_url.or(request_url) {
                    jar.changed |=
                        store_response_cookies(&mut self.store, response.headers(), &url);
                }
                #[cfg(not(target_arch = "wasm32"))]
                self.finalize(jar.changed)
                    .await
                    .map_err(MiddlewareError::Middleware)?;
                Ok(response)
            }
            Err(err) => {
                #[cfg(not(target_arch = "wasm32"))]
                if let Err(persist) = self.finalize(jar.changed).await {
                    tracing::warn!(error = %persist, "failed to persist cookies after endpoint error");
                }
                Err(MiddlewareError::Endpoint(err))
            }
        }
    }
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
    fn cookies_are_scoped_to_their_domain_and_path() {
        async_io::block_on(async {
            let mut store = CookieStore::default();
            let mut endpoint = ScopedEndpoint;
            let mut request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://example.com/private/start")
                .body(Body::empty())
                .unwrap();
            store.handle(&mut request, &mut endpoint).await.unwrap();

            // `home` (Path=/) reaches /other, `deep` (Path=/private) does not.
            let mut echo = RecordingEndpoint::default();
            let mut request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://example.com/other")
                .body(Body::empty())
                .unwrap();
            store.handle(&mut request, &mut echo).await.unwrap();
            let header = echo.last_cookie().expect("cookie header missing");
            assert!(header.contains("home=1"));
            assert!(!header.contains("deep=1"));

            // Nothing scoped to example.com leaves for another host.
            let mut echo = RecordingEndpoint::default();
            let mut request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://other.test/")
                .body(Body::empty())
                .unwrap();
            store.handle(&mut request, &mut echo).await.unwrap();
            assert!(echo.last_cookie().is_none());
        });
    }

    #[test]
    fn secure_cookies_are_not_sent_over_http() {
        async_io::block_on(async {
            let mut store = CookieStore::default();
            let mut endpoint = SecureEndpoint;
            let mut request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("https://example.com/")
                .body(Body::empty())
                .unwrap();
            store.handle(&mut request, &mut endpoint).await.unwrap();

            let mut echo = RecordingEndpoint::default();
            let mut request = HttpRequest::builder()
                .method(http_kit::Method::GET)
                .uri("http://example.com/")
                .body(Body::empty())
                .unwrap();
            store.handle(&mut request, &mut echo).await.unwrap();
            assert!(echo.last_cookie().is_none());
        });
    }

    struct SetCookieEndpoint;

    impl Endpoint for SetCookieEndpoint {
        type Error = Infallible;
        fn respond(
            &mut self,
            _request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Response, Self::Error>> {
            std::future::ready(Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .header(header::SET_COOKIE, "session=abc; Path=/")
                .header(header::SET_COOKIE, "theme=dark; Path=/")
                .body(Body::empty())
                .unwrap()))
        }
    }

    struct ScopedEndpoint;

    impl Endpoint for ScopedEndpoint {
        type Error = Infallible;
        fn respond(
            &mut self,
            _request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Response, Self::Error>> {
            std::future::ready(Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .header(header::SET_COOKIE, "home=1; Path=/")
                .header(header::SET_COOKIE, "deep=1; Path=/private")
                .body(Body::empty())
                .unwrap()))
        }
    }

    struct SecureEndpoint;

    impl Endpoint for SecureEndpoint {
        type Error = Infallible;
        fn respond(
            &mut self,
            _request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Response, Self::Error>> {
            std::future::ready(Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .header(header::SET_COOKIE, "locked=1; Secure; Path=/")
                .body(Body::empty())
                .unwrap()))
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
                .unwrap()))
        }
    }
}
