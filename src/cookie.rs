//! Middleware for managing cookies in HTTP requests and responses.

use crate::header;
use crate::{Endpoint, Middleware, Request, Response, Result};
use http_kit::cookie::{Cookie, CookieJar};
use http_kit::header::HeaderValue;
use http_kit::{ResultExt, StatusCode};
#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use {
    async_fs, serde_json,
    std::{
        collections::HashMap,
        convert::TryFrom,
        io::ErrorKind,
        path::{Path, PathBuf},
        sync::{Arc, LazyLock},
    },
    tokio::sync::Mutex as AsyncMutex,
};

#[cfg(not(target_arch = "wasm32"))]
use time::OffsetDateTime;

/// Middleware for managing cookies in HTTP requests and responses.
#[derive(Debug)]
pub struct CookieStore {
    store: CookieJar,
    #[cfg(not(target_arch = "wasm32"))]
    persistence: Option<Persistence>,
}

impl Default for CookieStore {
    fn default() -> Self {
        Self {
            store: CookieJar::new(),
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
            store: CookieJar::new(),
            persistence: Some(Persistence::new(path.into())),
        }
    }

    async fn prepare(&mut self) -> Result<()> {
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

    async fn finalize(&self, updated: bool) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if updated && let Some(persistence) = &self.persistence {
                self.persist_to_path(&persistence.path).await?;
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_from_disk(&mut self, path: &Path) -> Result<()> {
        let lock = file_mutex(path).await;
        let _guard = lock.lock().await;

        let data = match async_fs::read(path).await {
            Ok(data) => data,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => return Err(http_kit::Error::new(err, StatusCode::INTERNAL_SERVER_ERROR)),
        };

        if !data.is_empty() {
            let cookies: Vec<PersistedCookie> = serde_json::from_slice(&data)
                .map_err(|err| http_kit::Error::new(err, StatusCode::BAD_GATEWAY))?;
            for stored in cookies {
                self.store.add(stored.into_cookie());
            }
        }

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn persist_to_path(&self, path: &Path) -> Result<()> {
        let lock = file_mutex(path).await;
        let _guard = lock.lock().await;

        let snapshot: Vec<PersistedCookie> = self
            .store
            .iter()
            .map(|cookie| PersistedCookie::from_cookie(cookie.clone()))
            .collect();
        let data = serde_json::to_vec(&snapshot)
            .map_err(|err| http_kit::Error::new(err, StatusCode::BAD_GATEWAY))?;

        if let Some(parent) = path.parent() {
            async_fs::create_dir_all(parent)
                .await
                ?;
        }

        let tmp = path.with_extension("tmp");
        async_fs::write(&tmp, &data)
            .await
            ?;
        async_fs::rename(&tmp, path)
            .await
            ?;

        Ok(())
    }
}

impl Middleware for CookieStore {
    async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
        self.prepare().await?;

        let cookie_header = self
            .store
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(";");

        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_maybe_shared(cookie_header).status(StatusCode::BAD_REQUEST)?,
        );

        let res = next.respond(request).await?;

        let mut updated = false;
        for set_cookie in res.headers().get_all(header::SET_COOKIE) {
            let set_cookie = set_cookie.to_str().status(StatusCode::BAD_REQUEST)?;
            let cookie = set_cookie
                .parse::<Cookie>()
                .status(StatusCode::BAD_REQUEST)?;
            self.store.add(cookie);
            updated = true;
        }
        self.finalize(updated).await?;
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
    domain: Option<String>,
    path: Option<String>,
    secure: bool,
    http_only: bool,
    expires: Option<i128>,
}

#[cfg(not(target_arch = "wasm32"))]
impl PersistedCookie {
    fn from_cookie(cookie: Cookie<'_>) -> Self {
        let owned = cookie.into_owned();
        Self {
            name: owned.name().to_string(),
            value: owned.value().to_string(),
            domain: owned.domain().map(ToString::to_string),
            path: owned.path().map(ToString::to_string),
            secure: owned.secure().unwrap_or(false),
            http_only: owned.http_only().unwrap_or(false),
            expires: owned
                .expires_datetime()
                .map(|dt| i128::from(dt.unix_timestamp())),
        }
    }

    fn into_cookie(self) -> Cookie<'static> {
        let mut builder = Cookie::build((self.name, self.value));
        if let Some(domain) = self.domain {
            builder = builder.domain(domain);
        }
        if let Some(path) = self.path {
            builder = builder.path(path);
        }
        builder = builder.secure(self.secure).http_only(self.http_only);
        if let Some(timestamp) = self.expires
            && let Ok(secs) = i64::try_from(timestamp)
            && let Ok(datetime) = OffsetDateTime::from_unix_timestamp(secs)
        {
            builder = builder.expires(datetime);
        }
        builder.build()
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
    use super::*;
    use http::{Request as HttpRequest, Response as HttpResponse};
    use http_kit::Body;
    use tempfile::tempdir;

    #[tokio::test]
    async fn persistent_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cookies.json");

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
    }

    struct SetCookieEndpoint;

    impl Endpoint for SetCookieEndpoint {
        async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
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
        async fn respond(&mut self, request: &mut Request) -> Result<Response> {
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
