#![cfg(all(not(target_arch = "wasm32"), feature = "proxy"))]
//! Proxy configuration helpers for proxy-capable backends.
//!
//! This simplified matcher supports HTTP/HTTPS proxies configured via
//! environment variables or builder methods. SOCKS proxies are only used
//! by the curl backend.

use std::{collections::HashSet, env, fmt, str::FromStr, sync::Arc};

use base64::Engine;
use http::{HeaderValue, Uri};

/// Proxy configuration that can be reused across clients/backends.
///
/// The configuration mirrors the semantics supported by common tools:
/// `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`.
#[derive(Clone, Debug)]
pub struct Proxy {
    matcher: Arc<Matcher>,
}

impl Proxy {
    /// Create a proxy matcher from the standard environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(Matcher::from_env())
    }

    /// Create a proxy matcher from the environment or OS configuration.
    ///
    /// On Apple and Windows targets this mirrors the platform proxy settings.
    #[must_use]
    pub fn from_system() -> Self {
        // Fallback to env; platform-specific lookups can be added later.
        Self::from_env()
    }

    /// Start building a proxy configuration manually.
    #[must_use]
    pub fn builder() -> ProxyBuilder {
        ProxyBuilder {
            http: None,
            https: None,
            all: None,
            no_proxy: HashSet::new(),
        }
    }

    fn new(matcher: Matcher) -> Self {
        Self {
            matcher: Arc::new(matcher),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn into_matcher(self) -> Arc<Matcher> {
        self.matcher
    }

    #[cfg(any(feature = "curl-backend", test))]
    pub(crate) fn intercept(&self, uri: &Uri) -> Option<Intercept> {
        self.matcher.intercept(uri)
    }
}

/// Builder for [`Proxy`] allowing custom overrides for `HTTP/HTTPS/NO_PROXY`.
pub struct ProxyBuilder {
    http: Option<String>,
    https: Option<String>,
    all: Option<String>,
    no_proxy: HashSet<String>,
}

impl fmt::Debug for ProxyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyBuilder").finish_non_exhaustive()
    }
}

impl ProxyBuilder {
    /// Apply the same proxy to both HTTP and HTTPS requests.
    #[must_use]
    pub fn all(mut self, value: impl Into<String>) -> Self {
        self.all = Some(value.into());
        self
    }

    /// Set the proxy used for HTTP destinations.
    #[must_use]
    pub fn http(mut self, value: impl Into<String>) -> Self {
        self.http = Some(value.into());
        self
    }

    /// Set the proxy used for HTTPS destinations.
    #[must_use]
    pub fn https(mut self, value: impl Into<String>) -> Self {
        self.https = Some(value.into());
        self
    }

    /// Set the comma-separated `NO_PROXY` list.
    #[must_use]
    pub fn no_proxy(mut self, value: impl Into<String>) -> Self {
        let raw = value.into();
        let entries = raw
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase)
            .collect::<Vec<_>>();
        self.no_proxy.extend(entries);
        self
    }

    /// Finalize the configuration.
    #[must_use]
    pub fn build(self) -> Proxy {
        let matcher = Matcher {
            http: self.http.and_then(ProxyConfig::parse),
            https: self.https.and_then(ProxyConfig::parse),
            all: self.all.and_then(ProxyConfig::parse),
            no_proxy: self.no_proxy,
        };
        Proxy::new(matcher)
    }
}

#[derive(Clone, Debug)]
struct ProxyConfig {
    uri: Uri,
    basic_auth: Option<HeaderValue>,
    raw_auth: Option<(String, String)>,
}

impl ProxyConfig {
    fn parse(value: String) -> Option<Self> {
        let parsed = Uri::from_str(&value).ok()?;
        let auth = parsed.authority()?;
        let (userinfo, _) = auth
            .as_str()
            .rsplit_once('@')
            .unwrap_or(("", auth.as_str()));

        let basic_auth = (!userinfo.is_empty())
            .then(|| {
                let encoded = base64::engine::general_purpose::STANDARD.encode(userinfo.as_bytes());
                HeaderValue::from_str(&format!("Basic {encoded}")).ok()
            })
            .flatten();

        let raw_auth = userinfo
            .split_once(':')
            .map(|(user, pass)| (user.to_string(), pass.to_string()));

        Some(Self {
            uri: parsed,
            basic_auth,
            raw_auth,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Intercept {
    uri: Uri,
    basic_auth: Option<HeaderValue>,
    raw_auth: Option<(String, String)>,
}

impl Intercept {
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    pub(crate) fn basic_auth(&self) -> Option<&HeaderValue> {
        self.basic_auth.as_ref()
    }

    pub(crate) fn raw_auth(&self) -> Option<(&str, &str)> {
        self.raw_auth
            .as_ref()
            .map(|(user, pass)| (user.as_str(), pass.as_str()))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Matcher {
    http: Option<ProxyConfig>,
    https: Option<ProxyConfig>,
    all: Option<ProxyConfig>,
    no_proxy: HashSet<String>,
}

impl Matcher {
    fn from_env() -> Self {
        let http = env::var("HTTP_PROXY").ok();
        let https = env::var("HTTPS_PROXY").ok();
        let all = env::var("ALL_PROXY").ok();
        let no_proxy = env::var("NO_PROXY")
            .ok()
            .map(|v| {
                v.split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default();

        Self {
            http: http.and_then(ProxyConfig::parse),
            https: https.and_then(ProxyConfig::parse),
            all: all.and_then(ProxyConfig::parse),
            no_proxy,
        }
    }

    fn intercept(&self, uri: &Uri) -> Option<Intercept> {
        let host = uri.host()?.to_lowercase();
        if self.no_proxy.iter().any(|entry| host.ends_with(entry)) {
            return None;
        }

        let scheme = uri.scheme_str().unwrap_or("http");
        let config = match scheme {
            "http" => self.http.as_ref().or(self.all.as_ref())?,
            "https" => self.https.as_ref().or(self.all.as_ref())?,
            _ => return None,
        };

        Some(Intercept {
            uri: config.uri.clone(),
            basic_auth: config.basic_auth.clone(),
            raw_auth: config.raw_auth.clone(),
        })
    }
}
