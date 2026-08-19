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
    ///
    /// Reads `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`, each also
    /// accepted in lowercase, which is the more common spelling for `http_proxy`.
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

    /// Whether requests to `uri` are routed through a proxy.
    ///
    /// Returns `false` for destinations covered by `NO_PROXY`, for schemes other
    /// than `http`/`https`, and when no proxy is configured for the scheme.
    #[must_use]
    pub fn intercepts(&self, uri: &Uri) -> bool {
        self.matcher.intercept(uri).is_some()
    }

    /// Address of the proxy that serves `uri`, without any credentials.
    ///
    /// Credentials belong in the `Proxy-Authorization` header rather than the
    /// connect address; see [`Proxy::proxy_authorization`].
    #[must_use]
    pub fn proxy_uri(&self, uri: &Uri) -> Option<String> {
        let intercept = self.matcher.intercept(uri)?;
        let proxy = intercept.uri();
        let authority = proxy.authority()?;
        Some(format!(
            "{}://{authority}",
            proxy.scheme_str().unwrap_or("http")
        ))
    }

    /// `Proxy-Authorization` header value for `uri`, when the proxy needs credentials.
    #[must_use]
    pub fn proxy_authorization(&self, uri: &Uri) -> Option<String> {
        self.matcher
            .intercept(uri)?
            .basic_auth()
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

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
        self.no_proxy.extend(parse_no_proxy(&value.into()));
        self
    }

    /// Finalize the configuration.
    #[must_use]
    pub fn build(self) -> Proxy {
        let matcher = Matcher {
            http: self.http.as_deref().and_then(ProxyConfig::parse),
            https: self.https.as_deref().and_then(ProxyConfig::parse),
            all: self.all.as_deref().and_then(ProxyConfig::parse),
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
    fn parse(value: &str) -> Option<Self> {
        let parsed = Uri::from_str(value).ok()?;
        let authority = parsed.authority()?;
        let (userinfo, host_port) = authority
            .as_str()
            .rsplit_once('@')
            .unwrap_or(("", authority.as_str()));

        let basic_auth = (!userinfo.is_empty())
            .then(|| {
                let encoded = base64::engine::general_purpose::STANDARD.encode(userinfo.as_bytes());
                HeaderValue::from_str(&format!("Basic {encoded}")).ok()
            })
            .flatten();

        let raw_auth = userinfo
            .split_once(':')
            .map(|(user, pass)| (user.to_string(), pass.to_string()));

        // Rebuild the address without the userinfo: credentials are sent in the
        // `Proxy-Authorization` header, not in the address we connect to.
        let uri = if userinfo.is_empty() {
            parsed
        } else {
            let mut parts = parsed.clone().into_parts();
            parts.authority = host_port.parse().ok();
            // Uri::from_parts needs a path when an authority is present.
            if parts.path_and_query.is_none() {
                parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
            }
            Uri::from_parts(parts).unwrap_or(parsed)
        };

        Some(Self {
            uri,
            basic_auth,
            raw_auth,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Intercept {
    uri: Uri,
    basic_auth: Option<HeaderValue>,
    /// Username/password kept unencoded for libcurl, which does its own encoding.
    #[cfg_attr(not(feature = "curl-backend"), allow(dead_code))]
    raw_auth: Option<(String, String)>,
}

impl Intercept {
    pub(crate) const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Host of the proxy to connect to.
    #[cfg(feature = "hyper-backend")]
    pub(crate) fn host(&self) -> Option<&str> {
        self.uri.host()
    }

    /// Port of the proxy, defaulting to the scheme's usual port.
    #[cfg(feature = "hyper-backend")]
    pub(crate) fn port(&self) -> u16 {
        if let Some(port) = self.uri.port_u16() {
            return port;
        }
        if self.uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    }

    pub(crate) const fn basic_auth(&self) -> Option<&HeaderValue> {
        self.basic_auth.as_ref()
    }

    #[cfg(feature = "curl-backend")]
    pub(crate) fn raw_auth(&self) -> Option<(&str, &str)> {
        self.raw_auth
            .as_ref()
            .map(|(user, pass)| (user.as_str(), pass.as_str()))
    }
}

/// Whether `host` is exempted by a `NO_PROXY` entry.
///
/// An entry matches the host itself or any of its subdomains, but not a
/// different host that merely ends with the same text.
fn host_matches_no_proxy(host: &str, entry: &str) -> bool {
    if entry == "*" || host == entry {
        return true;
    }
    host.strip_suffix(entry)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

#[derive(Clone, Debug)]
pub(crate) struct Matcher {
    http: Option<ProxyConfig>,
    https: Option<ProxyConfig>,
    all: Option<ProxyConfig>,
    no_proxy: HashSet<String>,
}

/// Read an environment variable, accepting either case of its name.
fn proxy_env(name: &str) -> Option<String> {
    env::var(name.to_uppercase())
        .or_else(|_| env::var(name.to_lowercase()))
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Split a `NO_PROXY`-style list into lowercase host suffixes.
fn parse_no_proxy(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|entry| entry.trim().trim_start_matches('.').to_lowercase())
        .filter(|entry| !entry.is_empty())
        .collect()
}

impl Matcher {
    fn from_env() -> Self {
        let http = proxy_env("HTTP_PROXY");
        let https = proxy_env("HTTPS_PROXY");
        let all = proxy_env("ALL_PROXY");
        let no_proxy = proxy_env("NO_PROXY")
            .map(|raw| parse_no_proxy(&raw))
            .unwrap_or_default();

        Self {
            http: http.as_deref().and_then(ProxyConfig::parse),
            https: https.as_deref().and_then(ProxyConfig::parse),
            all: all.as_deref().and_then(ProxyConfig::parse),
            no_proxy,
        }
    }

    fn intercept(&self, uri: &Uri) -> Option<Intercept> {
        let host = uri.host()?.trim_matches('.').to_lowercase();
        if host.is_empty() {
            return None;
        }
        if self
            .no_proxy
            .iter()
            .any(|entry| host_matches_no_proxy(&host, entry))
        {
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
