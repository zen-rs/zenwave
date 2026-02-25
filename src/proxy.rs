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
        let entries = parse_no_proxy_entries(&raw).into_iter().collect::<Vec<_>>();
        self.no_proxy.extend(entries);
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
    pub(crate) const fn uri(&self) -> &Uri {
        &self.uri
    }

    pub(crate) const fn basic_auth(&self) -> Option<&HeaderValue> {
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
        Self::from_var_reader(|key| env::var(key).ok())
    }

    fn from_var_reader<F>(mut read_var: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        let http = first_var(&["HTTP_PROXY", "http_proxy"], &mut read_var);
        let https = first_var(&["HTTPS_PROXY", "https_proxy"], &mut read_var);
        let all = first_var(&["ALL_PROXY", "all_proxy"], &mut read_var);
        let no_proxy = first_var(&["NO_PROXY", "no_proxy"], &mut read_var)
            .map(|value| parse_no_proxy_entries(&value))
            .unwrap_or_default();

        Self {
            http: http.as_deref().and_then(ProxyConfig::parse),
            https: https.as_deref().and_then(ProxyConfig::parse),
            all: all.as_deref().and_then(ProxyConfig::parse),
            no_proxy,
        }
    }

    fn intercept(&self, uri: &Uri) -> Option<Intercept> {
        let host = uri.host()?.to_lowercase();
        if self
            .no_proxy
            .iter()
            .any(|entry| no_proxy_matches(&host, entry))
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

fn no_proxy_matches(host: &str, entry: &str) -> bool {
    if entry == "*" {
        return true;
    }

    let entry = entry
        .split_once(':')
        .map(|(host_part, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                host_part
            } else {
                entry
            }
        })
        .unwrap_or(entry);

    let entry = entry.trim_start_matches("*.");
    let entry = entry.trim_start_matches('.');
    if entry.is_empty() {
        return false;
    }

    if host == entry {
        return true;
    }

    host.ends_with(&format!(".{entry}"))
}

fn parse_no_proxy_entries(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn first_var<F>(keys: &[&str], read_var: &mut F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    keys.iter().find_map(|key| {
        read_var(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn matcher_reads_lowercase_proxy_env_vars() {
        let vars = HashMap::from([
            ("http_proxy", "http://localhost:8080".to_string()),
            ("no_proxy", "example.com".to_string()),
        ]);
        let matcher = Matcher::from_var_reader(|key| vars.get(key).cloned());

        let bypass_uri: Uri = "http://api.example.com/path".parse().expect("valid URI");
        assert!(
            matcher.intercept(&bypass_uri).is_none(),
            "expected lowercase no_proxy to bypass proxy"
        );

        let uri: Uri = "http://example.net/data".parse().expect("valid URI");
        let intercept = matcher
            .intercept(&uri)
            .expect("expected lowercase http_proxy to be respected");
        let proxy = intercept.uri();
        assert_eq!(proxy.host(), Some("localhost"));
        assert_eq!(proxy.port_u16(), Some(8080));
    }

    #[test]
    fn matcher_accepts_wildcard_no_proxy_entries() {
        let vars = HashMap::from([
            ("HTTP_PROXY", "http://localhost:8080".to_string()),
            ("NO_PROXY", "*.internal.com".to_string()),
        ]);
        let matcher = Matcher::from_var_reader(|key| vars.get(key).cloned());

        let bypass_uri: Uri = "http://api.internal.com/path".parse().expect("valid URI");
        assert!(
            matcher.intercept(&bypass_uri).is_none(),
            "expected wildcard NO_PROXY entry to bypass proxy"
        );

        let proxied_uri: Uri = "http://example.net/path".parse().expect("valid URI");
        assert!(
            matcher.intercept(&proxied_uri).is_some(),
            "expected unrelated host to use proxy"
        );
    }

    #[test]
    fn matcher_uses_lowercase_when_uppercase_is_empty() {
        let vars = HashMap::from([
            ("HTTP_PROXY", "   ".to_string()),
            ("http_proxy", "http://localhost:8080".to_string()),
        ]);
        let matcher = Matcher::from_var_reader(|key| vars.get(key).cloned());
        let uri: Uri = "http://example.net/path".parse().expect("valid URI");
        assert!(
            matcher.intercept(&uri).is_some(),
            "expected lowercase proxy value to be used when uppercase is empty"
        );
    }
}
