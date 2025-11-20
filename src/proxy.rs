#![cfg(all(not(target_arch = "wasm32"), feature = "proxy-support"))]
//! Proxy configuration helpers for proxy-capable backends.

use std::{fmt, sync::Arc};

use http::Uri;
use hyper_util::client::proxy::matcher;

/// Proxy configuration that can be reused across clients/backends.
///
/// The configuration mirrors the semantics supported by `curl` and `reqwest`.
/// You can construct it from environment variables (`Proxy::from_env()`),
/// inherit system defaults (`Proxy::from_system()`), or build it manually
/// through [`Proxy::builder()`].
#[derive(Clone, Debug)]
pub struct Proxy {
    matcher: Arc<matcher::Matcher>,
}

impl Proxy {
    /// Create a proxy matcher from the standard environment variables.
    ///
    /// This reads `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`.
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(matcher::Matcher::from_env())
    }

    /// Create a proxy matcher from the environment or OS configuration.
    ///
    /// On Apple and Windows targets this mirrors the platform proxy settings.
    #[must_use]
    pub fn from_system() -> Self {
        Self::new(matcher::Matcher::from_system())
    }

    /// Start building a proxy configuration manually.
    #[must_use]
    pub fn builder() -> ProxyBuilder {
        ProxyBuilder {
            inner: matcher::Matcher::builder(),
        }
    }

    fn new(matcher: matcher::Matcher) -> Self {
        Self {
            matcher: Arc::new(matcher),
        }
    }

    pub(crate) fn into_matcher(self) -> Arc<matcher::Matcher> {
        self.matcher
    }

    #[cfg(any(feature = "curl-backend", test))]
    pub(crate) fn intercept(&self, uri: &Uri) -> Option<matcher::Intercept> {
        self.matcher.intercept(uri)
    }
}

/// Builder for [`Proxy`] allowing custom overrides for HTTP/HTTPS/NO_PROXY.
pub struct ProxyBuilder {
    inner: matcher::Builder,
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
        self.inner = self.inner.all(value.into());
        self
    }

    /// Set the proxy used for HTTP destinations.
    #[must_use]
    pub fn http(mut self, value: impl Into<String>) -> Self {
        self.inner = self.inner.http(value.into());
        self
    }

    /// Set the proxy used for HTTPS destinations.
    #[must_use]
    pub fn https(mut self, value: impl Into<String>) -> Self {
        self.inner = self.inner.https(value.into());
        self
    }

    /// Set the comma-separated `NO_PROXY` list.
    #[must_use]
    pub fn no_proxy(mut self, value: impl Into<String>) -> Self {
        self.inner = self.inner.no(value.into());
        self
    }

    /// Finalize the configuration.
    #[must_use]
    pub fn build(self) -> Proxy {
        Proxy::new(self.inner.build())
    }
}

#[cfg(test)]
mod tests {
    use super::Proxy;
    use http::Uri;

    #[test]
    fn builder_intercepts_http() {
        let proxy = Proxy::builder().http("http://localhost:8080").build();
        let uri: Uri = "http://example.com".parse().unwrap();
        let intercept = proxy.intercept(&uri).expect("intercept");
        assert_eq!(
            intercept.uri().authority().map(|a| a.as_str()),
            Some("localhost:8080")
        );
    }

    #[test]
    fn builder_respects_no_proxy() {
        let proxy = Proxy::builder()
            .http("http://localhost:8080")
            .no_proxy("example.com")
            .build();
        let uri: Uri = "http://example.com".parse().unwrap();
        assert!(proxy.intercept(&uri).is_none());
    }
}
