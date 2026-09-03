//! Which proxy, if any, a destination is reached through.
//!
//! Rules follow the conventions every HTTP tool shares: `HTTP_PROXY`,
//! `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` in either case (lower-case wins,
//! as in curl), `NO_PROXY` entries as domains with their subdomains, IP
//! addresses, CIDR ranges or `*`. Matching is delegated to
//! [`hyper_util::client::proxy::matcher`] so zenwave behaves exactly like the
//! rest of the hyper ecosystem.

use std::{fmt, sync::Arc};

use base64::Engine as _;
use http::Uri;
use hyper_util::client::proxy::matcher::{self, Matcher};

/// A matched proxy for one destination: its URI and credentials.
pub type Intercept = matcher::Intercept;

/// The username and password from the proxy URI, whatever the proxy speaks:
/// the matcher pre-encodes them as `Basic` for HTTP proxies and keeps them
/// raw for SOCKS.
#[must_use]
pub fn credentials(intercept: &Intercept) -> Option<(String, String)> {
    if let Some((user, password)) = intercept.raw_auth() {
        return Some((user.to_owned(), password.to_owned()));
    }
    let header = intercept.basic_auth()?.to_str().ok()?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(header.strip_prefix("Basic ")?)
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, password) = text
        .split_once(':')
        .map_or((text.as_str(), ""), |(user, password)| (user, password));
    Some((user.to_owned(), password.to_owned()))
}

/// Proxy rules applied to every connection a [`super::Transport`] opens.
///
/// Cheap to clone; all clones share one rule set.
#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    matcher: Matcher,
    source: Source,
}

/// Where the rules came from, for backends that can defer to the OS entirely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The operating system's proxy configuration, environment included.
    System,
    /// Rules the program stated itself (including "no proxy").
    Explicit,
}

impl Proxy {
    /// The environment variables, then the operating system's proxy settings
    /// (macOS System Settings, the Windows internet options). This is the
    /// default for every transport.
    ///
    /// The Apple backend hands this case to `URLSession`, which also honours
    /// PAC scripts; the other backends resolve it in-process.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Matcher::from_system(), Source::System)
    }

    /// Only the environment variables, ignoring OS settings.
    #[must_use]
    pub fn env() -> Self {
        Self::new(Matcher::from_env(), Source::Explicit)
    }

    /// Connect directly, whatever the environment says.
    #[must_use]
    pub fn none() -> Self {
        Self::new(Matcher::builder().build(), Source::Explicit)
    }

    /// State the rules explicitly.
    #[must_use]
    pub fn builder() -> ProxyBuilder {
        ProxyBuilder {
            inner: Matcher::builder(),
        }
    }

    fn new(matcher: Matcher, source: Source) -> Self {
        Self {
            inner: Arc::new(Inner { matcher, source }),
        }
    }

    /// The proxy to use for `destination`, if any rule matches.
    #[must_use]
    pub fn intercept(&self, destination: &Uri) -> Option<Intercept> {
        self.inner.matcher.intercept(destination)
    }

    /// Where the rules came from.
    #[must_use]
    pub fn source(&self) -> Source {
        self.inner.source
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("source", &self.inner.source)
            .field("rules", &self.inner.matcher)
            .finish()
    }
}

/// Builder for explicit [`Proxy`] rules.
///
/// Proxy URIs take the form `scheme://[user:password@]host[:port]` with
/// `http`, `https`, `socks5` or `socks5h` schemes (`socks4`/`socks4a` are
/// understood by the curl backend only).
#[derive(Default)]
pub struct ProxyBuilder {
    inner: matcher::Builder,
}

impl fmt::Debug for ProxyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyBuilder").finish_non_exhaustive()
    }
}

impl ProxyBuilder {
    /// Use one proxy for both `http` and `https` destinations.
    #[must_use]
    pub fn all(mut self, proxy_uri: impl Into<String>) -> Self {
        self.inner = self.inner.all(proxy_uri.into());
        self
    }

    /// The proxy for `http` destinations.
    #[must_use]
    pub fn http(mut self, proxy_uri: impl Into<String>) -> Self {
        self.inner = self.inner.http(proxy_uri.into());
        self
    }

    /// The proxy for `https` destinations.
    #[must_use]
    pub fn https(mut self, proxy_uri: impl Into<String>) -> Self {
        self.inner = self.inner.https(proxy_uri.into());
        self
    }

    /// Destinations reached directly: a comma-separated list of domains
    /// (matching their subdomains), IP addresses, CIDR ranges, or `*`.
    #[must_use]
    pub fn no_proxy(mut self, list: impl Into<String>) -> Self {
        self.inner = self.inner.no(list.into());
        self
    }

    /// Finish the rules.
    #[must_use]
    pub fn build(self) -> Proxy {
        Proxy::new(self.inner.build(), Source::Explicit)
    }
}
