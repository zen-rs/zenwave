//! Per-request transport timeouts.

use core::time::Duration;

use http_kit::Deadlines;

/// Per-request transport timeouts, carried in the request's extensions.
///
/// A field left unset takes the transport's default
/// ([`TransportBuilder::connect_timeout`](crate::TransportBuilder::connect_timeout),
/// `response_head_timeout` and `body_idle_timeout`); [`Duration::MAX`] asks
/// for no bound. A request sets them through its builder's
/// `connect_timeout`, `response_head_timeout` and `body_idle_timeout`, or
/// inserts the value into its extensions itself.
///
/// Only the native backend applies them. Every other backend answers a
/// request that carries one with
/// [`ConfigError::Unsupported`](crate::ConfigError::Unsupported).
///
/// # Examples
///
/// ```rust
/// use core::time::Duration;
/// use zenwave::Timeouts;
///
/// let mut request = zenwave::Request::new(zenwave::Body::empty());
/// request.extensions_mut().insert(
///     Timeouts::default()
///         .with_connect(Duration::from_secs(3))
///         .with_response_head(Duration::from_secs(10))
///         .with_body_idle(Duration::from_secs(30)),
/// );
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Timeouts {
    /// How long the request may wait for a connection: a pooled one, or one
    /// a dial opens (resolution, TCP, proxy, TLS). It bounds the request's
    /// wait, not the dial, which belongs to the origin and serves the next
    /// waiter. Expiry fails the request with
    /// [`TimedOut::Connect`](crate::TimedOut::Connect) and the phase the
    /// connection was in.
    pub connect: Option<Duration>,
    /// The response-head and body-idle deadlines, handed to the protocol
    /// crate with the request.
    pub exchange: Deadlines,
}

impl Timeouts {
    /// `self` with the connect timeout set. The struct is
    /// `#[non_exhaustive]`, so other crates build it from [`Default`]
    /// through these setters.
    #[must_use]
    pub const fn with_connect(mut self, timeout: Duration) -> Self {
        self.connect = Some(timeout);
        self
    }

    /// `self` with the response-head deadline set
    /// ([`Deadlines::response_head`]).
    #[must_use]
    pub const fn with_response_head(mut self, timeout: Duration) -> Self {
        self.exchange = self.exchange.with_response_head(timeout);
        self
    }

    /// `self` with the body-idle deadline set ([`Deadlines::body_idle`]).
    #[must_use]
    pub const fn with_body_idle(mut self, timeout: Duration) -> Self {
        self.exchange = self.exchange.with_body_idle(timeout);
        self
    }

    /// `self`, with every unset field taken from `defaults`.
    #[must_use]
    pub const fn or(self, defaults: Self) -> Self {
        let mut resolved = self;
        if resolved.connect.is_none() {
            resolved.connect = defaults.connect;
        }
        if resolved.exchange.response_head.is_none() {
            resolved.exchange.response_head = defaults.exchange.response_head;
        }
        if resolved.exchange.body_idle.is_none() {
            resolved.exchange.body_idle = defaults.exchange.body_idle;
        }
        resolved
    }
}

/// Refuses a request that carries [`Timeouts`], for a backend that applies
/// none of them: a bound the caller asked for is never dropped silently.
///
/// # Errors
///
/// [`ConfigError::Unsupported`](crate::ConfigError::Unsupported) when the
/// request carries `Timeouts`.
#[cfg(any(
    browser,
    apple_backend,
    all(reactor, feature = "hyper-backend"),
    all(reactor, feature = "curl-backend")
))]
pub fn refuse(request: &http_kit::Request) -> Result<(), crate::Error> {
    if request.extensions().get::<Timeouts>().is_some() {
        return Err(crate::Error::Config(crate::ConfigError::Unsupported {
            what: "per-request timeouts",
        }));
    }
    Ok(())
}
