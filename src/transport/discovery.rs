//! What a client knows about an origin's HTTP/3 support, and the policy over
//! it: which UDP port to race, when an HTTPS record lookup is owed, and how
//! long a failed QUIC handshake keeps the origin on TCP.
//!
//! [`H3Knowledge`] is plain state with `&mut self` methods. The hyper pool
//! keeps one per origin behind its entry's lock; the native backend's
//! per-thread pool owns one per origin outright.

use std::time::{Duration, Instant};

use http::HeaderMap;
use tracing::debug;

use super::alt_svc::{self, AltSvc};
use super::dns::HttpsRecord;
use crate::ResolveError;

/// How long a racing QUIC dial is given to finish before it loses; a detached
/// loser also ends at this deadline.
pub const H3_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// After a QUIC handshake fails, the origin is not offered QUIC again until
/// this much time has passed.
// `Duration::from_mins` is not a stable const fn yet.
#[expect(clippy::duration_suboptimal_units)]
pub const H3_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// A "no HTTPS record" answer is retried after this long — short enough to
/// pick a record up when one appears, long enough not to re-query per request.
// `Duration::from_mins` is not a stable const fn yet.
#[expect(clippy::duration_suboptimal_units)]
const HTTPS_RR_NEGATIVE_TTL: Duration = Duration::from_secs(5 * 60);

/// What the origin's HTTPS record says about HTTP/3 — negative answers are
/// cached for their TTL too.
#[derive(Clone, Copy, Debug)]
pub struct HttpsRr {
    /// The record's ALPN list advertises `h3`.
    pub h3: bool,
    /// The record's port override, if any.
    pub port: Option<u16>,
    /// When the cached answer stops being valid.
    pub expires: Instant,
}

impl HttpsRr {
    /// A cached negative answer: no record, or the lookup failed.
    pub(crate) fn negative(now: Instant) -> Self {
        Self {
            h3: false,
            port: None,
            expires: now + HTTPS_RR_NEGATIVE_TTL,
        }
    }

    /// The answer a lookup for `host`:`port` produced; a failed lookup is
    /// logged and cached as a negative answer rather than failing anything.
    pub(crate) fn from_lookup(
        lookup: Result<Option<HttpsRecord>, ResolveError>,
        host: &str,
        port: u16,
        now: Instant,
    ) -> Self {
        match lookup {
            Ok(Some(record)) => Self {
                h3: record.alpn.iter().any(|alpn| alpn == "h3"),
                port: record.port,
                expires: now + record.ttl,
            },
            Ok(None) => Self::negative(now),
            Err(error) => {
                debug!(%host, port, %error, "HTTPS record lookup failed");
                Self::negative(now)
            }
        }
    }
}

/// Where an origin's HTTPS record lookup stands.
#[derive(Clone, Copy, Debug)]
enum Discovery {
    /// No lookup has been issued.
    NotStarted,
    /// A lookup is in flight.
    InFlight,
    /// The lookup finished; `https_rr` holds the answer until it expires.
    Done,
}

/// One origin's HTTP/3 knowledge.
#[derive(Debug)]
pub struct H3Knowledge {
    /// The h3 alternative the origin last advertised through `Alt-Svc`.
    alt_svc: Option<AltSvc>,
    /// The origin's HTTPS record answer — positive or negative, until its
    /// TTL runs out.
    https_rr: Option<HttpsRr>,
    discovery: Discovery,
    /// QUIC to this origin is refused until this instant: the last QUIC
    /// handshake failed, so racing it again would just cost a timeout.
    broken_until: Option<Instant>,
    /// How long a racing QUIC dial is given; a test seam shrinks it so a
    /// dead UDP port falls back fast.
    connect_timeout: Duration,
    /// How long QUIC backoff lasts; a test seam lengthens it so a later
    /// request provably stays on TCP.
    backoff: Duration,
    /// The origin's port — the implicit `port` of an HTTPS record that
    /// overrides none.
    port: u16,
}

impl H3Knowledge {
    /// Nothing known yet about the origin on `port`.
    pub const fn new(port: u16) -> Self {
        Self {
            alt_svc: None,
            https_rr: None,
            discovery: Discovery::NotStarted,
            broken_until: None,
            connect_timeout: H3_CONNECT_TIMEOUT,
            backoff: H3_BACKOFF,
            port,
        }
    }

    /// Drops expired `Alt-Svc` and HTTPS answers.
    fn evict_expired(&mut self, now: Instant) {
        if self.alt_svc.is_some_and(|alt| alt.expires <= now) {
            self.alt_svc = None;
        }
        if self.https_rr.is_some_and(|rr| rr.expires <= now) {
            self.https_rr = None;
        }
    }

    /// Whether QUIC to the origin is in backoff.
    fn broken(&self, now: Instant) -> bool {
        self.broken_until.is_some_and(|until| until > now)
    }

    /// Whether anything here would change the next request's work: an
    /// unexpired `Alt-Svc` or HTTPS answer — a negative one included — or an
    /// active QUIC backoff. Expired values are evicted as they are read.
    pub fn is_live(&mut self, now: Instant) -> bool {
        self.evict_expired(now);
        self.broken(now) || self.alt_svc.is_some() || self.https_rr.is_some()
    }

    /// The UDP port an h3 dial to this origin should race for, or `None`
    /// when the origin has not advertised h3 (or QUIC is in backoff).
    /// `Alt-Svc` wins over the DNS answer, as the more recent claim.
    /// Expired knowledge is evicted as it is read.
    pub fn candidate(&mut self, now: Instant) -> Option<u16> {
        if self.broken(now) {
            return None;
        }
        self.evict_expired(now);
        if let Some(alt) = self.alt_svc {
            return Some(alt.port);
        }
        self.https_rr
            .and_then(|rr| rr.h3.then(|| rr.port.unwrap_or(self.port)))
    }

    /// Stores an `Alt-Svc` value: `accept` picks the origin's own h3
    /// alternative out of it, `clear` — and any advertisement with no
    /// acceptable h3 — drops the cached one. A malformed value is logged and
    /// ignored: it never fails the response that carried it.
    pub fn insert_alt_svc(&mut self, origin_host: &str, value: &str, now: Instant) {
        match alt_svc::parse(value) {
            Ok(advertised) => self.alt_svc = alt_svc::accept(&advertised, origin_host, now),
            Err(error) => debug!(%value, %error, "ignoring malformed Alt-Svc header"),
        }
    }

    /// Marks an HTTPS record lookup in flight when one is owed — none
    /// issued, or the cached answer is stale. `false` means a lookup is
    /// running or the fresh answer stands. Every `true` is followed by
    /// [`end_discovery`](Self::end_discovery).
    pub fn begin_discovery(&mut self, now: Instant) -> bool {
        let due = match self.discovery {
            Discovery::NotStarted => true,
            Discovery::InFlight => false,
            Discovery::Done => self.https_rr.is_none_or(|rr| rr.expires <= now),
        };
        if due {
            self.discovery = Discovery::InFlight;
        }
        due
    }

    /// Ends the lookup [`begin_discovery`](Self::begin_discovery) started,
    /// storing its answer when it produced one.
    pub const fn end_discovery(&mut self, answer: Option<HttpsRr>) {
        if let Some(rr) = answer {
            self.insert_https_rr(rr);
        }
        self.discovery = Discovery::Done;
    }

    /// Caches an HTTPS record answer, positive or negative.
    pub const fn insert_https_rr(&mut self, rr: HttpsRr) {
        self.https_rr = Some(rr);
    }

    /// A QUIC handshake to this origin failed; no h3 attempt until the
    /// backoff lapses.
    pub fn mark_broken(&mut self, now: Instant) {
        self.broken_until = Some(now + self.backoff);
    }

    /// How long a racing QUIC dial is given to finish.
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Overrides the QUIC dial deadline and failure backoff — the race tests
    /// shorten the deadline so a dead UDP port falls back fast.
    #[cfg(all(test, http3))]
    pub const fn set_timeouts(&mut self, connect_timeout: Duration, backoff: Duration) {
        self.connect_timeout = connect_timeout;
        self.backoff = backoff;
    }

    /// The cached HTTPS record answer — tests read it to see discovery ran.
    #[cfg(all(test, http3))]
    pub const fn https_rr(&self) -> Option<HttpsRr> {
        self.https_rr
    }

    /// When QUIC backoff ends, if it is active — tests read it to see a
    /// failed handshake put the origin into backoff.
    #[cfg(all(test, http3))]
    pub const fn broken_until(&self) -> Option<Instant> {
        self.broken_until
    }
}

/// A response's `Alt-Svc` fields as one comma-joined list (RFC 9110): a field
/// carrying `clear` or no usable h3 must not erase what its siblings
/// advertised. Non-ASCII values are logged and skipped; `None` when there is
/// nothing to record.
pub fn joined_alt_svc(headers: &HeaderMap) -> Option<String> {
    let mut joined = String::new();
    for value in headers.get_all(http::header::ALT_SVC) {
        if let Ok(value) = value.to_str() {
            if !joined.is_empty() {
                joined.push(',');
            }
            joined.push_str(value);
        } else {
            debug!(?value, "ignoring non-ASCII Alt-Svc header");
        }
    }
    (!joined.is_empty()).then_some(joined)
}
