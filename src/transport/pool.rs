//! The per-origin connection pool every hyper backend shares through its
//! [`Transport`](crate::Transport).
//!
//! `zenwave::get()` and friends build a client per call, so pooling lives on
//! the transport: one table keyed by [`Origin`]. An entry remembers the
//! protocol the origin was found to speak, holds a set of idle HTTP/1.1
//! senders leased out exclusively, and — with the `http2` feature — the one
//! h2 handle every request clones. Dead and expired idle connections are
//! evicted lazily at checkout; there is no sweeper task. The Alt-Svc /
//! HTTPS-RR knowledge and the h3 handle join the entry in #69 as plain
//! additional fields.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_lock::{MutexGuardArc, Semaphore, SemaphoreGuardArc};
use http::{Request, Response, uri::Scheme};
#[cfg(feature = "http2")]
use hyper::client::conn::http2;
use hyper::{
    body::Incoming,
    client::conn::{TrySendError, http1},
};

use super::connect::{Protocol, Via};

/// The most HTTP/1.1 connections one origin may have open at once: leased
/// or dialing — parked idle connections hold no slot and a new lease always
/// takes one first.
pub const MAX_H1_PER_ORIGIN: usize = 6;

/// An idle h1 connection is dropped once it has gone unused for this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// The connection table a [`Transport`](crate::Transport) owns, keyed by
/// origin. Backends built over the same transport check out of it together.
pub struct Pool {
    origins: Mutex<HashMap<Origin, Arc<OriginEntry>>>,
    idle_timeout: Duration,
}

/// The authority a connection belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    /// `http` or `https`: whether the connection carries TLS.
    pub scheme: Scheme,
    /// The target's hostname.
    pub host: String,
    /// The target's port.
    pub port: u16,
}

/// Per-origin connection state. The synchronous mutexes are never held
/// across an `.await`; `dialing` and `h1_slots` are the only async waits.
struct OriginEntry {
    /// Idle h1 senders, each an exclusive checkout. Idle connections hold no
    /// slot permit — the slot is freed when the connection is parked — so
    /// `h1_idle.len()` never exceeds the number of free slots.
    h1_idle: Mutex<Vec<IdleH1>>,
    /// `MAX_H1_PER_ORIGIN` permits, one per leased or dialing h1 connection.
    /// A parked idle connection holds none and re-acquires one at checkout.
    h1_slots: Arc<Semaphore>,
    /// The origin's shared h2 handle; clones multiplex over one connection.
    #[cfg(feature = "http2")]
    h2: Mutex<Option<http2::SendRequest<http_kit::Body>>>,
    /// The protocol the origin speaks: `Some` once a dial negotiated it, or
    /// immediately for plaintext — `http` has no ALPN, so it can only be h1.
    /// A known-h1 origin dials in parallel under `h1_slots` while anything
    /// else serializes on `dialing`.
    protocol: Mutex<Option<Protocol>>,
    /// Held while dialing an origin that is or may be h2, so concurrent first
    /// requests open one connection instead of N.
    dialing: Arc<async_lock::Mutex<()>>,
}

impl OriginEntry {
    fn new(origin: &Origin) -> Self {
        Self {
            h1_idle: Mutex::new(Vec::new()),
            h1_slots: Arc::new(Semaphore::new(MAX_H1_PER_ORIGIN)),
            #[cfg(feature = "http2")]
            h2: Mutex::new(None),
            protocol: Mutex::new((origin.scheme == Scheme::HTTP).then_some(Protocol::Http1)),
            dialing: Arc::new(async_lock::Mutex::new(())),
        }
    }

    /// Whether the entry still holds a usable connection — an idle h1 sender
    /// that is neither closed nor expired, or a live h2 handle. Dead and
    /// expired connections are evicted along the way. Connections leased
    /// out or still dialing do not appear here; they keep the entry alive
    /// through their own `Arc` instead.
    fn has_live_connections(&self, idle_timeout: Duration) -> bool {
        {
            let mut idle = self.h1_idle.lock().expect("pool state poisoned");
            idle.retain(|idle| {
                !idle.sender.is_closed() && idle.idle_since.elapsed() < idle_timeout
            });
            if !idle.is_empty() {
                return true;
            }
        }
        #[cfg(feature = "http2")]
        {
            let mut h2 = self.h2.lock().expect("pool state poisoned");
            if h2.as_ref().is_some_and(http2::SendRequest::is_closed) {
                *h2 = None;
            }
            if h2.is_some() {
                return true;
            }
        }
        false
    }
}

impl fmt::Debug for OriginEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginEntry").finish_non_exhaustive()
    }
}

/// An h1 connection resting between requests. It holds no slot permit: the
/// slot goes back to `h1_slots` when the connection is parked and is
/// re-acquired when it is leased again.
struct IdleH1 {
    sender: http1::SendRequest<http_kit::Body>,
    /// How the connection was reached; reapplied to every reused request.
    via: Via,
    idle_since: Instant,
}

/// Whether [`Pool::checkout`] may reuse a pooled connection.
pub enum Reuse {
    /// Anything pooled is fair game: a live h2 handle or an idle h1
    /// connection.
    Pooled,
    /// Nothing pooled: dial a fresh connection. The one retry after a
    /// pooled connection refused a request goes out this way — reusing
    /// another connection from the same pool could hit the same failure.
    FreshDial,
}

/// What [`Pool::checkout`] found for an origin.
pub enum Checkout {
    /// A clone of the origin's live h2 handle, ready to send.
    #[cfg(feature = "http2")]
    H2(http2::SendRequest<http_kit::Body>),
    /// An idle h1 connection, exclusively leased until the response body ends.
    H1(H1Lease),
    /// Nothing reusable: dial a new connection holding this permit.
    Dial(DialPermit),
}

impl fmt::Debug for Checkout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "http2")]
            Self::H2(_) => f.write_str("Checkout::H2"),
            Self::H1(_) => f.write_str("Checkout::H1"),
            Self::Dial(_) => f.write_str("Checkout::Dial"),
        }
    }
}

/// An h1 connection leased from the pool. Returned to the origin's idle set
/// by [`release`](Self::release) — which the backend calls when the response
/// body ends or is dropped — or dropped, closing the connection and freeing
/// its slot.
pub struct H1Lease {
    sender: http1::SendRequest<http_kit::Body>,
    entry: Arc<OriginEntry>,
    via: Via,
    permit: SemaphoreGuardArc,
}

impl H1Lease {
    /// How the leased connection was reached: origin-form requests when
    /// `Direct`, absolute-form plus `Proxy-Authorization` through a proxy.
    pub const fn via(&self) -> &Via {
        &self.via
    }

    /// Send `request` on the leased connection. On success the response comes
    /// back with the lease — the connection stays out of the pool until it is
    /// released or dropped. On failure the lease is consumed, freeing its
    /// slot; when the connection refused the request before anything was
    /// written, the request comes back inside the error
    /// (`TrySendError::take_message`) so it can go out on a fresh dial.
    // The `Err` variant is large because it can carry the unsent request,
    // which is exactly the payload the caller needs for a retry.
    #[allow(clippy::result_large_err)]
    pub async fn send(
        mut self,
        request: Request<http_kit::Body>,
    ) -> Result<(Response<Incoming>, Self), TrySendError<Request<http_kit::Body>>> {
        self.sender
            .try_send_request(request)
            .await
            .map(|response| (response, self))
    }

    /// Return the connection to the origin's idle set; a dead one is
    /// discarded instead. The slot permit is freed either way.
    pub fn release(self) {
        let Self {
            sender,
            entry,
            via,
            permit,
        } = self;
        // The lock is never held across an await, so a healthy connection is
        // always parked — never dropped because the mutex happened to be
        // contended.
        if !sender.is_closed() {
            entry
                .h1_idle
                .lock()
                .expect("pool state poisoned")
                .push(IdleH1 {
                    sender,
                    via,
                    idle_since: Instant::now(),
                });
        }
        drop(permit);
    }
}

impl fmt::Debug for H1Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H1Lease").finish_non_exhaustive()
    }
}

/// The right to dial one connection to an origin, handed out by
/// [`Pool::checkout`] when nothing was reusable. Passed to
/// [`Pool::insert_h1`] or [`Pool::insert_h2`] once the dial's handshake has
/// learned the protocol, or dropped on failure so the next waiter dials.
pub struct DialPermit {
    entry: Arc<OriginEntry>,
    hold: DialHold,
}

/// What a [`DialPermit`] keeps held while the dial runs.
enum DialHold {
    /// `dialing`: the origin is or may be h2, so this dial's result serves
    /// every waiter queued on the lock.
    Coalesced(MutexGuardArc<()>),
    /// One `h1_slots` permit: the origin is known to speak h1.
    H1(SemaphoreGuardArc),
}

impl fmt::Debug for DialPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DialPermit").finish_non_exhaustive()
    }
}

impl Pool {
    /// An empty pool with the default idle timeout.
    #[allow(clippy::missing_const_for_fn)] // `HashMap::new` is not const on this toolchain
    pub fn new() -> Self {
        Self {
            origins: Mutex::new(HashMap::new()),
            idle_timeout: IDLE_TIMEOUT,
        }
    }

    /// Check out a connection for `origin`: a clone of a live h2 handle, a
    /// lease on an idle h1 connection, or a [`DialPermit`] to dial a new one.
    /// `reuse` says whether pooled connections may be reused; `FreshDial`
    /// skips them so the retry after a refused request opens a new
    /// connection.
    pub async fn checkout(&self, origin: Origin, reuse: Reuse) -> Checkout {
        let entry = self.entry(&origin);
        let pooled = matches!(reuse, Reuse::Pooled);
        loop {
            #[cfg(feature = "http2")]
            if pooled && let Some(sender) = live_h2(&entry) {
                return Checkout::H2(sender);
            }
            // An idle h1 connection exists only after `insert_h1` recorded
            // the protocol, so `h1_idle` only has to be consulted on the
            // known-h1 path.
            if matches!(
                *entry.protocol.lock().expect("pool state poisoned"),
                Some(Protocol::Http1)
            ) {
                // A known-h1 origin: h1 connections are exclusive, so
                // parallel requests dial in parallel up to the slot limit,
                // then wait for a connection to come back. The slot is
                // acquired first and pairs with a parked connection if one
                // is reusable, or with the dial's permit otherwise.
                let permit = entry.h1_slots.acquire_arc().await;
                if !pooled {
                    return Checkout::Dial(DialPermit {
                        entry,
                        hold: DialHold::H1(permit),
                    });
                }
                match self.lease_idle(&entry, permit).await {
                    Ok(lease) => return Checkout::H1(lease),
                    Err(permit) => {
                        return Checkout::Dial(DialPermit {
                            entry,
                            hold: DialHold::H1(permit),
                        });
                    }
                }
            }

            // A new or h2-speaking origin: `dialing` coalesces concurrent
            // dials so one handshake serves every waiter.
            let dialing = entry.dialing.lock_arc().await;
            #[cfg(feature = "http2")]
            if pooled && let Some(sender) = live_h2(&entry) {
                return Checkout::H2(sender);
            }
            if matches!(
                *entry.protocol.lock().expect("pool state poisoned"),
                Some(Protocol::Http1)
            ) {
                // The dial ahead of this one learned the origin speaks h1;
                // take the semaphore path instead of holding `dialing`.
                drop(dialing);
                continue;
            }
            return Checkout::Dial(DialPermit {
                entry,
                hold: DialHold::Coalesced(dialing),
            });
        }
    }

    /// Record that `permit`'s dial negotiated h1: the origin is remembered as
    /// h1-speaking and the connection comes back as a lease holding its slot.
    pub async fn insert_h1(
        permit: DialPermit,
        sender: http1::SendRequest<http_kit::Body>,
        via: Via,
    ) -> H1Lease {
        let entry = permit.entry;
        *entry.protocol.lock().expect("pool state poisoned") = Some(Protocol::Http1);
        let slot = match permit.hold {
            DialHold::H1(slot) => slot,
            DialHold::Coalesced(dialing) => {
                // The protocol is learned; release the waiters and account
                // this connection under the h1 limit.
                drop(dialing);
                entry.h1_slots.acquire_arc().await
            }
        };
        H1Lease {
            sender,
            entry,
            via,
            permit: slot,
        }
    }

    /// Record that `permit`'s dial negotiated h2: the handle becomes the
    /// origin's shared connection. `permit` still holds `dialing`, so the
    /// waiters re-check and find the handle as soon as it is stored.
    #[cfg(feature = "http2")]
    pub fn insert_h2(permit: DialPermit, sender: http2::SendRequest<http_kit::Body>) {
        *permit.entry.protocol.lock().expect("pool state poisoned") = Some(Protocol::Http2);
        *permit.entry.h2.lock().expect("pool state poisoned") = Some(sender);
        // Idle h1 connections the dial replaces can never be checked out
        // again; drop them rather than leaving their drivers parked.
        permit
            .entry
            .h1_idle
            .lock()
            .expect("pool state poisoned")
            .clear();
        drop(permit);
    }

    /// The entry for `origin`, created on first contact. Inserting a new
    /// origin sweeps the table: an entry referenced only by the map that
    /// holds no live connection is finished and removed.
    fn entry(&self, origin: &Origin) -> Arc<OriginEntry> {
        let mut origins = self.origins.lock().expect("pool state poisoned");
        if let Some(entry) = origins.get(origin) {
            return entry.clone();
        }
        let entry = Arc::new(OriginEntry::new(origin));
        origins.insert(origin.clone(), entry.clone());
        origins.retain(|_, entry| {
            Arc::strong_count(entry) > 1 || entry.has_live_connections(self.idle_timeout)
        });
        entry
    }

    /// Lease the next reusable idle h1 connection for `entry` under the
    /// caller's slot `permit`. Dead and expired entries are evicted along the
    /// way; `Err(permit)` hands the slot back when nothing was reusable.
    async fn lease_idle(
        &self,
        entry: &Arc<OriginEntry>,
        permit: SemaphoreGuardArc,
    ) -> Result<H1Lease, SemaphoreGuardArc> {
        loop {
            let idle = {
                let mut idle = entry.h1_idle.lock().expect("pool state poisoned");
                idle.retain(|idle| {
                    !idle.sender.is_closed() && idle.idle_since.elapsed() < self.idle_timeout
                });
                idle.pop()
            };
            let Some(IdleH1 {
                mut sender, via, ..
            }) = idle
            else {
                return Err(permit);
            };
            // The sender is out of the idle set, so this wait holds no pool
            // lock. A connection that died while parked makes `ready` error;
            // it is dropped and the loop looks at the next.
            if sender.ready().await.is_ok() {
                return Ok(H1Lease {
                    sender,
                    entry: entry.clone(),
                    via,
                    permit,
                });
            }
        }
    }
}

/// A clone of `entry`'s live h2 handle, or `None` — a dead one is evicted so
/// the next checkout re-dials. `is_closed` is the whole liveness check: the
/// h2 dispatcher is always ready to accept a stream while it is open.
#[cfg(feature = "http2")]
fn live_h2(entry: &OriginEntry) -> Option<http2::SendRequest<http_kit::Body>> {
    let mut h2 = entry.h2.lock().expect("pool state poisoned");
    match h2.as_ref() {
        Some(sender) if sender.is_closed() => {
            *h2 = None;
            None
        }
        Some(sender) => Some(sender.clone()),
        None => None,
    }
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::Read as _,
        net::TcpListener,
        sync::Mutex,
        thread,
        time::{Duration, Instant},
    };

    use async_net::TcpStream;
    use futures_executor::block_on;
    use http::uri::Scheme;
    use hyper::client::conn::http1;

    use super::{Checkout, IdleH1, Origin, Pool, Reuse};
    use crate::transport::{
        connect::{Protocol, Via},
        hyper_io::HyperIo,
        stream::Stream,
    };

    /// A real h1 sender on a loopback connection the peer holds open.
    async fn h1_sender() -> http1::SendRequest<http_kit::Body> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test server must bind");
        let address = listener.local_addr().expect("test address must exist");
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("test connection must arrive");
            // Hold the connection until the client goes away.
            let mut buffer = [0_u8; 128];
            while socket.read(&mut buffer).unwrap_or(0) > 0 {}
        });
        let tcp = TcpStream::connect(address)
            .await
            .expect("test must connect");
        let (mut sender, driver) = http1::handshake(HyperIo(Stream::Tcp(tcp)))
            .await
            .expect("h1 handshake must succeed");
        thread::spawn(move || {
            let _ = async_io::block_on(driver);
        });
        // A pooled connection is only leased once its driver reports ready —
        // wait until this one has parked on the dispatch channel, the state a
        // production connection is in when it returns to idle.
        sender
            .ready()
            .await
            .expect("fresh connection must be ready");
        sender
    }

    fn origin() -> Origin {
        Origin {
            scheme: Scheme::HTTP,
            host: "127.0.0.1".to_owned(),
            port: 9,
        }
    }

    /// Park `sender` on the entry for `origin`, as a completed h1 dial would.
    fn park_idle(pool: &Pool, origin: &Origin, sender: http1::SendRequest<http_kit::Body>) {
        let entry = pool.entry(origin);
        *entry.protocol.lock().expect("pool state poisoned") = Some(Protocol::Http1);
        entry
            .h1_idle
            .lock()
            .expect("pool state poisoned")
            .push(IdleH1 {
                sender,
                via: Via::Direct,
                idle_since: Instant::now(),
            });
    }

    #[test]
    fn fresh_idle_connections_are_leased() {
        block_on(async {
            let pool = Pool::new();
            let origin = origin();
            park_idle(&pool, &origin, h1_sender().await);
            assert!(
                matches!(pool.checkout(origin, Reuse::Pooled).await, Checkout::H1(_)),
                "a live idle connection must be leased, not dialed past"
            );
        });
    }

    #[test]
    fn fresh_dial_skips_idle_connections() {
        block_on(async {
            let pool = Pool::new();
            let origin = origin();
            park_idle(&pool, &origin, h1_sender().await);
            assert!(
                matches!(
                    pool.checkout(origin, Reuse::FreshDial).await,
                    Checkout::Dial(_)
                ),
                "a fresh-dial checkout must ignore idle connections"
            );
        });
    }

    #[test]
    fn expired_idle_connections_are_evicted() {
        block_on(async {
            let pool = Pool {
                origins: Mutex::new(HashMap::new()),
                idle_timeout: Duration::ZERO,
            };
            let origin = origin();
            park_idle(&pool, &origin, h1_sender().await);
            let entry = pool.entry(&origin);
            assert!(
                matches!(
                    pool.checkout(origin, Reuse::Pooled).await,
                    Checkout::Dial(_)
                ),
                "an expired idle connection must be evicted, not leased"
            );
            assert!(
                entry
                    .h1_idle
                    .lock()
                    .expect("pool state poisoned")
                    .is_empty(),
                "the expired entry must be gone"
            );
        });
    }

    #[test]
    fn released_leases_return_to_idle() {
        block_on(async {
            let pool = Pool::new();
            let origin = origin();
            let Checkout::Dial(permit) = pool.checkout(origin.clone(), Reuse::Pooled).await else {
                panic!("an empty pool must hand out a dial permit");
            };
            Pool::insert_h1(permit, h1_sender().await, Via::Direct)
                .await
                .release();
            assert!(
                matches!(pool.checkout(origin, Reuse::Pooled).await, Checkout::H1(_)),
                "a released connection must come back out of idle"
            );
        });
    }

    #[test]
    fn finished_origins_are_swept_on_insert() {
        block_on(async {
            let pool = Pool {
                origins: Mutex::new(HashMap::new()),
                idle_timeout: Duration::ZERO,
            };
            for port in [9_u16, 10, 11] {
                let origin = Origin { port, ..origin() };
                park_idle(&pool, &origin, h1_sender().await);
            }
            // An entry kept alive by something else — here a checkout's dial
            // permit — must survive the sweep.
            let held = Origin {
                port: 12,
                ..origin()
            };
            let Checkout::Dial(permit) = pool.checkout(held.clone(), Reuse::Pooled).await else {
                panic!("an empty origin must hand out a dial permit");
            };

            pool.entry(&Origin {
                port: 13,
                ..origin()
            });
            let origins = pool.origins.lock().expect("pool state poisoned");
            assert!(
                !origins.contains_key(&origin())
                    && !origins.contains_key(&Origin {
                        port: 10,
                        ..origin()
                    })
                    && !origins.contains_key(&Origin {
                        port: 11,
                        ..origin()
                    }),
                "expired, unreferenced entries must be swept"
            );
            assert!(
                origins.contains_key(&held),
                "an entry still referenced by a permit must survive"
            );
            assert!(
                origins.contains_key(&Origin {
                    port: 13,
                    ..origin()
                }),
                "the newly inserted origin must survive"
            );
            assert_eq!(origins.len(), 2);
            drop(origins);
            drop(permit);
        });
    }
}
