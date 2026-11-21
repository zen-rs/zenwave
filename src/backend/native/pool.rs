//! The native backend's connection pool: one per thread, owned outright by
//! a single local task.
//!
//! The task holds every origin's state and every connection's driver, so
//! nothing in it is shared and nothing is locked. Requests reach it through
//! a [`PoolHandle`], a channel sender that is `Send` and `Sync`: a request
//! future asks for a connection, gets back a `Send` handle (an HTTP/1.1
//! sender leased exclusively, or a clone of the origin's HTTP/2 or HTTP/3
//! sender), and talks to the connection through it. A thread-per-core caller
//! runs one pool per thread and its requests never leave that thread.
//!
//! HTTP/1.1 and HTTP/2 follow the hyper pool's rules: an HTTPS origin whose
//! protocol is not yet known (or is known to be HTTP/2) coalesces concurrent
//! dials into one handshake so a single HTTP/2 connection serves every
//! waiter; an origin known to speak HTTP/1.1 opens up to
//! [`MAX_H1_PER_ORIGIN`] connections leased or dialing per origin, parks idle
//! connections until [`IDLE_TIMEOUT`], and serves waiters in order.

use std::{
    cell::Cell,
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures_channel::{mpsc, oneshot};
use futures_util::{
    FutureExt, StreamExt,
    future::{Either, LocalBoxFuture, select},
    pin_mut,
    stream::FuturesUnordered,
};
use tracing::debug;

use super::connect::{
    self, DialBound, DialOptions, Dialed, DialedConn, H1Send, NativeIo, NativeResolve,
    TlsConnectors,
};
use crate::{
    ConnectPhase, Error, TimedOut,
    clock::Clock,
    transport::{
        WeakTransport,
        route::{IDLE_TIMEOUT, MAX_H1_PER_ORIGIN, Origin, Protocols, Via},
    },
};

#[cfg(native_h3)]
use super::h3::{self, H3Slot};

/// Whether a request may go over the origin's HTTP/3 connection.
#[cfg(native_h3)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H3Use {
    /// Never: the request is plaintext, asks for an HTTP/1.1 upgrade, or goes
    /// through a proxy.
    Blocked,
    /// Whenever the origin has a connection whose handshake completed, or
    /// one completes while the request waits for TCP.
    Allowed,
}

/// What a request asks the pool for.
#[derive(Clone, Copy, Debug)]
pub struct Want {
    /// Dial a new connection rather than reuse an idle one: the retry after a
    /// pooled connection failed under the request.
    pub fresh: bool,
    /// Whether the request may use HTTP/2 (`false` when asking for an
    /// HTTP/1.1 `101 Switching Protocols` upgrade).
    #[cfg(native_h2)]
    pub allow_h2: bool,
    /// An HTTP/2 connection generation that already rejected or failed this
    /// request: evict it if still pooled, while allowing reuse of a newer
    /// generation another task already opened.
    #[cfg(native_h2)]
    pub avoid_h2: Option<u64>,
    #[cfg(native_h3)]
    pub h3: H3Use,
}

/// A connection the pool hands a request.
#[derive(Debug)]
pub enum Grant {
    /// An HTTP/1.1 connection, leased until the request's response body
    /// ends; `reused` when it served a request before.
    H1 {
        send: H1Send,
        via: Via,
        reused: bool,
    },
    /// The origin's shared HTTP/2 connection.
    #[cfg(native_h2)]
    H2 {
        send: http_kit_h2::SendRequest,
        generation: u64,
        reused: bool,
    },
    /// The origin's HTTP/3 connection.
    #[cfg(native_h3)]
    H3(http_kit_h3::SendRequest),
}

/// What a request sends the pool.
#[derive(Debug)]
pub enum Command {
    /// A connection for `origin`.
    Checkout {
        origin: Origin,
        want: Want,
        /// When the request stops waiting for a connection, if it does.
        deadline: Option<Instant>,
        reply: oneshot::Sender<Result<Grant, Error>>,
    },
    /// A leased HTTP/1.1 connection whose response body ended.
    Release {
        origin: Origin,
        send: H1Send,
        via: Via,
    },
    /// A leased HTTP/1.1 connection that cannot serve again: its request
    /// failed or its body was dropped unread.
    Discard { origin: Origin },
    /// A response for `origin` carried these `Alt-Svc` fields, joined.
    #[cfg(native_h3)]
    AltSvc { origin: Origin, value: String },
    /// Answer on `reply` once `duration` has passed on the pool's timer.
    Sleep {
        duration: Duration,
        reply: oneshot::Sender<()>,
    },
}

/// The `Send` side of a pool: requests reach the pool's thread through it.
/// The pool runs while any handle exists.
#[derive(Clone, Debug)]
pub struct PoolHandle(mpsc::UnboundedSender<Command>);

/// The clock of a native backend: sleeps run on its pool's timer.
///
/// That is the `http_kit_io::Timer` the connect and read deadlines use. The
/// pool answers over a channel, so the sleep future is `Send` whatever the
/// timer's is.
///
/// A sleep whose pool has stopped completes at once; the request it guards
/// fails on the stopped pool anyway.
#[derive(Clone, Debug)]
pub struct PoolClock(PoolHandle);

impl PoolClock {
    /// The clock of the pool `handle` reaches.
    pub(super) const fn new(handle: PoolHandle) -> Self {
        Self(handle)
    }
}

impl Clock for PoolClock {
    type Sleep = PoolSleep;

    fn sleep(&self, duration: Duration) -> PoolSleep {
        let (reply, answered) = oneshot::channel();
        self.0.send(Command::Sleep { duration, reply });
        PoolSleep(answered)
    }
}

/// A sleep running on a native pool's timer; completes when the pool answers
/// or has stopped.
#[derive(Debug)]
pub struct PoolSleep(oneshot::Receiver<()>);

impl Future for PoolSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // `Err` is a pool that stopped before answering.
        Pin::new(&mut self.0).poll(cx).map(drop)
    }
}

/// The pool's end of its channel, handed to [`run`] on the pool's thread.
#[derive(Debug)]
pub struct PoolReceiver(mpsc::UnboundedReceiver<Command>);

impl PoolHandle {
    /// A handle and the receiver its pool runs on.
    pub fn channel() -> (Self, PoolReceiver) {
        let (sender, receiver) = mpsc::unbounded();
        (Self(sender), PoolReceiver(receiver))
    }

    /// A connection for `origin`, dialed if none is free, waited for at most
    /// `connect` (counted from this call; `None`, or a duration too long to
    /// be an `Instant`, waits as long as the dials take).
    ///
    /// # Errors
    ///
    /// The dial failed, `connect` passed first ([`TimedOut::Connect`] with
    /// the phase the origin's connection was in), or the pool is gone.
    pub async fn checkout(
        &self,
        origin: Origin,
        want: Want,
        connect: Option<Duration>,
    ) -> Result<Grant, Error> {
        let (reply, granted) = oneshot::channel();
        self.send(Command::Checkout {
            origin,
            want,
            deadline: connect.and_then(|connect| Instant::now().checked_add(connect)),
            reply,
        });
        granted.await.map_err(|_| gone())?
    }

    /// Sends `command`; a pool that has stopped has nothing left to tell.
    pub fn send(&self, command: Command) {
        if self.0.unbounded_send(command).is_err() {
            debug!("native connection pool has stopped");
        }
    }
}

const fn gone() -> Error {
    Error::Stopped
}

/// How far along a connection's setup `phase` is: the later the phase, the
/// closer the connection is to ready.
const fn phase_rank(phase: ConnectPhase) -> u8 {
    match phase {
        ConnectPhase::Queued => 0,
        ConnectPhase::Resolve => 1,
        ConnectPhase::Tcp => 2,
        ConnectPhase::Proxy => 3,
        ConnectPhase::Tls => 4,
        ConnectPhase::Quic => 5,
    }
}

/// Something a pool task finished.
pub enum Event {
    /// A TCP/TLS dial for `origin` ended.
    TcpDialed {
        origin: Origin,
        protocols: Protocols,
        /// The phase tracker identifying this dial in `Entry::dials`.
        phase: Rc<Cell<ConnectPhase>>,
        result: Result<Dialed, Error>,
    },
    /// An HTTP/2 connection driver for `origin` ended.
    #[cfg(native_h2)]
    H2Ended {
        origin: Origin,
        generation: u64,
        result: Result<(), http_kit_h2::Error>,
    },
    /// A request's connect timeout passed while it waited at `origin`.
    CheckoutExpired { origin: Origin, waiter: WaiterId },
    #[cfg(native_h3)]
    H3(h3::H3Event),
}

/// Names a waiter among its origin's, so its expiry finds it again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaiterId(u64);

/// A request waiting for a connection.
struct Waiter {
    id: WaiterId,
    /// When the request's connect timeout passes; none when it has no bound.
    /// Its own expiry task is the only thing that fails it for that.
    deadline: Option<Instant>,
    /// Dropped with the waiter, which ends the task counting down its
    /// connect timeout.
    _expiry: Option<oneshot::Sender<()>>,
    reply: oneshot::Sender<Result<Grant, Error>>,
    fresh: bool,
    #[cfg(native_h2)]
    allow_h2: bool,
    #[cfg(native_h2)]
    avoid_h2: Option<u64>,
    /// The request may take an HTTP/3 connection whose dial completes
    /// while it waits.
    #[cfg(native_h3)]
    h3: bool,
    /// The TCP dial that would have served the request failed while a QUIC
    /// dial still raced for it: the request waits on QUIC, and fails with
    /// this if QUIC fails too.
    #[cfg(native_h3)]
    tcp_error: Option<Error>,
}

/// The bound on a dial that serves requests with these deadlines: the
/// latest of them, or none when any is unbounded (or when there are none).
fn latest_deadline(deadlines: impl IntoIterator<Item = Option<Instant>>) -> Option<Instant> {
    let mut latest = None;
    for deadline in deadlines {
        latest = latest.max(Some(deadline?));
    }
    latest
}

impl Waiter {
    fn gone(&self) -> bool {
        self.reply.is_canceled()
    }

    /// Whether the request's connect timeout has passed, so its expiry is
    /// about to fail it and no dial is owed for it.
    fn expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| deadline <= now)
    }

    /// Whether the request is owed a TCP dial: unless its own failed while it
    /// waits on QUIC.
    #[cfg_attr(
        not(native_h3),
        expect(
            clippy::unused_self,
            reason = "without HTTP/3 every waiter is owed a dial"
        )
    )]
    const fn awaits_dial(&self) -> bool {
        #[cfg(native_h3)]
        return self.tcp_error.is_none();
        #[cfg(not(native_h3))]
        true
    }

    /// Whether this waiter may take an HTTP/1.1 connection (`reused` when it
    /// already served a request) at an origin where `known_h1` says HTTP/1.1
    /// is the origin's protocol.
    const fn accepts_h1(&self, known_h1: bool, reused: bool) -> bool {
        if reused && self.fresh {
            return false;
        }
        #[cfg(native_h2)]
        if self.allow_h2 && !known_h1 {
            return false;
        }
        #[cfg(not(native_h2))]
        let _ = known_h1;
        true
    }

    /// Whether this waiter needs an `Http1` dial (`known_h1` says the origin
    /// only speaks HTTP/1.1).
    #[cfg_attr(
        not(native_h2),
        expect(
            clippy::unused_self,
            reason = "without HTTP/2 every waiter dials HTTP/1.1"
        )
    )]
    const fn needs_h1_dial(&self, known_h1: bool) -> bool {
        #[cfg(native_h2)]
        return known_h1 || !self.allow_h2;
        #[cfg(not(native_h2))]
        {
            let _ = known_h1;
            true
        }
    }

    /// Hands `grant` over, or back when the request is gone.
    fn grant(self, grant: Grant) -> Option<Grant> {
        self.reply.send(Ok(grant)).err().and_then(Result::ok)
    }

    /// Hands an HTTP/1.1 connection over, or back when the request is gone.
    fn grant_h1(self, send: H1Send, via: Via, reused: bool) -> Option<(H1Send, Via)> {
        match self.grant(Grant::H1 { send, via, reused })? {
            Grant::H1 { send, via, .. } => Some((send, via)),
            #[cfg(native_h2)]
            Grant::H2 { .. } => unreachable!("an HTTP/1.1 grant comes back as one"),
            #[cfg(native_h3)]
            Grant::H3(_) => unreachable!("an HTTP/1.1 grant comes back as one"),
        }
    }

    fn fail(self, error: Error) {
        if self.reply.send(Err(error)).is_err() {
            debug!("a dial failed for a request that is gone");
        }
    }
}

/// The TCP HTTP version an origin was found to speak.
#[cfg(native_h2)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    /// Plaintext (`http://`), or `https://` where ALPN did not choose `h2`.
    Http1,
    /// `https://` where ALPN chose `h2`.
    Http2,
}

/// The origin's shared HTTP/2 connection.
#[cfg(native_h2)]
struct PooledH2 {
    send: http_kit_h2::SendRequest,
    generation: u64,
    since: Instant,
}

#[cfg(native_h2)]
impl PooledH2 {
    fn usable(&self) -> bool {
        !self.send.is_closed() && self.since.elapsed() < IDLE_TIMEOUT
    }
}

/// A TCP/TLS dial currently running for an origin.
struct InFlightDial {
    protocols: Protocols,
    phase: Rc<Cell<ConnectPhase>>,
    bound: Rc<DialBound>,
}

/// An HTTP/1.1 connection parked between requests.
struct Idle {
    send: H1Send,
    via: Via,
    since: Instant,
}

impl Idle {
    fn usable(&self) -> bool {
        !self.send.is_closed() && self.since.elapsed() < IDLE_TIMEOUT
    }
}

/// One origin's connections.
pub struct Entry {
    idle: Vec<Idle>,
    /// HTTP/1.1 connections leased to requests.
    leased: usize,
    /// TCP/TLS dials in flight (`Http1` or coalesced `Http2OrHttp1`).
    dials: Vec<InFlightDial>,
    waiters: VecDeque<Waiter>,
    #[cfg(native_h2)]
    protocol: Option<Protocol>,
    #[cfg(native_h2)]
    h2: Option<PooledH2>,
    #[cfg(native_h2)]
    h2_generation: u64,
    #[cfg(native_h3)]
    pub h3: H3Slot,
}

impl Entry {
    #[allow(clippy::missing_const_for_fn)] // `Scheme` equality under `native_h2` is not `const`
    fn new(
        #[cfg_attr(not(any(native_h2, native_h3)), expect(unused_variables))] origin: &Origin,
    ) -> Self {
        Self {
            idle: Vec::new(),
            leased: 0,
            dials: Vec::new(),
            waiters: VecDeque::new(),
            #[cfg(native_h2)]
            protocol: (origin.scheme == http::uri::Scheme::HTTP).then_some(Protocol::Http1),
            #[cfg(native_h2)]
            h2: None,
            #[cfg(native_h2)]
            h2_generation: 0,
            #[cfg(native_h3)]
            h3: H3Slot::new(origin.port),
        }
    }

    #[cfg_attr(
        not(native_h2),
        expect(clippy::unused_self, reason = "without HTTP/2 every origin speaks h1")
    )]
    const fn is_known_h1(&self) -> bool {
        #[cfg(native_h2)]
        return matches!(self.protocol, Some(Protocol::Http1));
        #[cfg(not(native_h2))]
        true
    }

    #[cfg_attr(
        not(native_h2),
        expect(
            clippy::unused_self,
            reason = "without HTTP/2 every idle h1 connection may park"
        )
    )]
    const fn may_park_h1(&self) -> bool {
        #[cfg(native_h2)]
        return !matches!(self.protocol, Some(Protocol::Http2));
        #[cfg(not(native_h2))]
        true
    }

    fn h1_dialing(&self) -> usize {
        self.dials
            .iter()
            .filter(|dial| matches!(dial.protocols, Protocols::Http1))
            .count()
    }

    /// Hands clones of the pooled HTTP/2 connection to every waiter that may
    /// use it.
    #[cfg(native_h2)]
    fn grant_pooled_h2(&mut self, now: Instant) {
        if self.h2.as_ref().is_some_and(|h2| !h2.usable()) {
            self.h2 = None;
        }
        let Some(h2) = self.h2.as_mut() else {
            return;
        };
        let generation = h2.generation;
        let send = h2.send.clone();
        let mut handed_out = false;
        for waiter in std::mem::take(&mut self.waiters) {
            if waiter.allow_h2
                && waiter.avoid_h2 != Some(generation)
                && !(waiter.fresh && waiter.avoid_h2.is_none())
            {
                if waiter
                    .grant(Grant::H2 {
                        send: send.clone(),
                        generation,
                        reused: true,
                    })
                    .is_none()
                {
                    handed_out = true;
                }
            } else {
                self.waiters.push_back(waiter);
            }
        }
        if handed_out {
            h2.since = now;
        }
    }

    /// Leases parked HTTP/1.1 connections to the first waiters that accept one.
    fn grant_idle_h1(&mut self, now: Instant) {
        let known_h1 = self.is_known_h1();
        let mut next = 0;
        while next < self.waiters.len()
            && let Some(idle) = self.idle.pop()
        {
            if !self.waiters[next].accepts_h1(known_h1, true) {
                self.idle.push(idle);
                next += 1;
                continue;
            }
            let waiter = self.waiters.remove(next).expect("the index is in range");
            match waiter.grant_h1(idle.send, idle.via, true) {
                None => self.leased += 1,
                Some((send, via)) => self.idle.push(Idle {
                    send,
                    via,
                    since: now,
                }),
            }
        }
    }

    /// Whether nothing here would change a later request's work.
    fn vacant(&mut self, now: Instant) -> bool {
        self.idle.retain(Idle::usable);
        #[cfg(native_h2)]
        let h2 = {
            if self.h2.as_ref().is_some_and(|h2| !h2.usable()) {
                self.h2 = None;
            }
            self.h2.is_none()
        };
        #[cfg(not(native_h2))]
        let h2 = true;
        #[cfg(native_h3)]
        let h3 = self.h3.vacant(now);
        #[cfg(not(native_h3))]
        let h3 = {
            let _ = now;
            true
        };
        self.idle.is_empty()
            && self.leased == 0
            && self.dials.is_empty()
            && self.waiters.is_empty()
            && h2
            && h3
    }
}

/// The pool's state: everything its task owns.
pub struct Pool<I, R> {
    pub io: I,
    /// The resolver every dial task shares, on the pool's thread.
    pub resolver: Rc<R>,
    pub transport: WeakTransport,
    tls: Option<TlsConnectors>,
    pub origins: HashMap<Origin, Entry>,
    /// The id the next waiter takes.
    next_waiter: u64,
    pub tasks: FuturesUnordered<LocalBoxFuture<'static, Option<Event>>>,
    #[cfg(native_h3)]
    pub h3: h3::H3Client,
}

/// Runs a pool over `io` until every [`PoolHandle`] is dropped. Connections
/// still open then close with it.
pub async fn run<I: NativeIo, R: NativeResolve>(
    io: I,
    resolver: R,
    transport: WeakTransport,
    receiver: PoolReceiver,
) {
    let mut pool = Pool {
        io,
        resolver: Rc::new(resolver),
        transport,
        tls: None,
        origins: HashMap::new(),
        next_waiter: 0,
        tasks: FuturesUnordered::new(),
        #[cfg(native_h3)]
        h3: h3::H3Client::default(),
    };
    let mut commands = receiver.0;
    loop {
        futures_util::select_biased! {
            event = pool.tasks.select_next_some() => {
                if let Some(event) = event {
                    pool.event(event);
                }
            }
            command = commands.next() => match command {
                Some(command) => pool.command(command),
                None => break,
            },
        }
    }
}

impl<I: NativeIo, R: NativeResolve> Pool<I, R> {
    fn command(&mut self, command: Command) {
        match command {
            Command::Checkout {
                origin,
                want,
                deadline,
                reply,
            } => self.checkout(&origin, want, deadline, reply),
            Command::Release { origin, send, via } => {
                self.entry(&origin).leased -= 1;
                self.offer(&origin, send, via, true);
            }
            Command::Discard { origin } => {
                self.entry(&origin).leased -= 1;
                self.serve_waiters(&origin);
            }
            #[cfg(native_h3)]
            Command::AltSvc { origin, value } => self.alt_svc(&origin, &value),
            Command::Sleep { duration, reply } => self.sleep(duration, reply),
        }
    }

    /// Sleeps `duration` on the pool's timer, the one connection deadlines
    /// run on, and answers `reply`. A request that no longer waits for the
    /// answer (`reply` canceled) ends the sleep early.
    fn sleep(&self, duration: Duration, mut reply: oneshot::Sender<()>) {
        let io = self.io.clone();
        // A duration too long to be an `Instant` never elapses, as for
        // `async_io::Timer`.
        let deadline = Instant::now().checked_add(duration);
        self.tasks.push(
            async move {
                {
                    let elapsed = async {
                        match deadline {
                            Some(deadline) => io.sleep_until(deadline).await,
                            None => std::future::pending().await,
                        }
                    };
                    let canceled = reply.cancellation();
                    pin_mut!(elapsed, canceled);
                    if let Either::Right(_) = select(elapsed, canceled).await {
                        return None;
                    }
                }
                // The sleep's future was dropped meanwhile: nobody to tell.
                let _ = reply.send(());
                None
            }
            .boxed_local(),
        );
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::TcpDialed {
                origin,
                protocols,
                phase,
                result,
            } => self.tcp_dialed(&origin, protocols, &phase, result),
            #[cfg(native_h2)]
            Event::H2Ended {
                origin,
                generation,
                result,
            } => self.h2_ended(&origin, generation, result),
            Event::CheckoutExpired { origin, waiter } => self.checkout_expired(&origin, waiter),
            #[cfg(native_h3)]
            Event::H3(event) => self.h3_event(event),
        }
    }

    /// The entry for `origin`, created on first contact. A new origin sweeps
    /// the table of entries that hold nothing.
    pub fn entry(&mut self, origin: &Origin) -> &mut Entry {
        if !self.origins.contains_key(origin) {
            let now = Instant::now();
            self.origins.retain(|_, entry| !entry.vacant(now));
            self.origins.insert(origin.clone(), Entry::new(origin));
        }
        self.origins
            .get_mut(origin)
            .expect("the entry was inserted above")
    }

    fn checkout(
        &mut self,
        origin: &Origin,
        want: Want,
        deadline: Option<Instant>,
        reply: oneshot::Sender<Result<Grant, Error>>,
    ) {
        if reply.is_canceled() {
            return;
        }
        #[cfg(native_h3)]
        let h3 = want.h3 == H3Use::Allowed;
        #[cfg(native_h3)]
        if h3 && let Some(send) = self.h3_checkout(origin, deadline) {
            if reply.send(Ok(Grant::H3(send))).is_err() {
                debug!("an HTTP/3 grant found its request gone");
            }
            return;
        }
        #[cfg(native_h2)]
        if want.allow_h2
            && let Some(grant) = self.h2_checkout(origin, want)
        {
            if reply.send(Ok(grant)).is_err() {
                debug!("an HTTP/2 grant found its request gone");
            }
            return;
        }
        let id = WaiterId(self.next_waiter);
        self.next_waiter += 1;
        let expiry = deadline.map(|deadline| self.expire_at(origin, id, deadline));
        self.entry(origin).waiters.push_back(Waiter {
            id,
            deadline,
            _expiry: expiry,
            reply,
            fresh: want.fresh,
            #[cfg(native_h2)]
            allow_h2: want.allow_h2,
            #[cfg(native_h2)]
            avoid_h2: want.avoid_h2,
            #[cfg(native_h3)]
            h3,
            #[cfg(native_h3)]
            tcp_error: None,
        });
        self.serve_waiters(origin);
    }

    /// Checks out a clone of `origin`'s live HTTP/2 handle, evicting a closed,
    /// idle-expired, or explicitly avoided handle along the way.
    #[cfg(native_h2)]
    fn h2_checkout(&mut self, origin: &Origin, want: Want) -> Option<Grant> {
        let entry = self.entry(origin);
        let evict = entry.h2.as_ref().is_some_and(|h2| {
            !h2.usable()
                || want.avoid_h2 == Some(h2.generation)
                || (want.fresh && want.avoid_h2.is_none())
        });
        if evict {
            entry.h2 = None;
        }
        let h2 = entry.h2.as_mut()?;
        h2.since = Instant::now();
        Some(Grant::H2 {
            send: h2.send.clone(),
            generation: h2.generation,
            reused: true,
        })
    }

    /// The bound on a QUIC dial for `origin` started for a request with
    /// `deadline`: the latest deadline among it and the waiters that may take
    /// the connection, none when any has no bound.
    #[cfg(native_h3)]
    pub(super) fn h3_bound(
        &mut self,
        origin: &Origin,
        deadline: Option<Instant>,
    ) -> Option<Instant> {
        let now = Instant::now();
        latest_deadline(
            std::iter::once(deadline).chain(
                self.entry(origin)
                    .waiters
                    .iter()
                    .filter(|waiter| waiter.h3 && !waiter.expired(now))
                    .map(|waiter| waiter.deadline),
            ),
        )
    }

    /// Starts the countdown to `deadline` for waiter `id` at `origin`, on the
    /// pool's timer. The sender it returns ends the countdown when the
    /// waiter holding it goes away, served or not.
    fn expire_at(&self, origin: &Origin, id: WaiterId, deadline: Instant) -> oneshot::Sender<()> {
        let io = self.io.clone();
        let origin = origin.clone();
        let (expiry, mut ended) = oneshot::channel::<()>();
        self.tasks.push(
            async move {
                let elapsed = io.sleep_until(deadline);
                pin_mut!(elapsed);
                match select(elapsed, &mut ended).await {
                    Either::Left(_) => Some(Event::CheckoutExpired { origin, waiter: id }),
                    Either::Right(_) => None,
                }
            }
            .boxed_local(),
        );
        expiry
    }

    /// A request's connect timeout passed: unless it was served meanwhile,
    /// it fails with the phase the origin's connection was in.
    fn checkout_expired(&mut self, origin: &Origin, id: WaiterId) {
        let Some(entry) = self.origins.get_mut(origin) else {
            return;
        };
        let Some(at) = entry.waiters.iter().position(|waiter| waiter.id == id) else {
            return;
        };
        let waiter = entry.waiters.remove(at).expect("the position is in range");
        let dials = entry.dials.iter().map(|dial| dial.phase.get());
        #[cfg(native_h3)]
        let dials = dials.chain((waiter.h3 && entry.h3.dialing()).then_some(ConnectPhase::Quic));
        let during = dials
            .max_by_key(|phase| phase_rank(*phase))
            .unwrap_or(ConnectPhase::Queued);
        debug!(host = %origin.host, %during, "a request's connect timeout passed while it waited");
        waiter.fail(Error::Timeout(TimedOut::Connect { during }));
        self.serve_waiters(origin);
    }

    /// Serves `origin`'s waiters in order: live HTTP/2 or idle HTTP/1.1
    /// connections to waiters that may reuse them, a single coalesced
    /// `Http2OrHttp1` dial when the origin may speak HTTP/2, and parallel
    /// `Http1` dials up to [`MAX_H1_PER_ORIGIN`] when HTTP/1.1 is owed.
    fn serve_waiters(&mut self, origin: &Origin) {
        let Some(entry) = self.origins.get_mut(origin) else {
            return;
        };
        let now = Instant::now();
        entry.idle.retain(Idle::usable);
        entry.waiters.retain(|waiter| !waiter.gone());
        #[cfg(native_h2)]
        entry.grant_pooled_h2(now);
        entry.grant_idle_h1(now);

        let known_h1 = entry.is_known_h1();
        #[cfg(native_h2)]
        let start_h2 = if !known_h1
            && entry
                .waiters
                .iter()
                .any(|waiter| waiter.awaits_dial() && !waiter.expired(now) && waiter.allow_h2)
        {
            let bound = latest_deadline(
                entry
                    .waiters
                    .iter()
                    .filter(|waiter| {
                        waiter.awaits_dial() && !waiter.expired(now) && waiter.allow_h2
                    })
                    .map(|waiter| waiter.deadline),
            );
            entry
                .dials
                .iter()
                .find(|dial| matches!(dial.protocols, Protocols::Http2OrHttp1))
                .map_or(Some(bound), |running| {
                    running.bound.set(bound);
                    None
                })
        } else {
            None
        };

        let h1_waiter = |waiter: &&Waiter| -> bool {
            waiter.awaits_dial() && !waiter.expired(now) && waiter.needs_h1_dial(known_h1)
        };
        let active_h1 = entry.waiters.iter().filter(h1_waiter).count();
        let h1_bound = latest_deadline(entry.waiters.iter().filter(h1_waiter).map(|w| w.deadline));
        if active_h1 > 0 {
            for dial in &entry.dials {
                if matches!(dial.protocols, Protocols::Http1) {
                    dial.bound.set(h1_bound);
                }
            }
        }
        let mut h1_dialing = entry.h1_dialing();
        let owed = active_h1.saturating_sub(h1_dialing);
        let mut h1_dials = 0;
        while h1_dials < owed && entry.leased + h1_dialing < MAX_H1_PER_ORIGIN {
            // An idle connection beyond the limit gives way so the total
            // stays within it.
            if entry.leased + h1_dialing + entry.idle.len() >= MAX_H1_PER_ORIGIN
                && !entry.idle.is_empty()
            {
                entry.idle.remove(0);
            }
            h1_dialing += 1;
            h1_dials += 1;
        }

        #[cfg(native_h2)]
        if let Some(bound) = start_h2 {
            self.start_dial(origin.clone(), Protocols::Http2OrHttp1, bound);
        }
        for _ in 0..h1_dials {
            self.start_dial(origin.clone(), Protocols::Http1, h1_bound);
        }
    }

    /// Starts a TCP/TLS dial for `origin` offering `protocols`, bounded by
    /// `initial_bound` (and updated in place as later waiters join).
    fn start_dial(&mut self, origin: Origin, protocols: Protocols, initial_bound: Option<Instant>) {
        let phase = Rc::new(Cell::new(ConnectPhase::Resolve));
        let bound = Rc::new(DialBound::new(initial_bound));
        self.entry(&origin).dials.push(InFlightDial {
            protocols,
            phase: Rc::clone(&phase),
            bound: Rc::clone(&bound),
        });
        let Some(transport) = self.transport.upgrade() else {
            self.tasks.push(
                async move {
                    Some(Event::TcpDialed {
                        origin,
                        protocols,
                        phase,
                        result: Err(gone()),
                    })
                }
                .boxed_local(),
            );
            return;
        };
        let tls = match &self.tls {
            Some(tls) => tls.clone(),
            None => match connect::connectors(transport.tls()) {
                Ok(tls) => self.tls.insert(tls).clone(),
                Err(error) => {
                    self.tasks.push(
                        async move {
                            Some(Event::TcpDialed {
                                origin,
                                protocols,
                                phase,
                                result: Err(error),
                            })
                        }
                        .boxed_local(),
                    );
                    return;
                }
            },
        };
        let io = self.io.clone();
        let resolver = Rc::clone(&self.resolver);
        self.tasks.push(
            async move {
                let result = connect::dial(
                    &io,
                    &*resolver,
                    &transport,
                    &tls,
                    &origin,
                    DialOptions {
                        protocols,
                        bound: &bound,
                        phase: &phase,
                    },
                )
                .await;
                Some(Event::TcpDialed {
                    origin,
                    protocols,
                    phase,
                    result,
                })
            }
            .boxed_local(),
        );
    }

    fn tcp_dialed(
        &mut self,
        origin: &Origin,
        protocols: Protocols,
        phase: &Rc<Cell<ConnectPhase>>,
        result: Result<Dialed, Error>,
    ) {
        let entry = self.entry(origin);
        entry
            .dials
            .retain(|running| !Rc::ptr_eq(&running.phase, phase));
        match result {
            Ok(Dialed {
                conn: DialedConn::H1 { send, via, driver },
                ..
            }) => {
                #[cfg(native_h2)]
                if matches!(protocols, Protocols::Http2OrHttp1) {
                    entry.protocol = Some(Protocol::Http1);
                }
                #[cfg(not(native_h2))]
                let _ = protocols;
                self.tasks.push(driver.map(|()| None).boxed_local());
                self.offer(origin, send, via, false);
            }
            #[cfg(native_h2)]
            Ok(Dialed {
                conn: DialedConn::H2 { send, driver },
                ..
            }) => {
                let now = Instant::now();
                entry.protocol = Some(Protocol::Http2);
                entry.idle.clear();
                entry.h2_generation += 1;
                let generation = entry.h2_generation;
                entry.h2 = Some(PooledH2 {
                    send: send.clone(),
                    generation,
                    since: now,
                });
                let ended = origin.clone();
                self.tasks.push(
                    driver
                        .map(move |result| {
                            Some(Event::H2Ended {
                                origin: ended,
                                generation,
                                result,
                            })
                        })
                        .boxed_local(),
                );
                let entry = self.entry(origin);
                let mut first = true;
                for waiter in std::mem::take(&mut entry.waiters) {
                    if waiter.gone() {
                        continue;
                    }
                    if waiter.allow_h2 {
                        let reused = !first;
                        if waiter
                            .grant(Grant::H2 {
                                send: send.clone(),
                                generation,
                                reused,
                            })
                            .is_none()
                        {
                            first = false;
                        } else {
                            debug!("an HTTP/2 grant found its request gone");
                        }
                    } else {
                        entry.waiters.push_back(waiter);
                    }
                }
                self.serve_waiters(origin);
            }
            Err(error) => {
                self.dial_failed(origin, protocols, error);
                self.serve_waiters(origin);
            }
        }
    }

    #[cfg(native_h2)]
    fn h2_ended(
        &mut self,
        origin: &Origin,
        generation: u64,
        result: Result<(), http_kit_h2::Error>,
    ) {
        if let Err(error) = result {
            debug!(host = %origin.host, %error, "HTTP/2 connection ended with an error");
        }
        let Some(entry) = self.origins.get_mut(origin) else {
            return;
        };
        if entry
            .h2
            .as_ref()
            .is_some_and(|h2| h2.generation == generation)
        {
            entry.h2 = None;
        }
    }

    /// A free HTTP/1.1 connection: the first waiter that may take it does,
    /// or it parks. A closed one only frees its slot.
    fn offer(&mut self, origin: &Origin, send: H1Send, via: Via, reused: bool) {
        let now = Instant::now();
        let entry = self.entry(origin);
        let known_h1 = entry.is_known_h1();
        let mut free = (!send.is_closed()).then_some((send, via));
        while let Some((send, via)) = free.take() {
            entry.waiters.retain(|waiter| !waiter.gone());
            let Some(at) = entry
                .waiters
                .iter()
                .position(|waiter| waiter.accepts_h1(known_h1, reused))
            else {
                if entry.may_park_h1() {
                    entry.idle.push(Idle {
                        send,
                        via,
                        since: now,
                    });
                }
                break;
            };
            let waiter = entry.waiters.remove(at).expect("the position is in range");
            match waiter.grant_h1(send, via, reused) {
                None => entry.leased += 1,
                Some(back) => free = Some(back),
            }
        }
        self.serve_waiters(origin);
    }

    /// A dial for `origin` failed: the first waiter still owed a dial of that
    /// kind gets the error, unless a QUIC dial races for it, which it then
    /// waits on. A dial that timed out answers no one: it stopped at the
    /// latest deadline of the waiters it was started for, which have expired
    /// through their own tasks, and a waiter still within its deadline stays
    /// queued for the next dial.
    fn dial_failed(&mut self, origin: &Origin, protocols: Protocols, error: Error) {
        let entry = self.entry(origin);
        if let Error::Timeout(TimedOut::Connect { during }) = error {
            debug!(host = %origin.host, %error, "a dial stopped at its deadline");
            let now = Instant::now();
            for waiter in std::mem::take(&mut entry.waiters) {
                if waiter.expired(now) {
                    waiter.fail(Error::Timeout(TimedOut::Connect { during }));
                } else {
                    entry.waiters.push_back(waiter);
                }
            }
            return;
        }
        entry.waiters.retain(|waiter| !waiter.gone());
        let known_h1 = entry.is_known_h1();
        let matches_dial = |waiter: &Waiter| -> bool {
            if !waiter.awaits_dial() {
                return false;
            }
            #[cfg(native_h2)]
            return match protocols {
                Protocols::Http2OrHttp1 => waiter.allow_h2,
                Protocols::Http1 => known_h1 || !waiter.allow_h2,
            };
            #[cfg(not(native_h2))]
            {
                let _ = (protocols, known_h1);
                true
            }
        };
        let Some(at) = entry.waiters.iter().position(matches_dial) else {
            debug!(host = %origin.host, %error, "a dial failed with no request waiting on it");
            return;
        };
        #[cfg(native_h3)]
        if entry.h3.dialing() && entry.waiters[at].h3 {
            debug!(host = %origin.host, %error, "TCP dial failed; the request waits on QUIC");
            entry.waiters[at].tcp_error = Some(error);
            return;
        }
        entry
            .waiters
            .remove(at)
            .expect("the position is in range")
            .fail(error);
    }

    /// A QUIC connection to `origin` completed its handshake: every waiter
    /// that may use it takes it.
    #[cfg(native_h3)]
    pub(super) fn h3_won(&mut self, origin: &Origin, send: &http_kit_h3::SendRequest) {
        let entry = self.entry(origin);
        for waiter in std::mem::take(&mut entry.waiters) {
            if waiter.h3 {
                if waiter.grant(Grant::H3(send.clone())).is_some() {
                    debug!("an HTTP/3 grant found its request gone");
                }
            } else {
                entry.waiters.push_back(waiter);
            }
        }
    }

    /// The QUIC dial to `origin` failed: the waiters whose TCP dial had
    /// failed too fail with that error; the rest stay on TCP.
    #[cfg(native_h3)]
    pub(super) fn h3_lost(&mut self, origin: &Origin) {
        let entry = self.entry(origin);
        for mut waiter in std::mem::take(&mut entry.waiters) {
            match waiter.tcp_error.take() {
                Some(error) => waiter.fail(error),
                None => entry.waiters.push_back(waiter),
            }
        }
    }
}
