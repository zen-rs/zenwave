//! The native backend's connection pool: one per thread, owned outright by
//! a single local task.
//!
//! The task holds every origin's state and every connection's driver, so
//! nothing in it is shared and nothing is locked. Requests reach it through
//! a [`PoolHandle`], a channel sender that is `Send` and `Sync`: a request
//! future asks for a connection, gets back a `Send` handle (an HTTP/1.1
//! sender leased exclusively, or a clone of the origin's HTTP/3 sender), and
//! talks to the connection through it. A thread-per-core caller runs one
//! pool per thread and its requests never leave that thread.
//!
//! HTTP/1.1 follows the hyper pool's rules: at most
//! [`MAX_H1_PER_ORIGIN`] connections leased or dialing per origin, idle
//! connections parked until [`IDLE_TIMEOUT`], waiters served in order. A
//! dial belongs to the origin, not to the request that caused it: the
//! connection it opens goes to the first request still waiting, so a
//! request that a QUIC connection served meanwhile leaves it to the next.

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
use http_kit_tls::TlsConnector;
use tracing::debug;

use super::connect::{self, Dialed, H1Send, NativeIo, NativeResolve};
use crate::{
    ConnectPhase, Error, TimedOut,
    clock::Clock,
    transport::{
        WeakTransport,
        route::{IDLE_TIMEOUT, MAX_H1_PER_ORIGIN, Origin, Via},
    },
};

#[cfg(native_h3)]
use super::h3::{self, H3Slot};

/// Whether a request may go over the origin's HTTP/3 connection.
#[cfg(native_h3)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H3Use {
    /// Never: the request is plaintext or goes through a proxy.
    Blocked,
    /// Whenever the origin has a connection whose handshake completed, or
    /// one completes while the request waits for HTTP/1.1.
    Allowed,
}

/// What a request asks the pool for.
#[derive(Clone, Copy, Debug)]
pub struct Want {
    /// Dial a new HTTP/1.1 connection rather than reuse an idle one: the
    /// retry after a reused connection failed under the request.
    pub fresh: bool,
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
    /// An HTTP/1.1 dial for `origin` ended.
    H1Dialed {
        origin: Origin,
        /// The phase the dial was in, which the origin stops reporting.
        phase: Rc<Cell<ConnectPhase>>,
        result: Result<Dialed, Error>,
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
    /// Dropped with the waiter, which ends the task counting down its
    /// connect timeout.
    _expiry: Option<oneshot::Sender<()>>,
    reply: oneshot::Sender<Result<Grant, Error>>,
    fresh: bool,
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

impl Waiter {
    fn gone(&self) -> bool {
        self.reply.is_canceled()
    }

    /// Whether the request is owed an HTTP/1.1 dial: unless its own failed
    /// while it waits on QUIC.
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

    /// Hands `grant` over, or back when the request is gone.
    fn grant(self, grant: Grant) -> Option<Grant> {
        self.reply.send(Ok(grant)).err().and_then(Result::ok)
    }

    /// Hands an HTTP/1.1 connection over, or back when the request is gone.
    fn grant_h1(self, send: H1Send, via: Via, reused: bool) -> Option<(H1Send, Via)> {
        match self.grant(Grant::H1 { send, via, reused })? {
            Grant::H1 { send, via, .. } => Some((send, via)),
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
    /// HTTP/1.1 dials in flight.
    dialing: usize,
    /// The phase of each HTTP/1.1 dial in flight.
    dial_phases: Vec<Rc<Cell<ConnectPhase>>>,
    waiters: VecDeque<Waiter>,
    #[cfg(native_h3)]
    pub h3: H3Slot,
}

impl Entry {
    const fn new(#[cfg_attr(not(native_h3), expect(unused_variables))] origin: &Origin) -> Self {
        Self {
            idle: Vec::new(),
            leased: 0,
            dialing: 0,
            dial_phases: Vec::new(),
            waiters: VecDeque::new(),
            #[cfg(native_h3)]
            h3: H3Slot::new(origin.port),
        }
    }

    /// Whether nothing here would change a later request's work.
    fn vacant(&mut self, now: Instant) -> bool {
        self.idle.retain(Idle::usable);
        #[cfg(native_h3)]
        let h3 = self.h3.vacant(now);
        #[cfg(not(native_h3))]
        let h3 = {
            let _ = now;
            true
        };
        self.idle.is_empty()
            && self.leased == 0
            && self.dialing == 0
            && self.waiters.is_empty()
            && h3
    }
}

/// The pool's state: everything its task owns.
pub struct Pool<I, R> {
    pub io: I,
    /// The resolver every dial task shares, on the pool's thread.
    pub resolver: Rc<R>,
    pub transport: WeakTransport,
    tls: Option<TlsConnector>,
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
            Event::H1Dialed {
                origin,
                phase,
                result,
            } => self.h1_dialed(&origin, &phase, result),
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
        if h3 && let Some(send) = self.h3_checkout(origin) {
            if reply.send(Ok(Grant::H3(send))).is_err() {
                debug!("an HTTP/3 grant found its request gone");
            }
            return;
        }
        let id = WaiterId(self.next_waiter);
        self.next_waiter += 1;
        let expiry = deadline.map(|deadline| self.expire_at(origin, id, deadline));
        self.entry(origin).waiters.push_back(Waiter {
            id,
            _expiry: expiry,
            reply,
            fresh: want.fresh,
            #[cfg(native_h3)]
            h3,
            #[cfg(native_h3)]
            tcp_error: None,
        });
        self.serve_waiters(origin);
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
        let dials = entry.dial_phases.iter().map(|phase| phase.get());
        #[cfg(native_h3)]
        let dials = dials.chain((waiter.h3 && entry.h3.dialing()).then_some(ConnectPhase::Quic));
        let during = dials
            .max_by_key(|phase| phase_rank(*phase))
            .unwrap_or(ConnectPhase::Queued);
        debug!(host = %origin.host, %during, "a request's connect timeout passed while it waited");
        waiter.fail(Error::Timeout(TimedOut::Connect { during }));
        self.serve_waiters(origin);
    }

    /// Serves `origin`'s waiters in order: idle connections to the first
    /// that may reuse one, then a dial for each waiter no dial covers yet,
    /// while the origin has slots free.
    fn serve_waiters(&mut self, origin: &Origin) {
        let Some(entry) = self.origins.get_mut(origin) else {
            return;
        };
        let now = Instant::now();
        entry.idle.retain(Idle::usable);
        entry.waiters.retain(|waiter| !waiter.gone());
        let mut next = 0;
        while next < entry.waiters.len()
            && let Some(idle) = entry.idle.pop()
        {
            if entry.waiters[next].fresh {
                entry.idle.push(idle);
                next += 1;
                continue;
            }
            let waiter = entry.waiters.remove(next).expect("the index is in range");
            match waiter.grant_h1(idle.send, idle.via, true) {
                None => entry.leased += 1,
                Some((send, via)) => entry.idle.push(Idle {
                    send,
                    via,
                    since: now,
                }),
            }
        }
        let owed = entry
            .waiters
            .iter()
            .filter(|waiter| waiter.awaits_dial())
            .count()
            .saturating_sub(entry.dialing);
        let mut dials = 0;
        while dials < owed && entry.leased + entry.dialing < MAX_H1_PER_ORIGIN {
            // An idle connection beyond the limit gives way so the total
            // stays within it.
            if entry.leased + entry.dialing + entry.idle.len() >= MAX_H1_PER_ORIGIN
                && !entry.idle.is_empty()
            {
                entry.idle.remove(0);
            }
            entry.dialing += 1;
            dials += 1;
        }
        for _ in 0..dials {
            self.dial_h1(origin.clone());
        }
    }

    /// Starts an HTTP/1.1 dial for `origin`.
    fn dial_h1(&mut self, origin: Origin) {
        let phase = Rc::new(Cell::new(ConnectPhase::Resolve));
        self.entry(&origin).dial_phases.push(Rc::clone(&phase));
        let Some(transport) = self.transport.upgrade() else {
            self.tasks.push(
                async move {
                    Some(Event::H1Dialed {
                        origin,
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
            None => match connect::connector(transport.tls().http1_config().clone()) {
                Ok(tls) => self.tls.insert(tls).clone(),
                Err(error) => {
                    self.tasks.push(
                        async move {
                            Some(Event::H1Dialed {
                                origin,
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
                let result =
                    connect::dial(&io, &*resolver, &transport, &tls, &origin, &phase).await;
                Some(Event::H1Dialed {
                    origin,
                    phase,
                    result,
                })
            }
            .boxed_local(),
        );
    }

    fn h1_dialed(
        &mut self,
        origin: &Origin,
        phase: &Rc<Cell<ConnectPhase>>,
        result: Result<Dialed, Error>,
    ) {
        let entry = self.entry(origin);
        entry.dialing -= 1;
        entry
            .dial_phases
            .retain(|running| !Rc::ptr_eq(running, phase));
        match result {
            Ok(Dialed {
                send, via, driver, ..
            }) => {
                self.tasks.push(driver.map(|()| None).boxed_local());
                self.offer(origin, send, via, false);
            }
            Err(error) => {
                self.dial_failed(origin, error);
                self.serve_waiters(origin);
            }
        }
    }

    /// A free HTTP/1.1 connection: the first waiter that may take it does,
    /// or it parks. A closed one only frees its slot.
    fn offer(&mut self, origin: &Origin, send: H1Send, via: Via, reused: bool) {
        let now = Instant::now();
        let entry = self.entry(origin);
        let mut free = (!send.is_closed()).then_some((send, via));
        while let Some((send, via)) = free.take() {
            entry.waiters.retain(|waiter| !waiter.gone());
            let Some(at) = entry
                .waiters
                .iter()
                .position(|waiter| !(reused && waiter.fresh))
            else {
                entry.idle.push(Idle {
                    send,
                    via,
                    since: now,
                });
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

    /// A dial for `origin` failed: the first waiter still owed one gets the
    /// error, unless a QUIC dial races for it, which it then waits on.
    fn dial_failed(&mut self, origin: &Origin, error: Error) {
        let entry = self.entry(origin);
        entry.waiters.retain(|waiter| !waiter.gone());
        let Some(at) = entry.waiters.iter().position(Waiter::awaits_dial) else {
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
    /// failed too fail with that error; the rest stay on HTTP/1.1.
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
