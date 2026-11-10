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
//! connections parked until [`IDLE_TIMEOUT`], waiters served in order.

use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

use futures_channel::{mpsc, oneshot};
use futures_util::{FutureExt, StreamExt, future::LocalBoxFuture, stream::FuturesUnordered};
use http_kit_h1::SendRequest;
use http_kit_tls::TlsConnector;
use tracing::debug;

use super::connect::{self, Dialed, NativeIo};
use crate::{
    Error,
    transport::{
        WeakTransport,
        route::{IDLE_TIMEOUT, MAX_H1_PER_ORIGIN, Origin, Via},
    },
};

#[cfg(native_h3)]
use super::h3::{self, H3Slot};

/// How a request may use the origin's HTTP/3 connection.
#[cfg(native_h3)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H3Use {
    /// Never: the request is plaintext or goes through a proxy.
    Blocked,
    /// Only once the connection has carried a response: the request cannot
    /// be sent again on TCP if the QUIC handshake turns out to fail.
    Proven,
    /// Also while the connection is unproven: the request is idempotent and
    /// its body replayable, so it goes again on TCP if QUIC fails.
    Any,
}

/// What a request asks the pool for.
#[derive(Clone, Copy, Debug)]
pub struct Want {
    /// Dial a new HTTP/1.1 connection rather than reuse an idle one: the
    /// retry after a reused connection closed under the request.
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
        send: SendRequest,
        via: Via,
        reused: bool,
    },
    /// The origin's HTTP/3 connection.
    #[cfg(native_h3)]
    H3(h3::H3Grant),
}

/// What a request sends the pool.
#[derive(Debug)]
pub enum Command {
    /// A connection for `origin`.
    Checkout {
        origin: Origin,
        want: Want,
        reply: oneshot::Sender<Result<Grant, Error>>,
    },
    /// A leased HTTP/1.1 connection whose response body ended.
    Release {
        origin: Origin,
        send: SendRequest,
        via: Via,
    },
    /// A leased HTTP/1.1 connection that cannot serve again: its request
    /// failed or its body was dropped unread.
    Discard { origin: Origin },
    /// HTTP/3 news from a request.
    #[cfg(native_h3)]
    H3(h3::H3Report),
}

/// The `Send` side of a pool: requests reach the pool's thread through it.
/// The pool runs while any handle exists.
#[derive(Clone, Debug)]
pub struct PoolHandle(mpsc::UnboundedSender<Command>);

/// The pool's end of its channel, handed to [`run`] on the pool's thread.
#[derive(Debug)]
pub struct PoolReceiver(mpsc::UnboundedReceiver<Command>);

impl PoolHandle {
    /// A handle and the receiver its pool runs on.
    pub fn channel() -> (Self, PoolReceiver) {
        let (sender, receiver) = mpsc::unbounded();
        (Self(sender), PoolReceiver(receiver))
    }

    /// A connection for `origin`, dialed if none is free.
    ///
    /// # Errors
    ///
    /// The dial failed, or the pool is gone.
    pub async fn checkout(&self, origin: Origin, want: Want) -> Result<Grant, Error> {
        let (reply, granted) = oneshot::channel();
        self.send(Command::Checkout {
            origin,
            want,
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

fn gone() -> Error {
    Error::Transport(Box::new(std::io::Error::other(
        "the native connection pool's thread has stopped",
    )))
}

/// Something a pool task finished.
pub enum Event {
    /// An HTTP/1.1 dial for `waiter` ended.
    H1Dialed {
        origin: Origin,
        waiter: Waiter,
        result: Result<Dialed, Error>,
    },
    #[cfg(native_h3)]
    H3(h3::H3Event),
}

/// A request waiting for a connection.
pub struct Waiter {
    reply: oneshot::Sender<Result<Grant, Error>>,
    fresh: bool,
}

impl Waiter {
    /// Hands `grant` over, or back when the request is gone.
    fn grant(self, grant: Grant) -> Option<Grant> {
        self.reply.send(Ok(grant)).err().and_then(Result::ok)
    }

    fn fail(self, error: Error) {
        if self.reply.send(Err(error)).is_err() {
            debug!("a dial failed for a request that is gone");
        }
    }
}

/// An HTTP/1.1 connection parked between requests.
struct Idle {
    send: SendRequest,
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
    /// HTTP/1.1 connections leased or dialing.
    busy: usize,
    waiters: VecDeque<Waiter>,
    #[cfg(native_h3)]
    pub h3: H3Slot,
}

impl Entry {
    const fn new(#[cfg_attr(not(native_h3), expect(unused_variables))] origin: &Origin) -> Self {
        Self {
            idle: Vec::new(),
            busy: 0,
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
        self.idle.is_empty() && self.busy == 0 && self.waiters.is_empty() && h3
    }
}

/// The pool's state: everything its task owns.
pub struct Pool<I> {
    pub io: I,
    pub transport: WeakTransport,
    tls: Option<TlsConnector>,
    pub origins: HashMap<Origin, Entry>,
    pub tasks: FuturesUnordered<LocalBoxFuture<'static, Option<Event>>>,
    #[cfg(native_h3)]
    pub h3: h3::H3Client,
}

/// Runs a pool over `io` until every [`PoolHandle`] is dropped. Connections
/// still open then close with it.
pub async fn run<I: NativeIo>(io: I, transport: WeakTransport, receiver: PoolReceiver) {
    let mut pool = Pool {
        io,
        transport,
        tls: None,
        origins: HashMap::new(),
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

impl<I: NativeIo> Pool<I> {
    fn command(&mut self, command: Command) {
        match command {
            Command::Checkout {
                origin,
                want,
                reply,
            } => self.checkout(&origin, want, reply),
            Command::Release { origin, send, via } => self.release(&origin, send, via),
            Command::Discard { origin } => {
                if let Some(entry) = self.origins.get_mut(&origin) {
                    entry.busy -= 1;
                }
                self.serve_waiters(&origin);
            }
            #[cfg(native_h3)]
            Command::H3(report) => self.h3_report(report),
        }
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::H1Dialed {
                origin,
                waiter,
                result,
            } => self.h1_dialed(&origin, waiter, result),
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
        reply: oneshot::Sender<Result<Grant, Error>>,
    ) {
        if reply.is_canceled() {
            return;
        }
        #[cfg(native_h3)]
        let Some(reply) = self.h3_checkout(origin, want.h3, reply) else {
            return;
        };
        self.entry(origin).waiters.push_back(Waiter {
            reply,
            fresh: want.fresh,
        });
        self.serve_waiters(origin);
    }

    /// Serves `origin`'s waiters in order: an idle connection when one is
    /// usable and the waiter may reuse it, a new dial while slots are free.
    fn serve_waiters(&mut self, origin: &Origin) {
        let Some(entry) = self.origins.get_mut(origin) else {
            return;
        };
        entry.idle.retain(Idle::usable);
        let mut dials = Vec::new();
        while let Some(waiter) = entry.waiters.pop_front() {
            if waiter.reply.is_canceled() {
                continue;
            }
            if !waiter.fresh
                && let Some(idle) = entry.idle.pop()
            {
                entry.busy += 1;
                let grant = Grant::H1 {
                    send: idle.send,
                    via: idle.via,
                    reused: true,
                };
                if let Some(Grant::H1 { send, via, .. }) = waiter.grant(grant) {
                    entry.busy -= 1;
                    entry.idle.push(Idle {
                        send,
                        via,
                        since: Instant::now(),
                    });
                }
                continue;
            }
            if entry.busy < MAX_H1_PER_ORIGIN {
                // A slot is free; an idle connection beyond the limit gives
                // way so the total stays within it.
                if entry.busy + entry.idle.len() >= MAX_H1_PER_ORIGIN && !entry.idle.is_empty() {
                    entry.idle.remove(0);
                }
                entry.busy += 1;
                dials.push(waiter);
                continue;
            }
            entry.waiters.push_front(waiter);
            break;
        }
        for waiter in dials {
            self.dial_h1(origin.clone(), waiter);
        }
    }

    /// Starts an HTTP/1.1 dial for `waiter`.
    fn dial_h1(&mut self, origin: Origin, waiter: Waiter) {
        let Some(transport) = self.transport.upgrade() else {
            waiter.fail(gone());
            self.entry(&origin).busy -= 1;
            return;
        };
        let tls = self
            .tls
            .get_or_insert_with(|| TlsConnector::new(transport.tls().http1_config().clone()))
            .clone();
        let io = self.io.clone();
        self.tasks.push(
            async move {
                let result = connect::dial(&io, &transport, &tls, &origin).await;
                Some(Event::H1Dialed {
                    origin,
                    waiter,
                    result,
                })
            }
            .boxed_local(),
        );
    }

    fn h1_dialed(&mut self, origin: &Origin, waiter: Waiter, result: Result<Dialed, Error>) {
        match result {
            Ok(Dialed { send, via, driver }) => {
                self.tasks.push(driver.map(|()| None).boxed_local());
                let grant = Grant::H1 {
                    send,
                    via,
                    reused: false,
                };
                if let Some(Grant::H1 { send, via, .. }) = waiter.grant(grant) {
                    // The request is gone; the connection serves the next.
                    self.release(origin, send, via);
                }
            }
            Err(error) => {
                waiter.fail(error);
                self.entry(origin).busy -= 1;
                self.serve_waiters(origin);
            }
        }
    }

    /// A leased connection is free again: the next waiter takes it, or it
    /// parks. A closed one frees its slot instead.
    fn release(&mut self, origin: &Origin, send: SendRequest, via: Via) {
        let entry = self.entry(origin);
        entry.busy -= 1;
        if !send.is_closed() {
            entry.idle.push(Idle {
                send,
                via,
                since: Instant::now(),
            });
        }
        self.serve_waiters(origin);
    }
}
