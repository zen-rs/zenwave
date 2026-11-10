//! HTTP/3 in the native pool: `http-kit-h3` connections over the pool's
//! `http-kit-io` UDP sockets, discovered through `Alt-Svc` and HTTPS records
//! with the hyper backend's [`H3Knowledge`] policy.
//!
//! `http-kit-h3` starts a connection without waiting for its handshake and
//! reports no handshake outcome, so a new connection is *unproven* until a
//! response arrives on it. The request that triggers the dial goes over TCP;
//! afterwards an unproven connection carries only requests that can be sent
//! again on TCP — idempotent, with a replayable body — and it is abandoned,
//! with QUIC put into backoff for the origin, if it fails or carries no
//! response within the connect timeout. Once proven it carries every
//! request.

use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    time::Instant,
};

use futures_channel::oneshot;
use futures_util::{
    FutureExt,
    future::{Either, LocalBoxFuture, select},
    pin_mut,
};
use http_kit_h3::{Client, ClientConfig, Roots, SendRequest};
use http_kit_io::Io;
use tracing::debug;

use super::{
    connect::NativeIo,
    pool::{Command, Event, Grant, H3Use, Pool},
};
use crate::{
    Error, Transport,
    transport::{
        Spawn,
        discovery::{H3Knowledge, HttpsRr},
        happy_eyeballs,
        route::{IDLE_TIMEOUT, Origin},
    },
};

/// The largest response header section accepted, the HTTP/1.1 client's
/// head limit, so both protocols bound a head alike.
const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// The origin's HTTP/3 connection, as handed to a request.
#[derive(Debug)]
pub struct H3Grant {
    pub send: SendRequest,
    /// Which of the origin's connections this is, for the report back.
    pub generation: u64,
    /// For an unproven connection: fires when the pool abandons it, so the
    /// request stops waiting on it and goes over TCP. Dropped unfired once
    /// the connection is proven.
    pub verdict: Option<oneshot::Receiver<()>>,
}

/// What a request learned about HTTP/3.
#[derive(Debug)]
pub enum H3Report {
    /// A response arrived on connection `generation`.
    Proven { origin: Origin, generation: u64 },
    /// A request on unproven connection `generation` failed.
    Failed { origin: Origin, generation: u64 },
    /// A response for `origin` carried these `Alt-Svc` fields, joined.
    AltSvc { origin: Origin, value: String },
}

/// What an HTTP/3 task finished.
pub enum H3Event {
    Connected {
        origin: Origin,
        generation: u64,
        result: Result<
            (
                SendRequest,
                LocalBoxFuture<'static, Result<(), http_kit_h3::Error>>,
            ),
            Error,
        >,
    },
    /// Connection `generation`'s driver returned.
    Ended {
        origin: Origin,
        generation: u64,
        result: Result<(), http_kit_h3::Error>,
    },
    /// Connection `generation` has had its connect timeout to prove itself.
    Deadline {
        origin: Origin,
        generation: u64,
    },
    Discovered {
        origin: Origin,
        rr: HttpsRr,
    },
}

/// The pool's prepared `http-kit-h3` client, built on first use from the
/// transport's roots. Shared with connect tasks, which borrow it only for
/// the synchronous `connect` call.
#[derive(Default, Clone)]
pub struct H3Client(Rc<RefCell<Option<Client>>>);

/// One origin's HTTP/3 state.
pub struct H3Slot {
    knowledge: H3Knowledge,
    conn: Option<Pooled>,
    dialing: bool,
    generation: u64,
}

struct Pooled {
    send: SendRequest,
    generation: u64,
    since: Instant,
    proven: bool,
    verdicts: Vec<oneshot::Sender<()>>,
}

impl H3Slot {
    pub const fn new(port: u16) -> Self {
        Self {
            knowledge: H3Knowledge::new(port),
            conn: None,
            dialing: false,
            generation: 0,
        }
    }

    /// Whether nothing here would change a later request's work.
    pub fn vacant(&mut self, now: Instant) -> bool {
        self.evict();
        self.conn.is_none() && !self.dialing && !self.knowledge.is_live(now)
    }

    /// Drops a closed connection, or one unused for the idle window.
    fn evict(&mut self) {
        if self
            .conn
            .as_ref()
            .is_some_and(|conn| conn.send.is_closed() || conn.since.elapsed() >= IDLE_TIMEOUT)
        {
            self.conn = None;
        }
    }

    /// The connection for a request that may use it as `using` says.
    fn lease(&mut self, using: H3Use, now: Instant) -> Option<H3Grant> {
        self.evict();
        let conn = self.conn.as_mut()?;
        let verdict = if conn.proven {
            None
        } else if using == H3Use::Any {
            let (abandon, verdict) = oneshot::channel();
            conn.verdicts.push(abandon);
            Some(verdict)
        } else {
            return None;
        };
        conn.since = now;
        Some(H3Grant {
            send: conn.send.clone(),
            generation: conn.generation,
            verdict,
        })
    }

    /// The live connection, when it is connection `generation`.
    fn current(&mut self, generation: u64) -> Option<&mut Pooled> {
        self.conn
            .as_mut()
            .filter(|conn| conn.generation == generation)
    }

    /// Abandons the unproven connection and keeps QUIC off for the backoff;
    /// requests waiting on it go over TCP.
    fn fail(&mut self, now: Instant) {
        self.knowledge.mark_broken(now);
        if let Some(conn) = self.conn.take() {
            for abandon in conn.verdicts {
                abandon.send(()).ok();
            }
        }
    }
}

impl<I: NativeIo> Pool<I> {
    /// Serves `reply` from the origin's HTTP/3 connection when `using`
    /// allows, and starts discovery or a QUIC dial when they are due. Hands
    /// `reply` back when HTTP/1.1 must serve it.
    pub(super) fn h3_checkout(
        &mut self,
        origin: &Origin,
        using: H3Use,
        reply: oneshot::Sender<Result<Grant, Error>>,
    ) -> Option<oneshot::Sender<Result<Grant, Error>>> {
        if using == H3Use::Blocked {
            return Some(reply);
        }
        let now = Instant::now();
        let slot = &mut self.entry(origin).h3;
        if let Some(grant) = slot.lease(using, now) {
            if reply.send(Ok(Grant::H3(grant))).is_err() {
                debug!("an HTTP/3 grant found its request gone");
            }
            return None;
        }
        let discover = slot.knowledge.begin_discovery(now);
        let dial = slot
            .knowledge
            .candidate(now)
            .filter(|_| !slot.dialing && slot.conn.is_none());
        let timeout = slot.knowledge.connect_timeout();
        if dial.is_some() {
            slot.dialing = true;
            slot.generation += 1;
        }
        let generation = slot.generation;
        if let Some(transport) = self.transport.upgrade() {
            if discover {
                self.tasks
                    .push(discover_task(transport.clone(), origin.clone()));
            }
            if let Some(port) = dial {
                let io = self.io.clone();
                let client = self.h3.clone();
                let origin = origin.clone();
                self.tasks.push(
                    async move {
                        let deadline = Instant::now() + timeout;
                        let result =
                            connect(&io, &transport, &client, &origin.host, port, deadline).await;
                        Some(Event::H3(H3Event::Connected {
                            origin,
                            generation,
                            result,
                        }))
                    }
                    .boxed_local(),
                );
            }
        }
        Some(reply)
    }

    pub(super) fn h3_report(&mut self, report: H3Report) {
        let now = Instant::now();
        match report {
            H3Report::Proven { origin, generation } => {
                if let Some(conn) = self.entry(&origin).h3.current(generation) {
                    conn.proven = true;
                    conn.verdicts.clear();
                }
            }
            H3Report::Failed { origin, generation } => {
                let slot = &mut self.entry(&origin).h3;
                if slot.current(generation).is_some_and(|conn| !conn.proven) {
                    debug!(host = %origin.host, "HTTP/3 connection failed unproven; backing off");
                    slot.fail(now);
                }
            }
            H3Report::AltSvc { origin, value } => {
                let host = origin.host.clone();
                self.entry(&origin)
                    .h3
                    .knowledge
                    .insert_alt_svc(&host, &value, now);
            }
        }
    }

    pub(super) fn h3_event(&mut self, event: H3Event) {
        let now = Instant::now();
        match event {
            H3Event::Connected {
                origin,
                generation,
                result,
            } => {
                let timeout = {
                    let slot = &mut self.entry(&origin).h3;
                    slot.dialing = false;
                    slot.knowledge.connect_timeout()
                };
                match result {
                    Ok((send, driver)) => {
                        self.entry(&origin).h3.conn = Some(Pooled {
                            send,
                            generation,
                            since: now,
                            proven: false,
                            verdicts: Vec::new(),
                        });
                        let ended = origin.clone();
                        self.tasks.push(
                            driver
                                .map(move |result| {
                                    Some(Event::H3(H3Event::Ended {
                                        origin: ended,
                                        generation,
                                        result,
                                    }))
                                })
                                .boxed_local(),
                        );
                        let io = self.io.clone();
                        self.tasks.push(
                            async move {
                                io.sleep(timeout).await;
                                Some(Event::H3(H3Event::Deadline { origin, generation }))
                            }
                            .boxed_local(),
                        );
                    }
                    Err(error) => {
                        debug!(host = %origin.host, %error, "QUIC dial failed; backing off");
                        self.entry(&origin).h3.knowledge.mark_broken(now);
                    }
                }
            }
            H3Event::Ended {
                origin,
                generation,
                result,
            } => {
                if let Err(error) = &result {
                    debug!(host = %origin.host, %error, "HTTP/3 connection ended with an error");
                }
                let slot = &mut self.entry(&origin).h3;
                match slot.current(generation).map(|conn| conn.proven) {
                    Some(false) => slot.fail(now),
                    Some(true) => slot.conn = None,
                    None => {}
                }
            }
            H3Event::Deadline { origin, generation } => {
                let slot = &mut self.entry(&origin).h3;
                if slot.current(generation).is_some_and(|conn| !conn.proven) {
                    debug!(host = %origin.host, "HTTP/3 connection unproven at its deadline");
                    slot.fail(now);
                }
            }
            H3Event::Discovered { origin, rr } => {
                self.entry(&origin).h3.knowledge.end_discovery(Some(rr));
            }
        }
    }
}

/// The HTTPS record lookup for `origin`, as a pool task.
fn discover_task(transport: Transport, origin: Origin) -> LocalBoxFuture<'static, Option<Event>> {
    async move {
        let lookup = transport
            .https_record(spawn_on_threads(), &origin.host, origin.port)
            .await;
        let rr = HttpsRr::from_lookup(lookup, &origin.host, origin.port, Instant::now());
        Some(Event::H3(H3Event::Discovered { origin, rr }))
    }
    .boxed_local()
}

/// The resolver's background work, each future on a thread of its own: the
/// transport's resolver is shared by every pool and outlives any one of
/// them, so its tasks cannot live on a pool's thread.
fn spawn_on_threads() -> Spawn {
    std::sync::Arc::new(crate::transport::spawn_thread)
}

/// Starts a QUIC connection to `host`:`port` on a UDP socket of the pool's
/// I/O, the address chosen as a TCP dial would order them. Resolution is
/// bounded by `deadline`.
async fn connect<I: Io>(
    io: &I,
    transport: &Transport,
    client: &H3Client,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<
    (
        SendRequest,
        LocalBoxFuture<'static, Result<(), http_kit_h3::Error>>,
    ),
    Error,
> {
    let addrs = {
        let resolve = happy_eyeballs::resolve(host, port);
        let expire = io.sleep_until(deadline);
        pin_mut!(resolve);
        pin_mut!(expire);
        match select(resolve, expire).await {
            Either::Left((addrs, _)) => addrs.map_err(|error| Error::Transport(Box::new(error)))?,
            Either::Right(((), _)) => {
                return Err(Error::Transport(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("resolving {host} for QUIC timed out"),
                ))));
            }
        }
    };
    let peer = *addrs.first().ok_or_else(|| {
        Error::Transport(Box::new(std::io::Error::other(format!(
            "{host} resolved to no address"
        ))))
    })?;
    let local = SocketAddr::new(
        match peer.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    );
    let socket = io
        .bind_udp(local)
        .map_err(|error| Error::Transport(Box::new(error)))?;
    let mut client = client.0.borrow_mut();
    let client = match &mut *client {
        Some(client) => client,
        empty => empty.insert(Client::new(&client_config(transport)).map_err(h3_error)?),
    };
    let (send, connection) = client
        .connect(socket, io.clone(), host, peer)
        .map_err(h3_error)?;
    Ok((send, connection.run().boxed_local()))
}

/// The client configuration: `BoringSSL`'s default verify paths plus the
/// transport's extra roots.
fn client_config(transport: &Transport) -> ClientConfig {
    let pem = transport
        .extra_roots()
        .iter()
        .map(|root| pem::encode(&pem::Pem::new("CERTIFICATE", root.to_vec())).into_bytes())
        .collect();
    ClientConfig::new(Roots { system: true, pem }, MAX_FIELD_SECTION_SIZE)
}

pub(super) fn h3_error(error: http_kit_h3::Error) -> Error {
    Error::Transport(Box::new(error))
}

/// Tells the pool about the `Alt-Svc` fields on `headers`, when there are
/// any.
pub(super) fn report_alt_svc(pool: &super::PoolHandle, origin: &Origin, headers: &http::HeaderMap) {
    if let Some(value) = crate::transport::discovery::joined_alt_svc(headers) {
        pool.send(Command::H3(H3Report::AltSvc {
            origin: origin.clone(),
            value,
        }));
    }
}
