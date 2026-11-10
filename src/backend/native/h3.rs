//! HTTP/3 in the native pool: `http-kit-h3` connections over the pool's
//! `http-kit-io` UDP sockets, discovered through `Alt-Svc` and HTTPS records
//! with the hyper backend's [`H3Knowledge`] policy.
//!
//! A QUIC dial races TCP, as in the hyper backend. Once an origin has
//! advertised h3, a request that finds no live HTTP/3 connection starts a
//! QUIC dial and also waits in the origin's HTTP/1.1 queue, which serves it
//! from an idle connection or a TCP dial; whichever is usable first carries
//! it. A QUIC connection joins the pool only once its handshake completed
//! ([`SendRequest::ready`]), so the server's chain has passed the same
//! verifier TCP connections use, and from then on it carries every request
//! that may use HTTP/3. A dial that fails, or does not complete within the
//! connect timeout, puts the origin into QUIC backoff.

use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    sync::Arc,
    time::Instant,
};

use futures_util::{
    FutureExt,
    future::{Either, LocalBoxFuture, select},
    pin_mut,
};
use http_kit_h3::{Client, ClientConfig, Rejection, SendRequest, Verifier};
use http_kit_io::Io;
use rustls::{
    CertificateError,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tracing::debug;

use super::{
    connect::NativeIo,
    pool::{Command, Event, Pool},
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

/// A QUIC connection whose handshake completed, and the future that drives
/// it from here on.
type Established = (
    SendRequest,
    LocalBoxFuture<'static, Result<(), http_kit_h3::Error>>,
);

/// What an HTTP/3 task finished.
pub enum H3Event {
    /// Dial `generation` ended: a connection whose handshake completed, or
    /// why none did.
    Connected {
        origin: Origin,
        generation: u64,
        result: Result<Established, Error>,
    },
    /// Connection `generation`'s driver returned.
    Ended {
        origin: Origin,
        generation: u64,
        result: Result<(), http_kit_h3::Error>,
    },
    Discovered {
        origin: Origin,
        rr: HttpsRr,
    },
}

/// The pool's prepared `http-kit-h3` client, built on first use with the
/// transport's verifier. Shared with dial tasks, which borrow it only for
/// the synchronous `connect` call.
#[derive(Default, Clone)]
pub struct H3Client(Rc<RefCell<Option<Client>>>);

/// One origin's HTTP/3 state.
pub struct H3Slot {
    knowledge: H3Knowledge,
    conn: Option<Pooled>,
    dialing: bool,
    /// Numbers dials, so a late event about a replaced connection is
    /// recognised as such.
    generation: u64,
}

struct Pooled {
    send: SendRequest,
    generation: u64,
    since: Instant,
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

    /// Whether a QUIC dial is racing for the origin.
    pub const fn dialing(&self) -> bool {
        self.dialing
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

    /// The live connection's handle, its idle clock restarted.
    fn lease(&mut self, now: Instant) -> Option<SendRequest> {
        self.evict();
        let conn = self.conn.as_mut()?;
        conn.since = now;
        Some(conn.send.clone())
    }

    /// Whether `generation` is the dial or connection the slot knows now.
    const fn is_current(&self, generation: u64) -> bool {
        self.generation == generation
    }
}

impl<I: NativeIo> Pool<I> {
    /// The origin's live HTTP/3 connection for a request that may use it.
    /// Without one, starts the HTTPS record lookup and the QUIC dial when
    /// they are due; the request then waits in the HTTP/1.1 queue, where a
    /// dial that completes in time finds it.
    pub(super) fn h3_checkout(&mut self, origin: &Origin) -> Option<SendRequest> {
        let now = Instant::now();
        // Without the transport no dial can start; HTTP/1.1 reports why.
        let transport = self.transport.upgrade()?;
        let slot = &mut self.entry(origin).h3;
        if let Some(send) = slot.lease(now) {
            return Some(send);
        }
        let discover = slot.knowledge.begin_discovery(now);
        let dial = slot.knowledge.candidate(now).filter(|_| !slot.dialing);
        // The race's own deadline, or the transport's connect timeout when
        // that is shorter.
        let race = slot.knowledge.connect_timeout();
        let timeout = transport
            .connect_timeout()
            .map_or(race, |bound| bound.min(race));
        if dial.is_some() {
            slot.dialing = true;
            slot.generation += 1;
        }
        let generation = slot.generation;
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
        None
    }

    /// A response for `origin` carried these `Alt-Svc` fields, joined.
    pub(super) fn alt_svc(&mut self, origin: &Origin, value: &str) {
        let host = origin.host.clone();
        self.entry(origin)
            .h3
            .knowledge
            .insert_alt_svc(&host, value, Instant::now());
    }

    pub(super) fn h3_event(&mut self, event: H3Event) {
        let now = Instant::now();
        match event {
            H3Event::Connected {
                origin,
                generation,
                result,
            } => {
                let slot = &mut self.entry(&origin).h3;
                debug_assert!(slot.is_current(generation), "one QUIC dial at a time");
                slot.dialing = false;
                match result {
                    Ok((send, driver)) => {
                        slot.conn = Some(Pooled {
                            send: send.clone(),
                            generation,
                            since: now,
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
                        self.h3_won(&origin, &send);
                    }
                    Err(error) => {
                        debug!(host = %origin.host, %error, "QUIC dial failed; backing off");
                        slot.knowledge.mark_broken(now);
                        self.h3_lost(&origin);
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
                if slot
                    .conn
                    .as_ref()
                    .is_some_and(|conn| conn.generation == generation)
                {
                    slot.conn = None;
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
    Arc::new(crate::transport::spawn_thread)
}

/// A QUIC connection to `host`:`port` whose handshake completed by
/// `deadline`. The resolved addresses are tried one after another in the
/// order a TCP dial would race them, each on a UDP socket of the pool's
/// I/O, with `deadline` covering resolution and every attempt together.
async fn connect<I: Io>(
    io: &I,
    transport: &Transport,
    client: &H3Client,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<Established, Error> {
    let addrs = {
        let resolve = happy_eyeballs::resolve(host, port);
        let expire = io.sleep_until(deadline);
        pin_mut!(resolve, expire);
        match select(resolve, expire).await {
            Either::Left((addrs, _)) => addrs.map_err(|error| Error::Transport(Box::new(error)))?,
            Either::Right(((), _)) => Vec::new(),
        }
    };
    let mut last_error = None;
    for peer in addrs {
        if Instant::now() >= deadline {
            break;
        }
        match attempt(io, transport, client, host, peer, deadline).await {
            Ok(established) => return Ok(established),
            Err(error) => {
                debug!(%host, %peer, %error, "QUIC attempt failed");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        Error::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("QUIC connect to {host}:{port} timed out"),
        )))
    }))
}

/// One QUIC handshake with `peer`, driven until it completes, fails or
/// `deadline` passes.
async fn attempt<I: Io>(
    io: &I,
    transport: &Transport,
    client: &H3Client,
    host: &str,
    peer: SocketAddr,
    deadline: Instant,
) -> Result<Established, Error> {
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
    let (send, connection) = {
        let mut client = client.0.borrow_mut();
        let client = match &mut *client {
            Some(client) => client,
            empty => empty.insert(Client::new(&client_config(transport)).map_err(h3_error)?),
        };
        client
            .connect(socket, io.clone(), host, peer)
            .map_err(h3_error)?
    };
    let mut run = connection.run().boxed_local();
    let handshake = {
        let ready = send.ready();
        let expire = io.sleep_until(deadline);
        pin_mut!(ready, expire);
        match select(select(ready, &mut run), expire).await {
            Either::Left((Either::Left((ready, _)), _)) => ready.map_err(h3_error),
            Either::Left((Either::Right((ended, _)), _)) => Err(h3_error(
                ended.err().unwrap_or(http_kit_h3::Error::ConnectionClosed),
            )),
            Either::Right(((), _)) => Err(Error::Transport(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("QUIC handshake with {host} at {peer} timed out"),
            )))),
        }
    };
    handshake.map(|()| (send, run))
}

/// The client configuration: the server's chain goes to the transport's
/// verifier, the one its TCP connections use.
fn client_config(transport: &Transport) -> ClientConfig {
    let verifier = Arc::clone(transport.tls().verifier());
    ClientConfig::with_verifier(
        Verifier::new(move |chain, name| verify(&*verifier, chain, name)),
        MAX_FIELD_SECTION_SIZE,
    )
}

/// Judges the DER `chain` (leaf first) a server presented for `name`. No
/// OCSP response reaches this point; the verifier checks revocation as it
/// does for a TCP handshake that carried none.
fn verify(
    verifier: &dyn ServerCertVerifier,
    chain: &[Vec<u8>],
    name: &str,
) -> Result<(), Rejection> {
    let (leaf, intermediates) = chain.split_first().ok_or(Rejection::BadCertificate)?;
    let intermediates: Vec<_> = intermediates
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let server_name = ServerName::try_from(name).map_err(|_| Rejection::BadCertificate)?;
    verifier
        .verify_server_cert(
            &CertificateDer::from(leaf.as_slice()),
            &intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        )
        .map(drop)
        .map_err(|error| {
            debug!(%name, %error, "HTTP/3 server certificate refused");
            rejection(&error)
        })
}

/// The TLS alert a verification failure is reported to the server with.
const fn rejection(error: &rustls::Error) -> Rejection {
    match error {
        rustls::Error::InvalidCertificate(
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. },
        ) => Rejection::Expired,
        rustls::Error::InvalidCertificate(CertificateError::Revoked) => Rejection::Revoked,
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer) => Rejection::UnknownCa,
        _ => Rejection::BadCertificate,
    }
}

pub(super) fn h3_error(error: http_kit_h3::Error) -> Error {
    Error::Transport(Box::new(error))
}

/// Tells the pool about the `Alt-Svc` fields on `headers`, when there are
/// any.
pub(super) fn report_alt_svc(pool: &super::PoolHandle, origin: &Origin, headers: &http::HeaderMap) {
    if let Some(value) = crate::transport::discovery::joined_alt_svc(headers) {
        pool.send(Command::AltSvc {
            origin: origin.clone(),
            value,
        });
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::Proxy;

    /// The DER of a CA named `ca_name` and the DER of a leaf it signed for
    /// `localhost`. Distinct names matter: webpki matches an issuer by name
    /// before its signature, so a stranger sharing a trusted root's name is a
    /// bad signature, not an unknown CA.
    fn chain(ca_name: &str) -> (Vec<u8>, Vec<u8>) {
        let now = OffsetDateTime::now_utc();
        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name.push(DnType::CommonName, ca_name);
        ca.not_before = now - Duration::days(1);
        ca.not_after = now + Duration::days(30);
        let ca_der = ca
            .self_signed(&ca_key)
            .expect("self-sign CA")
            .der()
            .to_vec();
        let issuer = Issuer::new(ca, ca_key);
        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf params");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.not_before = now - Duration::days(1);
        leaf.not_after = now + Duration::days(30);
        let leaf_der = leaf
            .signed_by(&leaf_key, &issuer)
            .expect("sign leaf")
            .der()
            .to_vec();
        (ca_der, leaf_der)
    }

    /// The HTTP/3 verifier is the transport's: a chain to one of its extra
    /// roots passes for the leaf's name, a chain to any other root is an
    /// unknown CA, and the right chain for the wrong name is refused.
    #[test]
    fn h3_chains_meet_the_transport_verifier() {
        let (ca, leaf) = chain("zenwave h3 verifier test CA");
        let (_, stranger) = chain("zenwave h3 verifier stranger CA");
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .extra_root_certificate_der(ca)
            .build()
            .expect("transport builds");
        let verifier = transport.tls().verifier();
        assert_eq!(
            verify(&**verifier, std::slice::from_ref(&leaf), "localhost"),
            Ok(())
        );
        assert_eq!(
            verify(&**verifier, &[stranger], "localhost"),
            Err(Rejection::UnknownCa)
        );
        assert_eq!(
            verify(&**verifier, &[leaf], "example.com"),
            Err(Rejection::BadCertificate)
        );
        assert_eq!(
            verify(&**verifier, &[], "localhost"),
            Err(Rejection::BadCertificate)
        );
    }
}
