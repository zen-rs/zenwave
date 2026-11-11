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
    future::Future,
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
use http_kit_h3::{Client, ClientConfig, Presented, Rejection, SendRequest, Verifier};
use http_kit_io::{Datagram, Resolve, Timer};
use rustls::{
    CertificateError,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tracing::debug;

use super::{
    connect::{NativeIo, NativeResolve},
    pool::{Command, Event, Pool},
};
use crate::{
    Error, Transport,
    dns::ResolveHttps,
    transport::{
        discovery::{H3Knowledge, HttpsRr},
        happy_eyeballs::{self, Dialer},
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

impl<I: NativeIo, R: NativeResolve> Pool<I, R> {
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
                .push(discover_task(Rc::clone(&self.resolver), origin.clone()));
        }
        if let Some(port) = dial {
            let io = self.io.clone();
            let resolver = Rc::clone(&self.resolver);
            let client = self.h3.clone();
            let origin = origin.clone();
            self.tasks.push(
                async move {
                    let deadline = Instant::now() + timeout;
                    let result = connect(
                        &io,
                        &*resolver,
                        &transport,
                        &client,
                        &origin.host,
                        port,
                        deadline,
                    )
                    .await;
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
fn discover_task<R: ResolveHttps + 'static>(
    resolver: Rc<R>,
    origin: Origin,
) -> LocalBoxFuture<'static, Option<Event>> {
    async move {
        let lookup = resolver.https_record(&origin.host, origin.port).await;
        let rr = HttpsRr::from_lookup(lookup, &origin.host, origin.port, Instant::now());
        Some(Event::H3(H3Event::Discovered { origin, rr }))
    }
    .boxed_local()
}

/// A QUIC connection to `host`:`port` whose handshake completed by
/// `deadline`. The addresses are raced as a TCP dial races them (RFC 8305),
/// each attempt on a UDP socket of the pool's I/O: the dial starts with the
/// addresses known and takes a late family's as its lookup answers, so one
/// stalled lookup does not hold the other family back. `deadline` covers
/// resolution and every attempt together.
async fn connect<I: Datagram + Timer + Clone + 'static, R: Resolve>(
    io: &I,
    resolver: &R,
    transport: &Transport,
    client: &H3Client,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<Established, Error> {
    let dialer = QuicDialer {
        io,
        transport,
        client,
        host,
        deadline,
    };
    happy_eyeballs::within(
        &dialer,
        host,
        port,
        deadline,
        happy_eyeballs::connect(&dialer, resolver, host, port),
    )
    .await
    .map_err(|error| Error::Transport(Box::new(error)))
}

/// The happy eyeballs dialer for QUIC: an address is one handshake.
struct QuicDialer<'a, I> {
    io: &'a I,
    transport: &'a Transport,
    client: &'a H3Client,
    host: &'a str,
    deadline: Instant,
}

impl<I: Datagram + Timer + Clone + 'static> Dialer for QuicDialer<'_, I> {
    type Stream = Established;

    async fn dial(&self, addr: SocketAddr) -> std::io::Result<Established> {
        attempt(
            self.io,
            self.transport,
            self.client,
            self.host,
            addr,
            self.deadline,
        )
        .await
        .map_err(|error| {
            debug!(host = %self.host, peer = %addr, %error, "QUIC attempt failed");
            std::io::Error::other(error)
        })
    }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        self.io.sleep_until(deadline)
    }

    /// A QUIC handshake has the whole dial deadline, not TCP's bound.
    fn attempt_timeout(&self) -> std::time::Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// One QUIC handshake with `peer`, driven until it completes, fails or
/// `deadline` passes.
async fn attempt<I: Datagram + Timer + Clone + 'static>(
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
        .await
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

/// The client configuration: what the server presented goes to the
/// transport's verifier, the one its TCP connections use.
fn client_config(transport: &Transport) -> ClientConfig {
    verifying(Arc::clone(transport.tls().verifier()))
}

/// A client configuration whose handshakes `verifier` judges. The client
/// asks each server to staple an OCSP response, which reaches `verifier`
/// as it does over TLS.
fn verifying(verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    ClientConfig::with_verifier(
        Verifier::new(move |presented: &Presented<'_>| {
            verify(
                &*verifier,
                presented.chain,
                presented.server_name,
                presented.ocsp_response,
            )
        }),
        MAX_FIELD_SECTION_SIZE,
    )
}

/// Judges the DER `chain` (leaf first) a server presented for `name`, with
/// the OCSP response it stapled, empty when it stapled none.
fn verify(
    verifier: &dyn ServerCertVerifier,
    chain: &[Vec<u8>],
    name: &str,
    ocsp_response: &[u8],
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
            ocsp_response,
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

    use std::sync::Mutex;

    #[cfg(any(feature = "native-compio", feature = "native-tokio"))]
    use http_kit_io::{FromStd, Listen};

    use super::*;
    use crate::Proxy;

    /// A CA and the `localhost` leaf it signed, in the forms the tests need.
    struct Issued {
        ca_der: Vec<u8>,
        leaf_der: Vec<u8>,
        #[cfg_attr(
            not(any(feature = "native-compio", feature = "native-tokio")),
            expect(dead_code)
        )]
        leaf_pem: String,
        #[cfg_attr(
            not(any(feature = "native-compio", feature = "native-tokio")),
            expect(dead_code)
        )]
        leaf_key_pem: String,
        #[cfg_attr(
            not(any(feature = "native-compio", feature = "native-tokio")),
            expect(dead_code)
        )]
        leaf_key_der: Vec<u8>,
    }

    /// The DER of a CA named `ca_name` and the DER of a leaf it signed for
    /// `localhost`. Distinct names matter: webpki matches an issuer by name
    /// before its signature, so a stranger sharing a trusted root's name is a
    /// bad signature, not an unknown CA.
    fn chain(ca_name: &str) -> (Vec<u8>, Vec<u8>) {
        let issued = issue(ca_name);
        (issued.ca_der, issued.leaf_der)
    }

    fn issue(ca_name: &str) -> Issued {
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
        let leaf = leaf.signed_by(&leaf_key, &issuer).expect("sign leaf");
        Issued {
            ca_der,
            leaf_der: leaf.der().to_vec(),
            leaf_pem: leaf.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
            leaf_key_der: leaf_key.serialize_der(),
        }
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
            verify(&**verifier, std::slice::from_ref(&leaf), "localhost", &[]),
            Ok(())
        );
        assert_eq!(
            verify(&**verifier, &[stranger], "localhost", &[]),
            Err(Rejection::UnknownCa)
        );
        assert_eq!(
            verify(&**verifier, &[leaf], "example.com", &[]),
            Err(Rejection::BadCertificate)
        );
        assert_eq!(
            verify(&**verifier, &[], "localhost", &[]),
            Err(Rejection::BadCertificate)
        );
    }

    /// The bytes a server staples in the tests below, standing for a
    /// `revoked` OCSP status, with the CJK text a real responder could carry.
    const REVOKED: &[u8] = "revoked 失効 失効済み 폐기됨".as_bytes();

    /// The transport's verifier with revocation decided by the stapled
    /// bytes: [`REVOKED`] is a revoked leaf, anything else passes through
    /// to the transport's verdict. It records what it was shown.
    #[derive(Debug)]
    struct Recording {
        inner: Arc<dyn ServerCertVerifier>,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ServerCertVerifier for Recording {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            self.seen
                .lock()
                .expect("not poisoned")
                .push(ocsp_response.to_vec());
            if ocsp_response == REVOKED {
                return Err(rustls::Error::InvalidCertificate(CertificateError::Revoked));
            }
            self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    /// One HTTP/3 handshake against a loopback server stapling `staple`
    /// (nothing when `None`), judged by the transport's verifier behind a
    /// [`Recording`]. Returns the handshake's outcome and the OCSP responses the verifier
    /// was shown.
    #[cfg(any(feature = "native-compio", feature = "native-tokio"))]
    async fn handshake<I: FromStd + Timer + Clone + 'static>(
        io: I,
        staple: Option<&[u8]>,
    ) -> (Result<(), Error>, Vec<Vec<u8>>) {
        let issued = issue("zenwave h3 ocsp test CA");
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .extra_root_certificate_der(issued.ca_der.clone())
            .build()
            .expect("transport builds");
        let recording = Arc::new(Recording {
            inner: Arc::clone(transport.tls().verifier()),
            seen: Arc::default(),
        });

        let mut identity = http_kit_h3::Identity::from_pem(issued.leaf_pem, issued.leaf_key_pem);
        if let Some(staple) = staple {
            identity = identity.with_ocsp_response(staple);
        }
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("UDP binds");
        let peer = server_socket.local_addr().expect("local address");
        let server = http_kit_h3::Server::new(
            io.udp_socket(server_socket).expect("adopt UDP socket"),
            io.clone(),
            &http_kit_h3::ServerConfig::new(identity, MAX_FIELD_SECTION_SIZE),
        )
        .expect("h3 server");
        let service = |_request: http_kit::Request| async {
            http_kit::Response::new(http_kit::Body::empty())
        };
        let serving = async {
            server.serve(&service).await.expect("h3 server runs");
        };

        let mut client = Client::new(&verifying(
            Arc::clone(&recording) as Arc<dyn ServerCertVerifier>
        ))
        .expect("h3 client");
        let socket = io
            .bind_udp("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("UDP binds");
        let (send, connection) = client
            .connect(socket, io.clone(), "localhost", peer)
            .expect("connection starts");
        let connecting = async {
            let mut run = connection.run().boxed_local();
            let ready = send.ready();
            pin_mut!(ready);
            match select(ready, &mut run).await {
                Either::Left((ready, _)) => ready.map_err(h3_error),
                Either::Right((ended, _)) => Err(h3_error(
                    ended.err().unwrap_or(http_kit_h3::Error::ConnectionClosed),
                )),
            }
        };
        let deadline = io.sleep(std::time::Duration::from_secs(10));
        pin_mut!(serving, connecting, deadline);
        let outcome = match select(connecting, select(serving, deadline)).await {
            Either::Left((outcome, _)) => outcome,
            Either::Right(_) => panic!("the handshake neither completed nor failed in time"),
        };
        let seen = recording.seen.lock().expect("not poisoned").clone();
        (outcome, seen)
    }

    /// The scenario: the OCSP response a server staples reaches the
    /// verifier exactly, a revoked one fails the handshake as the same
    /// verifier fails a TLS one, and no stapled response arrives empty.
    #[cfg(any(feature = "native-compio", feature = "native-tokio"))]
    async fn stapled_status_reaches_the_verifier<I: FromStd + Timer + Clone + 'static>(io: I) {
        let staple = "ocsp response 你好 こんにちは 안녕".as_bytes();
        let (outcome, seen) = handshake(io.clone(), Some(staple)).await;
        assert!(outcome.is_ok(), "a non-revoked staple passes: {outcome:?}");
        assert_eq!(seen, vec![staple.to_vec()]);

        let (outcome, seen) = handshake(io.clone(), Some(REVOKED)).await;
        assert!(outcome.is_err(), "a revoked staple fails the handshake");
        assert_eq!(seen, vec![REVOKED.to_vec()]);

        let (outcome, seen) = handshake(io, None).await;
        assert!(outcome.is_ok(), "no staple passes: {outcome:?}");
        assert_eq!(seen, vec![Vec::<u8>::new()]);
    }

    /// A QUIC dial to a name whose AAAA lookup never answers connects over
    /// the IPv4 address that did, once the resolution delay passes, far
    /// inside the dial's deadline: the dial does not wait on the stalled
    /// lookup. The server starts answering `server_delay` after the dial
    /// begins, as a slow path would; the time the dial took is returned.
    #[cfg(any(feature = "native-compio", feature = "native-tokio"))]
    async fn dial_with_stalled_aaaa<I: FromStd + Timer + Clone + 'static>(
        io: I,
        server_delay: std::time::Duration,
    ) -> std::time::Duration {
        let issued = issue("zenwave h3 stalled lookup CA");
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .extra_root_certificate_der(issued.ca_der.clone())
            .build()
            .expect("transport builds");
        let identity = http_kit_h3::Identity::from_pem(issued.leaf_pem, issued.leaf_key_pem);
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("UDP binds");
        let peer = server_socket.local_addr().expect("local address");
        let server = http_kit_h3::Server::new(
            io.udp_socket(server_socket).expect("adopt UDP socket"),
            io.clone(),
            &http_kit_h3::ServerConfig::new(identity, MAX_FIELD_SECTION_SIZE),
        )
        .expect("h3 server");
        let service = |_request: http_kit::Request| async {
            http_kit::Response::new(http_kit::Body::from_bytes("你好 こんにちは 안녕"))
        };
        let serving = async {
            io.sleep(server_delay).await;
            server.serve(&service).await.expect("h3 server runs");
        };

        // The A lookup answers with the server; the AAAA lookup is held for
        // as long as `stalled` lives.
        let (resolution, stalled) = happy_eyeballs::with_other_family_stalled(peer);
        let client = H3Client::default();
        let dialer = QuicDialer {
            io: &io,
            transport: &transport,
            client: &client,
            host: "localhost",
            deadline: Instant::now() + std::time::Duration::from_secs(5),
        };
        let started = Instant::now();
        let dial = happy_eyeballs::within(
            &dialer,
            "localhost",
            peer.port(),
            dialer.deadline,
            happy_eyeballs::race(&dialer, resolution),
        );
        pin_mut!(serving, dial);
        let established = match select(dial, serving).await {
            Either::Left((established, _)) => established,
            Either::Right(_) => unreachable!("the server runs until dropped"),
        };
        assert!(
            established.is_ok(),
            "the dial connects over IPv4 while AAAA is stalled: {:?}",
            established.err()
        );
        drop(stalled);
        started.elapsed()
    }

    /// The scenario: a stalled AAAA lookup does not hold the dial back.
    #[cfg(any(feature = "native-compio", feature = "native-tokio"))]
    async fn stalled_aaaa_does_not_hold_the_dial<I: FromStd + Timer + Clone + 'static>(io: I) {
        let took = dial_with_stalled_aaaa(io, std::time::Duration::ZERO).await;
        assert!(
            took < std::time::Duration::from_secs(2),
            "connected in {took:?}, well inside the 5 s deadline",
        );
    }

    /// The scenario: the one address's handshake takes longer than TCP's
    /// 2 s attempt bound and still completes inside the dial deadline.
    #[cfg(any(feature = "native-compio", feature = "native-tokio"))]
    async fn slow_quic_handshake_has_the_dial_deadline<I: FromStd + Timer + Clone + 'static>(
        io: I,
    ) {
        let took = dial_with_stalled_aaaa(io, std::time::Duration::from_millis(2500)).await;
        assert!(
            took >= std::time::Duration::from_millis(2500),
            "the handshake waited on the delayed server: {took:?}",
        );
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn h3_slow_handshake_succeeds_inside_the_deadline_on_compio() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime");
        runtime.block_on(slow_quic_handshake_has_the_dial_deadline(
            http_kit_io::compio::Compio,
        ));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn h3_slow_handshake_succeeds_inside_the_deadline_on_tokio() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &runtime,
            slow_quic_handshake_has_the_dial_deadline(http_kit_io::tokio::Tokio),
        );
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn h3_dial_survives_a_stalled_aaaa_on_compio() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime");
        runtime.block_on(stalled_aaaa_does_not_hold_the_dial(
            http_kit_io::compio::Compio,
        ));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn h3_dial_survives_a_stalled_aaaa_on_tokio() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &runtime,
            stalled_aaaa_does_not_hold_the_dial(http_kit_io::tokio::Tokio),
        );
    }

    /// The verifier's verdict on a revoked staple is the TLS one:
    /// `verify` maps it to the `certificate_revoked` alert.
    #[test]
    fn h3_revoked_staple_is_the_revoked_alert() {
        let issued = issue("zenwave h3 ocsp alert CA");
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .extra_root_certificate_der(issued.ca_der)
            .build()
            .expect("transport builds");
        let recording = Recording {
            inner: Arc::clone(transport.tls().verifier()),
            seen: Arc::default(),
        };
        assert_eq!(
            verify(
                &recording,
                std::slice::from_ref(&issued.leaf_der),
                "localhost",
                REVOKED
            ),
            Err(Rejection::Revoked)
        );
        assert_eq!(
            verify(&recording, &[issued.leaf_der], "localhost", b""),
            Ok(())
        );
    }

    /// The TLS side of [`stapled_status_reaches_the_verifier`]: the same
    /// [`Recording`] verifier, wrapped around the transport's own, judges a
    /// TCP+TLS handshake with a rustls server stapling the same bytes. It
    /// shows the verifier exactly the staple, as over HTTP/3, and fails the
    /// handshake on the revoked one. The revoked status is [`REVOKED`], a
    /// marker the verifier recognises: nothing here signs a real OCSP
    /// response.
    #[cfg(any(feature = "native-compio", feature = "native-tokio"))]
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario, with its server and handshake helpers beside it"
    )]
    async fn stapled_status_reaches_the_verifier_over_tls<I, E>(io: I, executor: &E)
    where
        I: super::NativeIo + Listen,
        E: executor_core::LocalExecutor,
    {
        use http_kit_io::Listener as _;

        async fn serve<I: super::NativeIo + Listen>(
            io: I,
            listener: I::Listener,
            acceptor: http_kit_tls::TlsAcceptor,
        ) {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                // A refused handshake ends in the client's alert: the
                // server only needs to carry on.
                let Ok(stream) = acceptor.accept(stream, &io).await else {
                    continue;
                };
                let service = |_request: http_kit::Request| async {
                    http_kit::Response::new(http_kit::Body::from_bytes("你好 こんにちは 안녕"))
                };
                let connection = http_kit_h1::ServerConnection::from_stream(
                    stream,
                    io.clone(),
                    http_kit_h1::ServerConfig::default(),
                );
                connection.serve(&service).await.ok();
            }
        }

        // One handshake against a server stapling `staple`: its outcome and
        // what the verifier was shown.
        async fn handshake<I, E>(
            io: &I,
            executor: &E,
            staple: Option<&[u8]>,
        ) -> (Result<(), Error>, Vec<Vec<u8>>)
        where
            I: super::NativeIo + Listen,
            E: executor_core::LocalExecutor,
        {
            let issued = issue("zenwave tls ocsp test CA");
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("default versions")
                .with_no_client_auth();
            let chain = vec![CertificateDer::from(issued.leaf_der.clone())];
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(issued.leaf_key_der.clone()),
            );
            let mut config = match staple {
                Some(staple) => builder.with_single_cert_with_ocsp(chain, key, staple.to_vec()),
                None => builder.with_single_cert(chain, key),
            }
            .expect("server certificate");
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let listener = io
                .bind_tcp("127.0.0.1:0".parse().expect("loopback"))
                .expect("bind");
            let port = listener.local_addr().expect("local address").port();
            let server = serve(
                io.clone(),
                listener,
                http_kit_tls::TlsAcceptor::new(Arc::new(config)),
            );

            let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
            let recorded = Arc::clone(&seen);
            let transport = Transport::builder()
                .proxy(Proxy::none())
                .extra_root_certificate_der(issued.ca_der)
                .wrap_verifier(move |inner| {
                    Arc::new(Recording {
                        inner,
                        seen: recorded,
                    })
                })
                .build()
                .expect("transport builds");
            let resolver = crate::dns::System::new(&transport);
            let mut client = crate::backend::NativeBackend::on_current_thread(
                transport,
                io.clone(),
                resolver,
                executor,
            );
            let request = async {
                use crate::Client as _;
                client
                    .get(format!("https://localhost:{port}/ocsp"))
                    .expect("request builds")
                    .await
                    .map(drop)
            };
            let deadline = io.sleep(std::time::Duration::from_secs(10));
            pin_mut!(server, request, deadline);
            let outcome = match select(request, select(server, deadline)).await {
                Either::Left((outcome, _)) => outcome,
                Either::Right(_) => panic!("the TLS handshake neither completed nor failed"),
            };
            let seen = seen.lock().expect("not poisoned").clone();
            (outcome, seen)
        }

        let staple = "ocsp response 你好 こんにちは 안녕".as_bytes();
        let (outcome, seen) = handshake(&io, executor, Some(staple)).await;
        assert!(outcome.is_ok(), "a non-revoked staple passes: {outcome:?}");
        assert_eq!(seen, vec![staple.to_vec()]);

        let (outcome, seen) = handshake(&io, executor, Some(REVOKED)).await;
        assert!(outcome.is_err(), "a revoked staple fails the handshake");
        assert_eq!(seen, vec![REVOKED.to_vec()]);

        let (outcome, seen) = handshake(&io, executor, None).await;
        assert!(outcome.is_ok(), "no staple passes: {outcome:?}");
        assert_eq!(seen, vec![Vec::<u8>::new()]);
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn tls_stapled_ocsp_reaches_the_verifier_on_compio() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime");
        runtime.block_on(stapled_status_reaches_the_verifier_over_tls(
            http_kit_io::compio::Compio,
            &runtime,
        ));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn tls_stapled_ocsp_reaches_the_verifier_on_tokio() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &runtime,
            stapled_status_reaches_the_verifier_over_tls(http_kit_io::tokio::Tokio, &local),
        );
    }

    #[cfg(feature = "native-compio")]
    #[test]
    fn h3_stapled_ocsp_reaches_the_verifier_on_compio() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime");
        runtime.block_on(stapled_status_reaches_the_verifier(
            http_kit_io::compio::Compio,
        ));
    }

    #[cfg(feature = "native-tokio")]
    #[test]
    fn h3_stapled_ocsp_reaches_the_verifier_on_tokio() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &runtime,
            stapled_status_reaches_the_verifier(http_kit_io::tokio::Tokio),
        );
    }
}
