//! Fixtures for HTTPS-record tests: an in-process UDP DNS server and the
//! hickory builders to answer it — shared between this module's unit tests
//! and the hyper backend's discovery tests.

use std::{
    net::{SocketAddr, UdpSocket},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{HTTPS, svcb::SVCB},
    },
};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};

use crate::transport::Spawn;

/// TTL of the synthetic records.
pub const TTL: u32 = 300;

/// How long a test waits for a query to arrive at the server.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// A DNS name for tests.
pub fn name(domain: &str) -> Name {
    domain.parse().expect("test domain must parse")
}

/// A UDP DNS server on a dedicated thread: `respond` answers every query,
/// and each queried name and record type is observable on the returned
/// channel. The thread lives until the test process ends.
pub fn serve(
    respond: impl Fn(&Message) -> Message + Send + 'static,
) -> (SocketAddr, Receiver<(Name, RecordType)>) {
    let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    let (names, queried) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buffer) {
            let Ok(query) = Message::from_vec(&buffer[..len]) else {
                continue;
            };
            if let Some(asked) = query.queries.first() {
                let _ = names.send((asked.name().clone(), asked.query_type()));
            }
            if let Ok(response) = respond(&query).to_vec() {
                let _ = socket.send_to(&response, peer);
            }
        }
    });
    (addr, queried)
}

/// A resolver config pointed at the in-process server.
pub fn resolver_config(server: SocketAddr) -> (ResolverConfig, ResolverOpts) {
    let mut udp = ConnectionConfig::udp();
    udp.port = server.port();
    let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(
        server.ip(),
        true,
        vec![udp],
    )]);
    let mut options = ResolverOpts::default();
    options.attempts = 1;
    (config, options)
}

/// A response echoing the query's metadata, with `rcode` and `answers`.
pub fn answer(
    query: &Message,
    rcode: hickory_proto::op::ResponseCode,
    answers: Vec<Record>,
) -> Message {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = rcode;
    response.queries.clone_from(&query.queries);
    response.answers = answers;
    response
}

/// An HTTPS RR owned by `owner` with `params` as its `SvcParams`.
pub fn https(
    owner: &str,
    priority: u16,
    target: &str,
    params: Vec<(
        hickory_proto::rr::rdata::svcb::SvcParamKey,
        hickory_proto::rr::rdata::svcb::SvcParamValue,
    )>,
) -> Record {
    Record::from_rdata(
        name(owner),
        TTL,
        RData::HTTPS(HTTPS(SVCB::new(priority, name(target), params))),
    )
}

/// A spawner that runs every background task on a dedicated thread —
/// the same fallback `HyperBackend` uses when no executor is supplied.
pub fn spawn() -> Spawn {
    crate::backend::test_support::thread_spawn()
}

/// The next `(name, record type)` the server was asked for.
pub fn queried_name(queried: &Receiver<(Name, RecordType)>) -> (Name, RecordType) {
    queried.recv_timeout(QUERY_TIMEOUT).unwrap()
}
