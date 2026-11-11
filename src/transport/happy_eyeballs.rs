//! RFC 8305 Happy Eyeballs: resolve both address families concurrently and
//! race connection attempts so a broken IPv6 path costs milliseconds, not a
//! timeout.
//!
//! The state machine and the resolution are runtime-independent: names go
//! to `getaddrinfo` on threads of their own — except localhost names, which
//! are the loopback addresses without a query (RFC 6761 §6.3), so a stalled
//! system resolver cannot hold up a local connection — and the sockets and timers come
//! from a [`Dialer`] — async-net for the hyper backend and websockets, an
//! `http-kit-io` implementation for the native backend.

use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    thread,
    time::{Duration, Instant},
};

use dns_lookup::{AddrFamily, AddrInfoHints, SockType, getaddrinfo};
use futures_channel::mpsc::{UnboundedReceiver, unbounded};
use futures_util::{
    FutureExt,
    future::{Either, pending, select},
    pin_mut,
    stream::{FuturesUnordered, StreamExt},
};

/// Opens TCP connections and keeps the race's deadlines.
pub trait Dialer {
    /// A connected stream.
    type Stream;

    /// Connects to `addr`, with `TCP_NODELAY` set where the socket allows
    /// it.
    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Stream>>;

    /// Completes at `deadline`.
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;
}

/// The async-io/async-net dialer the hyper backend and websockets use.
#[cfg(connector)]
#[derive(Clone, Copy, Debug)]
pub struct AsyncNet;

#[cfg(connector)]
impl Dialer for AsyncNet {
    type Stream = async_net::TcpStream;

    async fn dial(&self, addr: SocketAddr) -> io::Result<Self::Stream> {
        let stream = async_net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    async fn sleep_until(&self, deadline: Instant) {
        async_io::Timer::at(deadline).await;
    }
}

// RFC 8305 defaults: Resolution Delay = 50ms, First Address Family Count = 1,
// Connection Attempt Delay = 250ms.
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
const FIRST_ADDRESS_FAMILY_COUNT: usize = 1;
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const MIN_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(100);
const MAX_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolve `host`:`port` to socket addresses in the order [`connect`] would
/// attempt them — getaddrinfo's RFC 6724 ordering where the system reports
/// it, otherwise the RFC 8305 interleave, once every lookup has finished:
/// the hyper backend's QUIC dial and a SOCKS5 proxy that resolves nothing
/// itself, which is handed the first.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let mut state = HappyEyeballsState::new();
    let mut resolver = start_resolution(host, port);
    while let Some(event) = resolver.next().await {
        state.apply_resolution(event);
    }
    state.mark_resolution_stream_closed();

    let ordered = state.ordered_candidates();
    if ordered.is_empty() {
        return Err(state.into_connect_error());
    }
    Ok(ordered)
}

/// Connects to `host`:`port` through `dialer`, racing the resolved
/// addresses as RFC 8305 describes. The dialer's streams are TCP or
/// anything else one address connects to, QUIC included.
pub async fn connect<D: Dialer>(dialer: &D, host: &str, port: u16) -> io::Result<D::Stream> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return connect_with_timeout(dialer, addr)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("{addr}: {error}")));
    }

    race(dialer, Resolution(start_resolution(host, port))).await
}

/// A name's lookups in flight: each family's answer and the system's
/// sorted snapshot, as they arrive.
pub struct Resolution(UnboundedReceiver<ResolutionEvent>);

#[cfg(all(
    test,
    native_h3,
    any(feature = "native-compio", feature = "native-tokio")
))]
impl Resolution {
    /// `answer`'s family answered at once and the other family's lookup
    /// never does for as long as the returned sender lives, as a system
    /// resolver holding one query for seconds behaves. No sorted snapshot
    /// arrives either: it waits on the same resolver.
    pub(crate) fn with_other_family_stalled(answer: SocketAddr) -> (Self, Stall) {
        let (sender, receiver) = unbounded();
        let family = if answer.is_ipv6() {
            AddressFamilyKind::Ipv6
        } else {
            AddressFamilyKind::Ipv4
        };
        sender
            .unbounded_send(ResolutionEvent {
                kind: ResolutionEventKind::Family {
                    family,
                    result: ResolutionResult::Addresses(vec![answer]),
                },
            })
            .expect("the receiver is still held here");
        (Self(receiver), Stall(sender))
    }
}

/// Holds a stalled lookup open: the lookup answers nothing until this is
/// dropped.
#[cfg(all(
    test,
    native_h3,
    any(feature = "native-compio", feature = "native-tokio")
))]
pub struct Stall(#[expect(dead_code)] futures_channel::mpsc::UnboundedSender<ResolutionEvent>);

/// Races the addresses `resolution` delivers, starting with those known
/// and taking the rest as they arrive.
pub async fn race<D: Dialer>(dialer: &D, resolution: Resolution) -> io::Result<D::Stream> {
    let mut state = HappyEyeballsState::new();
    let mut attempts = FuturesUnordered::new();
    let mut resolver = resolution.0;
    let mut resolver_closed = false;

    loop {
        state.rebuild_pending();

        if let Some(addr) = state.pop_next_attempt(Instant::now()) {
            attempts.push(connect_attempt(dialer, addr));
            continue;
        }

        if state.is_terminal(attempts.is_empty()) {
            return Err(state.into_connect_error());
        }

        let resolver_event = async {
            if resolver_closed {
                pending::<Option<ResolutionEvent>>().await
            } else {
                resolver.next().await
            }
        };
        let resolution_delay = timer_at(dialer, state.resolution_delay.deadline());
        let next_attempt_due = timer_at(dialer, state.next_attempt_deadline());

        pin_mut!(resolver_event);
        pin_mut!(resolution_delay);
        pin_mut!(next_attempt_due);

        let attempt_result = async {
            match attempts.next().await {
                Some(outcome) => outcome,
                None => pending::<AttemptOutcome<D::Stream>>().await,
            }
        }
        .fuse();
        pin_mut!(attempt_result);

        futures_util::select_biased! {
            outcome = attempt_result => {
                match outcome.result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => state.record_attempt_failure(outcome.addr, &error),
                }
            }
            message = resolver_event.fuse() => {
                if let Some(message) = message { state.apply_resolution(message) } else {
                    resolver_closed = true;
                    state.mark_resolution_stream_closed();
                }
            }
            () = resolution_delay.fuse() => {
                state.open_resolution_gate();
            }
            () = next_attempt_due.fuse() => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AddressFamilyKind {
    Ipv6,
    Ipv4,
}

#[derive(Debug)]
enum ResolutionEventKind {
    Family {
        family: AddressFamilyKind,
        result: ResolutionResult,
    },
    SortedSnapshot(ResolutionResult),
}

#[derive(Debug)]
struct ResolutionEvent {
    kind: ResolutionEventKind,
}

#[derive(Debug)]
enum ResolutionResult {
    Addresses(Vec<SocketAddr>),
    Empty,
    Failed(String),
}

#[derive(Debug)]
enum FamilyResolution {
    Pending,
    Ready(Vec<SocketAddr>),
    Empty,
    Failed(String),
}

impl FamilyResolution {
    fn addrs(&self) -> &[SocketAddr] {
        match self {
            Self::Ready(addrs) => addrs,
            Self::Pending | Self::Empty | Self::Failed(_) => &[],
        }
    }

    const fn is_finished(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    const fn is_positive(&self) -> bool {
        matches!(self, Self::Ready(addrs) if !addrs.is_empty())
    }

    fn failure_message(&self, family: AddressFamilyKind) -> Option<String> {
        match self {
            Self::Failed(message) => Some(format!("{family:?} resolution failed: {message}")),
            Self::Empty => Some(format!("{family:?} resolution returned no addresses")),
            Self::Pending | Self::Ready(_) => None,
        }
    }
}

struct AttemptOutcome<S> {
    addr: SocketAddr,
    result: io::Result<S>,
}

/// The Resolution Delay an A answer that beats AAAA waits out (RFC 8305
/// §3) before IPv4 may start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolutionDelay {
    /// Not running: no A answer is waiting on AAAA.
    Idle,
    /// IPv4 waits until then for AAAA.
    Until(Instant),
    /// The delay ran out with AAAA still pending: IPv4 may start.
    Passed,
}

impl ResolutionDelay {
    const fn deadline(self) -> Option<Instant> {
        match self {
            Self::Until(deadline) => Some(deadline),
            Self::Idle | Self::Passed => None,
        }
    }

    fn has_passed(self, now: Instant) -> bool {
        match self {
            Self::Idle => false,
            Self::Until(deadline) => now >= deadline,
            Self::Passed => true,
        }
    }
}

#[derive(Debug)]
struct HappyEyeballsState {
    ipv6: FamilyResolution,
    ipv4: FamilyResolution,
    sorted_snapshot: Option<Vec<SocketAddr>>,
    first_positive_family: Option<AddressFamilyKind>,
    resolution_delay: ResolutionDelay,
    pending: VecDeque<SocketAddr>,
    attempted: HashSet<SocketAddr>,
    last_attempt_started_at: Option<Instant>,
    attempt_failures: Vec<String>,
}

impl HappyEyeballsState {
    fn new() -> Self {
        Self {
            ipv6: FamilyResolution::Pending,
            ipv4: FamilyResolution::Pending,
            sorted_snapshot: None,
            first_positive_family: None,
            resolution_delay: ResolutionDelay::Idle,
            pending: VecDeque::new(),
            attempted: HashSet::new(),
            last_attempt_started_at: None,
            attempt_failures: Vec::new(),
        }
    }

    fn apply_resolution(&mut self, event: ResolutionEvent) {
        match event.kind {
            ResolutionEventKind::Family { family, result } => {
                let resolution = match result {
                    ResolutionResult::Addresses(addrs) => FamilyResolution::Ready(addrs),
                    ResolutionResult::Empty => FamilyResolution::Empty,
                    ResolutionResult::Failed(message) => FamilyResolution::Failed(message),
                };
                match family {
                    AddressFamilyKind::Ipv6 => {
                        let ipv6_became_positive = !self.ipv6.is_positive()
                            && matches!(&resolution, FamilyResolution::Ready(_));
                        self.ipv6 = resolution;
                        if ipv6_became_positive {
                            if self.attempted.is_empty() {
                                self.first_positive_family = Some(AddressFamilyKind::Ipv6);
                            } else {
                                self.first_positive_family
                                    .get_or_insert(AddressFamilyKind::Ipv6);
                            }
                            self.resolution_delay = ResolutionDelay::Idle;
                        } else if self.ipv6.is_finished() && self.ipv4.is_positive() {
                            self.resolution_delay = ResolutionDelay::Idle;
                        }
                    }
                    AddressFamilyKind::Ipv4 => {
                        let ipv4_became_positive = !self.ipv4.is_positive()
                            && matches!(&resolution, FamilyResolution::Ready(_));
                        self.ipv4 = resolution;
                        if ipv4_became_positive && self.first_positive_family.is_none() {
                            self.first_positive_family = Some(AddressFamilyKind::Ipv4);
                            if !self.ipv6.is_finished() {
                                self.resolution_delay =
                                    ResolutionDelay::Until(Instant::now() + RESOLUTION_DELAY);
                            }
                        }
                    }
                }
            }
            ResolutionEventKind::SortedSnapshot(result) => match result {
                ResolutionResult::Addresses(addrs) => self.sorted_snapshot = Some(addrs),
                ResolutionResult::Empty => self.sorted_snapshot = Some(Vec::new()),
                ResolutionResult::Failed(_) => self.sorted_snapshot = None,
            },
        }
    }

    fn rebuild_pending(&mut self) {
        let ordered = self.ordered_candidates();
        self.pending = ordered
            .into_iter()
            .filter(|addr| !self.attempted.contains(addr))
            .collect();
    }

    fn ordered_candidates(&self) -> Vec<SocketAddr> {
        let available = self.available_set();
        if available.is_empty() {
            return Vec::new();
        }

        if let Some(snapshot) = &self.sorted_snapshot {
            let ordered = dedup_socket_addrs(
                snapshot
                    .iter()
                    .copied()
                    .filter(|addr| available.contains(addr))
                    .collect(),
            );
            if !ordered.is_empty() {
                return ordered;
            }
        }

        let ipv6 = self.ipv6.addrs();
        let ipv4 = self.ipv4.addrs();
        match self
            .first_positive_family
            .unwrap_or(AddressFamilyKind::Ipv6)
        {
            AddressFamilyKind::Ipv6 => {
                interleave_address_families(ipv6, ipv4, FIRST_ADDRESS_FAMILY_COUNT)
            }
            AddressFamilyKind::Ipv4 => {
                interleave_address_families(ipv4, ipv6, FIRST_ADDRESS_FAMILY_COUNT)
            }
        }
    }

    fn available_set(&self) -> HashSet<SocketAddr> {
        self.ipv6
            .addrs()
            .iter()
            .chain(self.ipv4.addrs())
            .copied()
            .collect()
    }

    fn pop_next_attempt(&mut self, now: Instant) -> Option<SocketAddr> {
        if !self.can_start_attempt(now) {
            return None;
        }

        let addr = self.pending.pop_front()?;
        self.attempted.insert(addr);
        self.last_attempt_started_at = Some(now);
        self.attempt_failures
            .retain(|failure| !failure.starts_with(&format!("{addr}:")));
        Some(addr)
    }

    fn can_start_attempt(&self, now: Instant) -> bool {
        if self.pending.is_empty() {
            return false;
        }

        if self.attempted.is_empty() {
            return self.initial_attempt_gate_open(now);
        }

        self.next_attempt_deadline()
            .is_some_and(|deadline| now >= deadline)
    }

    fn initial_attempt_gate_open(&self, now: Instant) -> bool {
        if self.ipv6.is_positive() {
            return true;
        }

        if !self.ipv4.is_positive() {
            return false;
        }

        if self.ipv6.is_finished() {
            return true;
        }

        self.resolution_delay.has_passed(now)
    }

    fn next_attempt_deadline(&self) -> Option<Instant> {
        if self.attempted.is_empty() || self.pending.is_empty() {
            return None;
        }
        self.last_attempt_started_at
            .map(|started_at| started_at + bounded_connection_attempt_delay())
    }

    /// The Resolution Delay's timer fired: IPv4 no longer waits on AAAA.
    const fn open_resolution_gate(&mut self) {
        self.resolution_delay = ResolutionDelay::Passed;
    }

    fn record_attempt_failure(&mut self, addr: SocketAddr, error: &io::Error) {
        self.attempt_failures.push(format!("{addr}: {error}"));
    }

    fn mark_resolution_stream_closed(&mut self) {
        if matches!(self.ipv6, FamilyResolution::Pending) {
            self.ipv6 = FamilyResolution::Failed(
                "resolver stream closed before IPv6 result was delivered".to_string(),
            );
        }
        if matches!(self.ipv4, FamilyResolution::Pending) {
            self.ipv4 = FamilyResolution::Failed(
                "resolver stream closed before IPv4 result was delivered".to_string(),
            );
        }
    }

    const fn resolution_complete(&self) -> bool {
        self.ipv6.is_finished() && self.ipv4.is_finished()
    }

    fn is_terminal(&self, no_attempts_running: bool) -> bool {
        no_attempts_running && self.pending.is_empty() && self.resolution_complete()
    }

    fn into_connect_error(self) -> io::Error {
        let mut diagnostics = Vec::new();
        if let Some(message) = self.ipv6.failure_message(AddressFamilyKind::Ipv6) {
            diagnostics.push(message);
        }
        if let Some(message) = self.ipv4.failure_message(AddressFamilyKind::Ipv4) {
            diagnostics.push(message);
        }
        diagnostics.extend(self.attempt_failures);

        io::Error::other(format!(
            "RFC 8305 connection setup failed: {}",
            diagnostics.join("; ")
        ))
    }
}

async fn connect_attempt<D: Dialer>(dialer: &D, addr: SocketAddr) -> AttemptOutcome<D::Stream> {
    AttemptOutcome {
        addr,
        result: connect_with_timeout(dialer, addr).await,
    }
}

async fn connect_with_timeout<D: Dialer>(dialer: &D, addr: SocketAddr) -> io::Result<D::Stream> {
    let connect = dialer.dial(addr);
    let timeout = async {
        dialer.sleep_until(Instant::now() + CONNECT_TIMEOUT).await;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out connecting to {addr}"),
        ))
    };

    pin_mut!(connect);
    pin_mut!(timeout);

    match select(connect, timeout).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

fn start_resolution(host: &str, port: u16) -> UnboundedReceiver<ResolutionEvent> {
    let (sender, receiver) = unbounded();
    if is_localhost(host) {
        for event in loopback_resolution(port) {
            sender
                .unbounded_send(event)
                .expect("the receiver is still held here");
        }
        return receiver;
    }
    for query in [
        ResolveQuery::Family(AddressFamilyKind::Ipv6),
        ResolveQuery::Family(AddressFamilyKind::Ipv4),
        ResolveQuery::SortedSnapshot,
    ] {
        spawn_blocking_resolution(host.to_string(), port, query, sender.clone());
    }
    drop(sender);
    receiver
}

/// Whether `host` is a localhost name: `localhost` or a name under it, in
/// any case, with or without the root label (RFC 6761 §6.3).
fn is_localhost(host: &str) -> bool {
    const LOCALHOST: &[u8] = b"localhost";
    let name = host.strip_suffix('.').unwrap_or(host).as_bytes();
    let Some(split) = name.len().checked_sub(LOCALHOST.len()) else {
        return false;
    };
    let (parent, last) = name.split_at(split);
    last.eq_ignore_ascii_case(LOCALHOST) && (parent.is_empty() || parent.ends_with(b"."))
}

/// What resolving a localhost name yields: the loopback addresses, with no
/// query sent, since RFC 6761 §6.3 makes them the only answer. `::1` comes
/// first, as RFC 6724's default policy table orders it.
fn loopback_resolution(port: u16) -> [ResolutionEvent; 3] {
    let ipv6 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port);
    let ipv4 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    [
        ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv6,
                result: ResolutionResult::Addresses(vec![ipv6]),
            },
        },
        ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv4,
                result: ResolutionResult::Addresses(vec![ipv4]),
            },
        },
        ResolutionEvent {
            kind: ResolutionEventKind::SortedSnapshot(ResolutionResult::Addresses(vec![
                ipv6, ipv4,
            ])),
        },
    ]
}

#[derive(Clone, Copy, Debug)]
enum ResolveQuery {
    Family(AddressFamilyKind),
    SortedSnapshot,
}

fn spawn_blocking_resolution(
    host: String,
    port: u16,
    query: ResolveQuery,
    sender: futures_channel::mpsc::UnboundedSender<ResolutionEvent>,
) {
    thread::spawn(move || {
        let result = match query {
            ResolveQuery::Family(family) => resolve_family_blocking(&host, port, Some(family)),
            ResolveQuery::SortedSnapshot => resolve_family_blocking(&host, port, None),
        };
        let kind = match query {
            ResolveQuery::Family(family) => ResolutionEventKind::Family { family, result },
            ResolveQuery::SortedSnapshot => ResolutionEventKind::SortedSnapshot(result),
        };
        let _ = sender.unbounded_send(ResolutionEvent { kind });
    });
}

fn resolve_family_blocking(
    host: &str,
    port: u16,
    family: Option<AddressFamilyKind>,
) -> ResolutionResult {
    let service = port.to_string();
    let hints = AddrInfoHints {
        address: family.map_or(0, |family| match family {
            AddressFamilyKind::Ipv6 => AddrFamily::Inet6.into(),
            AddressFamilyKind::Ipv4 => AddrFamily::Inet.into(),
        }),
        socktype: SockType::Stream.into(),
        ..AddrInfoHints::default()
    };

    match getaddrinfo(Some(host), Some(service.as_str()), Some(hints)) {
        Ok(iter) => match iter.collect::<io::Result<Vec<_>>>() {
            Ok(entries) => {
                let addrs =
                    dedup_socket_addrs(entries.into_iter().map(|entry| entry.sockaddr).collect());
                if addrs.is_empty() {
                    ResolutionResult::Empty
                } else {
                    ResolutionResult::Addresses(addrs)
                }
            }
            Err(error) => ResolutionResult::Failed(error.to_string()),
        },
        Err(error) => ResolutionResult::Failed(format!("{error:?}")),
    }
}

fn dedup_socket_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if seen.insert(addr) {
            deduped.push(addr);
        }
    }
    deduped
}

fn interleave_address_families(
    primary: &[SocketAddr],
    secondary: &[SocketAddr],
    first_family_count: usize,
) -> Vec<SocketAddr> {
    assert!(
        first_family_count > 0,
        "first address family count must be greater than zero",
    );

    let mut ordered = Vec::with_capacity(primary.len() + secondary.len());
    let mut primary_index = 0;
    let mut secondary_index = 0;

    while primary_index < primary.len() || secondary_index < secondary.len() {
        for _ in 0..first_family_count {
            if let Some(addr) = primary.get(primary_index) {
                ordered.push(*addr);
                primary_index += 1;
            }
        }

        if let Some(addr) = secondary.get(secondary_index) {
            ordered.push(*addr);
            secondary_index += 1;
        }

        if primary_index >= primary.len() && secondary_index < secondary.len() {
            ordered.extend_from_slice(&secondary[secondary_index..]);
            break;
        }
        if secondary_index >= secondary.len() && primary_index < primary.len() {
            ordered.extend_from_slice(&primary[primary_index..]);
            break;
        }
    }

    ordered
}

fn bounded_connection_attempt_delay() -> Duration {
    CONNECTION_ATTEMPT_DELAY
        .max(MIN_CONNECTION_ATTEMPT_DELAY)
        .min(MAX_CONNECTION_ATTEMPT_DELAY)
}

async fn timer_at<D: Dialer>(dialer: &D, deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => dialer.sleep_until(deadline).await,
        None => pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamilyKind, HappyEyeballsState, ResolutionEvent, ResolutionEventKind,
        ResolutionResult, interleave_address_families, is_localhost, resolve, start_resolution,
    };
    #[cfg(connector)]
    use super::{AsyncNet, connect};
    use futures_channel::mpsc::TryRecvError;
    use std::{net::SocketAddr, time::Instant};

    #[test]
    fn localhost_names_are_recognised() {
        for host in [
            "localhost",
            "localhost.",
            "LocalHost",
            "app.localhost",
            "a.b.LOCALHOST.",
        ] {
            assert!(is_localhost(host), "{host} is a localhost name");
        }
        for host in [
            "notlocalhost",
            "localhost.example.com",
            "localhost..",
            "localhos",
            "example.com",
        ] {
            assert!(!is_localhost(host), "{host} is not a localhost name");
        }
    }

    #[test]
    fn localhost_names_resolve_to_loopback_without_a_query() {
        let loopback: Vec<SocketAddr> = vec![
            "[::1]:8443".parse().expect("valid IPv6"),
            "127.0.0.1:8443".parse().expect("valid IPv4"),
        ];
        for host in ["localhost", "zenwave-test.localhost."] {
            // Every answer is in, and the stream closed, before anything ran:
            // no resolver thread holds a sender.
            let mut events = start_resolution(host, 8443);
            let mut answers = 0;
            loop {
                match events.try_recv() {
                    Ok(_) => answers += 1,
                    Err(TryRecvError::Closed) => break,
                    Err(TryRecvError::Empty) => panic!("{host} is waiting on a lookup"),
                }
            }
            assert_eq!(answers, 3, "{host}: both families and the sorted snapshot");
            let addrs = futures_executor::block_on(resolve(host, 8443)).expect("resolves");
            assert_eq!(addrs, loopback, "{host}");
        }
    }

    #[test]
    fn interleaves_addresses_with_first_family_count() {
        let ipv6 = vec![
            "[2001:db8::1]:443"
                .parse::<SocketAddr>()
                .expect("valid IPv6"),
            "[2001:db8::2]:443"
                .parse::<SocketAddr>()
                .expect("valid IPv6"),
        ];
        let ipv4 = vec![
            "203.0.113.10:443"
                .parse::<SocketAddr>()
                .expect("valid IPv4"),
            "203.0.113.11:443"
                .parse::<SocketAddr>()
                .expect("valid IPv4"),
        ];
        assert_eq!(
            interleave_address_families(&ipv6, &ipv4, 1),
            vec![
                "[2001:db8::1]:443".parse().expect("valid IPv6"),
                "203.0.113.10:443".parse().expect("valid IPv4"),
                "[2001:db8::2]:443".parse().expect("valid IPv6"),
                "203.0.113.11:443".parse().expect("valid IPv4"),
            ]
        );
    }

    #[test]
    fn promotes_ipv6_when_aaaa_arrives_during_resolution_delay() {
        let mut state = HappyEyeballsState::new();
        state.apply_resolution(ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv4,
                result: ResolutionResult::Addresses(vec![
                    "203.0.113.10:443"
                        .parse::<SocketAddr>()
                        .expect("valid IPv4"),
                ]),
            },
        });
        state.apply_resolution(ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv6,
                result: ResolutionResult::Addresses(vec![
                    "[2001:db8::1]:443"
                        .parse::<SocketAddr>()
                        .expect("valid IPv6"),
                ]),
            },
        });

        let ordered = state.ordered_candidates();
        assert_eq!(state.first_positive_family, Some(AddressFamilyKind::Ipv6));
        assert_eq!(
            ordered.first().copied(),
            Some("[2001:db8::1]:443".parse().expect("valid IPv6"))
        );
    }

    #[test]
    fn holds_ipv4_until_resolution_delay_expires_when_aaaa_is_still_pending() {
        let mut state = HappyEyeballsState::new();
        state.apply_resolution(ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv4,
                result: ResolutionResult::Addresses(vec![
                    "203.0.113.10:443"
                        .parse::<SocketAddr>()
                        .expect("valid IPv4"),
                ]),
            },
        });

        assert_eq!(state.first_positive_family, Some(AddressFamilyKind::Ipv4));
        assert!(
            state.resolution_delay.deadline().is_some(),
            "A responses must wait for the resolution delay while AAAA remains pending",
        );
        assert!(
            !state.initial_attempt_gate_open(Instant::now()),
            "IPv4 must not start immediately while AAAA is still pending",
        );
    }

    #[test]
    fn starts_ipv4_once_the_resolution_delay_passes_with_aaaa_still_pending() {
        let mut state = HappyEyeballsState::new();
        state.apply_resolution(ResolutionEvent {
            kind: ResolutionEventKind::Family {
                family: AddressFamilyKind::Ipv4,
                result: ResolutionResult::Addresses(vec![
                    "203.0.113.10:443"
                        .parse::<SocketAddr>()
                        .expect("valid IPv4"),
                ]),
            },
        });
        // The delay's timer fires; AAAA has still not answered.
        state.open_resolution_gate();
        state.rebuild_pending();

        assert_eq!(
            state.pop_next_attempt(Instant::now()),
            Some("203.0.113.10:443".parse().expect("valid IPv4")),
            "IPv4 starts once the resolution delay passes, without waiting on AAAA",
        );
    }

    #[cfg(connector)]
    #[test]
    fn literal_ip_connect_does_not_report_opposite_family_resolution() {
        let error = smol::block_on(connect(&AsyncNet, "127.0.0.1", 9))
            .expect_err("discard port should not accept connections in tests");
        let message = error.to_string();
        assert!(
            !message.contains("Ipv6 resolution"),
            "literal IPv4 must not run DNS or report IPv6 resolution: {message}",
        );
        assert!(
            message.contains("127.0.0.1:9"),
            "literal IP connection error should name the attempted socket address: {message}",
        );
    }
}
