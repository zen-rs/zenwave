//! RFC 8305 Happy Eyeballs: resolve both address families concurrently and
//! race connection attempts so a broken IPv6 path costs milliseconds, not a
//! timeout.

use std::{
    collections::{HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    thread,
    time::{Duration, Instant},
};

use async_io::Timer;
use async_net::TcpStream;
use dns_lookup::{AddrFamily, AddrInfoHints, SockType, getaddrinfo};
use futures_channel::mpsc::{UnboundedReceiver, unbounded};
use futures_util::{
    FutureExt,
    future::{Either, pending, select},
    pin_mut,
    stream::{FuturesUnordered, StreamExt},
};

// RFC 8305 defaults: Resolution Delay = 50ms, First Address Family Count = 1,
// Connection Attempt Delay = 250ms.
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
const FIRST_ADDRESS_FAMILY_COUNT: usize = 1;
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const MIN_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(100);
const MAX_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

pub async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return connect_with_timeout(addr)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("{addr}: {error}")));
    }

    let mut state = HappyEyeballsState::new();
    let mut attempts = FuturesUnordered::new();
    let mut resolver = start_resolution(host, port);
    let mut resolver_closed = false;

    loop {
        state.rebuild_pending();

        if let Some(addr) = state.pop_next_attempt(Instant::now()) {
            let attempt: AttemptFuture = Box::pin(connect_attempt(addr));
            attempts.push(attempt);
            continue;
        }

        if state.is_terminal(&attempts) {
            return Err(state.into_connect_error());
        }

        let resolver_event = async {
            if resolver_closed {
                pending::<Option<ResolutionEvent>>().await
            } else {
                resolver.next().await
            }
        };
        let resolution_delay = timer_at(state.resolution_delay_deadline);
        let next_attempt_due = timer_at(state.next_attempt_deadline());

        pin_mut!(resolver_event);
        pin_mut!(resolution_delay);
        pin_mut!(next_attempt_due);

        let attempt_result = async {
            match attempts.next().await {
                Some(outcome) => outcome,
                None => pending::<AttemptOutcome>().await,
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

#[derive(Debug)]
struct AttemptOutcome {
    addr: SocketAddr,
    result: io::Result<TcpStream>,
}

type AttemptFuture = Pin<Box<dyn Future<Output = AttemptOutcome> + Send>>;

#[derive(Debug)]
struct HappyEyeballsState {
    ipv6: FamilyResolution,
    ipv4: FamilyResolution,
    sorted_snapshot: Option<Vec<SocketAddr>>,
    first_positive_family: Option<AddressFamilyKind>,
    resolution_delay_deadline: Option<Instant>,
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
            resolution_delay_deadline: None,
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
                            self.resolution_delay_deadline = None;
                        } else if self.ipv6.is_finished() && self.ipv4.is_positive() {
                            self.resolution_delay_deadline = None;
                        }
                    }
                    AddressFamilyKind::Ipv4 => {
                        let ipv4_became_positive = !self.ipv4.is_positive()
                            && matches!(&resolution, FamilyResolution::Ready(_));
                        self.ipv4 = resolution;
                        if ipv4_became_positive && self.first_positive_family.is_none() {
                            self.first_positive_family = Some(AddressFamilyKind::Ipv4);
                            if !self.ipv6.is_finished() {
                                self.resolution_delay_deadline =
                                    Some(Instant::now() + RESOLUTION_DELAY);
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

        self.resolution_delay_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    fn next_attempt_deadline(&self) -> Option<Instant> {
        if self.attempted.is_empty() || self.pending.is_empty() {
            return None;
        }
        self.last_attempt_started_at
            .map(|started_at| started_at + bounded_connection_attempt_delay())
    }

    const fn open_resolution_gate(&mut self) {
        self.resolution_delay_deadline = None;
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

    fn is_terminal(&self, attempts: &FuturesUnordered<AttemptFuture>) -> bool {
        attempts.is_empty() && self.pending.is_empty() && self.resolution_complete()
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

async fn connect_attempt(addr: SocketAddr) -> AttemptOutcome {
    AttemptOutcome {
        addr,
        result: connect_with_timeout(addr).await,
    }
}

async fn connect_with_timeout(addr: SocketAddr) -> io::Result<TcpStream> {
    let connect = TcpStream::connect(addr);
    let timeout = async {
        Timer::after(CONNECT_TIMEOUT).await;
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

async fn timer_at(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => {
            Timer::at(deadline).await;
        }
        None => pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamilyKind, HappyEyeballsState, ResolutionEvent, ResolutionEventKind,
        ResolutionResult, connect, interleave_address_families,
    };
    use std::{net::SocketAddr, time::Instant};

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
            state.resolution_delay_deadline.is_some(),
            "A responses must wait for the resolution delay while AAAA remains pending",
        );
        assert!(
            !state.initial_attempt_gate_open(Instant::now()),
            "IPv4 must not start immediately while AAAA is still pending",
        );
    }

    #[test]
    fn literal_ip_connect_does_not_report_opposite_family_resolution() {
        let error = smol::block_on(connect("127.0.0.1", 9))
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
