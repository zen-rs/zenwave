//! Concurrent HTTP `Range` downloads into memory ([`Bytes`]) or files on disk,
//! with redirect pinning, validator checks, crash-safe sidecar resume, and
//! optional [`progressor`] integration.

use core::{
    fmt,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

#[cfg(reactor)]
use std::{
    io::{ErrorKind as IoErrorKind, SeekFrom},
    path::{Path, PathBuf},
};

#[cfg(reactor)]
use async_fs::OpenOptions;
use futures_channel::mpsc;
use futures_util::{
    SinkExt, StreamExt,
    stream::{FuturesUnordered, TryStreamExt},
};
use http::{Extensions, HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
#[cfg(reactor)]
use http_kit::utils::{AsyncSeekExt, AsyncWriteExt};
use http_kit::{Body, Request, Response, utils::Bytes};
#[cfg(reactor)]
use serde::{Deserialize, Serialize};

use crate::{
    Client, Error, ResponseExt,
    client::{DedicatedConnection, SuppressAuth},
    error::DownloadErrorKind,
    redirect::{RedirectOutcome, same_origin},
};

/// Default concurrent range workers.
const DEFAULT_CONCURRENCY: NonZeroUsize = NonZeroUsize::new(8).unwrap();
/// Default chunk size (2 MiB).
const DEFAULT_CHUNK_SIZE: NonZeroU64 = NonZeroU64::new(2 * 1024 * 1024).unwrap();
/// Default minimum total size before splitting into parallel range requests (1 MiB).
const DEFAULT_MIN_SPLIT_SIZE: NonZeroU64 = NonZeroU64::new(1024 * 1024).unwrap();
/// Default per-chunk transient retry budget.
const DEFAULT_PART_RETRIES: usize = 3;
/// Base backoff duration for transient chunk retries (doubles per attempt, capped at 2s).
const RETRY_BASE_DELAY_MS: u64 = 50;
/// Maximum backoff duration between transient chunk retries.
const RETRY_MAX_DELAY_MS: u64 = 2_000;
/// Sidecar schema version written into `<dest>.part.json`.
#[cfg(reactor)]
const SIDECAR_VERSION: u32 = 1;

/// Snapshot of an in-flight download's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    /// Total bytes available locally so far (including [`resumed_from`](Self::resumed_from)).
    pub downloaded: u64,
    /// Total expected size in bytes, when known.
    pub total: Option<u64>,
    /// Bytes reused from a prior partial download (`0` for fresh downloads).
    pub resumed_from: u64,
    /// Number of transfer workers currently active.
    pub active_workers: usize,
}

/// Observer invoked whenever a download publishes a [`DownloadProgress`] snapshot.
pub trait ProgressObserver: Send {
    /// Handle an updated progress snapshot.
    fn on_progress(&mut self, progress: DownloadProgress);

    /// Returns `true` when this observer discards every update, allowing the
    /// engine to skip buffering observer snapshots.
    #[doc(hidden)]
    fn is_noop(&self) -> bool {
        false
    }
}

/// Default no-op [`ProgressObserver`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserver;

impl ProgressObserver for NoObserver {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn on_progress(&mut self, _progress: DownloadProgress) {}

    #[inline]
    fn is_noop(&self) -> bool {
        true
    }
}

impl<F> ProgressObserver for F
where
    F: FnMut(DownloadProgress) + Send,
{
    #[inline]
    fn on_progress(&mut self, progress: DownloadProgress) {
        self(progress);
    }
}

/// Controls how concurrent download workers acquire transport connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionMode {
    /// Share the client's connection pool (HTTP/2 and HTTP/3 multiplexing or
    /// pooled HTTP/1.1 connections).
    #[default]
    SharedPool,
    /// Request a dedicated transport connection per worker, bypassing pooling
    /// and HTTP/2 or HTTP/3 multiplexing.
    Dedicated,
}

/// Controls how [`FileDownload`] interacts with prior partial downloads.
#[cfg(reactor)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResumeMode {
    /// Resume from a sibling `<file>.part` and `<file>.part.json` sidecar when
    /// the remote validator (`ETag` or `Last-Modified`) and total length still
    /// match; otherwise discard the partial state and start fresh.
    #[default]
    Sidecar,
    /// Discard any existing partial state and download from scratch.
    Overwrite,
}

/// Report describing a completed file download.
#[cfg(reactor)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadReport {
    /// Final destination path on disk.
    pub path: PathBuf,
    /// Bytes reused from a previous partial download (`0` for fresh downloads).
    pub resumed_from: u64,
    /// New bytes transferred during this download invocation.
    pub bytes_written: u64,
    /// Final URI after following any redirects.
    pub effective_uri: Uri,
}

#[cfg(reactor)]
impl DownloadReport {
    /// Total bytes now persisted at [`path`](Self::path).
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.resumed_from + self.bytes_written
    }
}

/// Configuration shared across [`Download`], [`BytesDownload`], and [`FileDownload`].
#[derive(Debug, Clone)]
struct DownloadConfig {
    concurrency: NonZeroUsize,
    chunk_size: NonZeroU64,
    min_split_size: NonZeroU64,
    max_bytes: Option<u64>,
    expected_size: Option<u64>,
    part_retries: usize,
    connection_mode: ConnectionMode,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            chunk_size: DEFAULT_CHUNK_SIZE,
            min_split_size: DEFAULT_MIN_SPLIT_SIZE,
            max_bytes: None,
            expected_size: None,
            part_retries: DEFAULT_PART_RETRIES,
            connection_mode: ConnectionMode::SharedPool,
        }
    }
}

/// Template extracted from the caller's [`Request`] for probing and chunk requests.
#[derive(Debug, Clone)]
struct RequestTemplate {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    extensions: Extensions,
}

impl RequestTemplate {
    fn from_request(request: Request) -> Self {
        let (parts, _body) = request.into_parts();
        Self {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            extensions: parts.extensions,
        }
    }

    fn build_probe(&self, with_range_zero: bool) -> Request {
        let mut req = http::Request::new(Body::empty());
        *req.method_mut() = self.method.clone();
        *req.uri_mut() = self.uri.clone();
        *req.headers_mut() = self.headers.clone();
        *req.extensions_mut() = self.extensions.clone();
        if with_range_zero {
            req.headers_mut()
                .insert(header::RANGE, HeaderValue::from_static("bytes=0-0"));
        } else {
            req.headers_mut().remove(header::RANGE);
        }
        req
    }

    fn build_chunk(
        &self,
        effective_uri: &Uri,
        stripped_credentials: bool,
        start: u64,
        end: u64,
        validator: &Validator,
        connection_mode: ConnectionMode,
    ) -> Request {
        let mut req = http::Request::new(Body::empty());
        *req.method_mut() = self.method.clone();
        *req.uri_mut() = effective_uri.clone();
        let mut headers = self.headers.clone();
        if stripped_credentials {
            headers.remove(header::AUTHORIZATION);
            headers.remove(header::COOKIE);
        }
        headers.remove(header::HOST);
        headers.insert(
            header::RANGE,
            HeaderValue::from_str(&format!("bytes={start}-{end}"))
                .expect("numeric byte range is a valid header value"),
        );
        if let Some(etag) = &validator.etag {
            if let Ok(value) = HeaderValue::from_str(etag) {
                headers.insert(header::IF_MATCH, value);
            }
        } else if let Some(last_modified) = &validator.last_modified
            && let Ok(value) = HeaderValue::from_str(last_modified)
        {
            headers.insert(header::IF_UNMODIFIED_SINCE, value);
        }
        *req.headers_mut() = headers;

        let mut extensions = self.extensions.clone();
        if stripped_credentials {
            extensions.insert(SuppressAuth);
        }
        if connection_mode == ConnectionMode::Dedicated {
            extensions.insert(DedicatedConnection);
        }
        *req.extensions_mut() = extensions;
        req
    }
}

/// Builder configuring a concurrent download to memory or disk.
pub struct Download<C, O = NoObserver> {
    client: C,
    template: RequestTemplate,
    config: DownloadConfig,
    observer: O,
}

impl<C: fmt::Debug, O> fmt::Debug for Download<C, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Download")
            .field("client", &self.client)
            .field("uri", &self.template.uri)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<C> Download<C, NoObserver> {
    pub(super) fn new(client: C, request: Request) -> Self {
        Self {
            client,
            template: RequestTemplate::from_request(request),
            config: DownloadConfig::default(),
            observer: NoObserver,
        }
    }
}

impl<C, O> Download<C, O> {
    /// Set the maximum number of concurrent range workers (`1` forces a single
    /// sequential transfer; default `8`).
    #[must_use]
    pub const fn concurrency(mut self, concurrency: NonZeroUsize) -> Self {
        self.config.concurrency = concurrency;
        self
    }

    /// Set the target byte size for each range chunk (default 2 MiB).
    #[must_use]
    pub const fn chunk_size(mut self, chunk_size: NonZeroU64) -> Self {
        self.config.chunk_size = chunk_size;
        self
    }

    /// Set the minimum total byte length before splitting into concurrent
    /// range requests (default 1 MiB).
    #[must_use]
    pub const fn min_split_size(mut self, min_split_size: NonZeroU64) -> Self {
        self.config.min_split_size = min_split_size;
        self
    }

    /// Abort with [`Error::ResponseBodyTooLarge`] if the response announces or
    /// streams more than `max_bytes` bytes.
    #[must_use]
    pub const fn max_bytes(mut self, max_bytes: u64) -> Self {
        self.config.max_bytes = Some(max_bytes);
        self
    }

    /// Require the downloaded resource to be exactly `expected_size` bytes,
    /// failing with [`DownloadErrorKind::SizeMismatch`] otherwise.
    #[must_use]
    pub const fn expected_size(mut self, expected_size: u64) -> Self {
        self.config.expected_size = Some(expected_size);
        self
    }

    /// Set how many times an individual chunk is retried on transient failures
    /// (default `3`).
    #[must_use]
    pub const fn part_retries(mut self, part_retries: usize) -> Self {
        self.config.part_retries = part_retries;
        self
    }

    /// Choose whether concurrent workers share the client's connection pool or
    /// request dedicated connections.
    #[must_use]
    pub const fn connection_mode(mut self, mode: ConnectionMode) -> Self {
        self.config.connection_mode = mode;
        self
    }

    /// Attach a [`ProgressObserver`] invoked as bytes are downloaded.
    #[must_use]
    pub fn on_progress<O2: ProgressObserver>(self, observer: O2) -> Download<C, O2> {
        Download {
            client: self.client,
            template: self.template,
            config: self.config,
            observer,
        }
    }

    /// Download the resource into memory as [`Bytes`].
    #[must_use]
    pub fn bytes(self) -> BytesDownload<C, O>
    where
        C: Client + Clone + Send + 'static,
        C::Error: Into<Error>,
        O: ProgressObserver,
    {
        #[cfg(feature = "progressor")]
        let (watch_tx, watch_rx) = progressor::watch(None);
        let observer_queue = (!self.observer.is_noop()).then(|| Arc::new(Mutex::new(Vec::new())));
        let init = BytesInit {
            client: self.client,
            template: self.template,
            config: self.config,
            observer_queue: observer_queue.clone(),
            #[cfg(feature = "progressor")]
            watch_tx,
        };
        BytesDownload {
            state: FutureState::Init(Some(Box::new(init))),
            observer: Box::new(self.observer),
            observer_queue,
            #[cfg(feature = "progressor")]
            watch_rx,
        }
    }

    /// Download the resource into `path` on disk, writing through a sibling
    /// `.part` file and renaming atomically upon completion.
    #[cfg(reactor)]
    #[must_use]
    pub fn to_path(self, path: impl Into<PathBuf>) -> FileDownload<C, O>
    where
        C: Client + Clone + Send + 'static,
        C::Error: Into<Error>,
        O: ProgressObserver,
    {
        #[cfg(feature = "progressor")]
        let (watch_tx, watch_rx) = progressor::watch(None);
        let observer_queue = (!self.observer.is_noop()).then(|| Arc::new(Mutex::new(Vec::new())));
        let init = FileInit {
            client: self.client,
            template: self.template,
            config: self.config,
            path: path.into(),
            resume_mode: ResumeMode::default(),
            observer_queue: observer_queue.clone(),
            #[cfg(feature = "progressor")]
            watch_tx,
        };
        FileDownload {
            state: FutureState::Init(Some(Box::new(init))),
            observer: Box::new(self.observer),
            observer_queue,
            #[cfg(feature = "progressor")]
            watch_rx,
        }
    }
}

enum FutureState<I, Out> {
    Init(Option<Box<I>>),
    Running(Pin<Box<dyn Future<Output = Out> + Send>>),
}

struct BytesInit<C> {
    client: C,
    template: RequestTemplate,
    config: DownloadConfig,
    observer_queue: Option<Arc<Mutex<Vec<DownloadProgress>>>>,
    #[cfg(feature = "progressor")]
    watch_tx: progressor::WatchSender<DownloadProgress>,
}

/// Future returned by [`Download::bytes`] and
/// [`RequestBuilder::download_bytes`](crate::RequestBuilder::download_bytes).
pub struct BytesDownload<C, O = NoObserver> {
    state: FutureState<BytesInit<C>, Result<Bytes, Error>>,
    observer: Box<O>,
    observer_queue: Option<Arc<Mutex<Vec<DownloadProgress>>>>,
    #[cfg(feature = "progressor")]
    watch_rx: progressor::WatchReceiver<DownloadProgress>,
}

impl<C, O> fmt::Debug for BytesDownload<C, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BytesDownload").finish_non_exhaustive()
    }
}

impl<C, O> Future for BytesDownload<C, O>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
    O: ProgressObserver,
{
    type Output = Result<Bytes, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let FutureState::Init(init) = &mut this.state {
            let init = init.take().expect("BytesDownload polled after completion");
            let emitter = ProgressEmitter::new(
                init.observer_queue,
                #[cfg(feature = "progressor")]
                init.watch_tx,
            );
            this.state = FutureState::Running(Box::pin(run_bytes_download(
                init.client,
                init.template,
                init.config,
                emitter,
            )));
        }
        let FutureState::Running(fut) = &mut this.state else {
            unreachable!()
        };
        let poll = fut.as_mut().poll(cx);
        drain_observer_queue(this.observer_queue.as_ref(), &mut *this.observer);
        poll
    }
}

#[cfg(feature = "progressor")]
impl<C, O> progressor::Progress for BytesDownload<C, O>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
    O: ProgressObserver,
{
    type Update = DownloadProgress;

    fn progress(
        &self,
    ) -> impl futures_util::Stream<Item = DownloadProgress> + Unpin + Send + 'static {
        self.watch_rx.clone()
    }
}

#[cfg(reactor)]
struct FileInit<C> {
    client: C,
    template: RequestTemplate,
    config: DownloadConfig,
    path: PathBuf,
    resume_mode: ResumeMode,
    observer_queue: Option<Arc<Mutex<Vec<DownloadProgress>>>>,
    #[cfg(feature = "progressor")]
    watch_tx: progressor::WatchSender<DownloadProgress>,
}

/// Future returned by [`Download::to_path`] and
/// [`RequestBuilder::download_to_path`](crate::RequestBuilder::download_to_path).
#[cfg(reactor)]
pub struct FileDownload<C, O = NoObserver> {
    state: FutureState<FileInit<C>, Result<DownloadReport, Error>>,
    observer: Box<O>,
    observer_queue: Option<Arc<Mutex<Vec<DownloadProgress>>>>,
    #[cfg(feature = "progressor")]
    watch_rx: progressor::WatchReceiver<DownloadProgress>,
}

#[cfg(reactor)]
impl<C, O> fmt::Debug for FileDownload<C, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileDownload").finish_non_exhaustive()
    }
}

#[cfg(reactor)]
impl<C, O> FileDownload<C, O> {
    /// Configure whether this download resumes from an existing `.part`
    /// sidecar ([`ResumeMode::Sidecar`], default) or starts fresh
    /// ([`ResumeMode::Overwrite`]).
    ///
    /// # Panics
    ///
    /// Panics if called after the future has already started polling.
    #[must_use]
    pub fn resume_mode(mut self, mode: ResumeMode) -> Self {
        match &mut self.state {
            FutureState::Init(Some(init)) => init.resume_mode = mode,
            _ => panic!("resume_mode cannot be changed after polling started"),
        }
        self
    }
}

#[cfg(reactor)]
impl<C, O> Future for FileDownload<C, O>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
    O: ProgressObserver,
{
    type Output = Result<DownloadReport, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let FutureState::Init(init) = &mut this.state {
            let init = init.take().expect("FileDownload polled after completion");
            let emitter = ProgressEmitter::new(
                init.observer_queue,
                #[cfg(feature = "progressor")]
                init.watch_tx,
            );
            this.state = FutureState::Running(Box::pin(run_file_download(
                init.client,
                init.template,
                init.config,
                init.path,
                init.resume_mode,
                emitter,
            )));
        }
        let FutureState::Running(fut) = &mut this.state else {
            unreachable!()
        };
        let poll = fut.as_mut().poll(cx);
        drain_observer_queue(this.observer_queue.as_ref(), &mut *this.observer);
        poll
    }
}

#[cfg(all(reactor, feature = "progressor"))]
impl<C, O> progressor::Progress for FileDownload<C, O>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
    O: ProgressObserver,
{
    type Update = DownloadProgress;

    fn progress(
        &self,
    ) -> impl futures_util::Stream<Item = DownloadProgress> + Unpin + Send + 'static {
        self.watch_rx.clone()
    }
}

fn drain_observer_queue<O: ProgressObserver>(
    queue: Option<&Arc<Mutex<Vec<DownloadProgress>>>>,
    observer: &mut O,
) {
    let Some(queue) = queue else {
        return;
    };
    let updates = {
        let mut guard = queue.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_empty() {
            return;
        }
        std::mem::take(&mut *guard)
    };
    for update in updates {
        observer.on_progress(update);
    }
}

#[derive(Clone)]
struct ProgressEmitter {
    observer_queue: Option<Arc<Mutex<Vec<DownloadProgress>>>>,
    #[cfg(feature = "progressor")]
    watch_tx: progressor::WatchSender<DownloadProgress>,
}

impl ProgressEmitter {
    const fn new(
        observer_queue: Option<Arc<Mutex<Vec<DownloadProgress>>>>,
        #[cfg(feature = "progressor")] watch_tx: progressor::WatchSender<DownloadProgress>,
    ) -> Self {
        Self {
            observer_queue,
            #[cfg(feature = "progressor")]
            watch_tx,
        }
    }

    fn emit(&self, snapshot: DownloadProgress) {
        if let Some(queue) = &self.observer_queue {
            queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(snapshot);
        }
        #[cfg(feature = "progressor")]
        self.watch_tx.send(snapshot);
    }
}

/// Tracks monotonic byte progress across concurrent chunks with retries.
struct SharedProgress {
    emitter: ProgressEmitter,
    total: Option<u64>,
    resumed_from: u64,
    downloaded: AtomicU64,
    active_workers: AtomicUsize,
    chunk_high_water: Mutex<Vec<u64>>,
}

impl SharedProgress {
    fn new(
        emitter: ProgressEmitter,
        total: Option<u64>,
        resumed_from: u64,
        initial_downloaded: u64,
        chunk_count: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            emitter,
            total,
            resumed_from,
            downloaded: AtomicU64::new(initial_downloaded),
            active_workers: AtomicUsize::new(0),
            chunk_high_water: Mutex::new(vec![0; chunk_count]),
        })
    }

    fn worker_entered(&self) {
        self.active_workers.fetch_add(1, Ordering::AcqRel);
        self.publish();
    }

    fn worker_exited(&self) {
        self.active_workers.fetch_sub(1, Ordering::AcqRel);
        self.publish();
    }

    /// Record that `slot` has reached `bytes_in_slot` bytes during the current
    /// attempt. Only advances total `downloaded` past the chunk's previous high
    /// watermark, guaranteeing monotonic progress even across chunk retries.
    fn record_chunk_progress(&self, slot: usize, bytes_in_slot: u64) {
        let delta = {
            let mut marks = self
                .chunk_high_water
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let prev = marks[slot];
            let diff = if bytes_in_slot > prev {
                marks[slot] = bytes_in_slot;
                bytes_in_slot - prev
            } else {
                0
            };
            drop(marks);
            diff
        };
        if delta > 0 {
            self.downloaded.fetch_add(delta, Ordering::AcqRel);
            self.publish();
        }
    }

    fn publish(&self) {
        self.emitter.emit(DownloadProgress {
            downloaded: self.downloaded.load(Ordering::Acquire),
            total: self.total,
            resumed_from: self.resumed_from,
            active_workers: self.active_workers.load(Ordering::Acquire),
        });
    }

    fn publish_complete(&self, total: u64) {
        self.downloaded.store(total, Ordering::Release);
        self.active_workers.store(0, Ordering::Release);
        self.emitter.emit(DownloadProgress {
            downloaded: total,
            total: Some(total),
            resumed_from: self.resumed_from,
            active_workers: 0,
        });
    }
}

/// Strong validator extracted from the initial probe response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Validator {
    /// Strong `ETag` (weak `W/` tags are ignored for range combining).
    etag: Option<String>,
    /// Raw `Last-Modified` header value.
    last_modified: Option<String>,
}

impl Validator {
    fn from_headers(headers: &HeaderMap) -> Self {
        let etag = headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty() && !v.starts_with("W/") && !v.starts_with("w/"))
            .map(ToOwned::to_owned);
        let last_modified = headers
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned);
        Self {
            etag,
            last_modified,
        }
    }

    #[cfg(reactor)]
    const fn has_any(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }

    fn matches_response(&self, headers: &HeaderMap) -> bool {
        if let Some(expected_etag) = &self.etag {
            if let Some(actual) = headers
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                && actual != expected_etag
            {
                return false;
            }
        } else if let Some(expected_lm) = &self.last_modified
            && let Some(actual) = headers
                .get(header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
            && actual != expected_lm
        {
            return false;
        }
        true
    }
}

/// Parsed RFC 9110 §14.4 `Content-Range` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentRange {
    /// `bytes <start>-<end>/<complete_length>` (`complete_length` is `None` for `/*`).
    Range {
        start: u64,
        end: u64,
        total: Option<u64>,
    },
    /// `bytes */<complete_length>`.
    Unsatisfied { total: u64 },
}

fn parse_content_range(value: &str) -> Option<ContentRange> {
    let rest = value.trim().strip_prefix("bytes ")?.trim();
    let (range_part, total_part) = rest.split_once('/')?;
    let range_part = range_part.trim();
    let total_part = total_part.trim();
    if range_part == "*" {
        let total = total_part.parse::<u64>().ok()?;
        return Some(ContentRange::Unsatisfied { total });
    }
    let (start_str, end_str) = range_part.split_once('-')?;
    let start = start_str.trim().parse::<u64>().ok()?;
    let end = end_str.trim().parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    let total = if total_part == "*" {
        None
    } else {
        let total = total_part.parse::<u64>().ok()?;
        if end >= total {
            return None;
        }
        Some(total)
    };
    Some(ContentRange::Range { start, end, total })
}

fn parse_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

const fn check_limits_upfront(config: &DownloadConfig, total: u64) -> Result<(), Error> {
    if let Some(limit) = config.max_bytes
        && total > limit
    {
        return Err(Error::ResponseBodyTooLarge { limit });
    }
    if let Some(expected) = config.expected_size
        && total != expected
    {
        return Err(Error::Download(DownloadErrorKind::SizeMismatch {
            expected,
            actual: total,
        }));
    }
    Ok(())
}

/// Outcome of the initial probe request.
enum ProbeOutcome {
    /// Server returned `416` with `Content-Range: bytes */0`.
    Empty {
        #[cfg(reactor)]
        effective_uri: Uri,
    },
    /// Server returned `200 OK` (either plain GET or ignored `Range`).
    FullStream {
        response: Response,
        #[cfg(reactor)]
        effective_uri: Uri,
    },
    /// Server honored `Range: bytes=0-0` with `206 Partial Content`.
    Partial {
        first_byte: u8,
        total: u64,
        validator: Validator,
        effective_uri: Uri,
        stripped_credentials: bool,
    },
}

fn extract_redirect_info(initial_uri: &Uri, response: &Response) -> (Uri, bool) {
    response.extensions().get::<RedirectOutcome>().map_or_else(
        || (initial_uri.clone(), false),
        |outcome| {
            let stripped =
                outcome.stripped_credentials || !same_origin(initial_uri, &outcome.effective_uri);
            (outcome.effective_uri.clone(), stripped)
        },
    )
}

async fn send_probe<C>(
    client: &mut C,
    template: &RequestTemplate,
    with_range_zero: bool,
    config: &DownloadConfig,
) -> Result<ProbeOutcome, Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let mut req = template.build_probe(with_range_zero);
    let response = client.respond_send(&mut req).await.map_err(Into::into)?;
    let (effective_uri, stripped_credentials) = extract_redirect_info(&template.uri, &response);
    let status = response.status();

    if with_range_zero && status == StatusCode::RANGE_NOT_SATISFIABLE {
        let cr = response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_content_range);
        if matches!(cr, Some(ContentRange::Unsatisfied { total: 0 })) {
            check_limits_upfront(config, 0)?;
            return Ok(ProbeOutcome::Empty {
                #[cfg(reactor)]
                effective_uri,
            });
        }
        return Err(response.error_for_status().await.unwrap_err());
    }

    if status.is_client_error() || status.is_server_error() {
        return Err(response.error_for_status().await.unwrap_err());
    }

    if status == StatusCode::OK {
        return Ok(ProbeOutcome::FullStream {
            response,
            #[cfg(reactor)]
            effective_uri,
        });
    }

    if with_range_zero && status == StatusCode::PARTIAL_CONTENT {
        let raw_cr = response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let Some(ContentRange::Range {
            start: 0,
            end: 0,
            total: Some(total),
        }) = raw_cr.as_deref().and_then(parse_content_range)
        else {
            return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
                expected: String::from("bytes 0-0/<total>"),
                actual: raw_cr,
            }));
        };
        if total == 0 {
            return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
                expected: String::from("bytes 0-0/<total>"),
                actual: raw_cr,
            }));
        }
        check_limits_upfront(config, total)?;
        let validator = Validator::from_headers(response.headers());
        let bytes = read_exact_probe_byte(response, total).await?;
        return Ok(ProbeOutcome::Partial {
            first_byte: bytes,
            total,
            validator,
            effective_uri,
            stripped_credentials,
        });
    }

    // Unexpected non-200/206 status (for example an unfollowed 3xx when
    // redirects were disabled): surface as an invalid range/protocol failure.
    Err(Error::Download(DownloadErrorKind::InvalidContentRange {
        expected: if with_range_zero {
            String::from("HTTP 200 or 206")
        } else {
            String::from("HTTP 200")
        },
        actual: Some(status.to_string()),
    }))
}

async fn read_exact_probe_byte(response: Response, total: u64) -> Result<u8, Error> {
    let mut stream = response.into_body().into_data_stream();
    let mut collected = Vec::with_capacity(1);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(DownloadErrorKind::BodyRead)?;
        if collected.len() + chunk.len() > 1 {
            return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
                expected: format!("bytes 0-0/{total}"),
                actual: Some(format!(
                    "probe body length {} exceeded 1 byte",
                    collected.len() + chunk.len()
                )),
            }));
        }
        collected.extend_from_slice(&chunk);
    }
    if collected.len() != 1 {
        return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
            expected: format!("bytes 0-0/{total}"),
            actual: Some(format!("probe body length {} != 1", collected.len())),
        }));
    }
    Ok(collected[0])
}

/// One scheduled byte interval to fetch via `Range`.
#[derive(Debug, Clone, Copy)]
struct ChunkSpec {
    /// Slot index in `SharedProgress::chunk_high_water`.
    slot: usize,
    /// Chunk index in the `chunk_size`-aligned bitmap (for sidecar resume).
    #[cfg_attr(not(reactor), allow(dead_code))]
    bitmap_index: usize,
    /// First byte offset to request (inclusive).
    start: u64,
    /// Last byte offset to request (inclusive).
    end: u64,
}

impl ChunkSpec {
    const fn len(self) -> u64 {
        self.end - self.start + 1
    }
}

/// Build remaining range specs for a fresh download after byte `0` was already
/// captured by the probe (`total > 1`).
fn plan_fresh_chunks(total: u64, config: &DownloadConfig) -> Vec<ChunkSpec> {
    if total <= 1 {
        return Vec::new();
    }
    if total <= config.min_split_size.get() || config.concurrency.get() == 1 {
        return vec![ChunkSpec {
            slot: 0,
            bitmap_index: 0,
            start: 1,
            end: total - 1,
        }];
    }
    let step = config.chunk_size.get();
    let chunk_count = total.div_ceil(step);
    let mut chunks = Vec::new();
    for idx in 0..chunk_count {
        let raw_start = idx * step;
        let end = ((idx + 1) * step).min(total) - 1;
        let start = if idx == 0 { 1 } else { raw_start };
        if start > end {
            // Occurs when `step == 1` and `idx == 0` (byte 0 already captured).
            continue;
        }
        let slot = chunks.len();
        chunks.push(ChunkSpec {
            slot,
            bitmap_index: usize::try_from(idx).unwrap_or(usize::MAX),
            start,
            end,
        });
    }
    chunks
}

/// Immutable parameters shared across every chunk worker in one download.
struct ChunkContext {
    template: RequestTemplate,
    effective_uri: Uri,
    stripped_credentials: bool,
    validator: Validator,
    total: u64,
    config: DownloadConfig,
    progress: Arc<SharedProgress>,
}

/// Fetch one chunk with per-chunk transient retries, forwarding received frames
/// over `sink`.
async fn fetch_chunk_with_retries<C, M>(
    client: &mut C,
    ctx: &ChunkContext,
    spec: ChunkSpec,
    sink: &mut mpsc::Sender<M>,
    mut make_data_msg: impl FnMut(u64, Bytes) -> M,
) -> Result<(), Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let mut attempt = 0;
    loop {
        match fetch_chunk_once(client, ctx, spec, sink, &mut make_data_msg).await {
            Ok(()) => return Ok(()),
            Err(err) if err.is_transient() && attempt < ctx.config.part_retries => {
                attempt += 1;
                tracing::debug!(
                    attempt,
                    start = spec.start,
                    end = spec.end,
                    error = %err,
                    "retrying failed download chunk"
                );
                sleep_backoff(attempt).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn fetch_chunk_once<C, M>(
    client: &mut C,
    ctx: &ChunkContext,
    spec: ChunkSpec,
    sink: &mut mpsc::Sender<M>,
    make_data_msg: &mut impl FnMut(u64, Bytes) -> M,
) -> Result<(), Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let mut req = ctx.template.build_chunk(
        &ctx.effective_uri,
        ctx.stripped_credentials,
        spec.start,
        spec.end,
        &ctx.validator,
        ctx.config.connection_mode,
    );
    let response = client.respond_send(&mut req).await.map_err(Into::into)?;
    let status = response.status();

    if status == StatusCode::PRECONDITION_FAILED {
        return Err(Error::Download(DownloadErrorKind::ResourceChanged));
    }
    if status.is_client_error() || status.is_server_error() {
        return Err(response.error_for_status().await.unwrap_err());
    }

    let expected_cr = format!("bytes {}-{}/{}", spec.start, spec.end, ctx.total);
    let raw_cr = response
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    if status != StatusCode::PARTIAL_CONTENT {
        return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
            expected: expected_cr,
            actual: raw_cr.or_else(|| Some(status.to_string())),
        }));
    }

    if !ctx.validator.matches_response(response.headers()) {
        return Err(Error::Download(DownloadErrorKind::ResourceChanged));
    }

    let parsed = raw_cr.as_deref().and_then(parse_content_range);
    if !matches!(
        parsed,
        Some(ContentRange::Range {
            start,
            end,
            total: Some(r_total),
        }) if start == spec.start && end == spec.end && r_total == ctx.total
    ) {
        return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
            expected: expected_cr,
            actual: raw_cr,
        }));
    }

    let expected_len = spec.len();
    let mut received_in_attempt = 0_u64;
    let mut stream = response.into_body().into_data_stream();
    while let Some(frame) = stream.next().await {
        let frame = frame.map_err(DownloadErrorKind::BodyRead)?;
        if frame.is_empty() {
            continue;
        }
        let frame_len = u64::try_from(frame.len()).unwrap_or(u64::MAX);
        let next = received_in_attempt.saturating_add(frame_len);
        if next > expected_len {
            return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
                expected: expected_cr,
                actual: Some(format!("body exceeded {expected_len} bytes")),
            }));
        }
        let offset = spec.start + received_in_attempt;
        sink.send(make_data_msg(offset, frame))
            .await
            .map_err(|_| Error::Stopped)?;
        received_in_attempt = next;
        ctx.progress
            .record_chunk_progress(spec.slot, received_in_attempt);
    }

    if received_in_attempt != expected_len {
        return Err(Error::Download(DownloadErrorKind::InvalidContentRange {
            expected: expected_cr,
            actual: Some(format!(
                "body length {received_in_attempt} != {expected_len}"
            )),
        }));
    }

    Ok(())
}

async fn sleep_backoff(attempt: usize) {
    let shift = u32::try_from(attempt.saturating_sub(1))
        .unwrap_or(16)
        .min(16);
    let delay_ms = RETRY_BASE_DELAY_MS
        .saturating_mul(1_u64 << shift)
        .min(RETRY_MAX_DELAY_MS);
    let delay = Duration::from_millis(delay_ms);

    #[cfg(reactor)]
    {
        async_io::Timer::after(delay).await;
    }
    #[cfg(browser)]
    {
        use crate::clock::Clock as _;
        crate::clock::BrowserClock.sleep(delay).await;
    }
    #[cfg(all(not(reactor), not(browser), wasi_backend))]
    {
        use crate::clock::Clock as _;
        crate::clock::WasiClock.sleep(delay).await;
    }
    #[cfg(all(not(reactor), not(browser), not(wasi_backend)))]
    {
        let _ = delay;
    }
}

/// Drive an in-memory download to completion.
async fn run_bytes_download<C>(
    mut client: C,
    template: RequestTemplate,
    config: DownloadConfig,
    emitter: ProgressEmitter,
) -> Result<Bytes, Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let with_range_zero = config.concurrency.get() > 1;
    match send_probe(&mut client, &template, with_range_zero, &config).await? {
        ProbeOutcome::Empty { .. } => {
            emitter.emit(DownloadProgress {
                downloaded: 0,
                total: Some(0),
                resumed_from: 0,
                active_workers: 0,
            });
            Ok(Bytes::new())
        }
        ProbeOutcome::FullStream { response, .. } => {
            stream_full_to_bytes(response, &config, &emitter).await
        }
        ProbeOutcome::Partial {
            first_byte,
            total,
            validator,
            effective_uri,
            stripped_credentials,
        } => {
            download_partial_bytes(
                client,
                template,
                config,
                emitter,
                first_byte,
                total,
                validator,
                effective_uri,
                stripped_credentials,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn download_partial_bytes<C>(
    client: C,
    template: RequestTemplate,
    config: DownloadConfig,
    emitter: ProgressEmitter,
    first_byte: u8,
    total: u64,
    validator: Validator,
    effective_uri: Uri,
    stripped_credentials: bool,
) -> Result<Bytes, Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let total_usize = usize::try_from(total).map_err(|_| Error::ResponseBodyTooLarge {
        limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
    })?;
    if total == 1 {
        emitter.emit(DownloadProgress {
            downloaded: 1,
            total: Some(1),
            resumed_from: 0,
            active_workers: 0,
        });
        return Ok(Bytes::from(vec![first_byte]));
    }

    let chunks = plan_fresh_chunks(total, &config);
    let progress = SharedProgress::new(emitter, Some(total), 0, 1, chunks.len());
    progress.publish();

    let worker_count = config.concurrency.get().min(chunks.len()).max(1);
    let queue = Arc::new(Mutex::new(VecDeque::from(chunks)));
    let ctx = Arc::new(ChunkContext {
        template,
        effective_uri,
        stripped_credentials,
        validator,
        total,
        config,
        progress: Arc::clone(&progress),
    });
    let (tx, mut rx) = mpsc::channel::<(u64, Bytes)>(worker_count * 4);

    let mut workers = FuturesUnordered::new();
    for _ in 0..worker_count {
        let mut worker_client = client.clone();
        let queue = Arc::clone(&queue);
        let ctx = Arc::clone(&ctx);
        let mut tx = tx.clone();
        workers.push(async move {
            ctx.progress.worker_entered();
            let result: Result<(), Error> = async {
                loop {
                    let next = queue
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .pop_front();
                    let Some(spec) = next else {
                        break Ok(());
                    };
                    fetch_chunk_with_retries(
                        &mut worker_client,
                        &ctx,
                        spec,
                        &mut tx,
                        |offset, bytes| (offset, bytes),
                    )
                    .await?;
                }
            }
            .await;
            ctx.progress.worker_exited();
            result
        });
    }
    drop(tx);

    let mut buf = vec![0_u8; total_usize];
    buf[0] = first_byte;

    let workers_fut = async move {
        while workers.try_next().await?.is_some() {}
        Ok::<(), Error>(())
    };
    let assemble_fut = async {
        while let Some((offset, bytes)) = rx.next().await {
            let start = usize::try_from(offset).expect("offset fits in buffer");
            let end = start + bytes.len();
            buf[start..end].copy_from_slice(&bytes);
        }
        Ok::<(), Error>(())
    };

    let (worker_res, _) = futures_util::future::join(workers_fut, assemble_fut).await;
    worker_res?;

    progress.publish_complete(total);
    Ok(Bytes::from(buf))
}

async fn stream_full_to_bytes(
    response: Response,
    config: &DownloadConfig,
    emitter: &ProgressEmitter,
) -> Result<Bytes, Error> {
    let announced = parse_content_length(response.headers());
    if let Some(total) = announced {
        check_limits_upfront(config, total)?;
    }
    let initial_cap = announced
        .and_then(|n| usize::try_from(n).ok())
        .map_or(0, |n| n.min(64 * 1024));
    let mut out = Vec::with_capacity(initial_cap);
    let mut downloaded = 0_u64;

    emitter.emit(DownloadProgress {
        downloaded: 0,
        total: announced,
        resumed_from: 0,
        active_workers: 1,
    });

    let mut stream = response.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(DownloadErrorKind::BodyRead)?;
        if chunk.is_empty() {
            continue;
        }
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let next =
            downloaded
                .checked_add(chunk_len)
                .ok_or_else(|| Error::ResponseBodyTooLarge {
                    limit: config.max_bytes.unwrap_or(u64::MAX),
                })?;
        if let Some(limit) = config.max_bytes
            && next > limit
        {
            return Err(Error::ResponseBodyTooLarge { limit });
        }
        out.extend_from_slice(&chunk);
        downloaded = next;
        emitter.emit(DownloadProgress {
            downloaded,
            total: announced,
            resumed_from: 0,
            active_workers: 1,
        });
    }

    if let Some(total) = announced
        && downloaded != total
    {
        return Err(Error::Download(DownloadErrorKind::SizeMismatch {
            expected: total,
            actual: downloaded,
        }));
    }
    if let Some(expected) = config.expected_size
        && downloaded != expected
    {
        return Err(Error::Download(DownloadErrorKind::SizeMismatch {
            expected,
            actual: downloaded,
        }));
    }

    emitter.emit(DownloadProgress {
        downloaded,
        total: Some(downloaded),
        resumed_from: 0,
        active_workers: 0,
    });
    Ok(Bytes::from(out))
}

#[cfg(reactor)]
fn sidecar_paths(dest: &Path) -> (PathBuf, PathBuf) {
    let mut part = dest.as_os_str().to_os_string();
    part.push(".part");
    let mut meta = part.clone();
    meta.push(".json");
    (PathBuf::from(part), PathBuf::from(meta))
}

#[cfg(reactor)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SidecarMeta {
    version: u32,
    total: u64,
    etag: Option<String>,
    last_modified: Option<String>,
    chunk_size: u64,
    /// Bit-packed completed chunks (LSB first within each byte).
    completed_bitmap: Vec<u8>,
}

#[cfg(reactor)]
impl SidecarMeta {
    fn new(total: u64, chunk_size: u64, validator: &Validator) -> Self {
        let num_chunks = usize::try_from(total.div_ceil(chunk_size)).unwrap_or(0);
        let bytes = num_chunks.div_ceil(8);
        Self {
            version: SIDECAR_VERSION,
            total,
            etag: validator.etag.clone(),
            last_modified: validator.last_modified.clone(),
            chunk_size,
            completed_bitmap: vec![0_u8; bytes],
        }
    }

    fn is_chunk_done(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        self.completed_bitmap
            .get(byte)
            .is_some_and(|b| (b & (1_u8 << bit)) != 0)
    }

    fn mark_chunk_done(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        if let Some(slot) = self.completed_bitmap.get_mut(byte) {
            *slot |= 1_u8 << bit;
        }
    }

    fn matches_probe(&self, total: u64, validator: &Validator) -> bool {
        if self.version != SIDECAR_VERSION || self.total != total || self.chunk_size == 0 {
            return false;
        }
        let Ok(num_chunks) = usize::try_from(total.div_ceil(self.chunk_size)) else {
            return false;
        };
        if self.completed_bitmap.len() != num_chunks.div_ceil(8) {
            return false;
        }
        if !validator.has_any() {
            return false;
        }
        validator.etag.as_ref().map_or_else(
            || {
                validator.last_modified.as_ref().is_some_and(|lm| {
                    self.etag.is_none() && self.last_modified.as_deref() == Some(lm.as_str())
                })
            },
            |etag| self.etag.as_deref() == Some(etag.as_str()),
        )
    }

    fn completed_bytes(&self) -> u64 {
        let num_chunks = self.total.div_ceil(self.chunk_size);
        let mut sum = 0_u64;
        for idx in 0..num_chunks {
            let Ok(idx_usize) = usize::try_from(idx) else {
                break;
            };
            if self.is_chunk_done(idx_usize) {
                let start = idx * self.chunk_size;
                let end = ((idx + 1) * self.chunk_size).min(self.total);
                sum += end - start;
            }
        }
        sum
    }
}

#[cfg(reactor)]
async fn remove_if_exists(path: &Path) -> Result<(), Error> {
    match async_fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == IoErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::Download(DownloadErrorKind::FileSystem(err))),
    }
}

#[cfg(reactor)]
async fn persist_sidecar(meta_path: &Path, meta: &SidecarMeta) -> Result<(), Error> {
    let encoded = serde_json::to_vec(meta).map_err(|err| {
        Error::Download(DownloadErrorKind::FileSystem(std::io::Error::other(err)))
    })?;
    let mut tmp = meta_path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    async_fs::write(&tmp_path, &encoded)
        .await
        .map_err(DownloadErrorKind::FileSystem)?;
    async_fs::rename(&tmp_path, meta_path)
        .await
        .map_err(DownloadErrorKind::FileSystem)?;
    Ok(())
}

#[cfg(reactor)]
async fn load_sidecar(
    part_path: &Path,
    meta_path: &Path,
    total: u64,
    validator: &Validator,
) -> Option<SidecarMeta> {
    let part_meta = async_fs::metadata(part_path).await.ok()?;
    if part_meta.len() != total {
        return None;
    }
    let raw = async_fs::read(meta_path).await.ok()?;
    let sidecar: SidecarMeta = serde_json::from_slice(&raw).ok()?;
    sidecar.matches_probe(total, validator).then_some(sidecar)
}

#[cfg(reactor)]
async fn has_sidecar_files(part_path: &Path, meta_path: &Path) -> bool {
    async_fs::metadata(part_path).await.is_ok() && async_fs::metadata(meta_path).await.is_ok()
}

#[cfg(reactor)]
enum FileWriteMsg {
    Data { offset: u64, bytes: Bytes },
    ChunkDone { bitmap_index: usize },
    Finish,
}

#[cfg(reactor)]
struct PreparedFile {
    file: async_fs::File,
    sidecar: Option<SidecarMeta>,
    chunks: Vec<ChunkSpec>,
    resumed_from: u64,
    initial_downloaded: u64,
}

#[cfg(reactor)]
async fn finalize_small_file(
    part_path: &Path,
    meta_path: &Path,
    dest_path: &Path,
    data: &[u8],
    effective_uri: Uri,
    emitter: &ProgressEmitter,
) -> Result<DownloadReport, Error> {
    remove_if_exists(meta_path).await?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)
        .await
        .map_err(DownloadErrorKind::FileSystem)?;
    if !data.is_empty() {
        file.write_all(data)
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
    }
    file.flush().await.map_err(DownloadErrorKind::FileSystem)?;
    file.sync_data()
        .await
        .map_err(DownloadErrorKind::FileSystem)?;
    drop(file);
    async_fs::rename(part_path, dest_path)
        .await
        .map_err(DownloadErrorKind::FileSystem)?;
    let len = u64::try_from(data.len()).unwrap_or(0);
    emitter.emit(DownloadProgress {
        downloaded: len,
        total: Some(len),
        resumed_from: 0,
        active_workers: 0,
    });
    Ok(DownloadReport {
        path: dest_path.to_path_buf(),
        resumed_from: 0,
        bytes_written: len,
        effective_uri,
    })
}

#[cfg(reactor)]
fn plan_resumed_chunks(sidecar: &SidecarMeta, total: u64) -> (Vec<ChunkSpec>, bool) {
    let step = sidecar.chunk_size;
    let num_chunks = total.div_ceil(step);
    let mut chunks = Vec::new();
    let mut chunk0_resumed = true;
    for idx in 0..num_chunks {
        let idx_usize = usize::try_from(idx).unwrap_or(usize::MAX);
        if sidecar.is_chunk_done(idx_usize) {
            continue;
        }
        let raw_start = idx * step;
        let end = ((idx + 1) * step).min(total) - 1;
        let start = if idx == 0 {
            chunk0_resumed = false;
            1
        } else {
            raw_start
        };
        if start > end {
            continue;
        }
        let slot = chunks.len();
        chunks.push(ChunkSpec {
            slot,
            bitmap_index: idx_usize,
            start,
            end,
        });
    }
    (chunks, chunk0_resumed)
}

#[cfg(reactor)]
async fn prepare_partial_file(
    part_path: &Path,
    meta_path: &Path,
    resume_mode: ResumeMode,
    config: &DownloadConfig,
    first_byte: u8,
    total: u64,
    validator: &Validator,
) -> Result<PreparedFile, Error> {
    let resumed_sidecar = if resume_mode == ResumeMode::Sidecar {
        load_sidecar(part_path, meta_path, total, validator).await
    } else {
        None
    };

    let (mut file, sidecar, chunks, resumed_from, initial_downloaded, write_byte_zero) =
        if let Some(sidecar) = resumed_sidecar {
            let resumed_from = sidecar.completed_bytes();
            let (chunks, chunk0_resumed) = plan_resumed_chunks(&sidecar, total);
            let file = OpenOptions::new()
                .write(true)
                .open(part_path)
                .await
                .map_err(DownloadErrorKind::FileSystem)?;
            let initial_downloaded = if chunk0_resumed {
                resumed_from
            } else {
                resumed_from + 1
            };
            (
                file,
                Some(sidecar),
                chunks,
                resumed_from,
                initial_downloaded,
                !chunk0_resumed,
            )
        } else {
            remove_if_exists(part_path).await?;
            remove_if_exists(meta_path).await?;
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(part_path)
                .await
                .map_err(DownloadErrorKind::FileSystem)?;
            file.set_len(total)
                .await
                .map_err(DownloadErrorKind::FileSystem)?;

            let chunks = plan_fresh_chunks(total, config);
            let use_sidecar = resume_mode == ResumeMode::Sidecar
                && validator.has_any()
                && total > config.min_split_size.get()
                && config.concurrency.get() > 1;
            let sidecar = use_sidecar.then(|| {
                let mut meta = SidecarMeta::new(total, config.chunk_size.get(), validator);
                if config.chunk_size.get() == 1 {
                    meta.mark_chunk_done(0);
                }
                meta
            });
            (file, sidecar, chunks, 0_u64, 1_u64, true)
        };

    if write_byte_zero {
        file.seek(SeekFrom::Start(0))
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
        file.write_all(&[first_byte])
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
    }
    if let Some(meta) = &sidecar {
        persist_sidecar(meta_path, meta).await?;
    }

    Ok(PreparedFile {
        file,
        sidecar,
        chunks,
        resumed_from,
        initial_downloaded,
    })
}

#[cfg(reactor)]
async fn run_file_writer(
    mut file: async_fs::File,
    mut sidecar: Option<SidecarMeta>,
    mut rx: mpsc::Receiver<FileWriteMsg>,
    part_path: &Path,
    meta_path: &Path,
    dest_path: &Path,
) -> Result<(), Error> {
    let mut finished = false;
    while let Some(msg) = rx.next().await {
        match msg {
            FileWriteMsg::Data { offset, bytes } => {
                file.seek(SeekFrom::Start(offset))
                    .await
                    .map_err(DownloadErrorKind::FileSystem)?;
                file.write_all(&bytes)
                    .await
                    .map_err(DownloadErrorKind::FileSystem)?;
            }
            FileWriteMsg::ChunkDone { bitmap_index } => {
                if let Some(meta) = &mut sidecar {
                    file.flush().await.map_err(DownloadErrorKind::FileSystem)?;
                    meta.mark_chunk_done(bitmap_index);
                    persist_sidecar(meta_path, meta).await?;
                }
            }
            FileWriteMsg::Finish => {
                finished = true;
                break;
            }
        }
    }
    file.flush().await.map_err(DownloadErrorKind::FileSystem)?;
    if finished {
        file.sync_data()
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
        drop(file);
        remove_if_exists(meta_path).await?;
        async_fs::rename(part_path, dest_path)
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
    }
    Ok(())
}

#[cfg(reactor)]
async fn run_file_download<C>(
    mut client: C,
    template: RequestTemplate,
    config: DownloadConfig,
    dest_path: PathBuf,
    resume_mode: ResumeMode,
    emitter: ProgressEmitter,
) -> Result<DownloadReport, Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let (part_path, meta_path) = sidecar_paths(&dest_path);
    if resume_mode == ResumeMode::Overwrite {
        remove_if_exists(&part_path).await?;
        remove_if_exists(&meta_path).await?;
    }

    let sidecar_present =
        resume_mode == ResumeMode::Sidecar && has_sidecar_files(&part_path, &meta_path).await;
    let with_range_zero = config.concurrency.get() > 1 || sidecar_present;

    match send_probe(&mut client, &template, with_range_zero, &config).await? {
        ProbeOutcome::Empty { effective_uri } => {
            finalize_small_file(
                &part_path,
                &meta_path,
                &dest_path,
                &[],
                effective_uri,
                &emitter,
            )
            .await
        }
        ProbeOutcome::FullStream {
            response,
            effective_uri,
        } => {
            remove_if_exists(&meta_path).await?;
            stream_full_to_file(
                response,
                &config,
                &part_path,
                &dest_path,
                effective_uri,
                &emitter,
            )
            .await
        }
        ProbeOutcome::Partial {
            first_byte,
            total,
            validator,
            effective_uri,
            stripped_credentials,
        } => {
            if total == 1 {
                return finalize_small_file(
                    &part_path,
                    &meta_path,
                    &dest_path,
                    &[first_byte],
                    effective_uri,
                    &emitter,
                )
                .await;
            }
            download_partial_file(
                client,
                template,
                config,
                dest_path,
                part_path,
                meta_path,
                resume_mode,
                emitter,
                first_byte,
                total,
                validator,
                effective_uri,
                stripped_credentials,
            )
            .await
        }
    }
}

#[cfg(reactor)]
async fn run_file_workers<C>(
    client: C,
    ctx: Arc<ChunkContext>,
    chunks: Vec<ChunkSpec>,
    worker_count: usize,
    mut finish_tx: mpsc::Sender<FileWriteMsg>,
) -> Result<(), Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let queue = Arc::new(Mutex::new(VecDeque::from(chunks)));
    let mut workers = FuturesUnordered::new();
    for _ in 0..worker_count {
        let mut worker_client = client.clone();
        let queue = Arc::clone(&queue);
        let ctx = Arc::clone(&ctx);
        let mut tx = finish_tx.clone();
        workers.push(async move {
            ctx.progress.worker_entered();
            let result: Result<(), Error> = async {
                loop {
                    let next = queue
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .pop_front();
                    let Some(spec) = next else {
                        break Ok(());
                    };
                    fetch_chunk_with_retries(
                        &mut worker_client,
                        &ctx,
                        spec,
                        &mut tx,
                        |offset, bytes| FileWriteMsg::Data { offset, bytes },
                    )
                    .await?;
                    tx.send(FileWriteMsg::ChunkDone {
                        bitmap_index: spec.bitmap_index,
                    })
                    .await
                    .map_err(|_| Error::Stopped)?;
                }
            }
            .await;
            ctx.progress.worker_exited();
            result
        });
    }

    let res = async {
        while workers.try_next().await?.is_some() {}
        Ok::<(), Error>(())
    }
    .await;
    if res.is_ok() {
        let _ = finish_tx.send(FileWriteMsg::Finish).await;
    }
    drop(finish_tx);
    res
}

#[cfg(reactor)]
#[allow(clippy::too_many_arguments)]
async fn download_partial_file<C>(
    client: C,
    template: RequestTemplate,
    config: DownloadConfig,
    dest_path: PathBuf,
    part_path: PathBuf,
    meta_path: PathBuf,
    resume_mode: ResumeMode,
    emitter: ProgressEmitter,
    first_byte: u8,
    total: u64,
    validator: Validator,
    effective_uri: Uri,
    stripped_credentials: bool,
) -> Result<DownloadReport, Error>
where
    C: Client + Clone + Send + 'static,
    C::Error: Into<Error>,
{
    let PreparedFile {
        mut file,
        sidecar,
        chunks,
        resumed_from,
        initial_downloaded,
    } = prepare_partial_file(
        &part_path,
        &meta_path,
        resume_mode,
        &config,
        first_byte,
        total,
        &validator,
    )
    .await?;

    if chunks.is_empty() {
        file.flush().await.map_err(DownloadErrorKind::FileSystem)?;
        file.sync_data()
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
        drop(file);
        remove_if_exists(&meta_path).await?;
        async_fs::rename(&part_path, &dest_path)
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
        let bytes_written = total.saturating_sub(resumed_from);
        emitter.emit(DownloadProgress {
            downloaded: total,
            total: Some(total),
            resumed_from,
            active_workers: 0,
        });
        return Ok(DownloadReport {
            path: dest_path,
            resumed_from,
            bytes_written,
            effective_uri,
        });
    }

    let progress = SharedProgress::new(
        emitter,
        Some(total),
        resumed_from,
        initial_downloaded,
        chunks.len(),
    );
    progress.publish();

    let worker_count = config.concurrency.get().min(chunks.len()).max(1);
    let ctx = Arc::new(ChunkContext {
        template,
        effective_uri: effective_uri.clone(),
        stripped_credentials,
        validator,
        total,
        config,
        progress: Arc::clone(&progress),
    });
    let (finish_tx, rx) = mpsc::channel::<FileWriteMsg>(worker_count * 4);

    let workers_fut = run_file_workers(client, ctx, chunks, worker_count, finish_tx);
    let writer_fut = run_file_writer(file, sidecar, rx, &part_path, &meta_path, &dest_path);
    let (worker_res, writer_res) = futures_util::future::join(workers_fut, writer_fut).await;
    worker_res?;
    writer_res?;

    let bytes_written = total.saturating_sub(resumed_from);
    progress.publish_complete(total);
    Ok(DownloadReport {
        path: dest_path,
        resumed_from,
        bytes_written,
        effective_uri,
    })
}

#[cfg(reactor)]
async fn stream_full_to_file(
    response: Response,
    config: &DownloadConfig,
    part_path: &Path,
    dest_path: &Path,
    effective_uri: Uri,
    emitter: &ProgressEmitter,
) -> Result<DownloadReport, Error> {
    let announced = parse_content_length(response.headers());
    if let Some(total) = announced {
        check_limits_upfront(config, total)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)
        .await
        .map_err(DownloadErrorKind::FileSystem)?;

    let mut downloaded = 0_u64;
    emitter.emit(DownloadProgress {
        downloaded: 0,
        total: announced,
        resumed_from: 0,
        active_workers: 1,
    });

    let mut stream = response.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(DownloadErrorKind::BodyRead)?;
        if chunk.is_empty() {
            continue;
        }
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let next =
            downloaded
                .checked_add(chunk_len)
                .ok_or_else(|| Error::ResponseBodyTooLarge {
                    limit: config.max_bytes.unwrap_or(u64::MAX),
                })?;
        if let Some(limit) = config.max_bytes
            && next > limit
        {
            drop(file);
            let _ = remove_if_exists(part_path).await;
            return Err(Error::ResponseBodyTooLarge { limit });
        }
        file.write_all(&chunk)
            .await
            .map_err(DownloadErrorKind::FileSystem)?;
        downloaded = next;
        emitter.emit(DownloadProgress {
            downloaded,
            total: announced,
            resumed_from: 0,
            active_workers: 1,
        });
    }

    if let Some(total) = announced
        && downloaded != total
    {
        drop(file);
        let _ = remove_if_exists(part_path).await;
        return Err(Error::Download(DownloadErrorKind::SizeMismatch {
            expected: total,
            actual: downloaded,
        }));
    }
    if let Some(expected) = config.expected_size
        && downloaded != expected
    {
        drop(file);
        let _ = remove_if_exists(part_path).await;
        return Err(Error::Download(DownloadErrorKind::SizeMismatch {
            expected,
            actual: downloaded,
        }));
    }

    file.flush().await.map_err(DownloadErrorKind::FileSystem)?;
    file.sync_data()
        .await
        .map_err(DownloadErrorKind::FileSystem)?;
    drop(file);
    async_fs::rename(part_path, dest_path)
        .await
        .map_err(DownloadErrorKind::FileSystem)?;

    emitter.emit(DownloadProgress {
        downloaded,
        total: Some(downloaded),
        resumed_from: 0,
        active_workers: 0,
    });

    Ok(DownloadReport {
        path: dest_path.to_path_buf(),
        resumed_from: 0,
        bytes_written: downloaded,
        effective_uri,
    })
}
