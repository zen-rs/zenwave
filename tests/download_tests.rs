//! Integration tests for concurrent Range downloads, resume, dedicated
//! connections, and optional `progressor` integration.
#![cfg(all(not(target_arch = "wasm32"), not(target_os = "none"), feature = "std"))]

use std::{
    collections::HashMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use futures_channel::oneshot;
use http::{HeaderValue, Response, StatusCode, header};
use http_kit::{Body, Endpoint, Request};
use tempfile::tempdir;
use zenwave::{Client, DownloadErrorKind, DownloadProgress, Error, ResumeMode};

type RequestRecord = (String, Option<String>, Option<String>);
type FixedErrorResponse = (StatusCode, Vec<(&'static str, &'static str)>, &'static str);

fn make_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + 17) % 251).expect("byte fits"))
        .collect()
}

fn parse_range(request: &Request, total: usize) -> Option<(usize, usize)> {
    let spec = request
        .headers()
        .get(header::RANGE)?
        .to_str()
        .ok()?
        .strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: usize = start.trim().parse().ok()?;
    if start >= total {
        return None;
    }
    let end = if end.trim().is_empty() {
        total - 1
    } else {
        end.trim().parse::<usize>().ok()?.min(total - 1)
    };
    (start <= end).then_some((start, end))
}

#[derive(Clone)]
struct MockRangeServer {
    state: Arc<MockState>,
}

struct MockState {
    payload: Mutex<Vec<u8>>,
    etag: Mutex<Option<String>>,
    honor_range: AtomicBool,
    omit_content_length_on_200: AtomicBool,
    requests: Mutex<Vec<RequestRecord>>,
    /// Fail requests whose `Range` matches a key for the first N attempts with a transient error.
    transient_failures: Mutex<HashMap<String, usize>>,
    /// Return a fixed status + headers + body for every request if set.
    fixed_error: Mutex<Option<FixedErrorResponse>>,
    /// Fail non-probe requests with a fatal non-transient error once this many chunks succeeded.
    fail_after_chunks: Mutex<Option<usize>>,
    chunks_served: AtomicUsize,
    /// Return wrong `Content-Range` on chunk requests when set.
    corrupt_content_range: AtomicBool,
    /// Return fewer bytes than `Content-Range` promises on chunk requests when set.
    truncate_chunk_body: AtomicBool,
    /// Switch the response `ETag` on non-probe chunks (without returning 412) when set.
    mutate_etag_silently: AtomicBool,
    /// Hold chunk at `bytes=1-` until another chunk releases `barrier_tx`.
    delay_first_chunk: Mutex<Option<oneshot::Receiver<()>>>,
    release_first_chunk: Mutex<Option<oneshot::Sender<()>>>,
}

impl MockRangeServer {
    fn new(payload: Vec<u8>, etag: Option<&str>) -> Self {
        Self {
            state: Arc::new(MockState {
                payload: Mutex::new(payload),
                etag: Mutex::new(etag.map(ToOwned::to_owned)),
                honor_range: AtomicBool::new(true),
                omit_content_length_on_200: AtomicBool::new(false),
                requests: Mutex::new(Vec::new()),
                transient_failures: Mutex::new(HashMap::new()),
                fixed_error: Mutex::new(None),
                fail_after_chunks: Mutex::new(None),
                chunks_served: AtomicUsize::new(0),
                corrupt_content_range: AtomicBool::new(false),
                truncate_chunk_body: AtomicBool::new(false),
                mutate_etag_silently: AtomicBool::new(false),
                delay_first_chunk: Mutex::new(None),
                release_first_chunk: Mutex::new(None),
            }),
        }
    }

    fn request_log(&self) -> Vec<RequestRecord> {
        self.state.requests.lock().unwrap().clone()
    }
}

impl Endpoint for MockRangeServer {
    type Error = Error;

    #[allow(clippy::too_many_lines)]
    async fn respond(&mut self, request: &mut Request) -> Result<Response<Body>, Self::Error> {
        let uri = request.uri().to_string();
        let range_hdr = request
            .headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let auth_hdr = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let if_match = request
            .headers()
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        self.state
            .requests
            .lock()
            .unwrap()
            .push((uri.clone(), range_hdr.clone(), auth_hdr));

        // Cross-origin redirector endpoint.
        if request.uri().host() == Some("api.origin.test") {
            let resp = Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    header::LOCATION,
                    "http://cdn.other.test/blobs/artifact.bin?sig=signed123",
                )
                .body(Body::empty())
                .unwrap();
            return Ok(resp);
        }

        let fixed = self.state.fixed_error.lock().unwrap().clone();
        if let Some((status, headers, body)) = fixed {
            let mut builder = Response::builder().status(status);
            for (k, v) in headers {
                builder = builder.header(k, v);
            }
            return Ok(builder.body(Body::from(body)).unwrap());
        }

        if let Some(range_key) = &range_hdr {
            let fail = {
                let mut map = self.state.transient_failures.lock().unwrap();
                if let Some(remaining) = map.get_mut(range_key)
                    && *remaining > 0
                {
                    *remaining -= 1;
                    true
                } else {
                    false
                }
            };
            if fail {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "simulated transient chunk drop",
                )));
            }
        }

        // Simulate concurrent out-of-order delivery: chunk 0 waits until chunk 1 arrives.
        if let Some(range_key) = &range_hdr {
            if range_key.starts_with("bytes=1-") {
                let rx = self.state.delay_first_chunk.lock().unwrap().take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
            } else if range_key != "bytes=0-0" {
                let tx = self.state.release_first_chunk.lock().unwrap().take();
                if let Some(tx) = tx {
                    let _ = tx.send(());
                }
            }
        }

        let payload = self.state.payload.lock().unwrap().clone();
        let current_etag = self.state.etag.lock().unwrap().clone();

        if let (Some(req_etag), Some(cur)) = (&if_match, &current_etag)
            && req_etag != cur
        {
            return Ok(Response::builder()
                .status(StatusCode::PRECONDITION_FAILED)
                .body(Body::empty())
                .unwrap());
        }

        if range_hdr.as_deref() != Some("bytes=0-0") && range_hdr.is_some() {
            let limit = *self.state.fail_after_chunks.lock().unwrap();
            if let Some(limit) = limit {
                let served = self.state.chunks_served.fetch_add(1, Ordering::SeqCst);
                if served >= limit {
                    return Err(Error::InvalidRequest(String::from("simulated crash")));
                }
            }
        }

        if !self.state.honor_range.load(Ordering::SeqCst) || range_hdr.is_none() {
            let mut builder = Response::builder().status(StatusCode::OK);
            if !self.state.omit_content_length_on_200.load(Ordering::SeqCst) {
                builder = builder.header(header::CONTENT_LENGTH, payload.len().to_string());
            }
            if let Some(etag) = current_etag {
                builder = builder.header(header::ETAG, etag);
            }
            let body = if payload.is_empty() {
                Body::empty()
            } else {
                // Stream in multiple frames so mid-stream aborts and progress are exercised.
                let chunks: Vec<Result<http_kit::utils::Bytes, std::io::Error>> = payload
                    .chunks(256)
                    .map(|c| Ok(http_kit::utils::Bytes::copy_from_slice(c)))
                    .collect();
                Body::from_stream(futures_util::stream::iter(chunks))
            };
            return Ok(builder.body(body).unwrap());
        }

        if payload.is_empty() {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, "bytes */0")
                .body(Body::empty())
                .unwrap());
        }

        let Some((start, end)) = parse_range(request, payload.len()) else {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{}", payload.len()))
                .body(Body::empty())
                .unwrap());
        };

        let is_probe = start == 0 && end == 0;
        let mut slice = payload[start..=end].to_vec();
        if !is_probe && self.state.truncate_chunk_body.load(Ordering::SeqCst) && slice.len() > 1 {
            slice.pop();
        }
        let content_range = if !is_probe && self.state.corrupt_content_range.load(Ordering::SeqCst)
        {
            format!("bytes {start}-{}/{}", end.saturating_sub(1), payload.len())
        } else {
            format!("bytes {start}-{end}/{}", payload.len())
        };

        let mut builder = Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_RANGE, content_range);
        if let Some(etag) = current_etag {
            let value = if !is_probe && self.state.mutate_etag_silently.load(Ordering::SeqCst) {
                String::from("\"mutated\"")
            } else {
                etag
            };
            builder = builder.header(header::ETAG, HeaderValue::from_str(&value).unwrap());
        }
        Ok(builder.body(Body::from(slice)).unwrap())
    }
}

http_kit::impl_send_endpoint!(MockRangeServer);
impl Client for MockRangeServer {}

#[test]
fn cross_origin_redirect_strips_auth_and_hits_redirector_once() {
    let payload = make_payload(8192);
    let server = MockRangeServer::new(payload.clone(), Some("\"v1\""));
    let mut client = server.clone().follow_redirect().bearer_auth("top-secret");

    let bytes = async_io::block_on(async {
        client
            .get("http://api.origin.test/releases/latest")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2048).unwrap())
            .bytes()
            .await
            .unwrap()
    });

    assert_eq!(bytes.as_ref(), payload.as_slice());

    let log = server.request_log();
    let api_hits: Vec<_> = log
        .iter()
        .filter(|(uri, _, _)| uri.contains("api.origin.test"))
        .collect();
    let cdn_hits: Vec<_> = log
        .iter()
        .filter(|(uri, _, _)| uri.contains("cdn.other.test"))
        .collect();

    assert_eq!(api_hits.len(), 1, "redirector must be hit only once");
    assert_eq!(api_hits[0].2.as_deref(), Some("Bearer top-secret"));
    assert!(
        cdn_hits.len() >= 4,
        "chunks must go straight to pinned CDN URI"
    );
    for (_, _, auth) in cdn_hits {
        assert!(
            auth.is_none(),
            "Authorization must never be sent to cross-origin CDN"
        );
    }
}

#[test]
fn concurrent_out_of_order_206_assembly_bytes_and_file() {
    let payload = make_payload(10_000);
    let server = MockRangeServer::new(payload.clone(), Some("\"etag-concurrent\""));
    let (tx, rx) = oneshot::channel();
    *server.state.delay_first_chunk.lock().unwrap() = Some(rx);
    *server.state.release_first_chunk.lock().unwrap() = Some(tx);

    let mut client = server.clone();
    let mut progress_seen: Vec<DownloadProgress> = Vec::new();
    let bytes = async_io::block_on(async {
        client
            .get("http://cdn.example.test/data.bin")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(1024).unwrap())
            .chunk_size(NonZeroU64::new(2500).unwrap())
            .on_progress(|p| progress_seen.push(p))
            .bytes()
            .await
            .unwrap()
    });
    assert_eq!(bytes.as_ref(), payload.as_slice());
    assert!(
        server.state.delay_first_chunk.lock().unwrap().is_none()
            && server.state.release_first_chunk.lock().unwrap().is_none(),
        "chunk 0 waited for chunk 1, proving concurrent execution"
    );
    assert!(
        progress_seen
            .windows(2)
            .all(|w| w[0].downloaded <= w[1].downloaded),
        "progress must be monotonic"
    );
    let last = progress_seen.last().copied().unwrap();
    assert_eq!(last.downloaded, payload.len() as u64);
    assert_eq!(last.total, Some(payload.len() as u64));
    assert_eq!(last.active_workers, 0);

    // Same concurrent barrier test for file downloads.
    let dir = tempdir().unwrap();
    let dest = dir.path().join("concurrent.bin");
    let (tx2, rx2) = oneshot::channel();
    *server.state.delay_first_chunk.lock().unwrap() = Some(rx2);
    *server.state.release_first_chunk.lock().unwrap() = Some(tx2);

    let report = async_io::block_on(async {
        client
            .get("http://cdn.example.test/data.bin")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(1024).unwrap())
            .chunk_size(NonZeroU64::new(2500).unwrap())
            .to_path(&dest)
            .await
            .unwrap()
    });
    assert_eq!(report.total_bytes(), payload.len() as u64);
    assert_eq!(std::fs::read(&dest).unwrap(), payload);
    assert!(!dir.path().join("concurrent.bin.part").exists());
    assert!(!dir.path().join("concurrent.bin.part.json").exists());
}

#[test]
fn ok_200_fallback_issues_single_request_only() {
    let payload = make_payload(4096);
    let server = MockRangeServer::new(payload.clone(), None);
    server.state.honor_range.store(false, Ordering::SeqCst);

    let mut client = server.clone();
    let bytes = async_io::block_on(async {
        client
            .get("http://cdn.example.test/no-range.bin")
            .unwrap()
            .download_bytes()
            .await
            .unwrap()
    });
    assert_eq!(bytes.as_ref(), payload.as_slice());
    assert_eq!(
        server.request_log().len(),
        1,
        "200 OK fallback must stream probe response directly without a second request"
    );
}

#[test]
fn zero_byte_resources_via_416_and_200() {
    let server_416 = MockRangeServer::new(Vec::new(), Some("\"empty\""));
    let mut client = server_416;
    let dir = tempdir().unwrap();
    let empty_416_path = dir.path().join("empty_416.bin");

    async_io::block_on(async {
        let bytes = client
            .get("http://cdn.example.test/empty")
            .unwrap()
            .download_bytes()
            .await
            .unwrap();
        assert!(bytes.is_empty());

        let report = client
            .get("http://cdn.example.test/empty")
            .unwrap()
            .download_to_path(&empty_416_path)
            .await
            .unwrap();
        assert_eq!(report.total_bytes(), 0);
        assert_eq!(std::fs::read(&empty_416_path).unwrap(), Vec::<u8>::new());
    });

    let server_200 = MockRangeServer::new(Vec::new(), None);
    server_200.state.honor_range.store(false, Ordering::SeqCst);
    let mut client = server_200;
    let empty_200_path = dir.path().join("empty_200.bin");

    async_io::block_on(async {
        let bytes = client
            .get("http://cdn.example.test/empty")
            .unwrap()
            .download_bytes()
            .await
            .unwrap();
        assert!(bytes.is_empty());

        let report = client
            .get("http://cdn.example.test/empty")
            .unwrap()
            .download_to_path(&empty_200_path)
            .await
            .unwrap();
        assert_eq!(report.total_bytes(), 0);
        assert_eq!(std::fs::read(&empty_200_path).unwrap(), Vec::<u8>::new());
    });
}

#[derive(Clone)]
struct FlipOnSecondRequest {
    calls: Arc<AtomicUsize>,
    inner: MockRangeServer,
}

impl Endpoint for FlipOnSecondRequest {
    type Error = Error;
    async fn respond(&mut self, req: &mut Request) -> Result<Response<Body>, Self::Error> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 1 {
            *self.inner.state.etag.lock().unwrap() = Some(String::from("\"v2\""));
        }
        self.inner.respond(req).await
    }
}

http_kit::impl_send_endpoint!(FlipOnSecondRequest);
impl Client for FlipOnSecondRequest {}

#[test]
fn resource_changed_on_412_and_silent_etag_change() {
    let payload = make_payload(6000);
    let server = MockRangeServer::new(payload, Some("\"v1\""));
    server
        .state
        .mutate_etag_silently
        .store(true, Ordering::SeqCst);

    let mut client = server;
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2000).unwrap())
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(
        matches!(err, Error::Download(DownloadErrorKind::ResourceChanged)),
        "expected ResourceChanged, got {err:?}"
    );

    // Explicitly trigger 412 Precondition Failed by mutating ETag mid-download via If-Match mismatch.
    let mut flipping = FlipOnSecondRequest {
        calls: Arc::new(AtomicUsize::new(0)),
        inner: MockRangeServer::new(make_payload(6000), Some("\"v1\"")),
    };
    let err = async_io::block_on(async {
        flipping
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2000).unwrap())
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(
        matches!(err, Error::Download(DownloadErrorKind::ResourceChanged)),
        "412 must map to ResourceChanged, got {err:?}"
    );
}

#[test]
fn http_404_and_429_preserve_status_retry_after_and_body() {
    let server = MockRangeServer::new(make_payload(100), None);
    *server.state.fixed_error.lock().unwrap() = Some((
        StatusCode::TOO_MANY_REQUESTS,
        vec![("retry-after", "120")],
        "rate limited",
    ));
    let mut client = server.clone();
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download_bytes()
            .await
            .unwrap_err()
    });
    match &err {
        Error::Http {
            status,
            message,
            response,
        } => {
            assert_eq!(*status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(message, "rate limited");
            assert_eq!(
                response.response.headers().get(header::RETRY_AFTER),
                Some(&HeaderValue::from_static("120"))
            );
        }
        other => panic!("expected Error::Http, got {other:?}"),
    }

    *server.state.fixed_error.lock().unwrap() =
        Some((StatusCode::NOT_FOUND, vec![], "missing artifact"));
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/missing")
            .unwrap()
            .download_bytes()
            .await
            .unwrap_err()
    });
    assert!(matches!(
        err,
        Error::Http {
            status: StatusCode::NOT_FOUND,
            ..
        }
    ));
    assert_eq!(err.response_body(), Some("missing artifact"));
}

#[test]
fn max_bytes_expected_size_and_invalid_content_range() {
    let payload = make_payload(4096);

    // Upfront max_bytes check on 206.
    let mut client = MockRangeServer::new(payload.clone(), Some("\"v1\""));
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .max_bytes(1024)
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(matches!(err, Error::ResponseBodyTooLarge { limit: 1024 }));

    // Mid-stream max_bytes abort on 200 without Content-Length.
    let server_stream = MockRangeServer::new(payload.clone(), None);
    server_stream
        .state
        .honor_range
        .store(false, Ordering::SeqCst);
    server_stream
        .state
        .omit_content_length_on_200
        .store(true, Ordering::SeqCst);
    let mut client = server_stream;
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/stream.bin")
            .unwrap()
            .download()
            .max_bytes(500)
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(matches!(err, Error::ResponseBodyTooLarge { limit: 500 }));

    // expected_size mismatch.
    let mut client = MockRangeServer::new(payload.clone(), Some("\"v1\""));
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .expected_size(9999)
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(matches!(
        err,
        Error::Download(DownloadErrorKind::SizeMismatch {
            expected: 9999,
            actual: 4096
        })
    ));

    // Corrupt Content-Range header.
    let server_bad_cr = MockRangeServer::new(payload.clone(), Some("\"v1\""));
    server_bad_cr
        .state
        .corrupt_content_range
        .store(true, Ordering::SeqCst);
    let mut client = server_bad_cr;
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(1024).unwrap())
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(matches!(
        err,
        Error::Download(DownloadErrorKind::InvalidContentRange { .. })
    ));

    // Truncated chunk body byte count mismatch.
    let server_short = MockRangeServer::new(payload, Some("\"v1\""));
    server_short
        .state
        .truncate_chunk_body
        .store(true, Ordering::SeqCst);
    let mut client = server_short;
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(1024).unwrap())
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(matches!(
        err,
        Error::Download(DownloadErrorKind::InvalidContentRange { .. })
    ));
}

#[test]
fn per_chunk_transient_failure_recovers_within_part_retries() {
    let payload = make_payload(8192);
    let server = MockRangeServer::new(payload.clone(), Some("\"v1\""));
    server
        .state
        .transient_failures
        .lock()
        .unwrap()
        .insert(String::from("bytes=2048-4095"), 2);

    let mut client = server.clone();
    let bytes = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2048).unwrap())
            .part_retries(2)
            .bytes()
            .await
            .unwrap()
    });
    assert_eq!(bytes.as_ref(), payload.as_slice());

    let retries_for_chunk = server
        .request_log()
        .iter()
        .filter(|(_, r, _)| r.as_deref() == Some("bytes=2048-4095"))
        .count();
    assert_eq!(retries_for_chunk, 3, "2 transient failures + 1 success");

    // Exhausting retries fails with the transient error.
    let server_fail = MockRangeServer::new(payload, Some("\"v1\""));
    server_fail
        .state
        .transient_failures
        .lock()
        .unwrap()
        .insert(String::from("bytes=2048-4095"), 3);
    let mut client = server_fail;
    let err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/file.bin")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2048).unwrap())
            .part_retries(1)
            .bytes()
            .await
            .unwrap_err()
    });
    assert!(err.is_transient(), "expected transient error, got {err:?}");
}

#[test]
fn sidecar_resumes_completed_chunks_and_restarts_on_etag_change() {
    let payload_v1 = make_payload(8192);
    let dir = tempdir().unwrap();
    let dest = dir.path().join("release.tar");
    let part = dir.path().join("release.tar.part");
    let meta = dir.path().join("release.tar.part.json");

    // First run fails after 2 chunks complete (concurrency 2 -> chunks 0 and 1 complete).
    let server = MockRangeServer::new(payload_v1.clone(), Some("\"v1\""));
    *server.state.fail_after_chunks.lock().unwrap() = Some(2);
    let mut client = server.clone();

    let first_err = async_io::block_on(async {
        client
            .get("http://cdn.example.test/release.tar")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(2).unwrap())
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2048).unwrap())
            .to_path(&dest)
            .resume_mode(ResumeMode::Sidecar)
            .await
            .unwrap_err()
    });
    assert!(matches!(first_err, Error::InvalidRequest(_)));
    assert!(
        !dest.exists(),
        "destination must not exist before completion"
    );
    assert!(part.exists(), ".part file must remain on failure");
    assert!(meta.exists(), ".part.json sidecar must remain on failure");

    // Second run with matching ETag resumes and skips already-completed chunks.
    *server.state.fail_after_chunks.lock().unwrap() = None;
    server.state.requests.lock().unwrap().clear();

    let report = async_io::block_on(async {
        client
            .get("http://cdn.example.test/release.tar")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2048).unwrap())
            .to_path(&dest)
            .resume_mode(ResumeMode::Sidecar)
            .await
            .unwrap()
    });
    assert!(
        report.resumed_from >= 2048,
        "expected resumed_from >= 2048, got {}",
        report.resumed_from
    );
    assert_eq!(report.total_bytes(), payload_v1.len() as u64);
    assert_eq!(std::fs::read(&dest).unwrap(), payload_v1);
    assert!(!part.exists());
    assert!(!meta.exists());

    // Now test ETag invalidation: fail after 2 chunks on v1, change server to v2, resume restarts fresh.
    let dest2 = dir.path().join("invalidated.tar");
    let server2 = MockRangeServer::new(payload_v1, Some("\"v1\""));
    *server2.state.fail_after_chunks.lock().unwrap() = Some(2);
    let mut client2 = server2.clone();

    let _ = async_io::block_on(async {
        client2
            .get("http://cdn.example.test/invalidated.tar")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(2).unwrap())
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2048).unwrap())
            .to_path(&dest2)
            .resume_mode(ResumeMode::Sidecar)
            .await
            .unwrap_err()
    });

    // Server rotates to v2 with new bytes.
    let payload_v2: Vec<u8> = (0..8192)
        .map(|i| u8::try_from((i * 13 + 7) % 251).unwrap())
        .collect();
    *server2.state.payload.lock().unwrap() = payload_v2.clone();
    *server2.state.etag.lock().unwrap() = Some(String::from("\"v2\""));
    *server2.state.fail_after_chunks.lock().unwrap() = None;

    let report2 = async_io::block_on(async {
        client2
            .get("http://cdn.example.test/invalidated.tar")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(512).unwrap())
            .chunk_size(NonZeroU64::new(2048).unwrap())
            .to_path(&dest2)
            .resume_mode(ResumeMode::Sidecar)
            .await
            .unwrap()
    });
    assert_eq!(
        report2.resumed_from, 0,
        "ETag change must invalidate sidecar"
    );
    assert_eq!(report2.bytes_written, payload_v2.len() as u64);
    assert_eq!(std::fs::read(&dest2).unwrap(), payload_v2);
}

#[cfg(feature = "progressor")]
#[test]
fn progressor_observe_delivers_monotonic_and_final_snapshots() {
    use progressor::ProgressExt as _;

    let payload = make_payload(12_000);
    let server = MockRangeServer::new(payload.clone(), Some("\"prog\""));
    let mut client = server;

    let mut seen: Vec<DownloadProgress> = Vec::new();
    let bytes = async_io::block_on(async {
        client
            .get("http://cdn.example.test/prog.bin")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(1024).unwrap())
            .chunk_size(NonZeroU64::new(3000).unwrap())
            .bytes()
            .observe(|snap| seen.push(snap))
            .await
            .unwrap()
    });

    assert_eq!(bytes.as_ref(), payload.as_slice());
    assert!(!seen.is_empty(), "observe must deliver progress snapshots");
    assert!(
        seen.windows(2).all(|w| w[0].downloaded <= w[1].downloaded),
        "progress snapshots must be monotonic: {seen:?}"
    );
    let last = seen.last().copied().unwrap();
    assert_eq!(last.downloaded, payload.len() as u64);
    assert_eq!(last.total, Some(payload.len() as u64));
    assert_eq!(last.active_workers, 0);

    // Also verify FileDownload implements Progress.
    let dir = tempdir().unwrap();
    let dest = dir.path().join("prog.bin");
    let mut file_seen: Vec<DownloadProgress> = Vec::new();
    let report = async_io::block_on(async {
        client
            .get("http://cdn.example.test/prog.bin")
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(1024).unwrap())
            .chunk_size(NonZeroU64::new(3000).unwrap())
            .to_path(&dest)
            .observe(|snap| file_seen.push(snap))
            .await
            .unwrap()
    });
    assert_eq!(report.total_bytes(), payload.len() as u64);
    let file_last = file_seen.last().copied().unwrap();
    assert_eq!(file_last.downloaded, payload.len() as u64);
    assert_eq!(file_last.total, Some(payload.len() as u64));
    assert_eq!(file_last.active_workers, 0);
}

#[cfg(all(feature = "hyper-backend", feature = "rustls-ring", feature = "http2"))]
#[allow(clippy::too_many_lines)]
#[test]
fn dedicated_connection_mode_opens_multiple_tcp_connections_against_h2_server() {
    use std::thread;
    use std::time::Duration;

    use async_net::TcpListener;
    use http_body_util::Full;
    use hyper::{body::Incoming, service::service_fn};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use rustls::{
        ServerConfig,
        crypto::ring,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use time::{Duration as TimeDelta, OffsetDateTime};
    use zenwave::{ConnectionMode, Proxy, Transport, client_with};
    use zenwave_test_fixture::TlsAcceptor;

    // Minimal hyper::rt adapters for the local test server.
    #[derive(Clone, Copy)]
    struct TestExec;
    impl<F: std::future::Future + Send + 'static> hyper::rt::Executor<F> for TestExec {
        fn execute(&self, fut: F) {
            thread::spawn(move || {
                let _ = async_io::block_on(fut);
            });
        }
    }

    struct Io<T>(T);
    impl<T: futures_util::AsyncRead + Unpin> hyper::rt::Read for Io<T> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            mut buf: hyper::rt::ReadBufCursor<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            // SAFETY: initializing temporary slice then advancing filled bytes.
            let slice = unsafe { buf.as_mut() };
            let mut tmp = vec![0_u8; slice.len()];
            match std::pin::Pin::new(&mut self.0).poll_read(cx, &mut tmp) {
                std::task::Poll::Ready(Ok(n)) => {
                    for (dst, src) in slice[..n].iter_mut().zip(&tmp[..n]) {
                        dst.write(*src);
                    }
                    unsafe { buf.advance(n) };
                    std::task::Poll::Ready(Ok(()))
                }
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }
    impl<T: futures_util::AsyncWrite + Unpin> hyper::rt::Write for Io<T> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_close(cx)
        }
    }

    // Generate throwaway CA + localhost leaf.
    let now = OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "zenwave dedicated test CA");
    ca_params.not_before = now - TimeDelta::days(1);
    ca_params.not_after = now + TimeDelta::days(365);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = now - TimeDelta::days(1);
    leaf_params.not_after = now + TimeDelta::days(365);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let mut tls_cfg = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    let payload = Arc::new(make_payload(16_384));
    let accepts = Arc::new(AtomicUsize::new(0));
    let (listener, addr) = async_io::block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    });

    let server_payload = Arc::clone(&payload);
    let server_accepts = Arc::clone(&accepts);
    thread::spawn(move || {
        async_io::block_on(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                server_accepts.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let payload = Arc::clone(&server_payload);
                thread::spawn(move || {
                    async_io::block_on(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                        let svc = service_fn(move |req: http::Request<Incoming>| {
                            let payload = Arc::clone(&payload);
                            async move {
                                let range = req
                                    .headers()
                                    .get(header::RANGE)
                                    .and_then(|v| v.to_str().ok())
                                    .and_then(|s| s.strip_prefix("bytes="))
                                    .and_then(|s| s.split_once('-'))
                                    .and_then(|(a, b)| {
                                        Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                                    });
                                let (start, end) = range.unwrap_or((0, payload.len() - 1));
                                // Small delay on chunks so concurrent workers hold connections simultaneously.
                                if !(start == 0 && end == 0) {
                                    async_io::Timer::after(Duration::from_millis(25)).await;
                                }
                                let body =
                                    hyper::body::Bytes::copy_from_slice(&payload[start..=end]);
                                let resp = Response::builder()
                                    .status(StatusCode::PARTIAL_CONTENT)
                                    .header(header::ETAG, "\"tls-h2\"")
                                    .header(
                                        header::CONTENT_RANGE,
                                        format!("bytes {start}-{end}/{}", payload.len()),
                                    )
                                    .body(Full::new(body))
                                    .unwrap();
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        if is_h2 {
                            let _ = hyper::server::conn::http2::Builder::new(TestExec)
                                .serve_connection(Io(tls), svc)
                                .await;
                        } else {
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(Io(tls), svc)
                                .await;
                        }
                    });
                });
            }
        });
    });

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificate_der(ca_cert.der().to_vec())
        .build()
        .unwrap();
    let mut client = client_with(transport);

    let url = format!("https://localhost:{}/blob.bin", addr.port());
    let bytes = async_io::block_on(async {
        client
            .get(&url)
            .unwrap()
            .download()
            .concurrency(NonZeroUsize::new(4).unwrap())
            .min_split_size(NonZeroU64::new(1024).unwrap())
            .chunk_size(NonZeroU64::new(4096).unwrap())
            .connection_mode(ConnectionMode::Dedicated)
            .bytes()
            .await
            .unwrap()
    });

    assert_eq!(bytes.as_ref(), payload.as_slice());
    let accepted = accepts.load(Ordering::SeqCst);
    assert!(
        accepted > 1,
        "ConnectionMode::Dedicated must open multiple TCP connections (accepted={accepted})"
    );
}
