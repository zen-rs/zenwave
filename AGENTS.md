# Zenwave

Async HTTP client library for Rust. Single crate, multiple backends
(Hyper, libcurl, Apple URLSession, browser Fetch), same API surface.

## Build and test

Requires nightly Rust (edition 2024).

```sh
# Default backend (hyper + rustls)
cargo check
cargo test

# Specific backend / TLS engine
cargo test --no-default-features --features curl-backend
cargo test --no-default-features --features hyper-backend,rustls,ws
cargo test --no-default-features --features hyper-backend,native-tls,ws
cargo test --no-default-features --features apple-backend  # macOS only
cargo test --no-default-features --features native-compio,native-http3
cargo test --no-default-features --features native-tokio,native-http3

# Clippy (treat warnings as errors, matches CI)
cargo clippy --all-targets --all-features -- -D warnings

# WASM build check
cargo build --target wasm32-unknown-unknown
```

## Project layout

```
src/
  lib.rs          — public API, re-exports, compile-time feature checks
  default_client.rs — DefaultClient, client(), get/post/put/delete: absent
                    without a DefaultBackend (`native-backend` with no driver)
  client.rs       — Client trait, RequestBuilder, middleware composition
  client/
    download.rs   — resumable file downloads (native only)
  backend/
    mod.rs        — DefaultBackend type alias based on features
    shared.rs     — request shaping and status mapping the hyper and native backends share
    hyper/
      mod.rs      — Hyper + async-net backend; ALPN picks h1 or h2 per connection
      rt.rs       — hyper::rt::Executor/Timer over the backend spawner + async-io
      h3.rs       — HTTP/3 connection over QUIC (h3 + h3-quinn; http3 feature)
      test_support.rs — shared test fixtures: throwaway CA, TLS and h3 servers
    native/
      mod.rs      — NativeBackend: h1 on http-kit-h1, h3 on http-kit-h3, over http-kit-io
      pool.rs     — the per-thread pool actor: h1 leases, waiters, dial results
      h3.rs       — the pool's h3 slot: QUIC dials raced against TCP, the transport's verifier, discovery
      connect.rs  — route execution on http-kit-io: unix sockets, happy eyeballs, CONNECT (TLS in TLS), SOCKS5, TLS
      runtime.rs  — Driver: compio and tokio driver threads for callers on no runtime
      upgrade.rs  — Upgrade/Switched: a 101's stream, claimed on the pool's thread
    curl.rs       — libcurl backend
    apple.rs      — URLSession backend (Apple platforms)
    web.rs        — Fetch API backend (wasm32)
  transport/
    mod.rs        — Transport / TransportBuilder (proxy rules + trusted roots; all targets)
    proxy.rs      — Proxy / ProxyBuilder over hyper-util's matcher (env + OS settings)
    tls.rs        — TLS engine: rustls + rustls-platform-verifier, or native-tls (one config per ALPN offer)
    native_tls_stream.rs — in-tree futures-io adapter for native-tls (ALPN access)
    stream.rs     — Stream (TCP / TLS / TLS-in-TLS)
    hyper_io.rs   — futures-io → hyper::rt adapter (also included by the hyper test server)
    route.rs      — route(proxy, target): which hops a connection takes, for every connector
    connect.rs    — async-net connector executing a route: direct, HTTP proxy, CONNECT tunnel, SOCKS5
    tunnel.rs     — HTTP CONNECT through hyper's upgrade machinery
    socks5.rs     — SOCKS5 CONNECT client (RFC 1928/1929), generic over the byte stream
    happy_eyeballs.rs — RFC 8305 TCP connection racing, generic over a Dialer
    discovery.rs  — per-origin h3 knowledge: Alt-Svc, HTTPS records, QUIC backoff
    alt_svc.rs    — RFC 7838 Alt-Svc parsing and the per-origin h3 advertisement
    pool.rs       — per-origin connection pool for the hyper backend (h1 leases, shared h2, dial coalescing)
    dns.rs        — HTTPS/SVCB record lookup for HTTP/3 discovery (RFC 9460)
    dns/runtime.rs — hickory RuntimeProvider on async-io/async-net
    dns/android.rs — android.net.DnsResolver.rawQuery over JNI
    quic.rs       — quinn::Runtime on async-io, shared QUIC endpoint (http3 feature)
    android.rs    — hands the JVM from ndk-context to the platform verifier
  ext.rs          — ResponseExt trait (into_json, into_string, etc.)
  cache.rs        — HTTP caching middleware (Cache-Control, ETag)
  cookie.rs       — cookie jar middleware (in-memory and persistent)
  oauth2.rs       — OAuth2 client credentials middleware
  auth.rs         — Bearer and Basic auth middleware
  redirect.rs     — redirect-following middleware (on by default)
  retry.rs        — retry middleware
  timeout.rs      — per-request timeout middleware
  status.rs       — ErrorForStatus: the opt-in layer turning 4xx/5xx into
                    Error::Http (backends return every status as Ok)
  websocket.rs    — cross-platform WebSocket client
  multipart.rs    — multipart/form-data
  error.rs        — error types
tests/
  common/
    fixture.rs    — local httpbin fixture: hyper server, thread-per-connection,
                    CORS on every response; shared by the native suites and the
                    standalone binary (kept free of `crate::` paths)
  fixture-server/ — zenwave-test-fixture: standalone binary serving the fixture
                    for the wasm and workerd lanes (own workspace, not a member)
```

## Architecture

Everything is middleware. `Client` is a trait extending `http_kit::SendEndpoint`,
and the middleware it composes are `http_kit::SendMiddleware`, so a request's
future is `Send` on every backend. A concrete type gets those impls from
`http_kit::impl_send_endpoint!` / `impl_send_middleware!`; a type generic over
its inner client calls `respond_send` on it.
Each middleware wraps the inner client and transforms requests/responses.
`zenwave::client()` returns a `DefaultClient` which is just the platform
backend over `Transport::system()` wrapped in `FollowRedirect`;
`zenwave::client_with(transport)` does the same over an explicit `Transport`. Backends are constructed from a
`Transport` (trusted roots, TLS engine); `Transport::system()` is built once
per process. The hyper backend's connections are pooled per origin on the
`Transport` (`transport/pool.rs`), so clients sharing one transport reuse
them. The native backend's pool is an actor owned by one thread
(`backend/native/pool.rs`): a `NativeBackend` holds only a channel to it, so a
thread-per-core caller builds one per thread and nothing crosses a lock.
`cfg` aliases (`native`, `tls_rustls`, `tls_native`, `tls_engine`,
`connector`, `dialer`, `native_backend`, `native_driver`, `native_h3`,
`https_rr`, `android_verifier`) come from `build.rs`.

The `http-kit` crate (separate dependency) defines `Endpoint`, `Middleware`,
`Request`, `Response`, `Body`, and SSE types.

## Branching

`main` is the only long-lived branch: topic branches start from it and merge
into it, and merging release-plz's release PR into it is the release.

## Release

Automated via release-plz. Do not hand-edit version numbers or CHANGELOG.md.
Write conventional commits (`feat:`, `fix:`, `feat!:` for breaking) and
release-plz computes the bump and opens a PR to main.

## CI

Runs on every PR and manual dispatch (`.github/workflows/ci.yml` +
`test.yml`), never on push. Every run is the full set below, except a
release-plz bump branch, which runs nothing; GitHub holds the runs of a
pull request the Actions bot opened until approved, so release.yml and
onecrl-pin.yml approve them (`.github/scripts/approve-held-runs.sh`). `CI result`
aggregates all jobs and is the required check on `main`.
- `cargo fmt --check`
- Features: clippy over every valid feature combination (`scripts/check-features.sh`,
  cargo-hack powerset) on Linux, Windows and macOS, one slice per TLS engine
  plus one for the native backend
- WASM build + clippy; mobile cross-compilation (iOS device/simulator,
  Android arm64/x86_64/armv7) with tests
- Tests: hyper (rustls and native-tls), curl, and native (compio and tokio,
  HTTP/3 included) on Linux/Windows/macOS; apple-backend on macOS, the suite on an iOS simulator (`scripts/test-ios.sh`,
  `simctl spawn`), wasm-pack in Chrome/Firefox/Safari, workerd
- Android runs on a physical device, not in CI: `scripts/test-android.sh`
  over adb (never an emulator); TLS on Android needs the JVM and is covered by
  the instrumented app under `tests/android`
