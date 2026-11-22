# Zenwave

Async HTTP client library for Rust. Single crate, multiple backends
(Hyper, Native, libcurl, Apple URLSession, browser Fetch, WASI Preview 3, embedded `no_std + alloc`), same API surface.

## Build and test

Requires nightly Rust (edition 2024).

```sh
# Default backend (hyper + rustls)
cargo check
cargo test

# Specific backend / TLS engine
cargo test --no-default-features --features curl-backend
cargo test --no-default-features --features hyper-backend,rustls-ring,ws
cargo test --no-default-features --features hyper-backend,native-tls,ws
cargo test --no-default-features --features apple-backend  # macOS only
cargo test --no-default-features --features native-compio,native-http2,native-http3
cargo test --no-default-features --features native-tokio,native-http2,native-http3

# Embedded no_std + alloc backend (ESP32-C6 / embedded-io-async + embedded-nal-async + unbuffered rustls)
cargo clippy --lib --no-default-features --features embedded-backend -- -D warnings
cargo clippy --lib --no-default-features --features embedded-tls -- -D warnings
cargo clippy --lib --no-default-features --features embedded-tls-ecdsa -- -D warnings
cargo clippy --lib --no-default-features --features embedded-tls12 -- -D warnings
cargo nextest run --lib --no-default-features --features embedded-tls-ecdsa

# Clippy (treat warnings as errors, matches CI)
cargo clippy --all-targets --all-features -- -D warnings

# WASM build check
cargo build --target wasm32-unknown-unknown

# WASI Preview 3 (`wasi:http/client`) — no C toolchain needed.
cargo clippy --target wasm32-wasip2 --no-default-features --features wasi-backend,public-suffix --lib --test wasi_backend -- -D warnings
cargo +nightly clippy --target wasm32-wasip3 --no-default-features --features wasi-backend,public-suffix --lib --test wasi_backend -- -D warnings

# WASI (the native backend over the host's sockets, resolver and clock).
# Pure-Rust (`native-backend` without `rustls-ring`, caller installs a CryptoProvider) needs no C toolchain;
# adding `rustls-ring` builds ring's C archive and needs llvm-ar: AR_wasm32_wasip2 / RANLIB_wasm32_wasip2.
cargo clippy --target wasm32-wasip2 --no-default-features --features native-backend,native-http2 --lib --test wasi_native_backend -- -D warnings
cargo +nightly clippy --target wasm32-wasip3 --no-default-features --features native-backend,native-http2 --lib --test wasi_native_backend -- -D warnings

# WASI with HTTP/3 (`native-http3`): cross-compiles BoringSSL (`boring-sys` / `quiche`) against
# `wasi-sdk-34+` (`WASI_SDK_PATH`) through `scripts/wasi-boringssl.cmake` (single-threaded:
# `-DOPENSSL_NO_ASM -DOPENSSL_NO_SOCK -DOPENSSL_NO_POSIX_IO -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED`,
# merging `noeh/libc++.a` + `noeh/libc++abi.a` for `BORING_BSSL_RUST_CPPLIB=c++`).
WASI_BINDGEN="--sysroot=$WASI_SDK_PATH/share/wasi-sysroot -fvisibility=default -DOPENSSL_NO_ASM -DOPENSSL_NO_SOCK -DOPENSSL_NO_POSIX_IO -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED"
LIBCLANG_PATH="$WASI_SDK_PATH/lib" \
  CMAKE_GENERATOR=Ninja \
  CMAKE_TOOLCHAIN_FILE_wasm32_wasip2="$PWD/scripts/wasi-boringssl.cmake" \
  BORING_BSSL_RUST_CPPLIB_wasm32_wasip2=c++ \
  BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip2="$WASI_BINDGEN" \
  cargo clippy --target wasm32-wasip2 --no-default-features --features native-backend,native-http2,native-http3 --lib --test wasi_native_backend -- -D warnings
LIBCLANG_PATH="$WASI_SDK_PATH/lib" \
  CMAKE_GENERATOR=Ninja \
  CMAKE_TOOLCHAIN_FILE_wasm32_wasip3="$PWD/scripts/wasi-boringssl.cmake" \
  BORING_BSSL_RUST_CPPLIB_wasm32_wasip3=c++ \
  BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip3="$WASI_BINDGEN" \
  cargo +nightly clippy --target wasm32-wasip3 --no-default-features --features native-backend,native-http2,native-http3 --lib --test wasi_native_backend -- -D warnings
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
      mod.rs      — NativeBackend: h1 on http-kit-h1, h2 on http-kit-h2, h3 on http-kit-h3, over http-kit-io
      pool.rs     — the per-thread pool actor: h1 leases, shared h2, dial coalescing, waiters, dial results
      h3.rs       — the pool's h3 slot: QUIC dials raced against TCP, the transport's verifier, discovery
      connect.rs  — route execution on http-kit-io: unix sockets, happy eyeballs, CONNECT (TLS in TLS), SOCKS5, TLS
      runtime.rs  — Driver: compio and tokio driver threads for callers on no runtime
      upgrade.rs  — Upgrade/Switched: a 101's stream, claimed on the pool's thread
    curl.rs       — libcurl backend
    apple.rs      — URLSession backend (Apple platforms)
    web.rs        — Fetch API backend (wasm32)
    wasi.rs       — WASI Preview 3 (`wasi:http/client`) backend
    embedded.rs   — `no_std + alloc` HTTP/1.1 backend over `embedded-io-async` / `embedded-nal-async` + unbuffered `rustls`
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
  esp32c6-smoke/  — standalone no_std firmware for the esp-emu lane: esp-hal +
                    esp-radio + embassy-net + EmbeddedBackend, HTTP and HTTPS
                    requests against a host fixture (own workspace, not a member;
                    fixture certs are generated, never committed)
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
`connector`, `dialer`, `native_backend`, `native_driver`, `native_h2`,
`native_h3`, `https_rr`, `android_verifier`) come from `build.rs`.

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
  HTTP/2 and HTTP/3 included) on Linux/Windows/macOS; apple-backend on macOS, the suite on an iOS simulator (`scripts/test-ios.sh`,
  `simctl spawn`), wasm-pack in Chrome/Firefox/Safari, workerd,
  ESP32-C6 firmware in esp-emu (`scripts/test-esp32c6.sh`, tests/esp32c6-smoke)
- Android runs on a physical device, not in CI: `scripts/test-android.sh`
  over adb (never an emulator); TLS on Android needs the JVM and is covered by
  the instrumented app under `tests/android`
