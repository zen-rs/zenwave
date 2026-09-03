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

# Clippy (treat warnings as errors, matches CI)
cargo clippy --all-targets --all-features -- -D warnings

# WASM build check
cargo build --target wasm32-unknown-unknown
```

## Project layout

```
src/
  lib.rs          — public API, re-exports, compile-time feature checks
  client.rs       — Client trait, RequestBuilder, middleware composition
  client/
    download.rs   — resumable file downloads (native only)
  backend/
    mod.rs        — DefaultBackend type alias based on features
    hyper.rs      — Hyper + async-net backend
    curl.rs       — libcurl backend
    apple.rs      — URLSession backend (Apple platforms)
    web.rs        — Fetch API backend (wasm32)
  transport/
    mod.rs        — Transport / TransportBuilder (proxy rules + trusted roots; all targets)
    proxy.rs      — Proxy / ProxyBuilder over hyper-util's matcher (env + OS settings)
    tls.rs        — TLS engine: rustls + rustls-platform-verifier, or native-tls
    stream.rs     — Stream (TCP / TLS / TLS-in-TLS) and the hyper I/O adapter
    connect.rs    — connect(transport, target): direct, HTTP proxy, CONNECT tunnel, SOCKS5
    tunnel.rs     — HTTP CONNECT through hyper's upgrade machinery
    socks5.rs     — SOCKS5 CONNECT client (RFC 1928/1929)
    happy_eyeballs.rs — RFC 8305 TCP connection racing
    android.rs    — hands the JVM from ndk-context to the platform verifier
  ext.rs          — ResponseExt trait (into_json, into_string, etc.)
  cache.rs        — HTTP caching middleware (Cache-Control, ETag)
  cookie.rs       — cookie jar middleware (in-memory and persistent)
  oauth2.rs       — OAuth2 client credentials middleware
  auth.rs         — Bearer and Basic auth middleware
  redirect.rs     — redirect-following middleware (on by default)
  retry.rs        — retry middleware
  timeout.rs      — per-request timeout middleware
  websocket.rs    — cross-platform WebSocket client
  multipart.rs    — multipart/form-data
  error.rs        — error types
```

## Architecture

Everything is middleware. `Client` is a trait extending `http_kit::Endpoint`.
Each middleware wraps the inner client and transforms requests/responses.
`zenwave::client()` returns a `DefaultClient` which is just the platform
backend over `Transport::system()` wrapped in `FollowRedirect`;
`zenwave::client_with(transport)` does the same over an explicit `Transport`. Backends are constructed from a
`Transport` (trusted roots, TLS engine); `Transport::system()` is built once
per process. `cfg` aliases (`native`, `tls_rustls`, `tls_native`,
`tls_engine`, `connector`, `android_verifier`) come from `build.rs`.

The `http-kit` crate (separate dependency) defines `Endpoint`, `Middleware`,
`Request`, `Response`, `Body`, and SSE types.

## Branching

- `main` — release branch, release-plz creates PRs into it
- `dev` — development branch, PRs go here

## Release

Automated via release-plz. Do not hand-edit version numbers or CHANGELOG.md.
Write conventional commits (`feat:`, `fix:`, `feat!:` for breaking) and
release-plz computes the bump and opens a PR to main.

## CI

Runs on every push and PR (`.github/workflows/ci.yml` + `test.yml`):
- `cargo fmt --check`
- Features: clippy over every valid feature combination (`scripts/check-features.sh`,
  cargo-hack powerset) on Linux, Windows and macOS, one slice per TLS engine
- WASM build check; mobile cross-compilation (iOS device/simulator, Android
  arm64/x86_64/armv7) with tests
- Tests: hyper (rustls and native-tls) and curl on Linux/Windows/macOS,
  apple-backend on macOS, the suite on an iOS simulator (`scripts/test-ios.sh`,
  cargo-dinghy), wasm-pack in Chrome/Firefox/Safari, workerd
- Android runs on a physical device, not in CI: `scripts/test-android.sh`
  over adb (never an emulator); TLS on Android needs the JVM and is covered by
  the instrumented app under `tests/android`
