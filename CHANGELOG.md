# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1](https://github.com/zen-rs/zenwave/compare/v0.7.0...v0.7.1) - 2026-09-23

### Fixed

- *(retry)* replay a copy of the request on every attempt ([#90](https://github.com/zen-rs/zenwave/pull/90))

## [0.7.0](https://github.com/zen-rs/zenwave/compare/v0.6.1...v0.7.0) - 2026-09-21

### Added

- add HTTP/3 discovery and connection racing
- pool hyper connections per origin in the transport
- *(hyper)* negotiate ALPN and speak HTTP/2 over TLS

### Fixed

- tell cargo-machete the fixture binary's dependencies are used
- address review findings on h3 discovery
- refuse non-HTTP schemes when building a request
- *(pool)* lossless lease release, fresh-dial retries, origin sweeping
- *(rustls)* allow unnecessary_wraps on negotiated_alpn
- *(native-tls)* propagate negotiated_alpn errors
- *(transport)* gate Protocol::Http2 behind the http2 feature
- *(transport)* allow Http2OrHttp1 unused without hyper-backend

### Other

- publish from the push event, waiting for the commit's checks
- Merge pull request #81 from zen-rs/ci/release-pr-on-dev
- open the release pull request against dev
- let release-plz's pull request reach main
- serve the wasm and workerd lanes from the local fixture
- extract the httpbin fixture for reuse and answer CORS preflights
- abandon a body the server never finishes
- prove pooled h1 reuse with fixture accept counts
- serve the local httpbin fixture with hyper's server
- note the per-origin connection pool in AGENTS.md
- Merge remote-tracking branch 'origin/dev' into feat/connection-pool
- restore trailing newlines
- Merge remote-tracking branch 'origin/dev' into feat/alpn-http2
- run tests with cargo nextest ([#63](https://github.com/zen-rs/zenwave/pull/63))
- publish to crates.io via OIDC trusted publishing ([#61](https://github.com/zen-rs/zenwave/pull/61))
- gate pull requests into main so only dev may merge ([#62](https://github.com/zen-rs/zenwave/pull/62))
- *(websocket)* drain the server socket through the close handshake
- *(release)* turn the semver check back on ([#59](https://github.com/zen-rs/zenwave/pull/59))

## [0.6.1](https://github.com/zen-rs/zenwave/compare/v0.6.0...v0.6.1) - 2026-09-11

### Fixed

- make the TLS engine features additive
- *(android)* keep rustls-platform-verifier off wasm32 as well
- *(android)* verify against the system trust anchors on disk

### Other

- Merge remote-tracking branch 'origin/main' into android/system-anchors

## [0.6.0](https://github.com/zen-rs/zenwave/compare/v0.5.3...v0.6.0) - 2026-09-03

### Added

- [**breaking**] build the default client from a Transport
- [**breaking**] apple backend follows Transport
- [**breaking**] curl backend follows Transport
- [**breaking**] transport-level proxy rules for hyper and websockets
- [**breaking**] unify TLS behind Transport with platform-verified rustls and extra roots

### Fixed

- compile the TLS engine only when hyper or websockets consume it
- *(curl)* check revocation best-effort so Schannel accepts CAs without a CRL

### Other

- Merge pull request #50 from zen-rs/main
- install cargo-audit as a prebuilt binary
- *(android)* tell cargo-machete about the fixtures included via #[path]
- *(android)* instrumented app exercising the platform verifier on a real device
- run the iOS suite with simctl spawn, document App Transport Security
- engineless feature slice with a single backend
- keep the slow backend far behind the timeout it must lose to
- clippy the feature powerset on three OSes, run the suite on an iOS simulator and an Android device
- keep the Transport doctest compiling on wasm32
- pick explicit TLS engines now that rustls and native-tls are exclusive

## [0.5.3](https://github.com/zen-rs/zenwave/compare/v0.5.2...v0.5.3) - 2026-09-02

### Fixed

- *(wasm)* find fetch on globalThis, not only on window

### Other

- run zenwave inside a real Cloudflare Worker, and take fetch from globalThis
- Merge pull request #26 from zen-rs/main

## [0.5.2](https://github.com/zen-rs/zenwave/compare/v0.5.1...v0.5.2) - 2026-09-02

### Fixed

- *(wasm)* hand fetch the request body as bytes, never a ReadableStream

### Other

- Merge pull request #22 from zen-rs/main

## [0.5.1](https://github.com/zen-rs/zenwave/compare/v0.5.0...v0.5.1) - 2026-08-29

### Fixed

- use wasm-streams 0.5 so wasm32 links with skyzen

### Other

- leave crate version to release-plz
- Merge pull request #14 from zen-rs/fix/wasm-streams-0.5
- Rewrite README, add AGENTS.md, remove stale AGENT.md

## [0.5.0](https://github.com/zen-rs/zenwave/compare/v0.4.0...v0.5.0) - 2026-07-18

### Other

- Fix cross-target redirect regression test
- stream response bodies incrementally

## [0.4.0](https://github.com/zen-rs/zenwave/compare/v0.3.0...v0.4.0) - 2026-07-11

### Other

- Reduce hyper error size
- Fix nightly async trait lint
- Fix release automation and pending dev changes
- Add mobile target CI checks
- Switch Async Runtime to Smol
- Add native WebSocket TLS support
- Delete BROWSER_TEST_STATUS.md
- Implement RFC 8305 Happy Eyeballs
- Enable redirects by default
- Polish request builder formatting
- Restore fallible request builder construction
- Use origin-form URIs in hyper backend requests
