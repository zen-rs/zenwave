# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
