# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
