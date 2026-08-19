# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Backends no longer replace the caller's request with a placeholder, so `Retry`
  re-sends the original method, URI, and headers instead of a bare `GET /`.
- `307`/`308` redirects now resend the request body instead of silently dropping it.
- Cookies are scoped per RFC 6265 (domain, path, `Secure`, expiry) instead of
  being sent to every host; a cookie set for an unrelated domain is rejected.
- `bearer_auth`/`basic_auth` and the `OAuth2` middleware no longer panic on a
  credential that cannot be a header value; they report an error instead.
- Retry backoff saturates instead of overflowing at high attempt counts.
- An `OAuth2` token endpoint reporting a zero or tiny `expires_in` no longer
  causes a token refetch on every request.
- DNS and connect failures are classified as transport errors rather than I/O errors.
- Resumed downloads verify the server's `Content-Range` before appending.
- A `HEAD` request through the curl backend hung until the connection timed out,
  because libcurl was given the method string but not told to expect no body.

### Added

- `patch`, `head`, and `options` request helpers, plus `query`, `form_body`,
  `text_body`, `multipart_body`, and `bytes_with_limit` on the request builder.
- The `multipart` module is now reachable from the request builder, generates a
  boundary guaranteed not to occur in the payload, and escapes field names.
- Proxy support for the hyper backend: absolute-form forwarding for `http` and
  `CONNECT` tunnelling for `https`. SOCKS remains curl-only and is now reported
  as unsupported rather than silently mistreated.
- `Proxy::intercepts`, `proxy_uri`, and `proxy_authorization` for inspecting a
  proxy configuration; `NO_PROXY` matching no longer exempts suffix lookalikes.
- A default `User-Agent` when the caller sets none.
- Download progress reporting via `download_to_path_with_progress`.
- `Cache::with_capacity` / `enable_cache_with_capacity`; the cache is now bounded
  with LRU eviction instead of growing without limit.
- `FollowRedirect::max_redirects` to configure the redirect limit.
- `ErrorKind` is re-exported at the crate root.

### Changed

- `bearer_auth`/`basic_auth` return `Result`, and the middleware combinators
  return concrete `WithMiddleware<…>` types so `.json()`/`.string()` remain
  callable after adding middleware.
- The hyper backend drives connections on one shared thread rather than spawning
  a thread per request.
- Error response bodies are captured up to a bounded prefix.
- Removed the unused `tower-service` and `once_cell` dependencies, moved `js-sys`
  to wasm-only, and made `anyhow` optional.

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
