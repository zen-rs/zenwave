# AGENT.md

## Repository shape

- `src/client.rs` — the `Client` trait and `RequestBuilder`. Middleware combinators
  (`retry`, `timeout`, `enable_cache`, `enable_cookie`, `bearer_auth`, …) return
  concrete `WithMiddleware<…>` types rather than `impl Client`, so the consuming
  helpers (`.json()`, `.string()`, …) stay available down a middleware chain.
- `src/backend/` — one transport per platform, selected by `DefaultBackend`.
  A backend must leave the caller's request usable: take the body, but keep the
  method, URI, and headers, because `Retry` and `FollowRedirect` re-send it.
- `src/{redirect,retry,timeout,cache,cookie,auth,oauth2}.rs` — middleware.
- `src/multipart.rs` — `multipart/form-data` encoding, reached through
  `RequestBuilder::multipart_body`.
- `tests/common/mod.rs` — a local httpbin-like server. Add a route here rather
  than reaching for a public service; the integration tests run offline.

## Invariants worth knowing

- **Backends turn 4xx/5xx into `Err`.** `Error::response()` and
  `Error::response_body()` recover the status and body. Only a prefix of an error
  body is captured (`MAX_ERROR_BODY_BYTES`).
- **Request bodies must be replayable to survive a retry or a 307/308.** Both
  `Retry` and `FollowRedirect` buffer a body of known length up front and refuse
  (rather than truncate) a streaming body they cannot rewind.
- **Cookies are scoped per RFC 6265** — domain, path, and `Secure` must match the
  outgoing request, and expired cookies are dropped. A cookie set for an
  unrelated domain is rejected.
- **The cache is bounded** (`Cache::DEFAULT_CAPACITY`) with LRU eviction.
- **Credentials are encoded once, at construction.** `BearerAuth::new` /
  `BasicAuth::new` are fallible so a token that cannot be a header value fails
  there instead of panicking per request.
- **The hyper backend drives connections on one shared thread**, not a thread per
  request. Pass an executor via `HyperBackend::with_executor` to use your own.

## Apple backend status

`apple-backend` is opt-in; Apple targets default to Hyper. The URLSession backend
owns an ephemeral `URLSession` with caching and cookie storage disabled
(`src/backend/apple.rs`).

URLSession follows redirects and manages cookies internally, so `FollowRedirect`
and `CookieStore` are redundant — and partly bypassed — on that backend. Deciding
whether to add a delegate that surfaces redirects and cookies to Rust, or to
document the URLSession semantics as the contract there, is the remaining open
question for that backend.

## Known gaps

- **No connection pooling.** Every request opens a fresh TCP (and TLS)
  connection. This is the largest remaining performance item.
- **DNS resolution spawns one thread per address family** per connect
  (`spawn_blocking_resolution`), as RFC 8305 happy-eyeballs needs concurrent
  lookups.
- **No response decompression.** No `Content-Encoding` handling is implemented,
  and no `Accept-Encoding` is sent.
- **Method quirks need explicit handling per backend.** libcurl, for instance,
  needs `nobody(true)` for `HEAD` on top of the method string, or it waits for a
  body that never arrives.
- **SOCKS proxies need `curl-backend`.** The hyper backend speaks HTTP proxying
  only and reports other schemes as unsupported.

## Testing checklist

- [ ] `cargo test` and `cargo test --features proxy`
- [ ] `cargo clippy --all-targets --features proxy`
- [ ] `cargo test --no-default-features --features curl-backend`
- [ ] `cargo build --no-default-features --features hyper-native-tls`
- [ ] `scripts/test-wasm.sh` for the web backend
- [ ] `scripts/test-apple.sh` on Apple hardware, including `--features apple-backend`
