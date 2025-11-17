# AGENT.md

## Current Status

- Apple backend now owns an `URLSession` created from `NSURLSessionConfiguration::ephemeralSessionConfiguration` with caching/cookie storage disabled (`src/backend/apple.rs`). The StrongPtr-backed session fixed the CFNetwork/autorelease crash we previously hit.
- The URLSession backend remains opt-in; Apple targets still default to the Hyper backend unless `features = ["apple-backend"]` is set in `Cargo.toml`.
- URLSession continues to auto-follow redirects and manages cookies internally, so middleware coverage is still uneven on Apple. `test_cookie_store_middleware`, `test_without_redirect_middleware`, and the integration cookie test stay ignored whenever `target_vendor = "apple"` (`tests/middleware_tests.rs`, `tests/integration_tests.rs`), and README already documents these limitations.
- With the crash addressed, the remaining Apple work is deciding whether we need redirect/cookie parity or if we permanently document/skip those behaviors.

## Next Steps

1. **Apple parity decision** – Decide whether we want middleware parity on Apple. If yes, implement a delegate that surfaces redirects/cookies to Rust so `FollowRedirect`/`CookieStore` behave consistently. If no, codify the Apple-specific semantics in docs/tests rather than leaving ignores.
2. **Test hygiene** – Revisit the ignored tests once the behavior is final (either un-ignore after adding delegate control or replace them with Apple-specific coverage).
3. **Test matrix** – Run `cargo test` (including `--features apple-backend`) and `cargo test --no-default-features --features curl-backend` on macOS/watchOS hardware to ensure the fixed backend stays stable.

## Testing Checklist

- [ ] `cargo test` (native + wasm targets, including `--features apple-backend` on Apple)
- [ ] `cargo test --no-default-features --features curl-backend`
- [ ] Apple/watchOS smoke test once redirect/cookie story is resolved
