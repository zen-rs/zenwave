# Apple Backend Status & Issues

## Overview

Zenwave’s Apple backend (`src/backend/apple.rs`) uses `NSURLSession` to satisfy App Store requirements (watchOS and friends must go through the system HTTP stack). We initially attempted to reimplement URLSession via `swift-bridge` and custom delegates, but that required a full Swift build pipeline and still crashed. The current implementation therefore relies on `URLSession::sharedSession` with Rust-side middleware.

### What Exists Today

```rust
// src/backend/apple.rs (truncated)
pub struct AppleBackend;

impl Endpoint for AppleBackend {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        let session = unsafe { OwnedSession::new() };
        send_with_url_session(&session, request).await
    }
}

fn start_task(
    session: &OwnedSession,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    sender: CompletionSender,
) -> Result<()> {
    autoreleasepool(|| unsafe {
        let session_ptr = session.session_ptr();
        // convert http_kit::Request into NSMutableURLRequest, call dataTaskWithRequest:completionHandler:
    })
}
```

- Each request spins up an `OwnedSession` that creates an `NSURLSession` with a private delegate/queue (so we can eventually disable automatic redirect/cookie handling). In Drop we call `finishTasksAndInvalidate()` to avoid leaking.
- On Apple platforms `FollowRedirect` and `CookieStore` middleware are essentially no-ops because URLSession still handles those behaviors itself, so the corresponding tests are `#[cfg_attr(target_vendor = "apple", ignore = ...)]`.
- README includes a note about the behavioral difference.

## Current Problems

1. **Cargo test crashes on macOS.** Running `cargo test` or `cargo test auth_tests` eventually segfaults inside `libobjc.A.dylib` (`objc_release` → `AutoreleasePoolPage::releaseUntil`). Crash logs live at `~/Library/Logs/DiagnosticReports/auth_tests-3e9babedbb72e7df-*.ips` (latest example: `auth_tests-3e9babedbb72e7df-2025-11-16-182022.ips`). Single tests pass; the crash only surfaces when dozens of URLSession tasks run in succession.
2. **Delegates were removed to avoid double-release.** The attempt to manage `URLSession` with custom delegate/queue still triggered the same crash and complicated lifetimes, so we reverted to shared-session semantics (no manual redirect/cookie control).
3. **Behavioral mismatches remain.** Because URLSession always manages redirects/cookies, our middleware cannot disable those features on Apple. Tests that asserted “no redirect follow” or “cookies not retained” are ignored on Apple targets. Users must accept that difference.

## Desired Outcome

1. **Stable URLSession usage:** figure out a safe pattern for per-request sessions (or shared session) that doesn’t crash when the full test suite runs. This probably requires native debugging (Instruments, Xcode) to see which callback is double-freeing (`objc_release` traces in crash log).
2. **Feature parity (optional):** if we need manual redirect/cookie control, reintroduce a custom delegate but keep strong references to delegate/queue and ensure callbacks run on a live run loop. Ideally handle redirects in Rust rather than letting URLSession auto-follow.
3. **Testing:** once Apple backend is stable, run the full matrix (`cargo test`, `cargo test --no-default-features --features curl-backend`) on macOS/watchOS targets and document any remaining platform differences explicitly in README + AGENT.md.

## Supporting Details

- Crash reports: `~/Library/Logs/DiagnosticReports/auth_tests-3e9babedbb72e7df-*.ips`; look for threads named `test_auth_headers_sent` showing `objc_release` → `AutoreleasePoolPage::releaseUntil`.
- Tests currently ignored on Apple: `tests/middleware_tests.rs::test_cookie_store_middleware`, `tests/middleware_tests.rs::test_without_redirect_middleware`.
- README note (search “Apple platforms”) explains why redirects/cookies behave differently.
- AGENT.md tracks the open issues, next steps, and testing checklist.
