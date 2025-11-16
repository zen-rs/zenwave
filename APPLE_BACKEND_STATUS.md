# Apple Backend – Single Reference Document

This file captures everything about the Apple-specific backend so experts do not need to hunt for context elsewhere. It includes the current implementation, known bugs, crash evidence, desired behavior, and the state of related documentation/tests.

---

## 1. Background & Goals

- **Motivation**: Zenwave must support Apple platforms (iOS, watchOS, etc.). WatchOS requires network traffic to go through `URLSession`, so we need a backend that does not rely solely on Hyper.
- **Attempted approaches**:
  1. *Hand-written Objective-C FFI (current)* – use `NSURLSession::sharedSession` or custom sessions via the `objc` crate.
  2. *swift-bridge* – explored but abandoned (requires `xcodebuild`, heavy build pipeline, async Swift→Rust not supported yet).
  3. *Custom delegates* – tried to manage redirects/cookies manually but ran into `objc_release` crashes; reverted.
- **Long-term wish**: Provide a stable URLSession-backed backend that mirrors the Hyper feature set (manual redirect/cookie control) without crashes, then run the full `cargo test` matrix on macOS/watchOS.

---

## 2. Current Implementation (Rust)

Located in `src/backend/apple.rs`. Key structure:

```rust
use objc::{class, msg_send, rc::autoreleasepool, runtime::{BOOL, Object, YES}, sel, sel_impl};
use block::ConcreteBlock;

pub struct AppleBackend;

impl Endpoint for AppleBackend {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        let session = unsafe { OwnedSession::new() };
        send_with_url_session(&session, request).await
    }
}

struct OwnedSession {
    session: *mut Object,
    delegate: *mut Object,
    queue: *mut Object,
}

impl Drop for OwnedSession {
    fn drop(&mut self) {
        unsafe {
            let _: () = msg_send![self.session, finishTasksAndInvalidate];
            let _: () = msg_send![self.session, release];
            let _: () = msg_send![self.delegate, release];
            let _: () = msg_send![self.queue, release];
        }
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
        let request = build_request(method, url, headers, body)?;

        let completion = ConcreteBlock::new(
            move |data: *mut Object, response: *mut Object, error: *mut Object| {
                let result = handle_completion(data, response, error);
                if let Some(tx) = sender.lock().expect("mutex poisoned").take() {
                    let _ = tx.send(result);
                }
            },
        )
        .copy();

        let task: *mut Object =
            msg_send![session_ptr, dataTaskWithRequest: request completionHandler: &*completion];
        if task.is_null() {
            return Err(http_kit::Error::new(
                anyhow!("Failed to create URLSession data task"),
                StatusCode::BAD_GATEWAY,
            ));
        }
        let _: () = msg_send![task, resume];
        Ok(())
    })
}
```

- Each request constructs a brand-new `OwnedSession` with its own delegate/queue so we *could* eventually intercept redirects/cookies. `Drop` calls `finishTasksAndInvalidate`.
- The `completionHandler` copies the Objective-C block, converts the response to `http_kit::Response`, and sends it back via a oneshot channel.
- Because this path still crashes (see below), the `apple-backend` feature is **experimental**. By default, Apple builds use Hyper again.

---

## 3. Runtime Behavior & Documentation

- **Default backend selection**:  
  *Apple builds now default to Hyper.* The URLSession backend only compiles when `features = ["apple-backend"]`.
- **README entry** (paraphrased for completeness):  
  > “By default Apple targets also use the Hyper backend. There is an experimental `apple-backend` feature that swaps Hyper out for `URLSession`, which satisfies watchOS/App Store restrictions but currently auto-follows redirects and auto-manages cookies…”
- **AGENT.md summary**:  
  - Apple backend still crashes under load (see crash log).  
  - Two middleware tests (`test_cookie_store_middleware`, `test_without_redirect_middleware`) are ignored on Apple when this feature is enabled.  
  - TODOs: diagnose crash with Instruments, decide on redirect/cookie parity, run full test suites once stable.

---

## 4. Crash Evidence (full excerpt)

Even with per-request sessions, `cargo test` on macOS eventually crashes. Example log (complete chunk from `auth_tests-3e9babedbb72e7df-2025-11-16-182022.ips`):

```
{"app_name":"auth_tests-3e9babedbb72e7df","timestamp":"2025-11-16 18:20:22.00 +0800","os_version":"macOS 26.0 (25A354)","incident_id":"F8549AD4-5727-46F3-BB6B-98FF7058F0F1"}
{
  "exception" : {"type":"EXC_BAD_ACCESS","signal":"SIGSEGV","subtype":"KERN_INVALID_ADDRESS at 0x0000000000002f38"},
  "threads" : [
    {"id":6436425,"name":"main","frames":[{"symbol":"__ulock_wait"}, {"symbol":"_pthread_join"}, ...]},
    {
      "triggered":true,
      "id":6436595,
      "name":"test_auth_headers_sent",
      "frames":[
        {"symbol":"objc_release","image":"libobjc.A.dylib"},
        {"symbol":"AutoreleasePoolPage::releaseUntil(objc_object**)"},
        {"symbol":"objc_autoreleasePoolPop"},
        {"symbol":"objc_tls_direct_base<AutoreleasePoolPage*, (tls_key)3, AutoreleasePoolPage::HotPageDealloc>::dtor_(void*)"},
        {"symbol":"_pthread_tsd_cleanup"},
        {"symbol":"_pthread_exit"},
        {"symbol":"_pthread_start"}
      ]
    }
  ],
  "images" : [
    {"name":"libobjc.A.dylib","uuid":"7443a268-c9f9-3d65-b497-4f8081799514"},
    {"name":"CoreFoundation","uuid":"edb39786-80b1-3bff-b6c3-e33f2e3ca867"},
    {"name":"CFNetwork","uuid":"10bc915e-16e7-3b21-8e1b-3295a051249f"}
  ],
  "logWritingSignature" : "3ee4979ce1f57e095a5c123cc219aa240eaa7350",
  "threads_skipped" : ["(additional IO threads parked in kevent)"]
}
```

Interpretation:
- Thread `test_auth_headers_sent` (Tokio worker) drains an autorelease pool and crashes in `objc_release`. This happens after many concurrent httpbin requests; single tests do not trigger it.
- Because the crash originates within Apple frameworks, further debugging (Instruments/Xcode, checking if we exit the run loop too early, etc.) is required.

---

## 5. Current Problems & Workarounds

1. **`cargo test` crashes** (see log above). Tests must be run individually if you enable `apple-backend`.
2. **Middleware parity**: URLSession automatically follows redirects and manages cookies. Our `FollowRedirect`/`CookieStore` middleware cannot disable those behaviors on Apple; associated tests are ignored when `apple-backend` is on.
3. **Feature flag**: To avoid shipping the unstable backend, Apple builds fall back to Hyper unless users explicitly enable the `apple-backend` feature.

---

## 6. Desired Outcome / Next Steps

1. **Stabilize URLSession usage**  
   - Debug the autorelease crash (likely the session/delegate/queue lifetime). Instruments or Xcode’s memory graph may show which callback double-frees.
   - Consider using `URLSessionConfiguration. ephemeralSessionConfiguration` or `finishTasksAndInvalidate` with delegate-runloop to avoid dangling tasks.
2. **Feature parity**  
   - Only if needed: implement a robust delegate that surfaces redirects/cookies to Rust, so middleware can decide. Requires strong references and a dedicated `NSOperationQueue`.
3. **Testing matrix**  
   - Once stable, run `cargo test`, `cargo test --no-default-features --features curl-backend`, and Apple/watchOS-specific builds. Document any remaining differences (e.g., Apple always proxies via URLSession’s cookie store).

---

## 7. Summary for Experts

- Everything about the Apple backend is in this file: code outline, feature flags, README/AGENT notes, crash logs, and TODOs.
- Presently the backend is **opt-in only** via `apple-backend`.
- Key blockers: autorelease crash during heavy testing and lack of manual redirect/cookie control.
- Suggested starting point: run Instruments with the provided log signature (`F8549AD4-5727-46F3-BB6B-98FF7058F0F1`) while stressing httpbin.org, verify delegate/queue lifetimes, and decide whether to keep per-request sessions or a single shared session with `finishTasksAndInvalidate`.
