# Browser Compatibility Test Status

Zenwave’s browser support is exercised through `wasm-pack test --headless` with
`--no-default-features` so that the wasm-only backend is
compiled and shipped without the native Hyper stack.

## Chrome

- Command  
  `wasm-pack test --headless --chrome --chromedriver /tmp/chromedriver --no-default-features`
- Result: ✅ Pass  
  After installing a matching ChromeDriver binary (v142.0.7444.162) the wasm
  tests run, including the new `tests/wasm_browser_tests.rs` suite that exercises
  `zenwave::get` and request-builder helpers directly inside Chrome.

## Firefox

- Command  
  `wasm-pack test --headless --firefox --geckodriver /opt/homebrew/bin/geckodriver --no-default-features`
- Result: ✅ Pass  
  Headless Firefox completes the same wasm tests with Geckodriver 0.36.0 and no
  additional configuration.

## Safari

- Command  
  `wasm-pack test --headless --safari --safaridriver /usr/bin/safaridriver --no-default-features`
- Result: ⚠️ Blocked  
  Safari’s WebDriver (`safaridriver`) exits with `SIGKILL`/HTTP 500 because the
  machine has not granted automation permission. On macOS this must be enabled
  once per user via `sudo safaridriver --enable`, which launches Safari and asks
  for confirmation in System Settings. Re-run the command after granting access.

## Notes

- All wasm tests are headless; the only suite that currently runs in browsers is
  `tests/wasm_browser_tests.rs`, which verifies end-to-end request execution.
- The native-only Tokio/Mio test modules are behind `#[cfg(all(test,
  not(target_arch = "wasm32")))]`, so wasm builds no longer try to compile the
  native runtime.
