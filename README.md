# Zenwave

[![crates.io](https://img.shields.io/crates/v/zenwave.svg)](https://crates.io/crates/zenwave)
[![docs.rs](https://docs.rs/zenwave/badge.svg)](https://docs.rs/zenwave)
[![License](https://img.shields.io/crates/l/zenwave.svg)](LICENSE)
[![Coverage](https://img.shields.io/codecov/c/github/zen-rs/zenwave?logo=codecov)](https://app.codecov.io/gh/zen-rs/zenwave)

Async HTTP client for Rust. Works on native (Tokio/Hyper, Apple URLSession, libcurl) and
wasm32 (Fetch API). Same API everywhere, middleware you compose yourself.

## Getting started

```toml
[dependencies]
zenwave = "0.5"
```

```rust
use zenwave::{get, ResponseExt};

async fn example() -> zenwave::Result<()> {
    let response = get("https://jsonplaceholder.typicode.com/todos/1").await?;
    let todo: serde_json::Value = response.into_json().await?;
    println!("{todo}");
    Ok(())
}
```

`get`, `post`, `put`, `delete` are one-shot convenience functions. For anything
more involved, build a client:

```rust
use std::time::Duration;
use zenwave::{self, Client, ResponseExt};

async fn example() -> zenwave::Result<()> {
    let mut client = zenwave::client()
        .timeout(Duration::from_secs(5))
        .enable_cache()
        .enable_cookie()
        .bearer_auth("my-token");

    let resp: serde_json::Value = client
        .post("https://httpbin.org/post")?
        .header("x-request-id", "abc123")?
        .json_body(&serde_json::json!({"msg": "hello"}))?
        .json()
        .await?;

    Ok(())
}
```

Every method on `Client` (`enable_cache`, `timeout`, `bearer_auth`, `basic_auth`,
`enable_cookie`, `retry`, `.with(custom_middleware)`) wraps the client in another
middleware layer. Order matters — the outermost layer runs first.

## Request builder

Once you have a client, `.get(url)`, `.post(url)`, etc. return a `RequestBuilder`.
It has methods for setting the request and methods for reading the response:

**Setting the request:**
`.header(name, value)`, `.bearer_auth(token)`, `.basic_auth(user, pass)`,
`.json_body(&T)`, `.bytes_body(vec)`, `.file_body("path").await`,
`.reader_body(reader, len)`, `.stream_body(stream)`

**Reading the response** (consume the `RequestBuilder` by awaiting, then call on
`Response`, or call directly on the builder as a shortcut):
`.json::<T>()`, `.string()`, `.bytes()`, `.form::<T>()`, `.sse()`

The `ResponseExt` trait adds `.into_json::<T>()`, `.into_string()`, `.into_bytes()`,
`.into_sse()`, `.error_for_status()` directly on `Response`.

## Middleware

All built-in features are middleware. You can write your own by implementing
the `Middleware` trait from `http-kit` and passing it to `.with()`.

Built-in middleware:

| Method | What it does |
|---|---|
| `.timeout(duration)` | Fails with 504 if the request takes longer than `duration` |
| `.enable_cache()` | RFC-compliant `Cache-Control` / `ETag` / `Last-Modified` caching in memory |
| `.enable_cookie()` | In-memory cookie jar |
| `.enable_persistent_cookie()` | Cookie jar backed by a file on disk (native only) |
| `.bearer_auth(token)` | Adds `Authorization: Bearer <token>` to every request |
| `.basic_auth(user, pass)` | Adds `Authorization: Basic <base64>` to every request |
| `.retry(n)` | Retries failed requests up to `n` times |
| `.with(OAuth2ClientCredentials::new(...))` | Client-credentials OAuth2 flow with automatic refresh |

Redirects are on by default. Call `zenwave::client().disable_redirect()` to get the
raw backend, or use `zenwave::raw_client()`.

## File downloads with resume

```rust
use zenwave::Client;

async fn example() -> zenwave::Result<()> {
    let mut client = zenwave::client();
    let report = client
        .get("https://example.com/big.iso")?
        .download_to_path("big.iso")
        .await?;

    println!(
        "resumed from {} bytes, wrote {} new bytes",
        report.resumed_from, report.bytes_written
    );
    Ok(())
}
```

If the file already exists, zenwave sends a `Range` header and appends. Pass
`DownloadOptions { resume_existing: false }` via `.download_to_path_with()` to
start from scratch. Native only.

## WebSockets

Requires the `ws` feature (on by default). Uses `async-tungstenite` on native,
`web_sys::WebSocket` on wasm.

```rust
use zenwave::websocket::{self, WebSocketMessage};

async fn example() -> zenwave::Result<()> {
    let socket = websocket::connect("wss://echo.websocket.events").await?;
    socket.send_text("hello").await?;

    if let Some(WebSocketMessage::Text(text)) = socket.recv().await? {
        println!("{text}");
    }

    socket.close().await
}
```

You can split a connection for concurrent send/recv:

```rust
# use zenwave::websocket;
# async fn example() -> zenwave::Result<()> {
let socket = websocket::connect("wss://echo.websocket.events").await?;
let (sender, receiver) = socket.split();
// sender.send(&my_struct).await?  — serializes to JSON
// receiver.recv().await?
# Ok(())
# }
```

## Trust and transport

Every backend is built from a `Transport`. `zenwave::client()` uses
`Transport::system()`: the operating system's trust store, verified by the
platform itself (Security.framework on macOS/iOS, CryptoAPI on Windows, the
Android trust manager, the system CA bundle on Linux), and in a browser or a
Cloudflare Worker whatever the runtime trusts. It is built once per process and
shared.

To trust a private CA in addition to the platform roots:

```rust
use zenwave::{Transport, backend::HyperBackend};

let transport = Transport::builder()
    .extra_root_certificates_pem(&std::fs::read("corp-root.pem")?)?
    .build()?;
let client = HyperBackend::new(transport);
```

Websockets take the same transport: `websocket::connect_with(uri, &transport, config)`.

On Android the platform verifier needs the JVM. zenwave reads it from
[`ndk-context`](https://crates.io/crates/ndk-context), which `android-activity`
and `ndk-glue` fill in before `main`; an app that embeds Rust calls
`ndk_context::initialize_android_context` from `JNI_OnLoad`. The Kotlin half of
`rustls-platform-verifier` must be on the class path; see that crate's README.

## Proxy support

Available with the `curl-backend` feature (native only).

```rust
use zenwave::Proxy;

// Read HTTP_PROXY / HTTPS_PROXY / NO_PROXY from env
let proxy = Proxy::from_env();

// Or build manually — supports http, socks4, socks4a, socks5, socks5h
let proxy = Proxy::builder()
    .http("http://corp-proxy:8080")
    .no_proxy("internal.example.com")
    .build();
```

## Backends and feature flags

On wasm32, the built-in Fetch backend is used automatically. No feature selection
needed or available.

On native, pick a backend, and for hyper exactly one TLS engine:

| Feature | Backend | TLS | Notes |
|---|---|---|---|
| `hyper-backend` + `rustls` | Hyper | rustls, verified by the OS (`rustls-platform-verifier`) | **Default.** |
| `hyper-backend` + `native-tls` | Hyper | Platform native | OpenSSL / SChannel / Security.framework |
| `curl-backend` | libcurl | libcurl's | Smaller binary if you have system libcurl |
| `apple-backend` | URLSession | Security.framework | Experimental. macOS/iOS only |

`rustls` and `native-tls` are mutually exclusive; `ws` (websockets) uses the same
engine as hyper. The `default` feature enables `hyper-backend`, `rustls` and `ws`.

Common dependency lines:

```toml
# Default — hyper + rustls with platform verification + websockets
zenwave = "0.5"

# Hyper with the platform's native TLS library
zenwave = { version = "0.5", default-features = false, features = ["hyper-native-tls", "ws"] }

# Curl backend
zenwave = { version = "0.5", default-features = false, features = ["curl-backend"] }

# Apple URLSession
zenwave = { version = "0.5", default-features = false, features = ["apple-backend"] }
```

Other features: `hyper-rustls` / `hyper-native-tls` (shorthands), `proxy`
(auto-enabled by `curl-backend`).

## Testing

Native backends are covered by `cargo test`. The wasm backend is tested in
three runtimes, because they differ in exactly the places that break:

- `scripts/test-wasm.sh <chrome|firefox|safari>` — wasm-pack in a browser
  page (a `Window`) and in a dedicated web worker (no `window`).
- `scripts/test-workerd.sh` — a real Cloudflare Worker. It builds the
  [skyzen](https://crates.io/crates/skyzen) app in `tests/workerd/`,
  path-patched to this checkout, runs it under `wrangler dev` (local
  workerd), and asserts that a bodiless GET, a JSON POST and a bytes PUT all
  round-trip through zenwave. Needs `skyzen`, `wrangler`, `jq` and the
  `wasm32-unknown-unknown` target.

CI runs all three.

## Examples

```sh
cargo run --example basic_get
cargo run --example custom_client
cargo run --example websocket_echo
```

## License

MIT
