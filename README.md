# Zenwave

Zenwave is an ergonomic, full-featured HTTP client framework for Rust. It exposes a modern,
middleware-friendly API that works on both native targets (Tokio + Hyper on Linux/Windows, Apple's
URLSession on iOS/tvOS/watchOS/macOS) and browser/Cloudflare Workers targets through the Fetch API.

## Why Zenwave?

- **Ergonomic requests** – convenience helpers (`get`, `post`, …) and a fluent `RequestBuilder`.
- **Opt-in middleware** – add redirect following, cookie storage, or authentication only when you
  need it.
- **Streaming bodies** – handle large uploads/downloads or upgrade to SSE without buffering.
- **WebSocket ready** – one API that works natively and in WASM.
- **Pluggable backends** – Hyper on general native targets, URLSession on Apple platforms, libcurl
  when you want small binaries, and Fetch on wasm, all behind the same `zenwave::client()` interface.

## Quick Start

```rust
use zenwave::{get, ResponseExt};

#[tokio::main]
async fn main() -> zenwave::Result<()> {
    let response = get("https://example.com/").await?;
    let text = response.into_string().await?;
    println!("{text}");
    Ok(())
}
```

The `ResponseExt` trait provides the `into_string`, `into_json`, `into_bytes`, and `into_sse` helpers
you will see throughout the API.

## Examples

Run the shipped samples with `cargo run --example <name>`:

- `basic_get` – one-off GET request parsed into a typed response.
- `custom_client` – compose middleware, send JSON, and read a typed response body.
- `websocket_echo` – connect to a public echo server using the cross-platform WebSocket client.

Feel free to copy these examples as starting points for your own projects.

## Building richer clients

```rust
use serde::{Deserialize, Serialize};
use zenwave::{self, Client};

#[derive(Serialize)]
struct MessageRequest<'a> {
    message: &'a str,
}

#[derive(Deserialize)]
struct EchoResponse {
    json: MessageResponse,
}

#[derive(Deserialize)]
struct MessageResponse {
    message: String,
}

#[tokio::main]
async fn main() -> zenwave::Result<()> {
    let token = std::env::var("ZENWAVE_TOKEN").unwrap_or_else(|_| "demo-token".into());

    // Compose only the middleware you need.
    let mut client = zenwave::client()
        .follow_redirect()
        .enable_cookie()
        .bearer_auth(token);

    let echo: EchoResponse = client
        .post("https://httpbin.org/post")
        .header("x-request-id", "demo-request")
        .json_body(&MessageRequest { message: "hello" })?
        .json()
        .await?;

    println!("{}", echo.json.message);
    Ok(())
}
```

You can also call `.basic_auth` or `.with(custom_middleware)` to plug in your own behavior. Every
request builder supports `.header`, `.bearer_auth`, `.basic_auth`, `.json_body`, `.bytes_body`, and
body readers (`.json()`, `.string()`, `.bytes()`, `.form()`, `.sse()`).

## Web & Cloudflare Workers

Zenwave targets both `wasm32` and native platforms. On wasm it relies on `web_sys::Request`/`Fetch`,
so it works in browsers and Cloudflare Workers without extra glue code. The API is identical, so
sharing code between targets is straightforward.

## Apple platforms

On Apple targets (iOS, iPadOS, tvOS, watchOS, and macOS) Zenwave dispatches HTTP requests through
`URLSession`. This satisfies App Store requirements for watchOS and gives you the same security,
power management, and proxy behavior as native Swift/Objective-C apps without changing any Rust
code. Note that `URLSession` always follows HTTP redirects and automatically manages cookies, so the
`FollowRedirect` and `CookieStore` middleware are effectively no-ops on Apple platforms. The two
tests that asserted “no redirect / no automatic cookies” are skipped on Apple for this reason.

## Curl backend

Many Linux distributions (and some embedded platforms) ship a system libcurl. Zenwave can reuse it
to avoid bundling Hyper/OpenSSL and shrink your binary. Disable the default features and enable the
curl backend:

```toml
[dependencies]
zenwave = { version = "0.1.0", default-features = false, features = ["curl-backend"] }
```

You still get the same middleware API; the only difference is which backend transports the bytes.

## WebSocket support

The `zenwave::websocket` module offers a cross-platform WebSocket client that hides the details of
`async-tungstenite` or `web_sys::WebSocket`. Connecting to an endpoint looks like:

```rust
use zenwave::websocket::{self, WebSocketMessage};

#[tokio::main]
async fn main() -> zenwave::Result<()> {
    let mut socket = websocket::connect("wss://echo.websocket.events").await?;
    socket.send_text("hello").await?;

    if let Some(WebSocketMessage::Text(text)) = socket.recv().await? {
        println!("Received: {text}");
    }

    socket.close().await
}
```

## Installation

Add Zenwave to your `Cargo.toml` (native defaults shown):

```toml
[dependencies]
zenwave = { version = "0.1.0" }
```

For browser/Workers builds you can opt out of the Hyper backend and depend only on the wasm
implementation:

```toml
[dependencies]
zenwave = { version = "0.1.0", default-features = false, features = ["web-backend"] }
```

### Feature flags

- `hyper-backend` (default) – enables the Hyper/Tokio-based backend for non-Apple native targets (it
  is still available on Apple if you instantiate `HyperBackend` explicitly).
- `web-backend` (default) – enables the Fetch-based backend for `wasm32`.
- `curl-backend` – enables the libcurl backend for platforms that provide libcurl (disable
  `hyper-backend` if you want to rely on libcurl exclusively).

Disable default features if you only need one backend. The URLSession-based backend is compiled
automatically on Apple targets and does not need a feature flag.

## License

MIT License
