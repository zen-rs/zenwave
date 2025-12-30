# Zenwave

[![crates.io](https://img.shields.io/crates/v/zenwave.svg)](https://crates.io/crates/zenwave)
[![Documentation](https://docs.rs/zenwave/badge.svg)](https://docs.rs/zenwave)
[![License](https://img.shields.io/crates/l/zenwave.svg)](LICENSE)
[![Coverage](https://img.shields.io/codecov/c/github/zen-rs/zenwave?logo=codecov)](https://app.codecov.io/gh/zen-rs/zenwave)

Zenwave is an ergonomic HTTP client framework for Rust with a unified API across native and WebAssembly targets.

## Features

- **Cross-platform** - Same API on Linux, Windows, macOS, iOS, Android, and browsers/Workers
- **Pluggable backends** - Hyper (default), Apple URLSession, libcurl, or browser Fetch API
- **Composable middleware** - Timeout, retry, caching, cookies, redirects, OAuth2
- **WebSocket support** - Unified WebSocket client for native and browser
- **Streaming** - Upload/download large files without buffering (native only)

## Quick Start

```rust
use zenwave::{get, ResponseExt};

#[async_std::main]
async fn main() -> zenwave::Result<()> {
    let response = get("https://httpbin.org/get").await?;
    let text = response.into_string().await?;
    println!("{text}");
    Ok(())
}
```

## Installation

```toml
[dependencies]
zenwave = "0.2"
```

## Backends

Zenwave provides multiple HTTP backends. The backend is selected at compile time.

| Backend | Platforms | TLS | Proxy | Notes |
|---------|-----------|-----|-------|-------|
| **hyper** (default) | All native | rustls or native-tls | Yes | Recommended for most use cases |
| **curl** | All native | System libcurl | Yes | Smaller binaries on systems with libcurl |
| **apple** | Apple platform(iOS, macOS, etc.) | Security.framework | No | Native Apple networking (experimental) |
| **web** | wasm32 | Browser | No | Automatic on wasm32, uses Fetch API, enforced CORS striction |
| **web** | wasm32 | Serverless | No | Automatic on wasm32, uses Fetch API, no CORS striction|

### Backend Selection

```toml
# Default: Hyper with rustls
zenwave = "0.2"

# Hyper with platform-native TLS (OpenSSL/Security.framework/SChannel)
zenwave = { version = "0.2", default-features = false, features = ["hyper-native-tls", "ws"] }

# libcurl backend
zenwave = { version = "0.2", default-features = false, features = ["curl-backend"] }

# Apple URLSession (macOS/iOS only, experimental)
zenwave = { version = "0.2", default-features = false, features = ["apple-backend"] }
```

On wasm32 targets, the web backend is always used automatically regardless of feature flags.

## Platform Support

### Native Platforms (Linux, Windows, macOS, Android, iOS)

Full feature support with the hyper backend:

- HTTP/HTTPS requests with configurable TLS
- Proxy support (HTTP CONNECT, SOCKS4/5)
- Persistent cookie storage
- File uploads/downloads with streaming
- Download resume via Range requests
- WebSocket with TLS

### Android

Requires Android NDK for cross-compilation. See the [Android build guide](docs/android.md).

```bash
# Set environment and build
export ANDROID_NDK=$HOME/Library/Android/sdk/ndk/29.0.14206865
cargo build --target aarch64-linux-android
```

### Browser (wasm32)

Uses the browser's native Fetch API:

| Feature | Available | Notes |
|---------|-----------|-------|
| HTTP/HTTPS | Yes | Browser handles TLS |
| Cookies | Browser-managed | Cannot access HttpOnly cookies from code |
| Proxy | No | Browser security restriction |
| File I/O | No | No filesystem access |
| WebSocket | Yes | Uses browser's WebSocket API |

**Limitations**: Cross-origin requests are subject to CORS. The server must send appropriate `Access-Control-*` headers or the browser will block the response. This cannot be bypassed from client code.

### Cloudflare Workers (wasm32)

Uses the Workers Fetch API. Workers run server-side, so there are no CORS restrictions:

| Feature | Available | Notes |
|---------|-----------|-------|
| HTTP/HTTPS | Yes | Workers runtime handles TLS |
| Cookies | Yes | In-memory cookie jar (no persistent storage) |
| Proxy | No | Not supported by Workers runtime |
| File I/O | No | Use Workers KV or R2 instead |
| WebSocket | Yes | Via Workers WebSocket API |

## Middleware

Compose middleware to add functionality:

```rust
use std::time::Duration;
use zenwave::{client, OAuth2ClientCredentials};

let client = client()
    .timeout(Duration::from_secs(30))   // Per-request timeout
    .retry(3)                            // Retry transport errors (not HTTP errors)
    .follow_redirect()                   // Follow up to 10 redirects
    .enable_cache()                      // RFC-compliant HTTP caching
    .enable_cookie()                     // In-memory cookie jar
    .bearer_auth("token")                // Authorization header
    .with(OAuth2ClientCredentials::new(  // Auto-refresh OAuth2 tokens
        "https://auth.example.com/token",
        "client-id",
        "client-secret",
    ));
```

### Available Middleware

| Middleware | Method | Description |
|------------|--------|-------------|
| Timeout | `.timeout(duration)` | Fails with 504 if exceeded |
| Retry | `.retry(max)` | Retries on transport errors only |
| Redirect | `.follow_redirect()` | Follows up to 10 redirects |
| Cache | `.enable_cache()` | Honors Cache-Control, ETag, etc. |
| Cookies | `.enable_cookie()` | In-memory cookie jar |
| Persistent Cookies | `.enable_persistent_cookie()` | Saves to disk (native only) |
| Bearer Auth | `.bearer_auth(token)` | Sets Authorization header |
| Basic Auth | `.basic_auth(user, pass)` | Sets Authorization header |
| OAuth2 | `.with(OAuth2ClientCredentials)` | Auto-refreshes tokens |
| Custom | `.with(middleware)` | Your own middleware |

## Request Building

```rust
use zenwave::client;

let client = client();

// JSON request/response
let response: MyResponse = client
    .post("https://api.example.com/data")?
    .header("X-Request-ID", "abc123")?
    .bearer_auth("token")?
    .json_body(&MyRequest { field: "value" })?
    .json()
    .await?;

// Form data
let response = client
    .post("https://example.com/form")?
    .form_body(&[("key", "value")])?
    .await?;

// Raw bytes
let response = client
    .post("https://example.com/upload")?
    .bytes_body(vec![1, 2, 3])
    .await?;
```

### File Operations (Native Only)

```rust
// Stream file upload without buffering
client
    .post("https://example.com/upload")?
    .file_body("large-file.zip")
    .await?
    .await?;

// Download with automatic resume
let report = client
    .get("https://example.com/large-file.iso")?
    .download_to_path("large-file.iso")
    .await?;

println!("Downloaded {} bytes", report.bytes_written);
```

## Proxy Support (Native Only)

```rust
use zenwave::{client_with_proxy, Proxy};

// From environment (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)
let client = client_with_proxy(Proxy::from_env());

// Manual configuration
let proxy = Proxy::builder()
    .http("http://proxy:8080")
    .https("http://proxy:8080")
    .no_proxy("localhost,*.internal.com")
    .build();
let client = client_with_proxy(proxy);
```

Supports HTTP CONNECT and SOCKS4/4a/5/5h proxies. Only available with hyper and curl backends.

## WebSocket

Cross-platform WebSocket client:

```rust
use zenwave::websocket::{self, WebSocketMessage};

let socket = websocket::connect("wss://echo.websocket.events").await?;

socket.send_text("hello").await?;

if let Some(WebSocketMessage::Text(text)) = socket.recv().await? {
    println!("Received: {text}");
}

socket.close().await?;
```

Split for concurrent send/receive:

```rust
let (sender, receiver) = socket.split();

// Send from one task
sender.send_text("message").await?;

// Receive from another
while let Some(msg) = receiver.recv().await? {
    println!("{:?}", msg);
}
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `default` | `hyper-backend` + `rustls` + `ws` |
| `hyper-backend` | Hyper HTTP client |
| `rustls` | Pure Rust TLS (default, good for cross-compilation) |
| `native-tls` | Platform TLS (OpenSSL/Security.framework/SChannel) |
| `hyper-native-tls` | Shorthand for `hyper-backend` + `native-tls` |
| `hyper-rustls` | Shorthand for `hyper-backend` + `rustls` |
| `curl-backend` | libcurl-based backend |
| `apple-backend` | Apple URLSession (experimental) |
| `ws` | WebSocket support |
| `proxy` | Proxy support (auto-enabled with curl-backend) |

## Examples

Run examples with `cargo run --example <name>`:

- `basic_get` - Simple GET request
- `custom_client` - Middleware composition and JSON
- `websocket_echo` - WebSocket echo client

## License

MIT License
