# Zenwave

Zenwave is an ergonomic, full-featured HTTP client framework for Rust. It provides a modern, extensible API for making HTTP requests, supporting both native (Hyper) and browser (Fetch API, including Cloudflare Workers) environments.

## Features

- Automatic redirect following
- Cookie store support
- Powerful middleware system (add features as you need)
- Streaming request and response bodies
- Pluggable backend and runtime (e.g., Hyper for native, Fetch API for browsers/Cloudflare Workers)
- Simple, ergonomic API

## Quick Start

```rust
use zenwave::get;

#[tokio::main]
async fn main() -> zenwave::Result<()> {
    let response = get("https://example.com/").await?;
    let text = response.into_string().await?;
    println!("{text}");
    Ok(())
}
```

## Usage

You can use the built-in HTTP methods directly:

```rust
let response = zenwave::get("https://api.example.com/data").await?;
let json: MyType = response.into_json().await?;
```

Or use a custom client with middleware:

```rust
let mut client = zenwave::client()
    .follow_redirect()
    .enable_cookie();

let response = client.get("https://example.com").await?;
```

## Web & Cloudflare Workers Support

Zenwave supports WASM targets and can run in browsers or Cloudflare Workers using the Fetch API. This makes it suitable for universal Rust applications.

## API Overview

- `zenwave::get(uri)`
- `zenwave::post(uri)`
- `zenwave::put(uri)`
- `zenwave::delete(uri)`
- Custom client: `zenwave::client()`
- Middleware support: `.with(middleware)`
- Cookie and redirect support

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
zenwave = { version = "0.1.0" }
```

## License

MIT License
