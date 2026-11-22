# Embedded (`no_std + alloc`) Guide

Zenwave runs on bare-metal microcontrollers that provide a global allocator (`alloc`) and hardware atomics, without an operating system, POSIX sockets, `compio-buf`, or `http-kit-io`. The reference target is **Espressif ESP32-C6** (`riscv32imac-unknown-none-elf`) with `esp-hal`, `esp-radio`, `embassy-net`, and `esp-emu`.

## Architecture on bare metal

Completion-based host I/O (`compio`, `http-kit-io`) exists for kernel-owned buffers (`io_uring`, IOCP) and is excluded completely when `default-features = false` disables `std`. Instead:

- **HTTP/1.1 framing** uses the sans-IO state machine in `http_kit_h1::proto` (`encode_request_head`, `BodyEncoder`, `parse_response_head`, `BodyDecoder`) directly over `bytes::BytesMut`.
- **Sockets and DNS** come from [`embedded-io-async`](https://crates.io/crates/embedded-io-async) (`Read`, `Write`) and [`embedded-nal-async`](https://crates.io/crates/embedded-nal-async) (`TcpConnect`, `Dns`), implemented out of the box by `embassy_net::tcp::client::TcpClient` and `embassy_net::dns::DnsSocket`.
- **TLS 1.2 / 1.3** (`embedded-tls` feature) drives `rustls::client::UnbufferedClientConnection` over the `embedded-io-async` socket with a caller-supplied `CryptoProvider` and `TimeProvider`.
- **Actor split for `!Send` hardware stacks**: embedded network handles borrow peripheral buffers and are `!Send`. `EmbeddedBackend::channel(transport)` returns a `Clone + Send + Sync` `EmbeddedBackend` (implementing `zenwave::Client` and composing with `FollowRedirect`, `BearerAuth`, `BasicAuth`, `ErrorForStatus`, `Timeout`, and `Retry`) paired with an `EmbeddedRunner` future that stays on the Embassy task owning the stack. Request and response bodies stream across bounded channels rather than buffering whole payloads in SRAM.

## Configuring `[patch.crates-io]`

Upstream [`http`](https://crates.io/crates/http) `1.5.0` defines a `std` feature flag in its manifest, but still emits a `compile_error!` when `std` is disabled ([hyperium/http#551](https://github.com/hyperium/http/issues/551)). Until upstream ships `no_std + alloc` on crates.io, bare-metal firmware workspaces patch `http` in their root `Cargo.toml`.

 Cargo applies `[patch.crates-io]` only at the **workspace root** `Cargo.toml` — patches in library dependencies are ignored by downstream builds.

### 1. Depending on `zenwave` from Git (`main`)

```toml
[dependencies]
zenwave = { git = "https://github.com/zen-rs/zenwave", branch = "main", default-features = false, features = [
    "embedded-tls", # or "embedded-backend" for plaintext HTTP/1.1 only
] }

[patch.crates-io]
http = { git = "https://github.com/lexoliu/http", branch = "v1.5-no-std" }
```

### 2. Depending on a released `zenwave` version

If your firmware pins a crates.io release before the next `http-kit` release is cut, patch `http-kit` and `http-kit-h1` alongside `http`:

```toml
[dependencies]
zenwave = { version = "0.12", default-features = false, features = ["embedded-tls"] }

[patch.crates-io]
http = { git = "https://github.com/lexoliu/http", branch = "v1.5-no-std" }
http-kit = { git = "https://github.com/zen-rs/http-kit", branch = "main" }
http-kit-h1 = { git = "https://github.com/zen-rs/http-kit", branch = "main" }
```

`v1.5-no-std` branches directly off the released `v1.5.0` tag of `hyperium/http`, keeping `std` builds byte-for-byte compatible when host tools or proc-macros in the same workspace resolve `http` with default features. Once upstream `http` publishes `no_std + alloc` support, remove the `http` line from `[patch.crates-io]` with no code changes.

## Feature matrix in `no_std + alloc`

Always set `default-features = false` on bare-metal targets.

| Feature / API | `embedded-backend` | `embedded-tls` | Requires `std` |
|---|---|---|---|
| `EmbeddedBackend` / `EmbeddedRunner` (HTTP/1.1) | Yes | Yes | No |
| HTTPS (`rustls` unbuffered TLS 1.2 / 1.3) | No | Yes | No |
| `Client` (`get`, `post`, `put`, `delete`, `json_body`, `bytes_body`, `stream_body`) | Yes | Yes | No |
| `ResponseExt` (`into_json`, `into_string`, `into_bytes`, `into_bytes_with_limit`, `into_sse`, `error_for_status`) | Yes | Yes | No |
| `FollowRedirect`, `BearerAuth`, `BasicAuth`, `ErrorForStatus`, `Timeout`, `Retry`, `Multipart` | Yes | Yes | No |
| `Cache`, `CookieStore`, `.form()`, `.reader_body()` | No | No | Yes (`std`) |
| `.file_body()`, `.download_to_path()`, `.enable_persistent_cookie()` | No | No | Yes (OS reactor) |

## Target setup: ESP32-C6 (`riscv32imac-unknown-none-elf`)

ESP32-C6 uses a standard 32-bit RISC-V core with hardware atomics (`RV32IMAC`), 512 KiB on-chip HP SRAM, Wi-Fi 6, and hardware cryptographic peripherals, so it builds with upstream `rustup` toolchains without a custom Xtensa compiler fork:

```sh
rustup target add riscv32imac-unknown-none-elf
```

### Memory budget recommendations (512 KiB HP SRAM)

- Reserve **128–192 KiB** for `esp_alloc::heap_allocator!` when running Wi-Fi (`esp-radio`) alongside TLS 1.3 handshakes and X.509 chain verification.
- Bound untrusted response bodies with `ResponseExt::into_bytes_with_limit(limit)` or consume `response.into_body().into_data_stream()` chunk-by-chunk; `EmbeddedRunner` uses a 2-frame bounded channel so TCP receive windows apply backpressure automatically.
- Size `TcpClientState<N, TX, RX>` buffers to `2048` or `4096` bytes per active socket.

### Wiring `embassy-net`, `embassy-time`, and `rustls` on ESP32-C6

```rust
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use embassy_net::{
    Stack,
    dns::DnsSocket,
    tcp::client::{TcpClient, TcpClientState},
};
use embassy_time::{Duration as EmbassyDuration, Instant, Timer};
use rustls_pki_types::UnixTime;
use serde::{Deserialize, Serialize};
use zenwave::{
    Client, Transport,
    backend::{EmbeddedBackend, EmbeddedRunner, EmbeddedTimer},
};

/// Bridges `embassy-time` to Zenwave's transport deadlines and `Timeout` / `Retry` middleware.
#[derive(Debug, Clone, Copy)]
struct EmbassyTimer;

impl EmbeddedTimer for EmbassyTimer {
    type After = Timer;

    fn after(&self, duration: Duration) -> Self::After {
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        Timer::after(EmbassyDuration::from_micros(micros))
    }
}

/// Supplies wall-clock time (synchronised via SNTP after DHCP) to `rustls` certificate validation.
#[derive(Debug)]
struct SntpTimeProvider {
    boot_unix_secs: u64,
}

impl rustls::time_provider::TimeProvider for SntpTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        let elapsed = Instant::now().as_secs();
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.boot_unix_secs.saturating_add(elapsed),
        )))
    }
}

#[embassy_executor::task]
async fn zenwave_net_runner(stack: Stack<'static>, runner: EmbeddedRunner) {
    let tcp_state = TcpClientState::<1, 4096, 4096>::new();
    let tcp = TcpClient::new(stack, &tcp_state);
    let dns = DnsSocket::new(stack);
    runner.run_with_timer(&tcp, &dns, &EmbassyTimer).await;
}

#[derive(Serialize, Deserialize)]
struct DeviceReport<'a> {
    chip: &'a str,
}

async fn send_telemetry(
    spawner: embassy_executor::Spawner,
    stack: Stack<'static>,
    root_ca_pem: &[u8],
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    boot_unix_secs: u64,
) -> Result<(), zenwave::Error> {
    let time_provider = Arc::new(SntpTimeProvider { boot_unix_secs });
    let transport = Transport::builder()
        .extra_root_certificates_pem(root_ca_pem)?
        .embedded_tls_provider(crypto_provider, time_provider)
        .connect_timeout(Duration::from_secs(10))
        .response_head_timeout(Duration::from_secs(15))
        .body_idle_timeout(Duration::from_secs(15))
        .build()?;

    let (backend, runner) = EmbeddedBackend::channel(transport);
    spawner.spawn(zenwave_net_runner(stack, runner)).ok();

    let mut client = backend
        .with_clock(EmbassyTimer)
        .follow_redirect()
        .retry(2)
        .timeout(Duration::from_secs(30))
        .bearer_auth("device-secret")
        .error_for_status();

    let status = client
        .post("https://10.0.2.1:8443/v1/telemetry")?
        .json_body(&DeviceReport { chip: "esp32c6" })?
        .await?
        .status();

    tracing::info!(%status, "telemetry delivered");
    Ok(())
}
```

For `crypto_provider` on `riscv32imac-unknown-none-elf`, pass a pure-Rust `no_std` provider such as [`rustls-rustcrypto`](https://crates.io/crates/rustls-rustcrypto) (`Arc::new(rustls_rustcrypto::provider())`), or an ESP32-C6 hardware-accelerated provider backed by `esp-hal`'s SHA/AES/ECC peripherals and `esp_hal::rng::Rng`.

## Running in `esp-emulator` (`esp-emu`)

[`espressif/esp-emulator`](https://github.com/espressif/esp-emulator) emulates ESP32-C6's RV32IMAC CPU, HP/LP SRAM, hardware RNG/crypto peripherals, virtual Wi-Fi AP (`myssid` / `mypassword`), OpenETH, and user-mode NAT (`--net user`) without root privileges or firmware code changes:

1. Build and merge a bootable ESP32-C6 flash image with `espflash`:
   ```sh
   cargo build --release --target riscv32imac-unknown-none-elf
   espflash save-image --chip esp32c6 --merge \
     target/riscv32imac-unknown-none-elf/release/firmware \
     target/esp32c6-merged.bin
   ```
2. Run headless against a local server on the host (`10.0.2.1` inside `--net user` maps to the host's `127.0.0.1`):
   ```sh
   esp-emu --chip esp32c6 \
     --firmware target/esp32c6-merged.bin \
     --net "user,net=10.0.2.0/24" \
     --exit-on "telemetry delivered" \
     --timeout 30s
   ```

### Alternative: ESP-IDF (`std`) on ESP32-C6

If your firmware already builds on ESP-IDF (`riscv32imac-esp-espidf` via `esp-idf-svc`), `std` is present and `[patch.crates-io]` is not needed — enable a `std` backend over your executor or bridge `esp-idf-svc` sockets without disabling `std`.
