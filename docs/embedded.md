# Embedded (`no_std + alloc`) Guide

Zenwave runs on bare-metal microcontrollers that provide a global allocator (`alloc`) and hardware atomics, without an operating system, POSIX sockets, `compio-buf`, or `http-kit-io`. The reference target is **Espressif ESP32-C6** (`riscv32imac-unknown-none-elf`) with `esp-hal`, `esp-radio`, `embassy-net`, and `esp-emu`.

## Architecture on bare metal

Completion-based host I/O (`compio`, `http-kit-io`) exists for kernel-owned buffers (`io_uring`, IOCP) and is excluded completely when `default-features = false` disables `std`. Instead:

- **HTTP/1.1 framing & Keep-Alive** uses the sans-IO state machine in `http_kit_h1::proto` (`encode_request_head`, `BodyEncoder`, `parse_response_head`, `BodyDecoder`) directly over `bytes::BytesMut`. `EmbeddedRunner` keeps a single idle connection slot for same-origin HTTP/1.1 reuse, closes stale sockets before redialing so single-socket `embassy-net` pools never exhaust, and returns short responses directly as `Body::from_bytes` without allocating a body channel.
- **Sockets and DNS** come from [`embedded-io-async`](https://crates.io/crates/embedded-io-async) (`Read`, `Write`) and [`embedded-nal-async`](https://crates.io/crates/embedded-nal-async) (`TcpConnect`, `Dns`), implemented out of the box by `embassy_net::tcp::client::TcpClient` and `embassy_net::dns::DnsSocket`.
- **TLS 1.3 (and optional TLS 1.2)** (`embedded-tls`, `embedded-tls-ecdsa`, `embedded-tls12`) drives `rustls::client::UnbufferedClientConnection` over the `embedded-io-async` socket with a bounded `no_std + alloc` `ClientSessionStore` enabled by default for TLS 1.3 PSK ticket resumption (`TransportBuilder::embedded_tls_session_cache_capacity`).
- **Actor split for `!Send` hardware stacks**: embedded network handles borrow peripheral buffers and are `!Send`. `EmbeddedBackend::channel(transport)` returns a `Clone + Send + Sync` `EmbeddedBackend` (implementing `zenwave::Client` and composing with `FollowRedirect`, `BearerAuth`, `BasicAuth`, `ErrorForStatus`, `Timeout`, and `Retry`) paired with an `EmbeddedRunner` future that stays on the Embassy task owning the stack. Request and response bodies stream across bounded channels rather than buffering whole payloads in SRAM.

## Configuring `[patch.crates-io]`

Upstream [`http`](https://crates.io/crates/http) `1.5.0` defines a `std` feature flag in its manifest, but still emits a `compile_error!` when `std` is disabled ([hyperium/http#551](https://github.com/hyperium/http/issues/551)). Until upstream ships `no_std + alloc` on crates.io, bare-metal firmware workspaces patch `http` in their root `Cargo.toml`.

 Cargo applies `[patch.crates-io]` only at the **workspace root** `Cargo.toml` — patches in library dependencies are ignored by downstream builds.

### 1. Depending on `zenwave` from Git (`main`)

```toml
[dependencies]
zenwave = { git = "https://github.com/zen-rs/zenwave", branch = "main", default-features = false, features = [
    "embedded-tls-ecdsa", # or "embedded-tls" / "embedded-backend"
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

Always set `default-features = false` on bare-metal targets. `FollowRedirect` resolves RFC 3986 relative `Location` targets directly on `http::Uri`, so `embedded-*` builds do not pull `url`, `idna`, or ICU4X normalization tables.

| Feature / API | `embedded-backend` | `embedded-tls` | `embedded-tls-ecdsa` | `embedded-tls12` | Requires `std` |
|---|---|---|---|---|---|
| `EmbeddedBackend` / `EmbeddedRunner` (HTTP/1.1 + Keep-Alive) | Yes | Yes | Yes | Yes | No |
| HTTPS (`rustls` unbuffered TLS 1.3 + bounded ticket store) | No | Yes | Yes | Yes | No |
| Lean `ecdsa_tls13_provider` / hardware RNG & SHA-256 hooks | No | No | Yes | Optional | No |
| Legacy TLS 1.2 alongside TLS 1.3 | No | No | No | Yes | No |
| `Client` (`get`, `post`, `put`, `delete`, `json_body`, `bytes_body`, `stream_body`) | Yes | Yes | Yes | Yes | No |
| `ResponseExt` (`into_json`, `into_string`, `into_bytes`, `into_bytes_with_limit`, `into_sse`, `error_for_status`) | Yes | Yes | Yes | Yes | No |
| `FollowRedirect`, `BearerAuth`, `BasicAuth`, `ErrorForStatus`, `Timeout`, `Retry`, `Multipart` | Yes | Yes | Yes | Yes | No |
| `Cache`, `.form()`, `.reader_body()`, `.download()`, `.download_bytes()` | No | No | No | No | Yes (`std`) |
| `CookieStore` | No | No | No | No | Yes (`cookie`) |
| `.file_body()`, `.download().to_path()`, `.download_to_path()`, `.enable_persistent_cookie()` | No | No | No | No | Yes (OS reactor) |

## Target setup: ESP32-C6 (`riscv32imac-unknown-none-elf`)

ESP32-C6 uses a standard 32-bit RISC-V core with hardware atomics (`RV32IMAC`), 512 KiB on-chip HP SRAM, Wi-Fi 6, and hardware cryptographic peripherals, so it builds with upstream `rustup` toolchains without a custom Xtensa compiler fork:

```sh
rustup target add riscv32imac-unknown-none-elf
```

### Memory budget & measured footprint (512 KiB HP SRAM)

Measured end-to-end on `esp-emu 1.2.0` with [`tests/esp32c6-smoke`](../tests/esp32c6-smoke) (`esp-hal 1.2.2` + `esp-radio 1.0.0-beta.1` + `embassy-net 0.9.1`, Wi-Fi associated + DHCP up, `embedded-tls-ecdsa` wired to ESP32-C6's hardware `Rng` and `Sha` peripherals):

| Metric | `embedded-tls` + `rustls-rustcrypto` (baseline) | `embedded-tls-ecdsa` + HW RNG/SHA-256 | Delta |
|---|---:|---:|---:|
| Merged app partition size (`espflash`) | `1,551,120` B (1.48 MiB) | `1,068,416` B (1.02 MiB) | **-471.4 KiB (-31.1%)** |
| `.text` + `.rodata` (Flash) | `1,432,980` B (`1,166,916` + `266,064`) | `950,942` B (`822,494` + `128,448`) | **-470.7 KiB (-33.6%)** |
| `zenwave_driver` Embassy task slot (`.bss`) | `6,184` B | `3,744` B | **-2,440 B (-39.5%)** |
| Heap baseline (`HEAP_PRE`, Wi-Fi + DHCP ready) | `50,976` B | `51,220` B | +244 B |
| Active TLS 1.3 exchange heap (`HEAP_MID HTTPS`) | `67,656` B | `65,520` B (`65,408` B on resumed ticket) | **-2.1 KiB** |
| Post-exchange steady-state heap (`HEAP_POST`) | `67,656` B | `59,528` B (with cached TLS 1.3 tickets) | **-7.9 KiB** |

- Reserve **128–192 KiB** for `esp_alloc::heap_allocator!` when running Wi-Fi (`esp-radio`) alongside TLS 1.3 handshakes and X.509 chain verification.
- Bound untrusted response bodies with `ResponseExt::into_bytes_with_limit(limit)` or consume `response.into_body().into_data_stream()` chunk-by-chunk; short responses that arrive with the response head return directly as `Body::from_bytes`, while multi-frame bodies stream over a 2-frame bounded channel so TCP receive windows apply backpressure automatically.
- Size `TcpClientState<N, TX, RX>` buffers to `2048` or `4096` bytes per active socket; `N = 1` suffices for sequential requests because `EmbeddedRunner` reuses the open keep-alive socket for same-origin calls and closes it before dialing another origin.

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

### Choosing a TLS `CryptoProvider`

#### 1. Recommended: `embedded-tls-ecdsa` + MCU hardware RNG / SHA-256

Enable `features = ["embedded-tls-ecdsa"]` to use `zenwave::backend::ecdsa_tls13_provider` (software SHA-256) or `ecdsa_tls13_provider_with_sha256` (hardware SHA-256). It supports RFC 8446's mandatory `TLS13_AES_128_GCM_SHA256` suite, X25519 + P-256 ECDHE, and ECDSA-P256-SHA256 certificates without linking RSA (`crypto_bigint`), SHA-384/512, P-384, Ed25519, `ChaCha20`, or `getrandom` — no `--cfg getrandom_backend="custom"` or `#[no_mangle]` shim is required:

```rust
use esp_hal::rng::Rng;
use rustls::crypto::{GetRandomFailed, SecureRandom};
use zenwave::backend::ecdsa_tls13_provider;

#[derive(Debug, Clone, Copy)]
struct EspRng;

impl SecureRandom for EspRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), GetRandomFailed> {
        let rng = Rng::new();
        for chunk in dest.chunks_mut(4) {
            let word = rng.random().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

let crypto_provider = Arc::new(ecdsa_tls13_provider(EspRng));
```

To also offload TLS 1.3 transcript hashes, HKDF key derivation, and ECDSA prehash digests to ESP32-C6's SHA peripheral (allowing LTO to dead-code-eliminate software `sha2`), pass a `rustls::crypto::hash::Hash` implementation over `esp_hal::sha::Sha` to `ecdsa_tls13_provider_with_sha256(EspRng, EspHwSha256(hw_sha))` — see [`tests/esp32c6-smoke/src/main.rs`](../tests/esp32c6-smoke/src/main.rs) for the complete implementation.

#### 2. Full algorithm suite (RSA / P-384 / Ed25519 / TLS 1.2): `rustls-rustcrypto`

When peers present RSA or P-384 certificates or require legacy TLS 1.2 (`features = ["embedded-tls12"]`), pass [`rustls-rustcrypto`](https://crates.io/crates/rustls-rustcrypto) (`Arc::new(rustls_rustcrypto::provider())`) with its `std` default feature disabled:

```toml
rustls-rustcrypto = { version = "0.1.0-pre.0", default-features = false, features = ["alloc", "tls12"] }
rustls = { version = "0.23", default-features = false, features = ["hashbrown", "tls12"] }
rustls-pki-types = { version = "1", default-features = false, features = ["alloc"] }
```

`rustls-rustcrypto`'s `getrandom` dependency has no built-in backend on `*-none-elf` targets; add `--cfg getrandom_backend="custom"` to `.cargo/config.toml` rustflags and export `__getrandom_v03_custom` backed by `esp_hal::rng::Rng`.

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
     --elf target/riscv32imac-unknown-none-elf/release/firmware \
     --net "user,net=10.0.2.0/24" \
     --exit-on "telemetry delivered" \
     --timeout 30s
   ```

Notes measured while bringing up the smoke firmware:

- **Console output**: `esp-println`'s `auto` printer picks UART vs. USB Serial JTAG by probing USB SOF interrupts; with no USB host attached the detection is unreliable and firmware logs can go silent. Lock the transport explicitly: `esp-println = { default-features = false, features = ["<chip>", "log-04", "uart", "critical-section"] }`.
- **`esp-rtos` executor start**: crates.io `esp-rtos 0.4` takes two arguments — `esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0)`.
- `TcpClient` in `embassy-net 0.9` is generic over socket count and buffer sizes (`TcpClient<'d, N, TX, RX>`); a `TcpClientState<N, TX, RX>` in a `static_cell` keeps the runner task `'static`.
- Version matrix verified end-to-end on `esp-emu 1.2.0`: `esp-hal 1.2.2`, `esp-radio 1.0.0-beta.1`, `esp-rtos 0.4.0`, `esp-alloc 0.11.0`, `esp-bootloader-esp-idf 0.6.0`, `esp-println 0.18.0` (`uart`), `esp-metadata-generated 0.5.3`, `embassy-net 0.9.1`, `embassy-executor 0.10.0`.

A complete, CI-exercised reference firmware lives at [`tests/esp32c6-smoke`](../tests/esp32c6-smoke): it joins the emulator's WPA2 SoftAP, wires ESP32-C6's hardware RNG and SHA-256 accelerator into `ecdsa_tls13_provider_with_sha256`, and verifies HTTP/1.1 keep-alive reuse plus TLS 1.3 PSK session ticket resumption against a host fixture via `scripts/test-esp32c6.sh`.

### Alternative: ESP-IDF (`std`) on ESP32-C6

If your firmware already builds on ESP-IDF (`riscv32imac-esp-espidf` via `esp-idf-svc`), `std` is present and `[patch.crates-io]` is not needed — enable a `std` backend over your executor or bridge `esp-idf-svc` sockets without disabling `std`.
