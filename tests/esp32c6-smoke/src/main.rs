//! ESP32-C6 e2e smoke for zenwave's embedded `no_std + alloc` backend.
//!
//! Runs in `esp-emu`: joins the emulator's virtual SoftAP (`myssid` /
//! `mypassword`), takes DHCP from `10.0.2.0/24`, then issues an HTTP GET to
//! the host-side fixture at `10.0.2.1:8080` through zenwave's
//! `EmbeddedBackend` + `FollowRedirect` middleware and prints the response.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::ToString;
use alloc::sync::Arc;
use embassy_executor::Spawner;
use embassy_net::{
    Runner,
    StackResources,
    dns::DnsSocket,
    tcp::client::{TcpClient, TcpClientState},
};
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{clock::CpuClock, ram, rng::Rng, timer::timg::TimerGroup};
use esp_println::println;
use esp_radio::wifi::{
    AuthenticationMethodConfig,
    Config,
    ControllerConfig,
    Interface,
    WifiController,
    sta::StationConfig,
};
use zenwave::{
    Client,
    ResponseExt,
    Transport,
    backend::{EmbeddedBackend, EmbeddedRunner},
};

esp_bootloader_esp_idf::esp_app_desc!();

/// `getrandom` custom backend: fills from the ESP32-C6 hardware RNG so
/// `rustls-rustcrypto` can draw key-exchange secrets on `*-none-elf`.
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    let buf = unsafe { core::slice::from_raw_parts_mut(dest, len) };
    let rng = esp_hal::rng::Rng::new();
    for chunk in buf.chunks_mut(4) {
        let word = rng.random().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    Ok(())
}

// Full `.dram2_uninit` region for this chip.
const DRAM2_UNINIT_SIZE: usize = {
    let range: core::ops::Range<usize> = esp_metadata_generated::memory_range!("DRAM2_UNINIT");
    range.end - range.start
};

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

// esp-emu's built-in virtual SoftAP defaults.
const SSID: &str = "myssid";
const PASSWORD: &str = "mypassword";

// The esp-emu `user` network maps the subnet gateway 10.0.2.1 to the host's
// 127.0.0.1, where the smoke fixture listens on :8080 (HTTP) and :8443 (HTTPS).
const HTTP_URL: &str = "http://10.0.2.1:8080/zenwave-smoke";
const HTTPS_URL: &str = "https://10.0.2.1:8443/zenwave-smoke";
const SMOKE_MARKER: &str = "ZENWAVE_ESP32C6_SMOKE_OK";

// Throwaway CA for the fixture server certificate (SAN `IP:10.0.2.1`),
// generated next to `fixture.py` and embedded as the only trust anchor.
const CA_DER: &[u8] = include_bytes!("../certs/ca.der");

// Build instant baked in by build.rs; the fixture cert is valid for 30 days
// around it, so this is a real timestamp inside its validity window.
const SMOKE_UNIX_TIME: &str = env!("SMOKE_UNIX_TIME");

/// rustls `TimeProvider` for the emulator: certificates are verified against
/// the fixed build instant (no RTC/SNTP needed for the smoke run).
#[derive(Debug)]
struct SmokeTimeProvider;

impl rustls::time_provider::TimeProvider for SmokeTimeProvider {
    fn current_time(&self) -> Option<rustls_pki_types::UnixTime> {
        let secs = SMOKE_UNIX_TIME.parse::<u64>().unwrap();
        Some(rustls_pki_types::UnixTime::since_unix_epoch(
            core::time::Duration::from_secs(secs),
        ))
    }
}

#[esp_hal::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    esp_alloc::heap_allocator!(#[ram(reclaimed)] size: DRAM2_UNINIT_SIZE);
    esp_alloc::heap_allocator!(size: 192 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let station_config = Config::Station(
        StationConfig::default()
            .with_ssid(SSID.try_into().unwrap())
            .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
                PASSWORD.try_into().unwrap(),
            )),
    );

    println!("WIFI_INIT");
    let wifi_interface = esp_radio::wifi::Interface::station();
    let controller = esp_radio::wifi::WifiController::new(
        peripherals.WIFI,
        ControllerConfig::default().with_initial_config(station_config),
    )
    .unwrap();

    let config = embassy_net::Config::dhcpv4(Default::default());
    let rng = Rng::new();
    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    let (stack, net_runner) = embassy_net::new(
        wifi_interface,
        config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    spawner.spawn(connection(controller).unwrap());
    spawner.spawn(net_task(net_runner).unwrap());

    stack.wait_config_up().await;
    if let Some(config) = stack.config_v4() {
        println!("DHCP_UP {}", config.address);
    }

    let tcp = mk_static!(
        TcpClient<'static, 1, 4096, 4096>,
        TcpClient::new(
            stack,
            mk_static!(
                TcpClientState<1, 4096, 4096>,
                TcpClientState::<1, 4096, 4096>::new()
            )
        )
    );
    let dns = mk_static!(DnsSocket<'static>, DnsSocket::new(stack));

    let transport = Transport::builder()
        .embedded_tls_provider(
            Arc::new(rustls_rustcrypto::provider()),
            Arc::new(SmokeTimeProvider),
        )
        .extra_root_certificate_der(CA_DER.to_vec())
        .build()
        .unwrap();
    let (client, runner) = EmbeddedBackend::channel(transport);
    spawner.spawn(zenwave_driver(runner, tcp, dns).unwrap());

    // Give the driver task a beat to start draining the request channel.
    Timer::after(Duration::from_millis(100)).await;

    let mut client = client.follow_redirect().error_for_status();
    println!(
        "HEAP_PRE used={} free={}",
        esp_alloc::HEAP.used(),
        esp_alloc::HEAP.free()
    );
    for (name, url) in [("HTTP", HTTP_URL), ("HTTPS", HTTPS_URL)] {
        println!("REQ_START {} {}", name, url);
        match client.get(url).unwrap().await {
            Ok(resp) => {
                println!("{}_STATUS {}", name, resp.status().as_u16());
                match resp.into_string().await {
                    Ok(body) => {
                        let text = alloc::string::String::from_utf8_lossy(body.as_ref());
                        println!("{}_BODY {}", name, text);
                        if text.contains(SMOKE_MARKER) {
                            println!("{}_RESULT PASS", name);
                        } else {
                            println!("{}_RESULT FAIL_NO_MARKER", name);
                        }
                    }
                    Err(e) => println!("{}_RESULT FAIL_BODY {:?}", name, e.to_string()),
                }
            }
            Err(e) => println!("{}_RESULT FAIL_REQ {:?}", name, e.to_string()),
        }
        println!("HEAP_MID used={}", esp_alloc::HEAP.used());
    }
    println!(
        "HEAP_POST used={} free={}",
        esp_alloc::HEAP.used(),
        esp_alloc::HEAP.free()
    );
    println!("SMOKE_DONE");

    loop {
        Timer::after(Duration::from_secs(60)).await;
    }
}

#[embassy_executor::task]
async fn zenwave_driver(
    runner: EmbeddedRunner,
    tcp: &'static TcpClient<'static, 1, 4096, 4096>,
    dns: &'static DnsSocket<'static>,
) {
    runner.run(tcp, dns).await
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    loop {
        match controller.connect_async().await {
            Ok(info) => {
                println!("WIFI_UP {:?}", info);
                let info = controller.wait_for_disconnect_async().await.ok();
                println!("WIFI_DOWN {:?}", info);
            }
            Err(e) => println!("WIFI_FAIL {:?}", e),
        }
        Timer::after(Duration::from_millis(2000)).await;
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface>) {
    runner.run().await
}
