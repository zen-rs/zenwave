//! ESP32-C6 e2e smoke for zenwave's embedded `no_std + alloc` backend.
//!
//! Runs in `esp-emu`: joins the emulator's virtual SoftAP (`myssid` /
//! `mypassword`), takes DHCP from `10.0.2.0/24`, wires ESP32-C6's hardware RNG
//! and hardware SHA-256 accelerator into `zenwave::backend::ecdsa_tls13_provider_with_sha256`,
//! and verifies HTTP/1.1 keep-alive connection reuse plus TLS 1.3 PSK ticket
//! session resumption against the host fixture.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::cell::RefCell;
use critical_section::Mutex;
use embassy_executor::Spawner;
use embassy_net::{
    Runner, StackResources,
    dns::DnsSocket,
    tcp::client::{TcpClient, TcpClientState},
};
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    ram,
    rng::Rng,
    sha::{Sha, Sha256},
    timer::timg::TimerGroup,
};
use esp_println::println;
use esp_radio::wifi::{
    AuthenticationMethodConfig, Config, ControllerConfig, Interface, WifiController,
    sta::StationConfig,
};
use rustls::crypto::{
    GetRandomFailed, SecureRandom,
    hash::{self, Hash, HashAlgorithm},
};
use zenwave::{
    Client, ResponseExt, Transport,
    backend::{EmbeddedBackend, EmbeddedRunner, ecdsa_tls13_provider_with_sha256},
};

esp_bootloader_esp_idf::esp_app_desc!();

/// Hardware TRNG adapter for `rustls::crypto::SecureRandom` over `esp_hal::rng::Rng`
/// — requires no global `getrandom` symbol or `unsafe` shim.
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

/// Hardware SHA-256 adapter routing TLS 1.3 transcript hashes, HKDF key
/// derivation, and ECDSA-P256 prehash verification through ESP32-C6's SHA
/// peripheral (`esp_hal::sha::Sha`).
#[derive(Clone, Copy)]
struct EspHwSha256(&'static Mutex<RefCell<Sha<'static>>>);

#[derive(Clone)]
struct EspHwSha256Ctx {
    sha: &'static Mutex<RefCell<Sha<'static>>>,
    buf: Vec<u8>,
}

impl Hash for EspHwSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(EspHwSha256Ctx {
            sha: self.0,
            buf: Vec::with_capacity(128),
        })
    }

    fn hash(&self, mut data: &[u8]) -> hash::Output {
        let mut out = [0u8; 32];
        critical_section::with(|cs| {
            let mut sha = self.0.borrow_ref_mut(cs);
            let mut digest = sha.start::<Sha256>();
            while !data.is_empty() {
                if let Ok(rest) = digest.update(data) {
                    data = rest;
                }
            }
            while digest.finish(&mut out).is_err() {}
        });
        hash::Output::new(&out)
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

impl hash::Context for EspHwSha256Ctx {
    fn fork_finish(&self) -> hash::Output {
        EspHwSha256(self.sha).hash(&self.buf)
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> hash::Output {
        EspHwSha256(self.sha).hash(&self.buf)
    }

    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
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

const SSID: &str = "myssid";
const PASSWORD: &str = "mypassword";

const HTTP_KEEPALIVE_URL: &str = "http://10.0.2.1:8080/zenwave-smoke?seq=1";
const HTTP_CLOSE_URL: &str = "http://10.0.2.1:8080/zenwave-smoke?seq=2&close=1";
const HTTPS_KEEPALIVE_URL: &str = "https://10.0.2.1:8443/zenwave-smoke?seq=1";
const HTTPS_CLOSE_URL: &str = "https://10.0.2.1:8443/zenwave-smoke?seq=2&close=1";
const HTTPS_RESUMED_URL: &str = "https://10.0.2.1:8443/zenwave-smoke?seq=3&close=1";
const SMOKE_MARKER: &str = "ZENWAVE_ESP32C6_SMOKE_OK";

const CA_DER: &[u8] = include_bytes!("../certs/ca.der");
const SMOKE_UNIX_TIME: &str = env!("SMOKE_UNIX_TIME");

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

    // Initialize ESP32-C6's hardware SHA accelerator peripheral.
    let hw_sha = mk_static!(
        Mutex<RefCell<Sha<'static>>>,
        Mutex::new(RefCell::new(Sha::new(peripherals.SHA)))
    );

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
    let seed = u64::from(rng.random()) << 32 | u64::from(rng.random());

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

    let crypto = ecdsa_tls13_provider_with_sha256(EspRng, EspHwSha256(hw_sha));
    let transport = Transport::builder()
        .embedded_tls_provider(Arc::new(crypto), Arc::new(SmokeTimeProvider))
        .extra_root_certificate_der(CA_DER.to_vec())
        .build()
        .unwrap();
    let (client, runner) = EmbeddedBackend::channel(transport);
    spawner.spawn(zenwave_driver(runner, tcp, dns).unwrap());

    Timer::after(Duration::from_millis(100)).await;

    let mut client = client.follow_redirect().error_for_status();
    println!(
        "HEAP_PRE used={} free={}",
        esp_alloc::HEAP.used(),
        esp_alloc::HEAP.free()
    );

    for (name, url, expected_sub) in [
        ("HTTP", HTTP_KEEPALIVE_URL, SMOKE_MARKER),
        ("HTTP_KA", HTTP_CLOSE_URL, SMOKE_MARKER),
        ("HTTPS", HTTPS_KEEPALIVE_URL, "reused=False"),
        ("HTTPS_KA", HTTPS_CLOSE_URL, "reused=False"),
        ("HTTPS_RESUMED", HTTPS_RESUMED_URL, "reused=True"),
    ] {
        println!("REQ_START {} {}", name, url);
        match client.get(url).unwrap().await {
            Ok(resp) => {
                println!("{}_STATUS {}", name, resp.status().as_u16());
                match resp.into_string().await {
                    Ok(body) => {
                        println!("{}_BODY {}", name, body.trim());
                        if body.contains(SMOKE_MARKER) && body.contains(expected_sub) {
                            println!("{}_RESULT PASS", name);
                        } else {
                            println!("{}_RESULT FAIL_BODY_MISMATCH", name);
                        }
                    }
                    Err(e) => println!("{}_RESULT FAIL_BODY {:?}", name, e.to_string()),
                }
            }
            Err(e) => println!("{}_RESULT FAIL_REQ {:?}", name, e.to_string()),
        }
        println!("HEAP_MID {} used={}", name, esp_alloc::HEAP.used());
    }

    // Let the runner task process `close_notify` and reset scratch buffers so
    // `HEAP_POST` reflects steady-state post-exchange memory.
    Timer::after(Duration::from_millis(20)).await;
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
