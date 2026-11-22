#!/usr/bin/env bash
# ESP32-C6 embedded smoke: builds the `tests/esp32c6-smoke` firmware for
# `riscv32imac-unknown-none-elf`, merges it with the ESP-IDF bootloader, and
# runs it under `esp-emu` against a host-side HTTP/HTTPS fixture. The firmware
# joins the emulator's virtual WPA2 SoftAP (`myssid`), takes DHCP from
# 10.0.2.0/24, and issues requests through zenwave's `EmbeddedBackend`; the
# `user` network maps gateway 10.0.2.1 to host loopback.
#
# Requires: nightly Rust with the riscv32imac target, `espflash`, `esp-emu`,
# python3 and openssl. CI installs the first four; see test.yml.
set -euo pipefail

cd "$(dirname "$0")/../tests/esp32c6-smoke"

# Throwaway CA + ECDSA server certificate with `IP:10.0.2.1` SAN. Regenerated
# whenever missing; nothing here is a real secret.
if [ ! -f certs/ca.der ]; then
    mkdir -p certs
    openssl ecparam -genkey -name prime256v1 -out certs/ca.key
    openssl req -new -x509 -key certs/ca.key -out certs/ca.pem \
        -days 30 -subj "/CN=zenwave-smoke-ca"
    openssl ecparam -genkey -name prime256v1 -out certs/server.key
    openssl req -new -key certs/server.key -out certs/server.csr \
        -subj "/CN=10.0.2.1"
    printf "[v3]\nsubjectAltName=IP:10.0.2.1\n" > certs/v3.ext
    openssl x509 -req -in certs/server.csr -CA certs/ca.pem -CAkey certs/ca.key \
        -CAcreateserial -out certs/server.pem -days 30 -extensions v3 \
        -extfile certs/v3.ext
    openssl x509 -in certs/ca.pem -outform DER -out certs/ca.der
fi

cargo build --release
espflash save-image --chip esp32c6 --merge \
    target/riscv32imac-unknown-none-elf/release/zenwave-esp32c6-smoke \
    merged.bin

python3 fixture.py &
FIXTURE_PID=$!
trap 'kill $FIXTURE_PID 2>/dev/null || true' EXIT
sleep 1

esp-emu --chip esp32c6 \
    --firmware merged.bin \
    --elf target/riscv32imac-unknown-none-elf/release/zenwave-esp32c6-smoke \
    --net "user,net=10.0.2.0/24" \
    --timeout 120s \
    --exit-on "SMOKE_DONE"
