#!/usr/bin/env bash
# Runs the zenwave WASIp3 smoke component inside Wasmtime against the local
# fixture server (`zenwave-test-fixture`) and asserts HTTP round-trips,
# streaming bodies, trailers, middleware, Timeouts, and typed failures.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WASI_TARGET="${WASI_TARGET:-wasm32-wasip2}"
FIXTURE_PID=""
FIXTURE_DIR=""

cleanup() {
  [ -z "$FIXTURE_PID" ] || kill "$FIXTURE_PID" 2>/dev/null || true
  wait "$FIXTURE_PID" 2>/dev/null || true
  [ -z "$FIXTURE_DIR" ] || rm -rf "$FIXTURE_DIR"
}
trap cleanup EXIT

for tool in cargo wasmtime curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done

rustup target add "$WASI_TARGET" >/dev/null

echo "building the test fixture..."
cargo build --manifest-path "$ROOT/tests/fixture-server/Cargo.toml"

FIXTURE_DIR="$(mktemp -d)"
mkfifo "$FIXTURE_DIR/out"
"$ROOT/tests/fixture-server/target/debug/zenwave-test-fixture" \
  >"$FIXTURE_DIR/out" 2>"$FIXTURE_DIR/err.log" &
FIXTURE_PID=$!

if ! IFS= read -r -t 60 fixture <"$FIXTURE_DIR/out"; then
  echo "the fixture did not report its address:" >&2
  cat "$FIXTURE_DIR/err.log" >&2
  exit 1
fi
export ZENWAVE_TEST_BASE_URL="${fixture%/}"
curl -sf "$ZENWAVE_TEST_BASE_URL/get" >/dev/null

ZENWAVE_CLOSED_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
export ZENWAVE_CLOSED_PORT

echo "building the wasip3 smoke component ($WASI_TARGET)..."
cargo build --manifest-path "$ROOT/tests/wasip3/Cargo.toml" --target "$WASI_TARGET"

COMPONENT="$ROOT/tests/wasip3/target/$WASI_TARGET/debug/zenwave_wasip3_smoke.wasm"
echo "running $COMPONENT in wasmtime..."
wasmtime run \
  -W component-model-async \
  -S p3 \
  -S http \
  --env "ZENWAVE_TEST_BASE_URL=$ZENWAVE_TEST_BASE_URL" \
  --env "ZENWAVE_CLOSED_PORT=$ZENWAVE_CLOSED_PORT" \
  "$COMPONENT"

echo "wasip3 smoke test passed"
