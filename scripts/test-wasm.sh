#!/usr/bin/env bash
set -euo pipefail

BROWSER="${1:-chrome}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required but not installed" >&2
  exit 1
fi

rustup target add wasm32-unknown-unknown

# The wasm tests bake the fixture URL in at compile time
# (option_env!("ZENWAVE_TEST_BASE_URL") in tests/common/mod.rs), so the
# fixture must be running — and its address known — before wasm-pack builds.
echo "building the test fixture..."
cargo build --manifest-path "$ROOT/tests/fixture-server/Cargo.toml"

FIXTURE_DIR="$(mktemp -d)"
mkfifo "$FIXTURE_DIR/out"
"$ROOT/tests/fixture-server/target/debug/zenwave-test-fixture" \
  >"$FIXTURE_DIR/out" 2>"$FIXTURE_DIR/err.log" &
FIXTURE_PID=$!
trap 'kill "$FIXTURE_PID" 2>/dev/null || true; wait "$FIXTURE_PID" 2>/dev/null || true; rm -rf "$FIXTURE_DIR"' EXIT

# The fixture prints its base URL as the first stdout line, once bound.
if ! IFS= read -r -t 60 base <"$FIXTURE_DIR/out"; then
  echo "the fixture did not report its address:" >&2
  cat "$FIXTURE_DIR/err.log" >&2
  exit 1
fi
export ZENWAVE_TEST_BASE_URL="${base%/}"
curl -sf "$ZENWAVE_TEST_BASE_URL/get" >/dev/null

echo "Running wasm-pack tests for browser=${BROWSER} against $ZENWAVE_TEST_BASE_URL..."
wasm-pack test --"${BROWSER}" --headless -- --no-default-features
