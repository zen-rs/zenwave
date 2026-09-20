#!/usr/bin/env bash
# Runs zenwave inside a real Cloudflare Worker (workerd via `wrangler dev`)
# and asserts that requests with and without bodies round-trip. The Worker
# is the skyzen app in tests/workerd, path-patched to this checkout.
set -euo pipefail

PORT="${PORT:-8787}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/tests/workerd"
DEV_PID=""
FIXTURE_PID=""
FIXTURE_DIR=""

cleanup() {
  [ -z "$DEV_PID" ] || kill "$DEV_PID" 2>/dev/null || true
  [ -z "$FIXTURE_PID" ] || kill "$FIXTURE_PID" 2>/dev/null || true
  wait $DEV_PID $FIXTURE_PID 2>/dev/null || true
  [ -z "$FIXTURE_DIR" ] || rm -rf "$FIXTURE_DIR"
}
trap cleanup EXIT

for tool in skyzen wrangler jq curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done

rustup target add wasm32-unknown-unknown >/dev/null

# The Worker bakes the fixture URL in at compile time
# (option_env!("ZENWAVE_TEST_BASE_URL") in tests/workerd/src/app.rs), so the
# fixture must be running — and its address known — before `skyzen build`.
echo "building the test fixture..."
cargo build --manifest-path "$ROOT/tests/fixture-server/Cargo.toml"

FIXTURE_DIR="$(mktemp -d)"
mkfifo "$FIXTURE_DIR/out"
"$ROOT/tests/fixture-server/target/debug/zenwave-test-fixture" \
  >"$FIXTURE_DIR/out" 2>"$FIXTURE_DIR/err.log" &
FIXTURE_PID=$!

# The fixture prints its base URL as the first stdout line, once bound.
if ! IFS= read -r -t 60 fixture <"$FIXTURE_DIR/out"; then
  echo "the fixture did not report its address:" >&2
  cat "$FIXTURE_DIR/err.log" >&2
  exit 1
fi
export ZENWAVE_TEST_BASE_URL="${fixture%/}"
curl -sf "$ZENWAVE_TEST_BASE_URL/get" >/dev/null

echo "building the smoke Worker..."
skyzen build -m "$APP/Skyzen.toml" -p cloudflare

echo "starting workerd on :$PORT..."
wrangler dev --config "$APP/.skyzen/gen/wrangler.toml" --port "$PORT" --local >"$APP/wrangler-dev.log" 2>&1 &
DEV_PID=$!

base="http://127.0.0.1:$PORT"
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null "$base/get"; then break; fi
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "wrangler dev exited early:" >&2
    cat "$APP/wrangler-dev.log" >&2
    exit 1
  fi
  sleep 1
done

fail() { echo "FAIL: $1" >&2; echo "--- wrangler dev log ---" >&2; tail -40 "$APP/wrangler-dev.log" >&2; exit 1; }

echo "GET without a body"
curl -sf "$base/get" | jq -e --arg url "$ZENWAVE_TEST_BASE_URL/get" '.url == $url' >/dev/null || fail "GET did not reach the fixture through zenwave"

echo "POST with a JSON body"
curl -sf -X POST -H 'Content-Type: application/json' --data '{"grant_type":"authorization_code","code":"workerd"}' "$base/post" \
  | jq -e '.json == {"grant_type":"authorization_code","code":"workerd"}' >/dev/null || fail "POST JSON body did not round-trip"

echo "PUT with a bytes body"
curl -sf -X PUT -H 'Content-Type: text/plain' --data-binary 'zenwave inside workerd' "$base/bytes" \
  | jq -e '.data == "zenwave inside workerd"' >/dev/null || fail "PUT bytes body did not round-trip"

echo "workerd smoke test passed"
