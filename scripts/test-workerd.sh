#!/usr/bin/env bash
# Runs zenwave inside a real Cloudflare Worker (workerd via `wrangler dev`)
# and asserts that requests with and without bodies round-trip. The Worker
# is the skyzen app in tests/workerd, path-patched to this checkout.
set -euo pipefail

PORT="${PORT:-8787}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/tests/workerd"

for tool in skyzen wrangler jq curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done

rustup target add wasm32-unknown-unknown >/dev/null

echo "building the smoke Worker..."
skyzen build -m "$APP/Skyzen.toml" -p cloudflare

echo "starting workerd on :$PORT..."
wrangler dev --config "$APP/.skyzen/gen/wrangler.toml" --port "$PORT" --local >"$APP/wrangler-dev.log" 2>&1 &
DEV_PID=$!
trap 'kill "$DEV_PID" 2>/dev/null || true; wait "$DEV_PID" 2>/dev/null || true' EXIT

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
curl -sf "$base/get" | jq -e '.url == "https://httpbingo.org/get"' >/dev/null || fail "GET did not reach httpbingo through zenwave"

echo "POST with a JSON body"
curl -sf -X POST -H 'Content-Type: application/json' --data '{"grant_type":"authorization_code","code":"workerd"}' "$base/post" \
  | jq -e '.json == {"grant_type":"authorization_code","code":"workerd"}' >/dev/null || fail "POST JSON body did not round-trip"

echo "PUT with a bytes body"
curl -sf -X PUT -H 'Content-Type: text/plain' --data-binary 'zenwave inside workerd' "$base/bytes" \
  | jq -e '.data == "zenwave inside workerd"' >/dev/null || fail "PUT bytes body did not round-trip"

echo "workerd smoke test passed"
