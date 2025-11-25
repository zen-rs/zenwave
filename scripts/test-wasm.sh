#!/usr/bin/env bash
set -euo pipefail

BROWSER="${1:-chrome}"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required but not installed" >&2
  exit 1
fi

rustup target add wasm32-unknown-unknown

echo "Running wasm-pack tests for browser=${BROWSER}..."
wasm-pack test --"${BROWSER}" --headless -- --no-default-features
