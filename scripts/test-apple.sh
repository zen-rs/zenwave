#!/usr/bin/env bash
set -euo pipefail

echo "Running tests (apple backend)..."
cargo nextest run --no-default-features --features apple-backend --workspace
