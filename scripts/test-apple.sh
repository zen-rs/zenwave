#!/usr/bin/env bash
set -euo pipefail

echo "Running tests (apple backend)..."
cargo test --no-default-features --features apple-backend --workspace
