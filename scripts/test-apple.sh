#!/usr/bin/env bash
set -euo pipefail

echo "Running fmt..."
cargo fmt --all -- --check

echo "Running clippy (apple backend)..."
cargo clippy --all-targets --no-default-features --features apple-backend --workspace -- -D warnings

echo "Running tests (apple backend)..."
cargo test --no-default-features --features apple-backend --workspace
