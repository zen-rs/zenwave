#!/usr/bin/env bash
set -euo pipefail

echo "Running fmt..."
cargo fmt --all -- --check

echo "Running clippy (all features)..."
cargo clippy --all-targets --all-features --workspace -- -D warnings

echo "Running tests (all features)..."
cargo test --all-features --workspace

echo "Running clippy (curl backend only)..."
cargo clippy --all-targets --no-default-features --features curl-backend --workspace -- -D warnings

echo "Running tests (curl backend only)..."
cargo test --no-default-features --features curl-backend --workspace
