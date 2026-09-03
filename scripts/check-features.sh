#!/usr/bin/env bash
# Clippy over every feature combination that is valid on this host.
#
# hyper and websockets need exactly one TLS engine, so the powerset is taken
# once per engine with that engine pinned, and once more without any engine
# over the backends that bring their own TLS. `apple-backend` only exists on
# Apple hosts. CI runs one slice per job:
#
#   check-features.sh rustls      powerset of backends and ws with rustls
#   check-features.sh native-tls  the same with native-tls
#   check-features.sh none        backends that need no engine, the default
#                                 feature set, and the engine shorthands
#   check-features.sh             all of the above, in sequence
set -euo pipefail

backends="hyper-backend,curl-backend"
engineless_backends="curl-backend"
if [[ "$(uname -s)" == "Darwin" ]]; then
  backends="$backends,apple-backend"
  engineless_backends="$engineless_backends,apple-backend"
fi

powerset=(
  cargo hack clippy --all-targets
  --feature-powerset --exclude-no-default-features --exclude-all-features
)

with_engine() {
  echo "::group::feature powerset with $1"
  "${powerset[@]}" --features "$1" \
    --include-features "$backends,ws" --at-least-one-of "$backends" \
    -- -D warnings
  echo "::endgroup::"
}

without_engine() {
  echo "::group::feature powerset without a TLS engine"
  "${powerset[@]}" \
    --include-features "$engineless_backends" --at-least-one-of "$engineless_backends" \
    -- -D warnings
  echo "::endgroup::"

  echo "::group::default features and the engine shorthands"
  cargo clippy --all-targets -- -D warnings
  cargo clippy --all-targets --no-default-features --features hyper-rustls,ws -- -D warnings
  cargo clippy --all-targets --no-default-features --features hyper-native-tls,ws -- -D warnings
  echo "::endgroup::"
}

case "${1:-all}" in
  rustls | native-tls) with_engine "$1" ;;
  none) without_engine ;;
  all)
    with_engine rustls
    with_engine native-tls
    without_engine
    ;;
  *) echo "usage: $0 [rustls|native-tls|none|all]" >&2; exit 2 ;;
esac
