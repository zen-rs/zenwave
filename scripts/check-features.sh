#!/usr/bin/env bash
# Clippy over every feature combination that is valid on this host.
#
# hyper and websockets need a TLS engine, so the powerset is taken
# once per engine with that engine pinned, and once more without any engine
# over the backends that bring their own TLS. `apple-backend` only exists on
# Apple hosts. CI runs one slice per job:
#
#   check-features.sh rustls      powerset of backends and ws with rustls
#   check-features.sh native-tls  the same with native-tls
#   check-features.sh none        backends that need no engine, the default
#                                 feature set, and the engine shorthands
#   check-features.sh native      powerset of the native backend's runtimes,
#                                 HTTP/2, HTTP/3 and kernel TLS, alone and beside the defaults
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
  # Backends that bring their own TLS never compile the engine, so an engine
  # beside them alone is a dead dependency under `cargo::unused_dependencies`.
  # Every combination needs both a backend and a connector (`hyper-backend`
  # or `ws`) that compiles the engine against it.
  local include="$backends,ws,http2"
  # http3 needs QUIC-capable TLS, so it only exists in the rustls slice.
  [[ "$1" == rustls ]] && include="$include,http3"
  "${powerset[@]}" --features "$1" \
    --include-features "$include" --at-least-one-of "$backends" \
    --at-least-one-of "hyper-backend,ws" \
    -- -D warnings
  echo "::endgroup::"
}

without_engine() {
  echo "::group::feature powerset without a TLS engine"
  # `--at-least-one-of` wants two or more features; with a single engineless
  # backend the powerset (minus the empty set) is that backend alone.
  local -a nonempty=()
  if [[ "$engineless_backends" == *,* ]]; then
    nonempty=(--at-least-one-of "$engineless_backends")
  fi
  "${powerset[@]}" --include-features "$engineless_backends" "${nonempty[@]}" -- -D warnings
  echo "::endgroup::"

  echo "::group::default features and the engine shorthands"
  cargo clippy --all-targets -- -D warnings
  cargo clippy --all-targets --no-default-features --features hyper-rustls,ws -- -D warnings
  cargo clippy --all-targets --no-default-features --features hyper-native-tls,ws -- -D warnings
  echo "::endgroup::"
}

native() {
  # The native backend brings rustls itself; alone it has no default backend
  # (its caller drives it), and a driver runtime makes it one. `native-http2`
  # adds HTTP/2 and `native-http3` adds quiche on top of any of them.
  echo "::group::native backend powerset"
  "${powerset[@]}" --include-features native-backend,native-compio,native-tokio,native-http2,native-http3,native-kernel-tls \
    --at-least-one-of native-backend,native-compio,native-tokio,native-http2,native-http3,native-kernel-tls -- -D warnings
  echo "::endgroup::"

  echo "::group::native and embedded backends beside the default features"
  cargo clippy --all-targets --features native-compio,native-tokio,native-http2,native-http3,native-kernel-tls,embedded-tls -- -D warnings
  echo "::endgroup::"

  echo "::group::embedded no_std + alloc backend"
  cargo clippy --lib --no-default-features --features embedded-backend -- -D warnings
  cargo clippy --lib --no-default-features --features embedded-tls -- -D warnings
  echo "::endgroup::"
}

case "${1:-all}" in
  rustls | native-tls) with_engine "$1" ;;
  none) without_engine ;;
  native) native ;;
  all)
    with_engine rustls
    with_engine native-tls
    without_engine
    native
    ;;
  *) echo "usage: $0 [rustls|native-tls|none|native|all]" >&2; exit 2 ;;
esac
