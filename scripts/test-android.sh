#!/usr/bin/env bash
# Run the test suite on a physical Android device over adb through cargo-dinghy.
#
# Emulators are deliberately not supported. Point ANDROID_SERIAL at the device
# when more than one is attached (a Tailscale-reachable device is attached with
# `adb connect <ip>:<port>` first). ANDROID_NDK_HOME is taken from the SDK's
# newest NDK when unset.
#
# The plain test binaries have no JVM, so the TLS cases are gated off them;
# the instrumented app under `tests/android` runs those afterwards through
# Gradle (`connectedDebugAndroidTest`), which needs `gradle` on the PATH.
set -euo pipefail

features=${1:-hyper-backend,rustls,ws}

if [[ -z "${ANDROID_SERIAL:-}" ]]; then
  devices=$(adb devices | awk 'NR > 1 && $2 == "device" { print $1 }')
  if [[ $(printf '%s\n' "$devices" | grep -c .) -ne 1 ]]; then
    echo "expected exactly one adb device, found: ${devices:-none}" >&2
    echo "set ANDROID_SERIAL to choose one" >&2
    exit 1
  fi
  export ANDROID_SERIAL=$devices
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}
  ANDROID_NDK_HOME=$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1)
  [[ -n "$ANDROID_NDK_HOME" ]] || { echo "no NDK under $sdk/ndk; set ANDROID_NDK_HOME" >&2; exit 1; }
  export ANDROID_NDK_HOME
fi

abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
case "$abi" in
  arm64-v8a) platform=auto-android-aarch64; target=aarch64-linux-android ;;
  x86_64) platform=auto-android-x86_64; target=x86_64-linux-android ;;
  armeabi-v7a) platform=auto-android-armv7; target=armv7-linux-androideabi ;;
  *) echo "unsupported device ABI $abi" >&2; exit 1 ;;
esac

rustup target add "$target"
echo "::group::plain test binaries on $ANDROID_SERIAL ($abi) with features $features"
cargo dinghy -d "$ANDROID_SERIAL" -p "$platform" test --no-default-features --features "$features"
echo "::endgroup::"

# TLS through the platform verifier needs the JVM: the instrumented app under
# tests/android registers the context with ndk-context and runs those cases.
echo "::group::instrumented TLS suite (tests/android)"
export ANDROID_HOME=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}
command -v gradle >/dev/null || { echo "gradle is required for the instrumented suite" >&2; exit 1; }
(cd "$(dirname "$0")/../tests/android" && gradle --console=plain connectedDebugAndroidTest)
echo "::endgroup::"
