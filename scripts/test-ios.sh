#!/usr/bin/env bash
# Run the test suite on an iOS simulator through cargo-dinghy.
#
# The first available iPhone simulator of an installed iOS runtime is booted,
# used for every feature set given as arguments (default: the Apple backend
# and hyper, each with websockets), and shut down again.
set -euo pipefail

feature_sets=("$@")
if [[ ${#feature_sets[@]} -eq 0 ]]; then
  feature_sets=("apple-backend,ws,rustls" "hyper-backend,rustls,ws")
fi

case "$(uname -m)" in
  arm64) target=aarch64-apple-ios-sim; platform=auto-ios-aarch64-sim ;;
  x86_64) target=x86_64-apple-ios; platform=auto-ios-x86_64 ;;
  *) echo "unsupported host architecture $(uname -m)" >&2; exit 1 ;;
esac

simulator=$(xcrun simctl list devices available -j \
  | jq -r '.devices | to_entries[] | select(.key | contains("iOS")) | .value[]
           | select(.name | startswith("iPhone")) | .udid' | head -1)
[[ -n "$simulator" ]] || {
  echo "no iPhone simulator is available for an installed iOS runtime" >&2
  exit 1
}

cleanup() {
  xcrun simctl shutdown "$simulator" >/dev/null 2>&1 || true
}
trap cleanup EXIT
echo "booting simulator $simulator"
xcrun simctl boot "$simulator" || true # already booted is fine
xcrun simctl bootstatus "$simulator" -b

rustup target add "$target"
for features in "${feature_sets[@]}"; do
  echo "::group::iOS simulator tests: $features"
  cargo dinghy -d "$simulator" -p "$platform" test --no-default-features --features "$features"
  echo "::endgroup::"
done
