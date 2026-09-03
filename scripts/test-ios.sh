#!/usr/bin/env bash
# Run the test suite on an iOS simulator.
#
# The first available iPhone simulator of an installed iOS runtime is booted;
# every test executable is built for the simulator target and run inside the
# simulator with `simctl spawn`, whose exit status is the test binary's. Each
# feature set given as an argument gets a run (default: the Apple backend and
# hyper, each with websockets).
#
# The binaries run as bare processes, not as an app bundle, so App Transport
# Security does not apply to URLSession here; real apps need the
# `NSExceptionDomains` entry described in the README to reach a server that
# only the extra roots trust.
set -euo pipefail

feature_sets=("$@")
if [[ ${#feature_sets[@]} -eq 0 ]]; then
  feature_sets=("apple-backend,ws,rustls" "hyper-backend,rustls,ws")
fi

case "$(uname -m)" in
  arm64) target=aarch64-apple-ios-sim ;;
  x86_64) target=x86_64-apple-ios ;;
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
xcrun simctl boot "$simulator" 2>/dev/null || true # already booted is fine
xcrun simctl bootstatus "$simulator" -b

rustup target add "$target"
for features in "${feature_sets[@]}"; do
  echo "::group::iOS simulator tests: $features"
  executables=$(cargo test --no-run --target "$target" --no-default-features --features "$features" \
      --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true) | .executable // empty')
  [[ -n "$executables" ]] || { echo "no test executables were built" >&2; exit 1; }
  while IFS= read -r executable; do
    echo "--- $(basename "$executable")"
    xcrun simctl spawn "$simulator" "$executable"
  done <<<"$executables"
  echo "::endgroup::"
done
