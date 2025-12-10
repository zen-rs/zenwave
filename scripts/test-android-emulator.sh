#!/usr/bin/env bash
set -euo pipefail

echo "Finding and running test binaries..."

for binary in target/x86_64-linux-android/debug/deps/zenwave-*; do
    if [ -f "$binary" ] && [ -x "$binary" ] && [[ ! "$binary" == *.d ]]; then
        name=$(basename "$binary")
        echo "Running test: $name"
        adb push "$binary" /data/local/tmp/"$name"
        adb shell chmod +x /data/local/tmp/"$name"
        adb shell "/data/local/tmp/$name --test-threads=1" || true
    fi
done

echo "Android emulator tests completed."
