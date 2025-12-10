# Building Zenwave for Android

Zenwave supports Android targets using rustls with the aws-lc-rs crypto provider. This guide covers setting up your environment for Android cross-compilation.

## Supported Targets

- `aarch64-linux-android` (ARM64, most modern devices)
- `armv7-linux-androideabi` (ARM32, older devices)
- `x86_64-linux-android` (x86_64 emulators)

## Prerequisites

1. **Rust nightly toolchain** with Android targets:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

2. **Android NDK** (r25 or later recommended):
   - Download from [Android NDK Downloads](https://developer.android.com/ndk/downloads)
   - Or install via Android Studio: SDK Manager > SDK Tools > NDK

3. **CMake** (required by aws-lc-rs):

```bash
# macOS
brew install cmake

# Ubuntu/Debian
sudo apt install cmake
```

## Environment Setup

Set the `ANDROID_NDK` environment variable to your NDK installation path:

```bash
# Example paths
export ANDROID_NDK=$HOME/Library/Android/sdk/ndk/29.0.14206865  # macOS with Android Studio
export ANDROID_NDK=$HOME/Android/Sdk/ndk/29.0.14206865          # Linux with Android Studio
export ANDROID_NDK=/opt/android-ndk-r27c                         # Standalone NDK
```

For the build to succeed, you also need to configure the C/C++ compilers. The NDK provides versioned clang compilers in the toolchain directory.

### Full Environment Configuration

```bash
# Set NDK path
NDK_PATH=$HOME/Library/Android/sdk/ndk/29.0.14206865

# Detect host platform
case "$(uname -s)" in
    Darwin) HOST_TAG="darwin-x86_64" ;;
    Linux)  HOST_TAG="linux-x86_64" ;;
esac

TOOLCHAIN=$NDK_PATH/toolchains/llvm/prebuilt/$HOST_TAG/bin

# Set environment variables for aarch64
export ANDROID_NDK_HOME="$NDK_PATH"
export CC_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android24-clang"
export CXX_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android24-clang++"
export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"

# For armv7
export CC_armv7_linux_androideabi="$TOOLCHAIN/armv7a-linux-androideabi24-clang"
export CXX_armv7_linux_androideabi="$TOOLCHAIN/armv7a-linux-androideabi24-clang++"
export AR_armv7_linux_androideabi="$TOOLCHAIN/llvm-ar"

# For x86_64
export CC_x86_64_linux_android="$TOOLCHAIN/x86_64-linux-android24-clang"
export CXX_x86_64_linux_android="$TOOLCHAIN/x86_64-linux-android24-clang++"
export AR_x86_64_linux_android="$TOOLCHAIN/llvm-ar"
```

The `24` in compiler names refers to the minimum Android API level (Android 7.0). Adjust based on your target requirements.

## Building

With the environment configured:

```bash
# Check compilation
cargo check --target aarch64-linux-android

# Build release
cargo build --target aarch64-linux-android --release
```

## Cargo Configuration

For convenience, you can add a `.cargo/config.toml` to your project:

```toml
[target.aarch64-linux-android]
linker = "/path/to/ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"

[target.armv7-linux-androideabi]
linker = "/path/to/ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi24-clang"

[target.x86_64-linux-android]
linker = "/path/to/ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android24-clang"
```

## Dependency Notes

Zenwave uses **rustls** with **aws-lc-rs** as the default TLS backend. This combination:

- Provides pure-Rust TLS (no OpenSSL dependency)
- Has good Android NDK cross-compilation support
- Requires CMake and a C compiler from the NDK

If you prefer using the platform's OpenSSL, you can use `native-tls` instead, but this requires cross-compiling OpenSSL for Android which is more complex.

## Troubleshooting

### "CMake was unable to find a build program"

Ensure `make` is installed:

```bash
# Ubuntu/Debian
sudo apt install build-essential

# macOS (comes with Xcode Command Line Tools)
xcode-select --install
```

### "Neither the NDK or a standalone toolchain was found"

The `ANDROID_NDK` or `ANDROID_NDK_HOME` environment variable is not set correctly. Verify the path exists:

```bash
ls $ANDROID_NDK/toolchains/llvm/prebuilt/
```

### "failed to find tool aarch64-linux-android-clang"

The compiler environment variables are not set. Use the full configuration shown above, or add the toolchain bin directory to your PATH:

```bash
export PATH="$NDK_PATH/toolchains/llvm/prebuilt/$HOST_TAG/bin:$PATH"
```

## Using with cargo-ndk

For a simpler setup, consider using [cargo-ndk](https://github.com/nicholasleblanc/cargo-ndk):

```bash
cargo install cargo-ndk
cargo ndk -t aarch64-linux-android build --release
```

This tool automatically configures the NDK environment for you.
