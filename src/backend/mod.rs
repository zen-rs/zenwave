//! Platform-specific HTTP client backends.
//!
//! This module exposes backend implementations for each supported target and
//! picks a [`DefaultBackend`] alias based on the current platform and enabled
//! Cargo features.
//!
//! # Backend Selection
//!
//! ## WASM (wasm32)
//! On wasm32 targets, the built-in [`WebBackend`] is always used automatically.
//! No backend selection is available or needed - the web backend uses the browser's
//! native Fetch API.
//!
//! ## WASI (`wasm32-wasip2`)
//! A WASI host has no browser and no OS reactor, but sockets, name resolution
//! and a clock through the host. Only `native-backend` exists there:
//! `NativeBackend::on_current_thread` over the host's `http-kit-io`
//! implementation (`Dial`, `Resolve`, `Timer`), HTTP/1.1, and TLS verified
//! against `webpki-roots` compiled into the binary, with the compiled OneCRL
//! table applied (its refresher needs a thread and a connector, and is left
//! out). `hyper-backend`, `curl-backend`, `ws`, `native-tls`, `native-compio`,
//! `native-tokio`, `native-http3` and `native-kernel-tls` are refused with a
//! compile error.
//!
//! ## Native Platforms
//! On native platforms, users can choose their preferred backend:
//!
//! - **`hyper-backend`** (default): Uses hyper with async-io/async-net. TLS comes
//!   from `rustls` (default) or `native-tls`; `rustls` wins when both are on.
//!   The only backend that speaks HTTP/2.
//! - **`native-backend`**: `NativeBackend`, HTTP/1.1 on `http-kit-h1` and,
//!   with `native-http3`, HTTP/3 on `http-kit-h3`, over `http-kit-io`'s
//!   owned-buffer streams, generic over the runtime. Its connection pool is
//!   an actor on one thread: a thread-per-core caller builds one per thread
//!   with `NativeBackend::on_current_thread`. `native-compio` or
//!   `native-tokio` adds a driver thread for callers on no runtime, and makes
//!   it the default backend when `hyper-backend` is off.
//! - **`curl-backend`**: Uses libcurl via the `curl` crate. Includes proxy support.
//! - **`apple-backend`**: Uses Apple's native `NSURLSession` (macOS/iOS only).
//!
//! Every backend is built from a [`crate::Transport`], which carries the
//! trusted roots; `Default` uses [`crate::Transport::system`].

// Request and response handling the hyper and native backends share.
#[cfg(any(default_hyper, native_backend))]
mod shared;

#[cfg(all(reactor, feature = "hyper-backend"))]
mod hyper;
#[cfg(all(reactor, feature = "hyper-backend"))]
pub use hyper::HyperBackend;
// The connection pool stores the h3 handle.
#[cfg(http3)]
pub(crate) use hyper::h3;
// The h3 fixtures also serve the pool's coalescing test.
#[cfg(all(test, http3))]
pub(crate) use hyper::test_support;

#[cfg(all(reactor, feature = "curl-backend"))]
mod curl;
#[cfg(all(reactor, feature = "curl-backend"))]
pub use curl::CurlBackend;

#[cfg(apple_backend)]
mod apple;
#[cfg(apple_backend)]
pub use apple::AppleBackend;

// ============================================================================
// Default backend selection for native platforms (non-wasm32)
// ============================================================================

/// The default HTTP client backend: Hyper with async-io.
///
/// Hyper takes precedence whenever it is enabled so Cargo feature unification
/// cannot silently replace an explicitly requested Hyper transport with a
/// platform backend pulled in by an unrelated dependency.
#[cfg(default_hyper)]
pub type DefaultBackend = HyperBackend;

#[cfg(native_backend)]
pub(crate) mod native;
#[cfg(feature = "native-compio")]
pub use native::Compio;
#[cfg(native_driver)]
pub use native::Driver;
#[cfg(feature = "native-tokio")]
pub use native::Tokio;
#[cfg(native_backend)]
pub use native::{NativeBackend, NativeIo, NativeResolve, QuicBind, Switched, UnixDial, Upgrade};

/// The default HTTP client backend: the native backend on its own driver
/// runtime.
///
/// Selected when `native-backend` comes with a runtime (`native-compio` or
/// `native-tokio`) and `hyper-backend` is off.
#[cfg(default_native)]
pub type DefaultBackend = NativeBackend;

/// The default HTTP client backend: Apple's `NSURLSession`.
///
/// This is selected on Apple platforms only when `apple-backend` is enabled
/// without `hyper-backend` or a native backend runtime.
#[cfg(default_apple)]
pub type DefaultBackend = AppleBackend;

/// The default HTTP client backend: libcurl.
/// This is selected when `curl-backend` is enabled and no backend above is.
#[cfg(default_curl)]
pub type DefaultBackend = CurlBackend;

// ============================================================================
// WASM backend (always used on wasm32, no user selection)
// ============================================================================

#[cfg(browser)]
mod web;
#[cfg(browser)]
pub use web::WebBackend;

/// The default HTTP client backend for WebAssembly.
/// On wasm32 targets, the built-in web backend using the Fetch API is always used.
/// This cannot be changed - it's the only backend available for wasm32.
#[cfg(browser)]
pub type DefaultBackend = WebBackend;

// ============================================================================
// Compile-time validation for native platforms
// ============================================================================

// `native-backend` alone is a backend without a default: its caller drives
// `NativeBackend::on_current_thread` on its own runtime, and the items that
// need a `DefaultBackend` (`zenwave::client()`, `DefaultClient`, the
// one-shot request functions) are absent.
#[cfg(all(
    native,
    not(apple_backend),
    not(feature = "hyper-backend"),
    not(feature = "curl-backend"),
    not(native_backend)
))]
compile_error!(
    "No backend enabled for native platform. \
     Please enable one of: `hyper-backend` (recommended), `curl-backend`, \
     `native-compio` or `native-tokio` (the native backend with a runtime of its own), \
     `native-backend` (the native backend on the caller's runtime, with no default client), \
     or `apple-backend` (Apple platforms only). \
     The default feature set includes `hyper-backend` with `rustls` TLS."
);

// ============================================================================
// Compile-time validation for wasm32: backend selection is NOT allowed
// ============================================================================

// Users cannot explicitly select backends on wasm32 - the web backend is always used.
// These compile errors help catch misconfigurations early.

#[cfg(all(browser, feature = "hyper-native-tls"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `hyper-native-tls` feature when targeting wasm32."
);

#[cfg(all(browser, feature = "hyper-rustls"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `hyper-rustls` feature when targeting wasm32."
);

#[cfg(all(browser, feature = "apple-backend"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `apple-backend` feature when targeting wasm32."
);

#[cfg(all(browser, feature = "curl-backend"))]
compile_error!(
    "Backend selection is not allowed on wasm32 targets. \
     The web backend using the browser's Fetch API is always used automatically. \
     Please remove the `curl-backend` feature when targeting wasm32."
);

// ============================================================================
// Compile-time validation for WASI: the native backend over the host's sockets
// ============================================================================

// A WASI host has no OS reactor, no `getaddrinfo`, no QUIC socket and no
// kernel TLS: the native backend runs there on the caller's `Dial`, `Resolve`
// and `Timer` with HTTP/1.1 over TLS, and every feature that needs more is
// refused instead of compiling to nothing.

#[cfg(all(target_os = "wasi", feature = "hyper-backend"))]
compile_error!(
    "`hyper-backend` needs an OS reactor, which WASI does not have. \
     Use `native-backend` with the host's `Dial`, `Resolve` and `Timer`."
);

#[cfg(all(target_os = "wasi", feature = "curl-backend"))]
compile_error!(
    "`curl-backend` needs libcurl and an OS reactor, which WASI does not have. \
     Use `native-backend` with the host's `Dial`, `Resolve` and `Timer`."
);

#[cfg(all(target_os = "wasi", feature = "ws"))]
compile_error!(
    "`ws` needs an OS reactor, which WASI does not have. \
     Disable it when targeting WASI."
);

#[cfg(all(target_os = "wasi", feature = "native-tls"))]
compile_error!(
    "`native-tls` needs the platform's TLS library, which WASI does not have. \
     `rustls` verifies against compiled-in `webpki-roots` there."
);

#[cfg(all(
    target_os = "wasi",
    any(feature = "native-compio", feature = "native-tokio")
))]
compile_error!(
    "`native-compio` and `native-tokio` drive the native backend on an OS reactor, \
     which WASI does not have. Construct `NativeBackend::on_current_thread` on the \
     host's executor instead."
);

#[cfg(all(target_os = "wasi", feature = "native-http3"))]
compile_error!(
    "`native-http3` needs QUIC sockets and a C toolchain for quiche, which are not \
     available on WASI."
);

#[cfg(all(target_os = "wasi", feature = "native-kernel-tls"))]
compile_error!(
    "`native-kernel-tls` moves a connection's record layer into the Linux kernel; it does not exist on WASI."
);
