//! Emits `cfg` aliases so platform and feature conditions read the same everywhere.
use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // Anything that is not the browser/Workers Fetch backend.
        native: { not(target_arch = "wasm32") },
        // The shared TCP/TLS connector is needed by hyper and by native websockets.
        connector: { all(not(target_arch = "wasm32"), any(feature = "hyper-backend", feature = "ws")) },
        // TLS engine compiled into that connector; an engine feature enabled
        // next to curl or URLSession alone has nothing to serve.
        tls_rustls: { all(connector, feature = "rustls") },
        tls_native: { all(connector, feature = "native-tls") },
        tls_engine: { any(tls_rustls, tls_native) },
        // rustls-platform-verifier needs a JVM handle on Android.
        android_verifier: { all(target_os = "android", tls_rustls) },
        // Which backend `DefaultBackend` resolves to: hyper wins, then URLSession, then libcurl.
        apple_backend: { all(target_vendor = "apple", feature = "apple-backend") },
        default_hyper: { all(not(target_arch = "wasm32"), feature = "hyper-backend") },
        default_apple: { all(target_vendor = "apple", feature = "apple-backend", not(feature = "hyper-backend")) },
        default_curl: { all(
            not(target_arch = "wasm32"),
            feature = "curl-backend",
            not(feature = "hyper-backend"),
            not(all(target_vendor = "apple", feature = "apple-backend"))
        ) },
    }
}
