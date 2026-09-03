//! Emits `cfg` aliases so platform and feature conditions read the same everywhere.
use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // Anything that is not the browser/Workers Fetch backend.
        native: { not(target_arch = "wasm32") },
        // TLS engine compiled into hyper and native websockets.
        tls_rustls: { all(not(target_arch = "wasm32"), feature = "rustls") },
        tls_native: { all(not(target_arch = "wasm32"), feature = "native-tls") },
        tls_engine: { all(not(target_arch = "wasm32"), any(feature = "rustls", feature = "native-tls")) },
        // The shared TCP/TLS connector is needed by hyper and by native websockets.
        connector: { all(not(target_arch = "wasm32"), any(feature = "hyper-backend", feature = "ws")) },
        // rustls-platform-verifier needs a JVM handle on Android.
        android_verifier: { all(target_os = "android", feature = "rustls") },
    }
}
