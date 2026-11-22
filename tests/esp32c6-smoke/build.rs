fn main() {
    // Embed the build instant so the firmware's rustls `TimeProvider` returns a
    // time inside the throwaway fixture certificate's validity window.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("cargo:rustc-env=SMOKE_UNIX_TIME={now}");
    println!("cargo:rerun-if-changed=certs/ca.der");
}
