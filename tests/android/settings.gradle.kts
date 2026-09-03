// The instrumented Android test app for zenwave's TLS path: `rustls-platform-verifier`
// needs the JVM, which the plain test binary run by `scripts/test-android.sh` does
// not have. Not a Cargo workspace member; driven by that script on a real device.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "zenwave-android-tests"
include(":app")
