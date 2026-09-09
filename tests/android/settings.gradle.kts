// The instrumented Android test app for zenwave's TLS path: it runs the TLS cases
// from a real application process, which reads the system trust anchors under the
// app's own SELinux domain rather than the shell's the plain test binaries get.
// Not a Cargo workspace member; driven by `scripts/test-android.sh` on a real device.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "zenwave-android-tests"
include(":app")
