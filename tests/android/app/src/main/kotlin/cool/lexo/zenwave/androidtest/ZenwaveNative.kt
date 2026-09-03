package cool.lexo.zenwave.androidtest

import android.content.Context

/** The Rust half of the test app; see `tests/android/rust`. */
object ZenwaveNative {
    init {
        System.loadLibrary("zenwave_android_tests")
    }

    /** Hands the JVM and the application context to `ndk-context`, once per process. */
    external fun initialize(context: Context)

    /** Runs the TLS cases; returns one line per failure, empty when everything passed. */
    external fun runSuite(): String
}
