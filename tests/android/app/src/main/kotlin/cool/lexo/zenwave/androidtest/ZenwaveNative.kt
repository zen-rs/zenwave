package cool.lexo.zenwave.androidtest

/** The Rust half of the test app; see `tests/android/rust`. */
object ZenwaveNative {
    init {
        System.loadLibrary("zenwave_android_tests")
    }

    /** Runs the TLS cases; returns one line per failure, empty when everything passed. */
    external fun runSuite(): String
}
