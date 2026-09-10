package cool.lexo.zenwave.androidtest

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TlsSuiteTest {
    @Test
    fun systemAnchorsAndExtraRootsWork() {
        assertEquals("", ZenwaveNative.runSuite())
    }
}
