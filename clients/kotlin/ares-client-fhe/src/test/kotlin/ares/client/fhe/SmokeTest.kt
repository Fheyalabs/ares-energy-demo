package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals

class SmokeTest {
    @Test fun linkedVersionAndSmoke() {
        assumeTrue(NativeFHE.loaded, "libares_fhe_jni not on java.library.path — run scripts/build-native.sh")
        assertEquals("v1.5.1", NativeFHE.version())
        assertEquals(0, NativeFHE.smoke())
    }
}
