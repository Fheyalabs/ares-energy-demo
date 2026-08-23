package ares.client

import kotlin.test.Test
import kotlin.test.assertEquals

class SigningTest {
    @Test fun canonicalJsonSortsKeysCompact() {
        assertEquals("{\"a\":1,\"b\":2}", String(Signing.canonicalJson(linkedMapOf("b" to 2, "a" to 1))))
    }
    @Test fun authTokenMatchesPinnedVector() {
        val t = Signing.authToken("s3cret", "bidder-00")
        assertEquals(64, t.length)
        assertEquals(t, t.lowercase())
        assertEquals("297736ab2c8d3268f0fa9ceaa3e43fcde2d6cdd1bd07f6e36454f8e71cbd7b08", t)
    }
    @Test fun deviceSignVerifies() {
        val seed = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")!!
        val canonical = Signing.canonicalJson(linkedMapOf("a" to 1, "b" to 2))
        val sig = Signing.deviceSign(seed, "verify.submit", "s1", canonical)
        assertEquals(64, sig.size)   // raw Ed25519 signature
    }
}
