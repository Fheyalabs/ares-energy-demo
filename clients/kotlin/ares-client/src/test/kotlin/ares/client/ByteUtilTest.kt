package ares.client

import kotlin.test.Test
import kotlin.test.assertEquals

class ByteUtilTest {
    @Test fun u32beIsBigEndian() {
        assertEquals("00000010", ByteUtil.hex(ByteUtil.u32be(16)))
        assertEquals("0000000d", ByteUtil.hex(ByteUtil.u32be(13)))
    }
    @Test fun lpPrependsBigEndianLength() {
        assertEquals("00000002aabb", ByteUtil.hex(ByteUtil.lp(byteArrayOf(0xaa.toByte(), 0xbb.toByte()))))
    }
    @Test fun hexRoundTrips() {
        assertEquals("00ff10", ByteUtil.hex(ByteUtil.fromHex("00ff10")!!))
    }
}
