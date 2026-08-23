package ares.smoke

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RawFramePayloadTest {
    @Test fun boundCheckReadsTheCurrentByteArrayTransportFrame() {
        val raw = """{"payload":{"checks":{"alice":"artifact:a","bob":"artifact:b"}}}"""
            .toByteArray()

        assertEquals(
            mapOf("alice" to "artifact:a", "bob" to "artifact:b"),
            BoundCheckFlow.extractStringMap(raw, "checks"),
        )
    }

    @Test fun votingReadsTheCurrentByteArrayTransportFrame() {
        val first = byteArrayOf(1, 2, 3)
        val second = byteArrayOf(4, 5, 6)
        val raw = """{"payload":{"onions":["${Base64.getEncoder().encodeToString(first)}","${Base64.getEncoder().encodeToString(second)}"]}}"""
            .toByteArray()

        val decoded = VotingFlow.decodeOnions(raw)

        assertContentEquals(first, decoded[0])
        assertContentEquals(second, decoded[1])
    }

    @Test fun rawFrameHelpersRejectInvalidUTF8() {
        assertFailsWith<IllegalArgumentException> {
            BoundCheckFlow.extractStringMap(byteArrayOf(0xc3.toByte(), 0x28), "checks")
        }
        assertFailsWith<IllegalArgumentException> {
            VotingFlow.decodeOnions(byteArrayOf(0xc3.toByte(), 0x28))
        }
    }
}
