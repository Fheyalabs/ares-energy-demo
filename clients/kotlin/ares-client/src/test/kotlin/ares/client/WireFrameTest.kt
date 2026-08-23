package ares.client

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WireFrameTest {
    @Test fun outboundV1OmitsLineageAndVersion() {
        val s = String(WireFrame.encodeOutbound("vote.ballot", "s1", 0, "{\"choice\":1}".toByteArray(), null))
        assertTrue(s.contains("\"type\":\"vote.ballot\""))
        assertTrue(s.contains("\"session_id\":\"s1\""))
        assertTrue(s.contains("\"payload\":{\"choice\":1}"))
        assertFalse(s.contains("\"lineage\""))
        assertFalse(s.contains("\"version\""))
    }
    @Test fun outboundV2IncludesVersionAndSnakeCaseLineage() {
        val node = Lineage.buildSlotNode("s1", "{\"slot_index\":0,\"slot_dk_pub\":\"aa\"}".toByteArray()).node
        val s = String(WireFrame.encodeOutbound("slot.submit", "s1", 0, "{\"x\":1}".toByteArray(), node))
        assertTrue(s.contains("\"version\":\"2\""))
        assertTrue(s.contains("\"lineage\""))
        assertTrue(s.contains("\"phase_id\":\"anon-g-verify\""))
        assertTrue(s.contains("\"payload_hash\""))
        assertTrue(s.contains("\"parent_roles\""))
    }
}
