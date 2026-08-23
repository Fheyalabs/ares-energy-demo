package ares.client

import ares.client.transport.GossipParticipant
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GossipParticipantTest {
    @Test fun buildBatchAndSlotSubmissionConsistent() {
        val sk = X25519PrivateKeyParameters(SecureRandom())
        val pub = sk.generatePublicKey().encoded
        val gp = GossipParticipant("vote-1", 0, sk.encoded, pub)
        val (payloadJson, memo) = gp.buildBatch(listOf(pub))
        assertTrue(String(payloadJson).contains("\"onions\""))
        assertTrue(memo.isNotEmpty())
        val (bytes, node) = gp.slotSubmission()
        assertEquals("anon-g-verify", node.phaseId)
        assertEquals("slot-submission", node.role)
        // slot.submit payload bytes are exactly what the node's payload_hash covers
        val h = ByteUtil.hex(MessageDigest.getInstance("SHA-256").digest(bytes))
        assertEquals(h, node.payloadHash)
        // slot entry is sorted-keys: slot_dk_pub before slot_index
        assertTrue(String(bytes).startsWith("{\"slot_dk_pub\""))
    }
}
