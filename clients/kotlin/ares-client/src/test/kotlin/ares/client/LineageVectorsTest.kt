package ares.client

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

class LineageVectorsTest {
    // working dir during tests = clients/kotlin/ares-client → repo root is ../../..
    private val vectorsPath = File("../../../pkg/ares/lineage/testdata/node_vectors.json")

    @Test fun reproducesGoldenVectorsByteForByte() {
        val vectors = MiniJson.parseArray(vectorsPath.readText())
        assertEquals(2, vectors.size, "expected 2 golden vectors")
        for (v in vectors) {
            @Suppress("UNCHECKED_CAST") val input = v["input"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST") val expected = v["expected"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST") val parentsHex = (input["parents_hex"] as List<Any>).map { it as String }
            val built = Lineage.buildSlotNode(
                sessionID = input["session_id"] as String,
                payloadBytes = ByteUtil.fromHex(input["payload_hex"] as String)!!,
                ed25519Seed = ByteUtil.fromHex(input["ed25519_seed_hex"] as String)!!,
                parentsHex = parentsHex,
                phaseID = input["phase_id"] as String,
                role = input["role"] as String,
            )
            assertEquals(expected["producer_hex"], built.node.producer, "producer")
            assertEquals(expected["payload_hash_hex"], built.node.payloadHash, "payload_hash")
            assertEquals(expected["node_hash_hex"], built.node.hash, "node_hash")
            assertEquals(expected["signing_msg_hex"], ByteUtil.hex(built.signingMsg), "signing_msg")
            assertEquals(expected["signature_hex"], built.node.signature, "signature")  // BC deterministic
            assertEquals("ed25519", built.node.algorithm)
        }
    }
}
