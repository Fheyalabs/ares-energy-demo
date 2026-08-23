// SPDX-License-Identifier: Apache-2.0

package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class PayloadChunkEncryptionTest {
    @Test fun encryptPayloadChunksPreservesMsbFirstBits() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4, batchSize = 128).use { ctx ->
            val share = ctx.keyGenFirst()
            val payload = ByteArray(80)
            payload[0] = 0x80.toByte()
            payload[1] = 0x01
            payload[79] = 0x81.toByte()

            val chunks = ctx.encryptPayloadChunks(payload, share.publicKey, 128)
            assertEquals(5, chunks.size)
            chunks.forEachIndexed { chunkIndex, serialized ->
                val ciphertext = ctx.deserializeCiphertext(serialized)
                val partial = ctx.partialDecrypt(ciphertext, share.secretKey)
                val slots = ctx.fuse(listOf(partial), 128)
                slots.indices.forEach { slot ->
                    val bitIndex = chunkIndex * 128 + slot
                    val expected = ((payload[bitIndex / 8].toInt() ushr (7 - (bitIndex % 8))) and 1).toDouble()
                    assertEquals(expected, slots[slot], 0.05, "bit $bitIndex")
                }
            }
        }
    }

    @Test fun encryptPayloadChunksRejectsInvalidChunkSizeAndLength() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4, batchSize = 128).use { ctx ->
            val share = ctx.keyGenFirst()
            assertFails { ctx.encryptPayloadChunks(ByteArray(80), share.publicKey, 64) }
            assertFails { ctx.encryptPayloadChunks(ByteArray(79), share.publicKey, 128) }
        }
    }
}
