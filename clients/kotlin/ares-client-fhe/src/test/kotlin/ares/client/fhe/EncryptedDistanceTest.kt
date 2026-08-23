// SPDX-License-Identifier: Apache-2.0

package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class EncryptedDistanceTest {
    @Test fun encryptedSquaredDistanceIsRepeatedAcrossSlots() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4, batchSize = 128).use { ctx ->
            val share = ctx.singleKeyGen()
            val originFirst = ctx.encryptRepeatedScalar(10.0, share.publicKey)
            val originSecond = ctx.encryptRepeatedScalar(20.0, share.publicKey)
            val distance = ctx.encryptedSquaredDistance(originFirst, originSecond, 7.0, 24.0)
            val ciphertext = ctx.deserializeCiphertext(distance)
            val partial = ctx.partialDecrypt(ciphertext, share.secretKey)
            val slots = ctx.fuse(listOf(partial), 128)

            assertEquals(128, slots.size)
            slots.forEachIndexed { index, slot ->
                assertEquals(25.0, slot, 0.1, "slot $index")
            }
        }
    }

    @Test fun encryptedSquaredDistanceRejectsMalformedOriginCiphertext() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4, batchSize = 128).use { ctx ->
            assertFails { ctx.encryptedSquaredDistance(byteArrayOf(1), byteArrayOf(2), 0.0, 0.0) }
        }
    }
}
