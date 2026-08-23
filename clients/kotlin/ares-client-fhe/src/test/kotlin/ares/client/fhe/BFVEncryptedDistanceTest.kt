// SPDX-License-Identifier: Apache-2.0

package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals

class BFVEncryptedDistanceTest {
    @Test fun packedIntegerProfilePreservesSignedInt7Slots() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(
            ringDim = 1024,
            multiplicativeDepth = 4,
            plaintextModulus = 65_537,
            batchSize = 128
        ).use { context ->
            val share = context.singleKeyGen()
            val expected = longArrayOf(-63, -1, 0, 1, 63)
            val ciphertext = context.encryptPackedInts(expected, share.publicKey)
            val partial = context.partialDecrypt(ciphertext, share.secretKey)
            val slots = context.fusePackedInt(listOf(partial), slotCapacity = 128)

            assertEquals(expected.size, slots.take(expected.size).size)
            expected.indices.forEach { index ->
                assertEquals(expected[index], slots[index], "slot $index")
            }
        }
    }

    @Test fun encryptedSquaredDistanceIsExactAcrossPackedSlots() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(
            ringDim = 1024,
            multiplicativeDepth = 4,
            plaintextModulus = 65_537,
            batchSize = 128
        ).use { context ->
            val share = context.singleKeyGen()
            val originFirst = context.encryptRepeatedScalarBFV(10, share.publicKey)
            val originSecond = context.encryptRepeatedScalarBFV(20, share.publicKey)
            val distance = context.encryptedSquaredDistanceBFV(
                originFirst = originFirst,
                originSecond = originSecond,
                localFirst = 7,
                localSecond = 24
            )

            val ciphertext = context.deserializeCiphertext(distance)
            val partial = context.partialDecrypt(ciphertext, share.secretKey)
            val slots = context.fusePackedInt(listOf(partial), slotCapacity = 128)

            assertEquals(128, slots.size)
            slots.forEachIndexed { index, slot ->
                assertEquals(25, slot, "slot $index")
            }
        }
    }
}
