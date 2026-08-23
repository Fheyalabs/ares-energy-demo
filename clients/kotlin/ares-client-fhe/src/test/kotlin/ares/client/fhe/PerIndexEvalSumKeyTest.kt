package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class PerIndexEvalSumKeyTest {
    @Test fun bfvContextsExposeTheConfiguredPerIndexRotationSet() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(
            ringDim = 1024,
            multiplicativeDepth = 4,
            plaintextModulus = 65537,
            batchSize = 8,
            minimalRotationKeys = true,
            profileDim = 4,
            payloadSlotCount = 8
        ).use { context ->
            val lead = context.keyGenFirst()
            val index = context.rotationIndices().first()
            context.generatePerIndexEvalSumKey(lead.secretKey, index).use { key ->
                assertTrue(context.serialize(key).isNotEmpty())
            }
            lead.secretKey.close()
            lead.publicKey.close()
        }
    }

    @Test fun explicitCKKSModulusSizesAreAcceptedByTheContextConstructor() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(
            ringDim = 1024,
            scalingFactor = Math.scalb(1.0, 50),
            depth = 4,
            batchSize = 8,
            scalingModSize = 50,
            firstModSize = 60
        ).use { context ->
            assertTrue(context.serialize(context.keyGenFirst().publicKey).isNotEmpty())
        }
    }

    @Test fun perIndexRotationKeysPreserveTheConfiguredRotationSet() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(
            ringDim = 1024,
            scalingFactor = Math.scalb(1.0, 50),
            depth = 4,
            batchSize = 8,
            minimalRotationKeys = true,
            profileDim = 4,
            payloadSlotCount = 8
        ).use { context ->
            val lead = context.keyGenFirst()
            val participant = context.keyGenNext(lead.publicKey)
            val indices = context.rotationIndices()

            assertContentEquals(intArrayOf(1, 2, -1, -2, -4), indices)
            val base = context.generatePerIndexEvalSumKey(lead.secretKey, indices.first())
            val share = context.generatePerIndexEvalSumShare(
                participant.secretKey,
                base,
                participant.publicKey,
                indices.first()
            )

            val leadA = context.serializeRotKeyAVectors(base)
            assertContentEquals(leadA, context.serializeRotKeyAVectors(share))
            val reconstructed = context.reconstructRotKeyFromAB(
                leadA,
                context.serializeRotKeyBVectors(share)
            )
            assertTrue(context.serialize(base).isNotEmpty())
            assertTrue(context.serialize(share).isNotEmpty())
            assertTrue(context.serialize(reconstructed).isNotEmpty())
        }
    }
}
