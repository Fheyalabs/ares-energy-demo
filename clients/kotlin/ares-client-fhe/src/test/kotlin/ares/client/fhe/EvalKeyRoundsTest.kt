package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals

class EvalKeyRoundsTest {
    @Test fun evalMultKeyTwoRoundAndEvalMult() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            // 3-party keygen
            val pks = ArrayList<PublicKey>(); val sks = ArrayList<SecretKeyShare>()
            val f = ctx.keyGenFirst(); pks.add(f.publicKey); sks.add(f.secretKey)
            repeat(2) { val n = ctx.keyGenNext(pks.last()); pks.add(n.publicKey); sks.add(n.secretKey) }
            val jointPK = ctx.multiAddPublicKeys(pks)

            // eval-mult-key 2-round protocol
            val lead = ctx.evalMultKeyGenLead(sks[0])
            val switch1 = ctx.evalMultKeySwitchShare(sks[1], lead)
            val switch2 = ctx.evalMultKeySwitchShare(sks[2], lead)
            // The lead base is slot zero's R1 contribution. Each later slot
            // derives its switch share against that published base.
            val joined = ctx.combineEvalMultSwitchShares(pks, listOf(lead, switch1, switch2))
            val final0 = ctx.evalMultKeyFinalShare(sks[0], joined, jointPK)
            val final1 = ctx.evalMultKeyFinalShare(sks[1], joined, jointPK)
            val final2 = ctx.evalMultKeyFinalShare(sks[2], joined, jointPK)
            val evalMultKey = ctx.combineEvalMultFinalShares(jointPK, listOf(final0, final1, final2))
            ctx.insertEvalMultKey(evalMultKey)

            // eval-sum key protocol
            val eskBase = ctx.evalSumKeyGenLead(sks[0])
            val esk1 = ctx.evalSumKeyShare(sks[1], eskBase, pks[1])
            val esk2 = ctx.evalSumKeyShare(sks[2], eskBase, pks[2])
            val evalSumKey = ctx.combineEvalSumKeys(pks, listOf(eskBase, esk1, esk2))
            ctx.insertEvalSumKey(evalSumKey)

            // EvalMult squares [2,3,4,5] to [4,9,16,25]
            val ct = ctx.encrypt(doubleArrayOf(2.0, 3.0, 4.0, 5.0), jointPK)
            val squared = ctx.evalMult(ct, ct)
            val partials = sks.map { ctx.partialDecrypt(squared, it) }
            val out = ctx.fuse(partials, 8)
            assertEquals(4.0, out[0], 0.1)
            assertEquals(9.0, out[1], 0.1)
            assertEquals(16.0, out[2], 0.1)
            assertEquals(25.0, out[3], 0.1)
        }
    }
}
