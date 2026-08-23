package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals

class EvalRoundTripTest {
    @Test fun fullSmokePortYields17_0625() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            val pks = ArrayList<PublicKey>(); val sks = ArrayList<SecretKeyShare>()
            val f = ctx.keyGenFirst(); pks.add(f.publicKey); sks.add(f.secretKey)
            repeat(2) { val n = ctx.keyGenNext(pks.last()); pks.add(n.publicKey); sks.add(n.secretKey) }
            sks.forEach { ctx.genEvalMultKeyShare(it); ctx.genRotKeyShare(it) }
            val input = doubleArrayOf(1.25, -2.5, 3.0, 0.5)
            val ct = ctx.encrypt(input, pks.last())
            val doubled = ctx.evalAdd(ct, ct)
            val restored = ctx.evalMultConst(doubled, 0.5)
            val squared = ctx.evalMult(restored, restored)
            val summed = ctx.evalSum(squared, input.size)
            val partials = sks.map { ctx.partialDecrypt(summed, it) }
            assertEquals(17.0625, ctx.fuse(partials, 8)[0], 0.05)
        }
    }
}
