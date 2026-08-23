package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals

class DecryptRoundTripTest {
    @Test fun threePartyRecoversInput() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            val pks = ArrayList<PublicKey>(); val sks = ArrayList<SecretKeyShare>()
            val f = ctx.keyGenFirst(); pks.add(f.publicKey); sks.add(f.secretKey)
            repeat(2) { val n = ctx.keyGenNext(pks.last()); pks.add(n.publicKey); sks.add(n.secretKey) }
            val input = doubleArrayOf(1.25, -2.5, 3.0, 0.5)
            val ct = ctx.encrypt(input, pks.last())
            val partials = sks.map { ctx.partialDecrypt(ct, it) }
            val out = ctx.fuse(partials, 8)
            for (i in input.indices) assertEquals(input[i], out[i], 0.05)
        }
    }
}
