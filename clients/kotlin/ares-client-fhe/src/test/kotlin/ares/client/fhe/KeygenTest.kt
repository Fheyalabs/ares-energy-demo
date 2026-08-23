package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals

class KeygenTest {
    @Test fun threePartyChain() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            val pks = ArrayList<PublicKey>(); val sks = ArrayList<SecretKeyShare>()
            val f = ctx.keyGenFirst(); pks.add(f.publicKey); sks.add(f.secretKey)
            repeat(2) { val n = ctx.keyGenNext(pks.last()); pks.add(n.publicKey); sks.add(n.secretKey) }
            assertEquals(3, pks.size); assertEquals(3, sks.size)
        }
    }
}
