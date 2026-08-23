// SPDX-License-Identifier: Apache-2.0

package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BoundCheckParticipantTest {
    // --- pure SHA-256 commitment tests: NO native lib needed ---
    @Test fun commitmentMatchesGoAlgorithm() {
        // commitment = SHA256( enc_check || SHA256(enc_x) || session_id )
        val encCheck = byteArrayOf(1, 2); val encX = byteArrayOf(3, 4); val sid = "s"
        val inner = MessageDigest.getInstance("SHA-256").digest(encX)
        val outer = MessageDigest.getInstance("SHA-256")
        outer.update(encCheck); outer.update(inner); outer.update(sid.toByteArray(Charsets.UTF_8))
        assertTrue(BoundCheckParticipant.commitment(encCheck, encX, sid).contentEquals(outer.digest()))
    }

    // --- participate(): needs the native FHE lib ---
    private fun twoParty(): Triple<CryptoContext, PublicKey, Pair<SecretKeyShare, SecretKeyShare>> {
        val ctx = CryptoContext(1024, Math.scalb(1.0, 50), 4)
        val a = ctx.keyGenFirst(); val b = ctx.keyGenNext(a.publicKey)
        return Triple(ctx, b.publicKey, Pair(a.secretKey, b.secretKey))
    }

    @Test fun implicitCheckPassesOnCorrectCommitment() {
        assumeTrue(NativeFHE.loaded)
        val (ctx, pk, sks) = twoParty()
        ctx.use {
            val encX = ctx.serialize(ctx.encrypt(doubleArrayOf(0.5, 0.0, 0.0, 0.0), pk))
            val encCheck = ctx.serialize(ctx.encrypt(doubleArrayOf(1.0, 0.0, 0.0, 0.0), pk))
            val sid = "adm-1"
            val commitment = BoundCheckParticipant.commitment(encCheck, encX, sid)
            val r = BoundCheckParticipant.participate(ctx, encCheck, encX, sid, commitment, sks.first)
            assertTrue(r.passed)
            assertTrue(r.partial.isNotEmpty())
        }
    }

    @Test fun implicitCheckFailsOnTamperedEncCheck() {
        assumeTrue(NativeFHE.loaded)
        val (ctx, pk, sks) = twoParty()
        ctx.use {
            val encX = ctx.serialize(ctx.encrypt(doubleArrayOf(0.5, 0.0, 0.0, 0.0), pk))
            val encCheck = ctx.serialize(ctx.encrypt(doubleArrayOf(1.0, 0.0, 0.0, 0.0), pk))
            val sid = "adm-1"
            val commitment = BoundCheckParticipant.commitment(encCheck, encX, sid)
            val tampered = ctx.serialize(ctx.encrypt(doubleArrayOf(9.0, 0.0, 0.0, 0.0), pk))  // server swapped enc_check
            val r = BoundCheckParticipant.participate(ctx, tampered, encX, sid, commitment, sks.first)
            assertFalse(r.passed)
        }
    }
}
