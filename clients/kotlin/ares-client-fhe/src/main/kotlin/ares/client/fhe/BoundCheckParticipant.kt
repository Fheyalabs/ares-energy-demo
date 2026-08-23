// SPDX-License-Identifier: Apache-2.0

package ares.client.fhe

import java.security.MessageDigest

/**
 * Outcome of participating in an ARES-BC bound check. `passed` is the IMPLICIT
 * integrity verdict (the lib verified the server's check_commitment automatically);
 * the app decides what to do with a `false` (abort / penalize / proceed) — that
 * policy is the app's, never the lib's.
 */
data class BoundCheckResult(
    val passed: Boolean,
    val partial: ByteArray,   // this party's partial decryption of enc_check (send as bound_check.partial)
)

object BoundCheckParticipant {
    /** commitment = SHA256( enc_check || SHA256(enc_x) || session_id ) — matches
     *  pkg/ares/phase/boundcheck/phase.go (binds enc_check to the submitted input). */
    fun commitment(encCheck: ByteArray, encX: ByteArray, sessionID: String): ByteArray {
        val inner = MessageDigest.getInstance("SHA-256").digest(encX)
        val outer = MessageDigest.getInstance("SHA-256")
        outer.update(encCheck)
        outer.update(inner)
        outer.update(sessionID.toByteArray(Charsets.UTF_8))
        return outer.digest()
    }

    /** Implicitly verify the server's commitment, then partial-decrypt enc_check.
     *  The app receives only [BoundCheckResult] — never the hash mechanics. */
    fun participate(
        ctx: CryptoContext,
        encCheckBytes: ByteArray,
        encXBytes: ByteArray,
        sessionID: String,
        expectedCommitment: ByteArray,
        sk: SecretKeyShare,
    ): BoundCheckResult {
        val recomputed = commitment(encCheckBytes, encXBytes, sessionID)
        val passed = MessageDigest.isEqual(recomputed, expectedCommitment)  // constant-time
        val ct = ctx.deserializeCiphertext(encCheckBytes)
        val partial = ctx.serialize(ctx.partialDecrypt(ct, sk))
        ct.close()
        return BoundCheckResult(passed, partial)
    }
}
