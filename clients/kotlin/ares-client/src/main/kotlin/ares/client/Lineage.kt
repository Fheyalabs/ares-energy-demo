package ares.client

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant

/**
 * SC-10 lineage DAGNode in the hex/snake_case v2 wire form.
 *
 * All content-bearing fields are lowercase hex strings. [createdAt] is an ISO-8601
 * timestamp that is excluded from [hash] and from the signing message, so it does
 * not affect cross-language byte parity.
 */
data class DAGNode(
    val hash: String,
    val sessionId: String,
    val phaseId: String,
    val role: String,
    val parents: List<String>,
    val parentRoles: List<String>,
    val payloadHash: String,
    val createdAt: String,
    val producer: String,
    val signature: String,
    val algorithm: String = "ed25519",
)

/** Result of [Lineage.buildSlotNode]: the fully-signed node plus raw key material. */
class BuiltNode(val node: DAGNode, val signingMsg: ByteArray, val sk: ByteArray, val pk: ByteArray)

/** SC-10 lineage helpers. Package: ares.client (no Fheya references). */
object Lineage {

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    /**
     * Build a signed SC-10 slot-submission DAGNode.
     *
     * Algorithm (mirrors Go and Swift byte-for-byte):
     *  1. payloadHash = SHA-256(payloadBytes)
     *  2. parents: hex-decode each → require 32 bytes → sort lexicographically by raw bytes
     *  3. nodeHash = SHA-256( lp(sid) ‖ lp(phase) ‖ lp(role) ‖ lp(payloadHash)
     *                        ‖ u32be(nParents) ‖ rawSortedParents… )
     *     (parents are raw 32 bytes, NO per-parent length prefix)
     *  4. signingMsg = nodeHash ‖ lp(sid) ‖ lp(phase) ‖ lp(role)
     *  5. Ed25519: seed → private key → public key (producer); sign(signingMsg)
     *  6. created_at is set to Instant.now() and is NOT included in the hashes
     *
     * Bouncy Castle's Ed25519 is deterministic (RFC 8032), so golden-vector
     * byte parity holds for the signature as well.
     *
     * @param sessionID  UTF-8 session identifier
     * @param payloadBytes  raw payload bytes (pre-serialised)
     * @param ed25519Seed  32-byte private key seed; random if null
     * @param parentsHex  lowercase hex parent node hashes (each must decode to 32 bytes)
     * @param phaseID  protocol phase identifier
     * @param role  node role label
     * @throws IllegalArgumentException if a parent hex is malformed or not 32 bytes, or if the seed is not 32 bytes
     */
    fun buildSlotNode(
        sessionID: String,
        payloadBytes: ByteArray,
        ed25519Seed: ByteArray? = null,
        parentsHex: List<String> = emptyList(),
        phaseID: String = "anon-g-verify",
        role: String = "slot-submission",
    ): BuiltNode {
        val sid   = sessionID.toByteArray(Charsets.UTF_8)
        val phase = phaseID.toByteArray(Charsets.UTF_8)
        val roleD = role.toByteArray(Charsets.UTF_8)

        val payloadHash = sha256(payloadBytes)

        // Decode + validate parents, then sort lexicographically by raw bytes.
        val parents: List<ByteArray> = parentsHex.map { ph ->
            val pb = ByteUtil.fromHex(ph)
                ?: throw IllegalArgumentException("malformed parent hex: $ph")
            require(pb.size == 32) { "parent must be 32 bytes, got ${pb.size}: $ph" }
            pb
        }.sortedWith(::compareLex)

        // Build the nodeHash preimage.
        val buf = ByteArrayOutputStream()
        buf.write(ByteUtil.lp(sid))
        buf.write(ByteUtil.lp(phase))
        buf.write(ByteUtil.lp(roleD))
        buf.write(ByteUtil.lp(payloadHash))
        buf.write(ByteUtil.u32be(parents.size))
        for (p in parents) buf.write(p)   // raw 32 bytes, no length prefix
        val nodeHash = sha256(buf.toByteArray())

        // signingMsg = nodeHash ‖ lp(sid) ‖ lp(phase) ‖ lp(role)
        val signingMsg: ByteArray = nodeHash +
            ByteUtil.lp(sid) +
            ByteUtil.lp(phase) +
            ByteUtil.lp(roleD)

        // Ed25519 key derivation + signing (Bouncy Castle, deterministic).
        val seed = ed25519Seed ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
        require(seed.size == 32) { "ed25519 seed must be exactly 32 bytes" }
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val pub  = priv.generatePublicKey().encoded
        val signer = Ed25519Signer().apply {
            init(true, priv)
            update(signingMsg, 0, signingMsg.size)
        }
        val sig = signer.generateSignature()

        val node = DAGNode(
            hash        = ByteUtil.hex(nodeHash),
            sessionId   = sessionID,
            phaseId     = phaseID,
            role        = role,
            parents     = parents.map { ByteUtil.hex(it) },
            parentRoles = emptyList(),
            payloadHash = ByteUtil.hex(payloadHash),
            createdAt   = Instant.now().toString(),
            producer    = ByteUtil.hex(pub),
            signature   = ByteUtil.hex(sig),
        )
        return BuiltNode(node, signingMsg, seed, pub)
    }

    /** Unsigned lexicographic comparison of two byte arrays. */
    private fun compareLex(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }
}
