package ares.client

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SC-2: N-layer onion encryption (ECIES per layer).
 *
 * Wire format per layer: ephPub(32) || nonce(12) || ciphertext || tag(16)
 *
 * Crypto primitives:
 *   - X25519 key agreement (BC lightweight API)
 *   - HKDF-SHA256(salt=empty, info="ares_onion_v1", 32 bytes) key derivation
 *   - AES-256-GCM, 12-byte nonce, 128-bit tag (JCA, GCM appends tag to ciphertext)
 */
object Onion {
    private val INFO = "ares_onion_v1".toByteArray(Charsets.UTF_8)
    private const val PUB_LEN = 32
    private const val NONCE_LEN = 12
    private const val TAG_LEN = 16
    private const val MIN_LAYER = PUB_LEN + NONCE_LEN + TAG_LEN

    private fun hkdf32(sharedSecret: ByteArray): ByteArray {
        val out = ByteArray(32)
        val gen = HKDFBytesGenerator(SHA256Digest())
        gen.init(HKDFParameters(sharedSecret, ByteArray(0), INFO))
        gen.generateBytes(out, 0, 32)
        return out
    }

    private fun eciesEncrypt(recipientPub: ByteArray, plaintext: ByteArray): ByteArray {
        // Ephemeral X25519 key pair
        val eph = X25519PrivateKeyParameters(SecureRandom())
        val ephPubBytes = eph.generatePublicKey().encoded

        // X25519 shared secret
        val shared = ByteArray(32)
        val agreement = X25519Agreement()
        agreement.init(eph)
        agreement.calculateAgreement(X25519PublicKeyParameters(recipientPub), shared, 0)

        // HKDF-SHA256 → 256-bit AES key
        val key = hkdf32(shared)

        // AES-256-GCM encrypt
        val nonce = ByteArray(NONCE_LEN).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
        val ctAndTag = cipher.doFinal(plaintext) // JCA GCM: ciphertext || 16-byte tag

        // Wire: ephPub(32) || nonce(12) || ciphertext || tag(16)
        return ephPubBytes + nonce + ctAndTag
    }

    private fun eciesDecrypt(mySk: ByteArray, layer: ByteArray): ByteArray {
        require(layer.size >= MIN_LAYER) { "onion layer too short: ${layer.size} bytes" }

        val ephPub = layer.copyOfRange(0, PUB_LEN)
        val nonce = layer.copyOfRange(PUB_LEN, PUB_LEN + NONCE_LEN)
        val ctAndTag = layer.copyOfRange(PUB_LEN + NONCE_LEN, layer.size)

        // X25519 shared secret
        val shared = ByteArray(32)
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(mySk))
        agreement.calculateAgreement(X25519PublicKeyParameters(ephPub), shared, 0)

        // HKDF-SHA256 → 256-bit AES key
        val key = hkdf32(shared)

        // AES-256-GCM decrypt (ctAndTag includes the 16-byte tag)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
        return cipher.doFinal(ctAndTag)
    }

    /**
     * Build an N-layer onion wrapping [payload] for all parties in [peerPubs].
     * Layers are applied in reverse index order (last party peels first).
     * [selfIndex] is the caller's own position in [peerPubs].
     * Returns the fully-wrapped onion and a selfMemo (the onion bytes immediately
     * after the caller's own layer was applied) for self-identification during peel.
     */
    fun build(payload: ByteArray, peerPubs: List<ByteArray>, selfIndex: Int): Pair<ByteArray, ByteArray> {
        require(selfIndex in peerPubs.indices) { "selfIndex $selfIndex out of range [0, ${peerPubs.size})" }
        var current = payload
        var selfMemo: ByteArray? = null
        for (i in peerPubs.indices.reversed()) {
            current = eciesEncrypt(peerPubs[i], current)
            if (i == selfIndex) {
                selfMemo = current.copyOf()
            }
        }
        return Pair(current, selfMemo!!)
    }

    /**
     * Peel one ECIES layer from every onion in [onions] using [mySk].
     * Identifies the caller's own item by exact byte-match against [selfMemo].
     * Throws [IllegalStateException] if [selfMemo] is non-null and no item matches.
     * Returns the list of peeled onions and the index of the caller's own item (-1 if selfMemo is null).
     */
    fun peelBatch(mySk: ByteArray, selfMemo: ByteArray?, onions: List<ByteArray>): Pair<List<ByteArray>, Int> {
        var ownIndex = -1
        val peeled = ArrayList<ByteArray>(onions.size)
        for ((i, o) in onions.withIndex()) {
            if (selfMemo != null && o.contentEquals(selfMemo)) {
                ownIndex = i
            }
            peeled.add(eciesDecrypt(mySk, o))
        }
        if (selfMemo != null && ownIndex < 0) {
            throw IllegalStateException("selfMemo matched no onion in the batch")
        }
        return Pair(peeled, ownIndex)
    }
}
