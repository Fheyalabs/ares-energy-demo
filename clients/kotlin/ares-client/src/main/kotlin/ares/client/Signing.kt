// SPDX-License-Identifier: Apache-2.0

package ares.client

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Canonical JSON serialisation, Ed25519 device signing, and HMAC-SHA256 auth-token.
 *
 * All operations are stateless and side-effect-free.
 */
object Signing {

    /**
     * Produce a compact, sorted-keys JSON byte string from [obj].
     *
     * Rules:
     *  - Keys are sorted lexicographically (top-level only — matches Go server behaviour).
     *  - No whitespace.
     *  - String values are JSON-escaped (backslash and double-quote only for basic safety).
     *  - Numeric types (Int, Long, Double) and Boolean are serialised without quotes.
     *  - Any other value is serialised as a quoted `toString()`.
     *
     * @param obj  map of top-level JSON fields; nested structures are not recursively sorted
     * @return UTF-8 encoded compact canonical JSON
     */
    fun canonicalJson(obj: Map<String, Any>): ByteArray {
        val sb = StringBuilder("{")
        for ((i, k) in obj.keys.sorted().withIndex()) {
            if (i > 0) sb.append(",")
            sb.append("\"").append(k.replace("\\", "\\\\").replace("\"", "\\\"")).append("\":")
            when (val v = obj[k]) {
                is String  -> sb.append("\"").append(v.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"")
                is Int, is Long, is Boolean -> sb.append(v.toString())
                is Double  -> sb.append(if (v % 1.0 == 0.0) v.toLong().toString() else v.toString())
                else       -> sb.append("\"").append(v.toString()).append("\"")
            }
        }
        sb.append("}")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Sign a canonical JSON payload with an Ed25519 device key.
     *
     * Signing message: `"$label|$sessionID|"` (UTF-8) concatenated with [canonical].
     * This matches the Swift `Signing.deviceSign` and the Go server's `verifySignedPayload`.
     *
     * @param seed      32-byte Ed25519 private key seed
     * @param label     message-type label (e.g. `"verify.submit"`)
     * @param sessionID session identifier
     * @param canonical canonical JSON bytes produced by [canonicalJson]
     * @return raw 64-byte Ed25519 signature (RFC 8032, deterministic)
     */
    fun deviceSign(seed: ByteArray, label: String, sessionID: String, canonical: ByteArray): ByteArray {
        val prefix = "$label|$sessionID|".toByteArray(Charsets.UTF_8)
        val msg = prefix + canonical
        val signer = Ed25519Signer().apply {
            init(true, Ed25519PrivateKeyParameters(seed, 0))
            update(msg, 0, msg.size)
        }
        return signer.generateSignature()
    }

    /**
     * Compute the ARES auth-token: `HMAC-SHA256(secret, pseudonym)` as lowercase hex.
     *
     * Both [secret] and [pseudonym] are interpreted as raw UTF-8 bytes.
     *
     * @param secret    shared HMAC secret
     * @param pseudonym caller pseudonym (the HMAC data)
     * @return 64-character lowercase hex string
     */
    fun authToken(secret: String, pseudonym: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return ByteUtil.hex(mac.doFinal(pseudonym.toByteArray(Charsets.UTF_8)))
    }
}
