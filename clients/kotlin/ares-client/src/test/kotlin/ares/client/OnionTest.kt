package ares.client

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class OnionTest {

    @Test fun nPartyBuildThenPeelRoundTrip() {
        val n = 4
        val sks = ArrayList<ByteArray>(); val pubs = ArrayList<ByteArray>()
        repeat(n) {
            val sk = X25519PrivateKeyParameters(SecureRandom())
            sks.add(sk.encoded); pubs.add(sk.generatePublicKey().encoded)
        }
        val payloads = (0 until n).map { "payload-$it".toByteArray() }
        val memos = ArrayList<ByteArray>()
        var batch = ArrayList<ByteArray>()
        for (i in 0 until n) {
            val (onion, memo) = Onion.build(payloads[i], pubs, i)
            batch.add(onion); memos.add(memo)
        }
        // Sequential peel: each party peels one layer off every onion, locating its own by selfMemo.
        for (round in 0 until n) {
            val (peeled, ownIdx) = Onion.peelBatch(sks[round], memos[round], batch)
            assertTrue(ownIdx >= 0, "party $round must locate its own item by selfMemo")
            batch = ArrayList(peeled)
        }
        // After n peels, each item at position i is the innermost payload for that builder.
        // Mirror Swift: assert positional equality batch[i] == payloads[i].
        for (i in 0 until n) {
            assertTrue(batch[i].contentEquals(payloads[i]), "party $i payload not recovered at position $i")
        }
    }

    @Test fun peelBatchThrowsWhenSelfMemoUnmatched() {
        val keys = (0 until 2).map {
            val sk = X25519PrivateKeyParameters(SecureRandom())
            Pair(sk.encoded, sk.generatePublicKey().encoded)
        }
        val pubs = keys.map { it.second }
        val (onion, _) = Onion.build("x".toByteArray(), pubs, 0)
        assertFailsWith<IllegalStateException> {
            Onion.peelBatch(keys[0].first, byteArrayOf(0xde.toByte(), 0xad.toByte()), listOf(onion))
        }
    }

    @Test fun buildRejectsBadSelfIndex() {
        val keys = (0 until 2).map {
            val sk = X25519PrivateKeyParameters(SecureRandom())
            Pair(sk.encoded, sk.generatePublicKey().encoded)
        }
        val pubs = keys.map { it.second }
        assertFailsWith<IllegalArgumentException> {
            Onion.build("x".toByteArray(), pubs, 5)
        }
    }

    @Test fun peelBatchRejectsMalformedShortLayer() {
        val sk = X25519PrivateKeyParameters(SecureRandom())
        assertFailsWith<IllegalArgumentException> {
            Onion.peelBatch(sk.encoded, null, listOf(byteArrayOf(0, 1, 2)))
        }
    }
}
