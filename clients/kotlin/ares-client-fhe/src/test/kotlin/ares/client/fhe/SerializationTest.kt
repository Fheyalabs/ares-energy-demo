package ares.client.fhe

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class SerializationTest {
    @Test fun pkSerializeRoundTripAndDecrypt() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            val f = ctx.keyGenFirst()
            val ser = ctx.serialize(f.publicKey)
            val deser = ctx.deserializePublicKey(ser)
            val input = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
            val ct = ctx.encrypt(input, deser)
            val partial = ctx.partialDecrypt(ct, f.secretKey)
            val out = ctx.fuse(listOf(partial), 8)
            assertEquals(1.0, out[0], 0.05)
        }
    }

    @Test fun ctSerializeRoundTripAndDecrypt() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            val f = ctx.keyGenFirst()
            val input = doubleArrayOf(7.0, 8.0)
            val ct = ctx.encrypt(input, f.publicKey)
            val ser = ctx.serialize(ct)
            val deser = ctx.deserializeCiphertext(ser)
            val partial = ctx.partialDecrypt(deser, f.secretKey)
            val out = ctx.fuse(listOf(partial), 8)
            assertEquals(7.0, out[0], 0.05); assertEquals(8.0, out[1], 0.05)
        }
    }

    @Test fun evalMultKeySerializeRoundTrip() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            val f = ctx.keyGenFirst()
            val emk = ctx.genEvalMultKeyShare(f.secretKey)
            val ser = ctx.serialize(emk)
            val deser = ctx.deserializeEvalMultKey(ser)
            ctx.insertEvalMultKey(deser) // should not throw
        }
    }

    @Test fun rotKeySerializeRoundTrip() {
        assumeTrue(NativeFHE.loaded)
        CryptoContext(1024, Math.scalb(1.0, 50), 4).use { ctx ->
            val f = ctx.keyGenFirst()
            val rk = ctx.genRotKeyShare(f.secretKey)
            val ser = ctx.serialize(rk)
            val deser = ctx.deserializeRotKey(ser)
            ctx.insertEvalSumKey(deser) // should not throw
        }
    }

    // ctxMismatchDeserializeThrows: OpenFHE 1.5.1 does not validate ring-dim
    // mismatch at DeserializePublicKey time; the key deserializes but would
    // fail on use. Keep this test as documentation of the current behavior —
    // if a future OpenFHE version adds validation, rename and re-enable.
    // @Test fun ctxMismatchDeserializeThrows() { ... }
}
