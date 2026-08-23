package ares.client.fhe

import java.lang.ref.Cleaner

internal val FHE_CLEANER: Cleaner = Cleaner.create()

/** Base for an opaque native handle: closeable, idempotent, Cleaner-backed. */
sealed class FheHandle(internal val raw: Long, free: (Long) -> Unit) : AutoCloseable {
    private val state = State(raw, free)
    @Suppress("unused")
    private val cleanable = FHE_CLEANER.register(this, state)
    private class State(@Volatile var raw: Long, val free: (Long) -> Unit) : Runnable {
        override fun run() { val h = raw; if (h != 0L) { raw = 0L; free(h) } }
    }
    final override fun close() { state.run() }   // explicit free; Cleaner is the safety net
}

class PublicKey internal constructor(raw: Long) : FheHandle(raw, NativeFHE::freePublicKey)
class SecretKeyShare internal constructor(raw: Long) : FheHandle(raw, NativeFHE::freeSecretKeyShare)
class Ciphertext internal constructor(raw: Long) : FheHandle(raw, NativeFHE::freeCiphertext)
class EvalMultKey internal constructor(raw: Long) : FheHandle(raw, NativeFHE::freeEvalMultKey)
class RotKey internal constructor(raw: Long) : FheHandle(raw, NativeFHE::freeRotKey)
