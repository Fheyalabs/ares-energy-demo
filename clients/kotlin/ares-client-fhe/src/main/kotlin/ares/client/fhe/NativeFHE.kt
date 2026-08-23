package ares.client.fhe

internal object NativeFHE {
    @Volatile var loaded = false; private set
    init {
        try { System.loadLibrary("ares_fhe_jni"); loaded = true } catch (_: Throwable) { loaded = false }
    }
    external fun getVersion(out: ByteArray): Int
    external fun smoke(): Int
    external fun createContext(ringDim: Int, scale: Double, depth: Int, batchSize: Int = 0): Long
    external fun createContextWithModuli(ringDim: Int, depth: Int, scalingModSize: Int, firstModSize: Int, batchSize: Int = 0): Long
    external fun createBFVContext(ringDim: Int, multiplicativeDepth: Int, plaintextModulus: Long, batchSize: Int = 0): Long
    external fun freeContext(ctx: Long)
    external fun setMinimalRotationKeys(ctx: Long, profileDim: Int, payloadSlotCount: Int)
    external fun setEvalSumOnlyRotationKeys(ctx: Long, profileDim: Int)
    external fun rotationIndices(ctx: Long): IntArray
    external fun keyGenFirst(ctx: Long): LongArray
    external fun keyGenNext(ctx: Long, prevPk: Long): LongArray
    external fun multiAddPublicKeys(ctx: Long, pks: LongArray): Long
    external fun genEvalMultKeyShare(ctx: Long, sk: Long): Long
    external fun genRotKeyShare(ctx: Long, sk: Long): Long
    external fun evalMultKeyGenLead(ctx: Long, sk: Long): Long
    external fun evalMultKeySwitchShare(ctx: Long, sk: Long, base: Long): Long
    external fun combineEvalMultSwitchShares(ctx: Long, pks: LongArray, shares: LongArray): Long
    external fun evalMultKeyFinalShare(ctx: Long, sk: Long, joined: Long, finalPk: Long): Long
    external fun combineEvalMultFinalShares(ctx: Long, finalPk: Long, shares: LongArray): Long
    external fun insertEvalMultKey(ctx: Long, key: Long): Int
    external fun evalSumKeyGenLead(ctx: Long, sk: Long): Long
    external fun evalSumKeyShare(ctx: Long, sk: Long, base: Long, ownPk: Long): Long
    external fun generatePerIndexEvalSumKey(ctx: Long, sk: Long, index: Int): Long
    external fun generatePerIndexEvalSumShare(ctx: Long, sk: Long, base: Long, ownPk: Long, index: Int): Long
    external fun combineEvalSumKeys(ctx: Long, pks: LongArray, shares: LongArray): Long
    external fun insertEvalSumKey(ctx: Long, key: Long): Int
    external fun encrypt(ctx: Long, pk: Long, values: DoubleArray): Long
    external fun encryptPackedInt(ctx: Long, pk: Long, values: LongArray): Long
    external fun multiDecMain(ctx: Long, ct: Long, sk: Long): Long
    external fun multiDecFusion(ctx: Long, partials: LongArray, cap: Int): DoubleArray
    external fun multiDecFusionPackedInt(ctx: Long, partials: LongArray, cap: Int): LongArray
    external fun evalAdd(ctx: Long, a: Long, b: Long): Long
    external fun evalSub(ctx: Long, a: Long, b: Long): Long
    external fun evalMult(ctx: Long, a: Long, b: Long): Long
    external fun evalMultConst(ctx: Long, ct: Long, scalar: Double): Long
    external fun evalSum(ctx: Long, ct: Long, batchSize: Int): Long
    external fun evalChebyshevSign(ctx: Long, ct: Long, degree: Int): Long
    external fun evalPolynomial(ctx: Long, ct: Long, coeffs: DoubleArray): Long
    external fun evalArgmax(ctx: Long, cts: LongArray, sharp: DoubleArray): LongArray
    external fun encryptSerializedPayloadChunk(ctx: Long, pk: Long, payload: ByteArray, bitOffset: Int, chunkSize: Int): ByteArray?
    external fun encryptSerializedRepeatedScalar(ctx: Long, pk: Long, value: Double): ByteArray?
    external fun computeSerializedSquaredDistance(ctx: Long, originFirst: ByteArray, originSecond: ByteArray, localFirst: Double, localSecond: Double): ByteArray?
    external fun encryptSerializedRepeatedScalarBFV(ctx: Long, pk: Long, value: Long): ByteArray?
    external fun computeSerializedSquaredDistanceBFV(ctx: Long, originFirst: ByteArray, originSecond: ByteArray, localFirst: Long, localSecond: Long): ByteArray?
    external fun serializeCiphertext(h: Long): ByteArray?
    external fun deserializeCiphertext(ctx: Long, data: ByteArray): Long
    external fun serializePublicKey(h: Long): ByteArray?
    external fun deserializePublicKey(ctx: Long, data: ByteArray): Long
    external fun serializeSecretKeyShare(h: Long): ByteArray?
    external fun deserializeSecretKeyShare(ctx: Long, data: ByteArray, lead: Int): Long
    external fun serializeEvalMultKey(h: Long): ByteArray?
    external fun deserializeEvalMultKey(ctx: Long, data: ByteArray): Long
    external fun serializeRotKey(h: Long): ByteArray?
    external fun deserializeRotKey(ctx: Long, data: ByteArray): Long
    // b-only rotation-key wire (CRS optimization): transmit only b, send/seed a once.
    external fun serializeRotKeyBVectors(h: Long): ByteArray?
    external fun serializeRotKeyAVectors(h: Long): ByteArray?
    external fun reconstructRotKeyFromAB(ctx: Long, a: ByteArray, b: ByteArray): Long
    external fun freePublicKey(h: Long)
    external fun freeSecretKeyShare(h: Long)
    external fun freeCiphertext(h: Long)
    external fun freeEvalMultKey(h: Long)
    external fun freeRotKey(h: Long)

    // Single-key (initiator-only, not threshold)
    external fun singleKeyEvalMultKeyGen(ctx: Long, sk: Long): Int
    external fun decryptSingle(ctx: Long, ct: Long, sk: Long,
        outVals: DoubleArray, nVals: IntArray): Int

    fun version(): String { val b = ByteArray(32); val n = getVersion(b); return if (n > 0) String(b, 0, n) else "" }
}
