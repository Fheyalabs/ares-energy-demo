// SPDX-License-Identifier: Apache-2.0
#include <jni.h>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "openfhe_wrapper.h"

static inline jlong H(void* p) { return reinterpret_cast<jlong>(p); }
static inline void* P(jlong h) { return reinterpret_cast<void*>(h); }

// Copy a C array of void* handles out of a Java long[].
static std::vector<void*> handles(JNIEnv* env, jlongArray arr) {
    jsize n = env->GetArrayLength(arr);
    std::vector<void*> out(n);
    jlong* e = env->GetLongArrayElements(arr, nullptr);
    for (jsize i = 0; i < n; i++) out[i] = P(e[i]);
    env->ReleaseLongArrayElements(arr, e, JNI_ABORT);
    return out;
}
// Wrap a malloc'd (uint8_t*,len) into a jbyteArray and free the C buffer.
static jbyteArray bytesAndFree(JNIEnv* env, uint8_t* buf, size_t len, int rc) {
    if (rc != 0 || buf == nullptr) { if (buf) free(buf); return nullptr; }
    jbyteArray out = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(out, 0, (jsize)len, reinterpret_cast<jbyte*>(buf));
    free(buf);
    return out;
}

extern "C" {

// ── version / smoke ──
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_getVersion(JNIEnv* env, jclass, jbyteArray out) {
    char buf[32] = {0};
    int n = GetOpenFHEVersion(buf, 32);
    if (n > 0) env->SetByteArrayRegion(out, 0, n, reinterpret_cast<jbyte*>(buf));
    return n;
}
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_smoke(JNIEnv*, jclass) {
    char err[1024] = {0}; return ARESOpenFHESmoke(err, sizeof err);
}

// ── context ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_createContext(JNIEnv*, jclass, jint ringDim, jdouble scale, jint depth, jint batchSize) {
    return H(CreateCKKSContext((uint32_t)ringDim, (double)scale, (uint32_t)depth, (uint32_t)batchSize));
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_createContextWithModuli(JNIEnv*, jclass, jint ringDim, jint depth, jint scalingModSize, jint firstModSize, jint batchSize) {
    return H(CreateCKKSContextWithModuli(
        (uint32_t)ringDim,
        (uint32_t)depth,
        (uint32_t)scalingModSize,
        (uint32_t)firstModSize,
        (uint32_t)batchSize));
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_createBFVContext(JNIEnv*, jclass, jint ringDim, jint multiplicativeDepth, jlong plaintextModulus, jint batchSize) {
    return H(CreateBFVContext(
        (uint32_t)ringDim,
        (uint32_t)multiplicativeDepth,
        (uint64_t)plaintextModulus,
        (uint32_t)batchSize
    ));
}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeContext(JNIEnv*, jclass, jlong c) { FreeCryptoContext(P(c)); }
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_setMinimalRotationKeys(JNIEnv*, jclass, jlong ctx, jint profileDim, jint payloadSlotCount) {
    SetMinimalRotationKeys(P(ctx), (int)profileDim, (int)payloadSlotCount);
}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_setEvalSumOnlyRotationKeys(JNIEnv*, jclass, jlong ctx, jint profileDim) {
    SetEvalSumOnlyRotationKeys(P(ctx), (int)profileDim);
}
JNIEXPORT jintArray JNICALL Java_ares_client_fhe_NativeFHE_rotationIndices(JNIEnv* env, jclass, jlong ctx) {
    int32_t count = 0;
    if (GetMinimalRotationIndices(P(ctx), nullptr, &count) != 0 || count <= 0) {
        return env->NewIntArray(0);
    }
    std::vector<int32_t> indices((size_t)count);
    if (GetMinimalRotationIndices(P(ctx), indices.data(), &count) != 0 || count <= 0) {
        return env->NewIntArray(0);
    }
    std::vector<jint> output((size_t)count);
    for (int32_t i = 0; i < count; i++) {
        output[(size_t)i] = static_cast<jint>(indices[(size_t)i]);
    }
    jintArray out = env->NewIntArray(count);
    env->SetIntArrayRegion(out, 0, count, output.data());
    return out;
}

// ── keygen ── (out-param pairs returned as long[]{pk,sk}; empty array on failure)
JNIEXPORT jlongArray JNICALL Java_ares_client_fhe_NativeFHE_keyGenFirst(JNIEnv* env, jclass, jlong ctx) {
    void* pk=nullptr; void* sk=nullptr;
    int rc = KeyGenFirst(P(ctx), &pk, &sk);
    jlongArray out = env->NewLongArray(rc==0 ? 2 : 0);
    if (rc==0) { jlong v[2]={H(pk),H(sk)}; env->SetLongArrayRegion(out,0,2,v); }
    return out;
}
JNIEXPORT jlongArray JNICALL Java_ares_client_fhe_NativeFHE_keyGenNext(JNIEnv* env, jclass, jlong ctx, jlong prevPk) {
    void* pk=nullptr; void* sk=nullptr;
    int rc = KeyGenNext(P(ctx), P(prevPk), &pk, &sk);
    jlongArray out = env->NewLongArray(rc==0 ? 2 : 0);
    if (rc==0) { jlong v[2]={H(pk),H(sk)}; env->SetLongArrayRegion(out,0,2,v); }
    return out;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_multiAddPublicKeys(JNIEnv* env, jclass, jlong ctx, jlongArray pks) {
    auto v = handles(env, pks); void* out=nullptr;
    int rc = MultiAddPublicKeys(P(ctx), v.data(), (int)v.size(), &out);
    return rc==0 ? H(out) : 0;
}

// ── eval-key shares ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_genEvalMultKeyShare(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return GenEvalMultKeyShare(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_genRotKeyShare(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return GenRotKeyShare(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}

// ── eval-mult-key 2-round ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultKeyGenLead(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return EvalMultKeyGenLead(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultKeySwitchShare(JNIEnv*, jclass, jlong ctx, jlong sk, jlong base) {
    void* out=nullptr; return EvalMultKeySwitchShare(P(ctx), P(sk), P(base), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_combineEvalMultSwitchShares(JNIEnv* env, jclass, jlong ctx, jlongArray pks, jlongArray shares) {
    auto pv = handles(env, pks); auto sv = handles(env, shares); void* out=nullptr;
    int rc = CombineEvalMultSwitchShares(P(ctx), pv.data(), sv.data(), (int)sv.size(), &out);
    return rc==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultKeyFinalShare(JNIEnv*, jclass, jlong ctx, jlong sk, jlong joined, jlong finalPk) {
    void* out=nullptr; return EvalMultKeyFinalShare(P(ctx), P(sk), P(joined), P(finalPk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_combineEvalMultFinalShares(JNIEnv* env, jclass, jlong ctx, jlong finalPk, jlongArray shares) {
    auto sv = handles(env, shares); void* out=nullptr;
    int rc = CombineEvalMultFinalShares(P(ctx), P(finalPk), sv.data(), (int)sv.size(), &out);
    return rc==0 ? H(out) : 0;
}
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_insertEvalMultKey(JNIEnv*, jclass, jlong ctx, jlong key) {
    return InsertEvalMultKey(P(ctx), P(key));
}

// ── eval-sum (rotation) key ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSumKeyGenLead(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return EvalSumKeyGenLead(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSumKeyShare(JNIEnv*, jclass, jlong ctx, jlong sk, jlong base, jlong ownPk) {
    void* out=nullptr; return EvalSumKeyShare(P(ctx), P(sk), P(base), P(ownPk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_generatePerIndexEvalSumKey(JNIEnv*, jclass, jlong ctx, jlong sk, jint index) {
    void* out=nullptr; return GeneratePerIndexEvalSumKey(P(ctx), P(sk), (int32_t)index, &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_generatePerIndexEvalSumShare(JNIEnv*, jclass, jlong ctx, jlong sk, jlong base, jlong ownPk, jint index) {
    void* out=nullptr; return GeneratePerIndexEvalSumShare(P(ctx), P(sk), P(base), P(ownPk), (int32_t)index, &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_combineEvalSumKeys(JNIEnv* env, jclass, jlong ctx, jlongArray pks, jlongArray shares) {
    auto pv = handles(env, pks); auto sv = handles(env, shares); void* out=nullptr;
    int rc = CombineEvalSumKeys(P(ctx), pv.data(), sv.data(), (int)sv.size(), &out);
    return rc==0 ? H(out) : 0;
}
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_insertEvalSumKey(JNIEnv*, jclass, jlong ctx, jlong key) {
    return InsertEvalSumKey(P(ctx), P(key));
}

// ── encrypt / decrypt ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_encrypt(JNIEnv* env, jclass, jlong ctx, jlong pk, jdoubleArray values) {
    jsize n = env->GetArrayLength(values);
    jdouble* v = env->GetDoubleArrayElements(values, nullptr);
    void* out = Encrypt(P(ctx), P(pk), v, (int)n);
    env->ReleaseDoubleArrayElements(values, v, JNI_ABORT);
    return H(out);
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_encryptPackedInt(JNIEnv* env, jclass, jlong ctx, jlong pk, jlongArray values) {
    if (values == nullptr) return 0;
    jsize n = env->GetArrayLength(values);
    if (n <= 0) return 0;
    jlong* packed = env->GetLongArrayElements(values, nullptr);
    if (packed == nullptr) return 0;
    std::vector<int64_t> nativeValues((size_t)n);
    for (jsize i = 0; i < n; ++i) nativeValues[(size_t)i] = (int64_t)packed[i];
    void* out = EncryptPackedInt(P(ctx), P(pk), nativeValues.data(), (int)n);
    env->ReleaseLongArrayElements(values, packed, JNI_ABORT);
    return H(out);
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_multiDecMain(JNIEnv*, jclass, jlong ctx, jlong ct, jlong sk) {
    void* out=nullptr; return MultiDecMain(P(ctx), P(ct), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jdoubleArray JNICALL Java_ares_client_fhe_NativeFHE_multiDecFusion(JNIEnv* env, jclass, jlong ctx, jlongArray partials, jint cap) {
    auto pv = handles(env, partials);
    std::vector<double> out((size_t)cap); int n = cap;
    int rc = MultiDecFusion(P(ctx), pv.data(), (int)pv.size(), out.data(), &n);
    if (rc != 0) return env->NewDoubleArray(0);
    jdoubleArray arr = env->NewDoubleArray(n);
    env->SetDoubleArrayRegion(arr, 0, n, out.data());
    return arr;
}
JNIEXPORT jlongArray JNICALL Java_ares_client_fhe_NativeFHE_multiDecFusionPackedInt(JNIEnv* env, jclass, jlong ctx, jlongArray partials, jint cap) {
    if (partials == nullptr || cap <= 0) return env->NewLongArray(0);
    auto pv = handles(env, partials);
    std::vector<int64_t> out((size_t)cap, 0);
    int n = cap;
    if (MultiDecFusionPackedInt(P(ctx), pv.data(), (int)pv.size(), out.data(), &n) != 0 || n <= 0) {
        return env->NewLongArray(0);
    }
    jlongArray arr = env->NewLongArray(n);
    std::vector<jlong> javaValues((size_t)n);
    for (int i = 0; i < n; ++i) javaValues[(size_t)i] = (jlong)out[(size_t)i];
    env->SetLongArrayRegion(arr, 0, n, javaValues.data());
    return arr;
}

// ── homomorphic ops ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalAdd(JNIEnv*, jclass, jlong c, jlong a, jlong b){return H(EvalAdd(P(c),P(a),P(b)));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSub(JNIEnv*, jclass, jlong c, jlong a, jlong b){return H(EvalSub(P(c),P(a),P(b)));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMult(JNIEnv*, jclass, jlong c, jlong a, jlong b){return H(EvalMult(P(c),P(a),P(b)));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultConst(JNIEnv*, jclass, jlong c, jlong ct, jdouble s){return H(EvalMultConst(P(c),P(ct),s));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSum(JNIEnv*, jclass, jlong c, jlong ct, jint bs){return H(EvalSum(P(c),P(ct),(int)bs));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalChebyshevSign(JNIEnv*, jclass, jlong c, jlong ct, jint deg){return H(EvalChebyshevSign(P(c),P(ct),(int)deg));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalPolynomial(JNIEnv* env, jclass, jlong c, jlong ct, jdoubleArray coeffs) {
    jsize n = env->GetArrayLength(coeffs); jdouble* v = env->GetDoubleArrayElements(coeffs, nullptr);
    void* out = EvalPolynomial(P(c), P(ct), v, (int)n);
    env->ReleaseDoubleArrayElements(coeffs, v, JNI_ABORT);
    return H(out);
}
JNIEXPORT jlongArray JNICALL Java_ares_client_fhe_NativeFHE_evalArgmax(JNIEnv* env, jclass, jlong c, jlongArray cts, jdoubleArray sharp) {
    auto cv = handles(env, cts);
    jsize sn = env->GetArrayLength(sharp); jdouble* sv = env->GetDoubleArrayElements(sharp, nullptr);
    std::vector<void*> masks(cv.size());
    int rc = EvalArgmax(P(c), (const CiphertextHandle*)cv.data(), (int)cv.size(), sv, (int)sn, masks.data());
    env->ReleaseDoubleArrayElements(sharp, sv, JNI_ABORT);
    if (rc != 0) return env->NewLongArray(0);
    jlongArray out = env->NewLongArray((jsize)masks.size());
    std::vector<jlong> jm(masks.size()); for (size_t i=0;i<masks.size();i++) jm[i]=H(masks[i]);
    env->SetLongArrayRegion(out, 0, (jsize)jm.size(), jm.data());
    return out;
}

// ── serialization ── (serialize → byte[] | null; deserialize → handle | 0)
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_encryptSerializedPayloadChunk(JNIEnv* env, jclass, jlong ctx, jlong pk, jbyteArray payload, jint bitOffset, jint chunkSize) {
    if (payload == nullptr || bitOffset < 0 || chunkSize <= 0) return nullptr;
    const jsize len = env->GetArrayLength(payload);
    jbyte* data = env->GetByteArrayElements(payload, nullptr);
    if (data == nullptr) return nullptr;
    uint8_t* out = nullptr;
    size_t outLen = 0;
    const int rc = EncryptSerializedPayloadChunk(P(ctx), P(pk), reinterpret_cast<const uint8_t*>(data),
        static_cast<size_t>(len), static_cast<size_t>(bitOffset), static_cast<size_t>(chunkSize), &out, &outLen);
    env->ReleaseByteArrayElements(payload, data, JNI_ABORT);
    return bytesAndFree(env, out, outLen, rc);
}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_encryptSerializedRepeatedScalar(JNIEnv* env, jclass, jlong ctx, jlong pk, jdouble value) {
    uint8_t* out = nullptr;
    size_t outLen = 0;
    const int rc = EncryptSerializedRepeatedScalarCKKS(P(ctx), P(pk), static_cast<double>(value), &out, &outLen);
    return bytesAndFree(env, out, outLen, rc);
}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_computeSerializedSquaredDistance(JNIEnv* env, jclass, jlong ctx, jbyteArray originFirst, jbyteArray originSecond, jdouble localFirst, jdouble localSecond) {
    if (originFirst == nullptr || originSecond == nullptr) return nullptr;
    const jsize firstLen = env->GetArrayLength(originFirst);
    const jsize secondLen = env->GetArrayLength(originSecond);
    jbyte* first = env->GetByteArrayElements(originFirst, nullptr);
    jbyte* second = env->GetByteArrayElements(originSecond, nullptr);
    if (first == nullptr || second == nullptr) {
        if (first != nullptr) env->ReleaseByteArrayElements(originFirst, first, JNI_ABORT);
        if (second != nullptr) env->ReleaseByteArrayElements(originSecond, second, JNI_ABORT);
        return nullptr;
    }
    uint8_t* out = nullptr;
    size_t outLen = 0;
    const int rc = ComputeSerializedSquaredDistanceCKKS(P(ctx),
        reinterpret_cast<const uint8_t*>(first), static_cast<size_t>(firstLen),
        reinterpret_cast<const uint8_t*>(second), static_cast<size_t>(secondLen),
        static_cast<double>(localFirst), static_cast<double>(localSecond), &out, &outLen);
    env->ReleaseByteArrayElements(originFirst, first, JNI_ABORT);
    env->ReleaseByteArrayElements(originSecond, second, JNI_ABORT);
    return bytesAndFree(env, out, outLen, rc);
}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_encryptSerializedRepeatedScalarBFV(JNIEnv* env, jclass, jlong ctx, jlong pk, jlong value) {
    uint8_t* out = nullptr;
    size_t outLen = 0;
    const int rc = EncryptSerializedRepeatedScalarBFV(P(ctx), P(pk), (int64_t)value, &out, &outLen);
    return bytesAndFree(env, out, outLen, rc);
}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_computeSerializedSquaredDistanceBFV(JNIEnv* env, jclass, jlong ctx, jbyteArray originFirst, jbyteArray originSecond, jlong localFirst, jlong localSecond) {
    if (originFirst == nullptr || originSecond == nullptr) return nullptr;
    const jsize firstLen = env->GetArrayLength(originFirst);
    const jsize secondLen = env->GetArrayLength(originSecond);
    if (firstLen <= 0 || secondLen <= 0) return nullptr;
    jbyte* first = env->GetByteArrayElements(originFirst, nullptr);
    jbyte* second = env->GetByteArrayElements(originSecond, nullptr);
    if (first == nullptr || second == nullptr) {
        if (first != nullptr) env->ReleaseByteArrayElements(originFirst, first, JNI_ABORT);
        if (second != nullptr) env->ReleaseByteArrayElements(originSecond, second, JNI_ABORT);
        return nullptr;
    }
    uint8_t* out = nullptr;
    size_t outLen = 0;
    const int rc = ComputeSerializedSquaredDistanceBFV(
        P(ctx),
        reinterpret_cast<const uint8_t*>(first), static_cast<size_t>(firstLen),
        reinterpret_cast<const uint8_t*>(second), static_cast<size_t>(secondLen),
        (int64_t)localFirst, (int64_t)localSecond,
        &out, &outLen
    );
    env->ReleaseByteArrayElements(originFirst, first, JNI_ABORT);
    env->ReleaseByteArrayElements(originSecond, second, JNI_ABORT);
    return bytesAndFree(env, out, outLen, rc);
}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeCiphertext(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeCiphertext(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeCiphertext(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeCiphertext(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializePublicKey(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializePublicKey(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializePublicKey(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializePublicKey(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeSecretKeyShare(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeSecretKeyShare(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeSecretKeyShare(JNIEnv* env, jclass, jlong ctx, jbyteArray d, jint lead){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeSecretKeyShare(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n,(int)lead); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeEvalMultKey(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeEvalMultKey(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeEvalMultKey(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeEvalMultKey(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeRotKey(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeRotKey(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeRotKey(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeRotKey(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}

// b-only rotation-key wire (CRS optimization): transmit only b, send/seed a once,
// rebuild the full share from shared a + party b. The wrapper provides
// SerializeRotKeyBVectors / SerializeRotKeyAVectors / ReconstructRotKeyFromAB.
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeRotKeyBVectors(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeRotKeyBVectors(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeRotKeyAVectors(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeRotKeyAVectors(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_reconstructRotKeyFromAB(JNIEnv* env, jclass, jlong ctx, jbyteArray a, jbyteArray b){jsize an=env->GetArrayLength(a); jbyte* ap=env->GetByteArrayElements(a,nullptr); jsize bn=env->GetArrayLength(b); jbyte* bp=env->GetByteArrayElements(b,nullptr); void* out=ReconstructRotKeyFromAB(P(ctx),reinterpret_cast<const uint8_t*>(ap),(size_t)an,reinterpret_cast<const uint8_t*>(bp),(size_t)bn); env->ReleaseByteArrayElements(a,ap,JNI_ABORT); env->ReleaseByteArrayElements(b,bp,JNI_ABORT); return H(out);}

// ── free ──
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freePublicKey(JNIEnv*, jclass, jlong h){FreePublicKey(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeSecretKeyShare(JNIEnv*, jclass, jlong h){FreeSecretKeyShare(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeCiphertext(JNIEnv*, jclass, jlong h){FreeCiphertext(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeEvalMultKey(JNIEnv*, jclass, jlong h){FreeEvalMultKey(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeRotKey(JNIEnv*, jclass, jlong h){FreeRotKey(P(h));}


// ── single-key (initiator-only, not threshold) ──

JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_singleKeyEvalMultKeyGen
  (JNIEnv*, jclass, jlong ctx, jlong sk) {
    return SingleKeyEvalMultKeyGen(P(ctx), P(sk));
}

JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_decryptSingle
  (JNIEnv* env, jclass, jlong ctx, jlong ct, jlong sk,
   jdoubleArray outVals, jintArray nVals) {
    jint* nPtr = env->GetIntArrayElements(nVals, nullptr);
    jint cap = env->GetArrayLength(outVals);
    jdouble* v = env->GetDoubleArrayElements(outVals, nullptr);
    int n = (int)cap;
    int rc = DecryptSingle(P(ctx), P(ct), P(sk), v, &n);
    env->ReleaseDoubleArrayElements(outVals, v, 0);
    *nPtr = (jint)n;
    env->ReleaseIntArrayElements(nVals, nPtr, 0);
    return rc;
}

} // extern "C"
