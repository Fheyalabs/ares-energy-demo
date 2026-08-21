// SPDX-License-Identifier: Apache-2.0

// pool_wasm exposes the browser-side surface of the uniform-price pool.
//
// It is a thin embind veneer over ARES-core's existing C wrapper
// (pkg/ares/crypto/cgo/openfhe_wrapper.{h,cpp}) — the same file the Go
// bridge and the iOS/Android ports compile. Reusing it verbatim means the
// browser runs the validated API rather than a second implementation that
// would have to be kept in sync.
//
// Everything here runs inside the tab. No plaintext offer curve is ever
// serialised out of this module.

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#include "openfhe_wrapper.h"

using emscripten::val;

namespace {

// Serialised OpenFHE objects cross the JS boundary as Uint8Array.
//
// Note what is NOT used here: std::string. embind runs std::string through
// UTF-8 conversion, which silently mangles every byte above 0x7F and
// corrupts serialised keys and ciphertexts. basic_string<unsigned char>
// would avoid that but libc++ has no char_traits for it. A byte vector
// plus explicit typed-array marshalling is the combination that works.
using Bytes = std::vector<uint8_t>;

Bytes fromVal(const val& v) {
    return emscripten::convertJSArrayToNumberVector<uint8_t>(v);
}

// slice() copies out of the WASM heap, so the result stays valid after the
// underlying buffer is freed or memory grows.
val toVal(const Bytes& b) {
    return val(emscripten::typed_memory_view(b.size(), b.data())).call<val>("slice");
}

Bytes takeBuffer(uint8_t* data, size_t len) {
    if (!data) throw std::runtime_error("pool_wasm: null buffer");
    Bytes out(data, data + len);
    free(data);
    return out;
}

void must(int rc, const char* what) {
    if (rc != 0) throw std::runtime_error(std::string("pool_wasm: ") + what + " failed");
}

template <typename T>
T notNull(T h, const char* what) {
    if (!h) throw std::runtime_error(std::string("pool_wasm: ") + what + " returned null");
    return h;
}

// Session owns one CKKS context plus this tab's key share. One tab, one
// Session — the object graph mirrors the trust boundary.
class Session {
public:
    Session(uint32_t ringDim, uint32_t depth, uint32_t scalingModSize,
            uint32_t firstModSize, uint32_t batchSize) {
        ctx_ = notNull(CreateCKKSContextWithModuli(ringDim, depth, scalingModSize,
                                                   firstModSize, batchSize),
                       "CreateCKKSContext");
    }
    ~Session() {
        if (ctx_) FreeCryptoContext(ctx_);
    }

    // ---- threshold keygen chain -------------------------------------
    // The first tab in a pool calls keyGenFirst; every later tab calls
    // keyGenNext with the previous tab's public key. The last public key
    // in the chain is the joint key everyone encrypts under, and no tab
    // ever holds more than its own share.

    val keyGenFirst() {
        PublicKeyHandle pk = nullptr;
        SecretKeyShareHandle sk = nullptr;
        must(KeyGenFirst(ctx_, &pk, &sk), "KeyGenFirst");
        sk_ = sk;
        return toVal(serializePK(pk));
    }

    val keyGenNext(const val& prevPKv) {
        Bytes prevPK = fromVal(prevPKv);
        PublicKeyHandle prev = notNull(
            DeserializePublicKey(ctx_, prevPK.data(), prevPK.size()),
            "DeserializePublicKey");
        PublicKeyHandle pk = nullptr;
        SecretKeyShareHandle sk = nullptr;
        must(KeyGenNext(ctx_, prev, &pk, &sk), "KeyGenNext");
        sk_ = sk;
        return toVal(serializePK(pk));
    }

    // ---- the operation that carries the privacy claim ---------------
    // The offer curve is encoded and encrypted here, in the tab. Only the
    // ciphertext leaves.
    val encrypt(const val& jointPKv, const val& values) {
        Bytes jointPK = fromVal(jointPKv);
        auto vals = emscripten::convertJSArrayToNumberVector<double>(values);
        PublicKeyHandle pk = notNull(
            DeserializePublicKey(ctx_, jointPK.data(), jointPK.size()),
            "DeserializePublicKey");
        CiphertextHandle ct = notNull(
            Encrypt(ctx_, pk, vals.data(), static_cast<int>(vals.size())), "Encrypt");
        return toVal(serializeCT(ct));
    }

    // ---- clearing circuit -------------------------------------------
    val evalAdd(const val& a, const val& b) { return binop(a, b, OpAdd); }
    val evalSub(const val& a, const val& b) { return binop(a, b, OpSub); }
    val evalMult(const val& a, const val& b) { return binop(a, b, OpMult); }

    val evalMultConst(const val& a, double k) {
        CiphertextHandle ca = deserializeCT(fromVal(a));
        CiphertextHandle out = notNull(EvalMultConst(ctx_, ca, k), "EvalMultConst");
        FreeCiphertext(ca);
        return toVal(serializeCT(out));
    }

    val evalPoly(const val& a, const val& coeffs) {
        auto cs = emscripten::convertJSArrayToNumberVector<double>(coeffs);
        CiphertextHandle ca = deserializeCT(fromVal(a));
        CiphertextHandle out = notNull(
            EvalPolynomial(ctx_, ca, cs.data(), static_cast<int>(cs.size())),
            "EvalPolynomial");
        FreeCiphertext(ca);
        return toVal(serializeCT(out));
    }

    val evalAtIndex(const val& a, int index) {
        CiphertextHandle ca = deserializeCT(fromVal(a));
        CiphertextHandle out = notNull(EvalAtIndex(ctx_, ca, index), "EvalAtIndex");
        FreeCiphertext(ca);
        return toVal(serializeCT(out));
    }

    // ---- threshold decryption ---------------------------------------
    // Each tab contributes a partial with its own share; nobody can open a
    // ciphertext alone.
    val partialDecrypt(const val& ctv) {
        if (!sk_) throw std::runtime_error("pool_wasm: this tab holds no key share");
        CiphertextHandle c = deserializeCT(fromVal(ctv));
        CiphertextHandle partial = nullptr;
        int rc = MultiDecMain(ctx_, c, sk_, &partial);
        FreeCiphertext(c);
        must(rc, "MultiDecMain");
        return toVal(serializeCT(partial));
    }

    val fuse(const val& partialsJS, int nSlots) {
        const unsigned n = partialsJS["length"].as<unsigned>();
        std::vector<CiphertextHandle> handles;
        handles.reserve(n);
        for (unsigned i = 0; i < n; ++i) {
            handles.push_back(deserializeCT(fromVal(partialsJS[i])));
        }

        std::vector<double> out(static_cast<size_t>(nSlots));
        int got = nSlots;
        int rc = MultiDecFusion(ctx_, handles.data(), static_cast<int>(handles.size()),
                                out.data(), &got);
        for (auto h : handles) FreeCiphertext(h);
        must(rc, "MultiDecFusion");

        val arr = val::array();
        for (int i = 0; i < got && i < nSlots; ++i) arr.set(i, out[static_cast<size_t>(i)]);
        return arr;
    }

private:
    enum Op { OpAdd, OpSub, OpMult };

    val binop(const val& av, const val& bv, Op op) {
        CiphertextHandle ca = deserializeCT(fromVal(av));
        CiphertextHandle cb = deserializeCT(fromVal(bv));
        CiphertextHandle out = nullptr;
        switch (op) {
            case OpAdd:  out = EvalAdd(ctx_, ca, cb);  break;
            case OpSub:  out = EvalSub(ctx_, ca, cb);  break;
            case OpMult: out = EvalMult(ctx_, ca, cb); break;
        }
        FreeCiphertext(ca);
        FreeCiphertext(cb);
        return toVal(serializeCT(notNull(out, "binop")));
    }

    CiphertextHandle deserializeCT(const Bytes& b) {
        return notNull(
            DeserializeCiphertext(ctx_, const_cast<uint8_t*>(b.data()), b.size()),
            "DeserializeCiphertext");
    }

    Bytes serializeCT(CiphertextHandle ct) {
        uint8_t* data = nullptr;
        size_t len = 0;
        int rc = SerializeCiphertext(ct, &data, &len);
        FreeCiphertext(ct);
        must(rc, "SerializeCiphertext");
        return takeBuffer(data, len);
    }

    Bytes serializePK(PublicKeyHandle pk) {
        uint8_t* data = nullptr;
        size_t len = 0;
        must(SerializePublicKey(pk, &data, &len), "SerializePublicKey");
        return takeBuffer(data, len);
    }

    CryptoContextHandle ctx_ = nullptr;
    SecretKeyShareHandle sk_ = nullptr;
};

std::string version() {
    char buf[64] = {0};
    GetOpenFHEVersion(buf, static_cast<int>(sizeof(buf)));
    return std::string(buf);
}

}  // namespace

EMSCRIPTEN_BINDINGS(pool_wasm) {
    emscripten::function("openfheVersion", &version);
    emscripten::class_<Session>("Session")
        .constructor<uint32_t, uint32_t, uint32_t, uint32_t, uint32_t>()
        .function("keyGenFirst", &Session::keyGenFirst)
        .function("keyGenNext", &Session::keyGenNext)
        .function("encrypt", &Session::encrypt)
        .function("evalAdd", &Session::evalAdd)
        .function("evalSub", &Session::evalSub)
        .function("evalMult", &Session::evalMult)
        .function("evalMultConst", &Session::evalMultConst)
        .function("evalPoly", &Session::evalPoly)
        .function("evalAtIndex", &Session::evalAtIndex)
        .function("partialDecrypt", &Session::partialDecrypt)
        .function("fuse", &Session::fuse);
}
