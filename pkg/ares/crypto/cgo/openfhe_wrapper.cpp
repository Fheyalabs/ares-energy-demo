// SPDX-License-Identifier: Apache-2.0

// OpenFHE C wrapper implementation.

#include <openfhe.h>
#include <ciphertext-ser.h>
#include <cryptocontext-ser.h>
#include <scheme/ckksrns/ckksrns-ser.h>
#include <key/key-ser.h>
#include <version.h>
#include "openfhe_wrapper.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <stdlib.h>
#include <streambuf>
#include <cstdio>
#include <stdexcept>
#include <string.h>
#include <string>
#include <vector>

// --- RSS heap instrumentation ---
#ifdef __APPLE__
#include <mach/mach.h>
static size_t current_rss_kb() {
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &count) == KERN_SUCCESS) {
        return info.resident_size / 1024;
    }
    return 0;
}
#else
#include <unistd.h>
static size_t current_rss_kb() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    size_t rss = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "VmRSS: %zu kB", &rss) == 1) break;
    }
    fclose(f);
    return rss;
}
#endif

static void logHeap(const char* label) {
    static bool enabled = []() {
        const char* value = getenv("ARES_OPENFHE_HEAP_LOG");
        return value != nullptr && value[0] != '\0' && strcmp(value, "0") != 0;
    }();
    if (!enabled) return;
    static size_t last_rss = 0;
    size_t rss = current_rss_kb();
    if (last_rss == 0) last_rss = rss;
    fprintf(stderr, "[heap] %-40s  RSS=%7.1f MB  Δ=%+6.1f MB\n",
        label, rss / 1024.0, (rss - last_rss) / 1024.0);
    last_rss = rss;
}
#define HEAP_LOG(label) logHeap(label)
// --- end heap instrumentation ---

using namespace lbcrypto;

class MemoryInputBuffer : public std::streambuf {
public:
    MemoryInputBuffer(const uint8_t* data, size_t len) {
        char* begin = const_cast<char*>(reinterpret_cast<const char*>(data));
        setg(begin, begin, begin + len);
    }
};

template <typename T>
static void deserialize_from_memory(T& out, const uint8_t* data, size_t len) {
    MemoryInputBuffer buffer(data, len);
    std::istream input(&buffer);
    Serial::Deserialize(out, input, SerType::BINARY);
}

struct ARESCryptoContext {
    CryptoContext<DCRTPoly> cc;
    uint32_t batch_size;
    std::vector<PublicKey<DCRTPoly>> public_keys;
    std::vector<PrivateKey<DCRTPoly>> secret_keys;
    EvalKey<DCRTPoly> eval_mult_base;
    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> eval_sum_base;
    int profile_dim = 0;
    int payload_slot_count = 0;
    bool minimal_rotation_keys = false;
    // eval_sum_only: generate ONLY the standard EvalSumKeyGen map (which REPLICATES the
    // batch sum across slots, batch_size = profile_dim -> 7 keys at dim 128) and NO
    // broadcast at-index keys. This is the rotation set the chunked fusion needs
    // (ARESChunkedFusePayloadCKKS calls EvalSum). Distinct from minimal_rotation_keys,
    // which builds the EvalAtIndex fold-to-slot-0 + broadcast set for the broadcast fusion.
    bool eval_sum_only = false;
};

struct ARESPublicKey {
    PublicKey<DCRTPoly> pk;
};

struct ARESSecretKeyShare {
    PrivateKey<DCRTPoly> sk;
    bool lead;
};

struct ARESEvalMultKey {
    EvalKey<DCRTPoly> key;
};

struct ARESRotKey {
    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> keys;
};

struct ARESCiphertext {
    Ciphertext<DCRTPoly> ct;
};

static ARESCryptoContext* as_ctx(CryptoContextHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE context handle");
    }
    return reinterpret_cast<ARESCryptoContext*>(handle);
}

static ARESPublicKey* as_pk(PublicKeyHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE public key handle");
    }
    return reinterpret_cast<ARESPublicKey*>(handle);
}

static ARESSecretKeyShare* as_sk(SecretKeyShareHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE secret key share handle");
    }
    return reinterpret_cast<ARESSecretKeyShare*>(handle);
}

static ARESCiphertext* as_ct(CiphertextHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE ciphertext handle");
    }
    return reinterpret_cast<ARESCiphertext*>(handle);
}

static ARESEvalMultKey* as_eval_mult(EvalMultKeyHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE eval-mult key handle");
    }
    return reinterpret_cast<ARESEvalMultKey*>(handle);
}

static ARESRotKey* as_rot(RotKeyHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE rotation/eval-sum key handle");
    }
    return reinterpret_cast<ARESRotKey*>(handle);
}

static uint32_t infer_scaling_mod_size(double scaling_factor) {
    if (!std::isfinite(scaling_factor) || scaling_factor <= 1.0) {
        return 50;
    }
    auto bits = static_cast<uint32_t>(std::round(std::log2(scaling_factor)));
    return std::min<uint32_t>(std::max<uint32_t>(bits, 30), 60);
}

static void set_error(char* err, size_t err_len, const std::string& msg) {
    if (err == nullptr || err_len == 0) {
        return;
    }
    size_t n = std::min(err_len - 1, msg.size());
    memcpy(err, msg.data(), n);
    err[n] = '\0';
}

static uint32_t next_power_of_two(uint32_t value) {
    if (value <= 1) {
        return 1;
    }
    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1;
}

static double decrypt_first_slot(const CryptoContext<DCRTPoly>& cc,
    const PrivateKey<DCRTPoly>& sk,
    const Ciphertext<DCRTPoly>& ct) {
    Plaintext out;
    cc->Decrypt(sk, ct, &out);
    out->SetLength(1);
    auto values = out->GetCKKSPackedValue();
    if (values.empty()) {
        return 0.0;
    }
    return values[0].real();
}

// ares_fhe_allow_insecure reports whether CKKS security enforcement should be
// disabled (HEStd_NotSet). The DEFAULT is secure (HEStd_128_classic): a context
// whose ring dimension is too small for the requested depth will be rejected by
// OpenFHE's parameter generator. Tests and local dev that deliberately use small,
// fast, sub-128-bit rings opt out by setting ARES_FHE_ALLOW_INSECURE to any
// non-empty value other than "0". Opting out emits a one-time stderr warning so
// an insecure run is never silent.
static bool ares_fhe_allow_insecure() {
    const char* v = getenv("ARES_FHE_ALLOW_INSECURE");
    bool allow = (v != nullptr && v[0] != '\0' && !(v[0] == '0' && v[1] == '\0'));
    if (allow) {
        static bool warned = false;
        if (!warned) {
            fprintf(stderr,
                "[ares/openfhe] WARNING: ARES_FHE_ALLOW_INSECURE set -> CKKS security "
                "level is HEStd_NotSet (NO 128-bit guarantee). For tests/dev only; "
                "never in production.\n");
            warned = true;
        }
    }
    return allow;
}

static CryptoContext<DCRTPoly> make_ckks_context(uint32_t batch_size, uint32_t depth,
    int scaling_mod_size, int first_mod_size, uint32_t ring_dim = 0) {
    HEAP_LOG("make_ckks_context start");
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaling_mod_size > 0 ? scaling_mod_size : 50);
    parameters.SetFirstModSize(first_mod_size > 0 ? first_mod_size : 60);
    parameters.SetBatchSize(batch_size);
    parameters.SetSecurityLevel(ares_fhe_allow_insecure() ? HEStd_NotSet : HEStd_128_classic);
    parameters.SetRingDim(ring_dim > 0 ? ring_dim : std::max<uint32_t>(1 << 10, batch_size * 2));

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);
    HEAP_LOG("make_ckks_context done");
    return cc;
}

static CryptoContext<DCRTPoly> make_bfv_context(uint32_t ring_dim, uint32_t depth,
    uint64_t plaintext_modulus, uint32_t batch_size) {
    HEAP_LOG("make_bfv_context start");
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetBatchSize(batch_size);
    parameters.SetRingDim(ring_dim);
    parameters.SetSecurityLevel(ares_fhe_allow_insecure() ? HEStd_NotSet : HEStd_128_classic);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);
    HEAP_LOG("make_bfv_context done");
    return cc;
}

static Ciphertext<DCRTPoly> encrypt_repeated_scalar(const CryptoContext<DCRTPoly>& cc,
    const PublicKey<DCRTPoly>& pk, double value, uint32_t batch_size) {
    std::vector<double> values(batch_size, value);
    auto pt = cc->MakeCKKSPackedPlaintext(values);
    return cc->Encrypt(pk, pt);
}

static Ciphertext<DCRTPoly> eval_tanh_chebyshev(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& diff, double input_scale, double gain, double bound, int degree) {
    auto scaled = diff;
    if (std::fabs(input_scale - 1.0) > 1e-12) {
        scaled = cc->EvalMult(scaled, input_scale);
    }
    auto tanh_step = [gain](double x) -> double {
        double v = gain * x;
        if (v > 20.0) {
            return 1.0;
        }
        if (v < -20.0) {
            return 0.0;
        }
        return 0.5 * (1.0 + std::tanh(v));
    };
    return cc->EvalChebyshevFunction(tanh_step, scaled, -bound, bound, static_cast<uint32_t>(degree));
}

static Ciphertext<DCRTPoly> eval_logistic_chebyshev(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& diff, double input_scale, double gain, double bound, int degree) {
    auto scaled = diff;
    if (std::fabs(input_scale - 1.0) > 1e-12) {
        scaled = cc->EvalMult(scaled, input_scale);
    }
    scaled = cc->EvalMult(scaled, gain);
    return cc->EvalLogistic(scaled, -gain * bound, gain * bound, static_cast<uint32_t>(degree));
}

static Ciphertext<DCRTPoly> smoothstep5(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& x) {
    auto x2 = cc->EvalMult(x, x);
    auto x3 = cc->EvalMult(x2, x);
    auto six_x = cc->EvalMult(x, 6.0);
    auto inner = cc->EvalAdd(cc->EvalMult(x, cc->EvalAdd(six_x, -15.0)), 10.0);
    return cc->EvalMult(x3, inner);
}

static Ciphertext<DCRTPoly> smoothstep7(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& x) {
    auto x2 = cc->EvalMult(x, x);
    auto x4 = cc->EvalMult(x2, x2);
    auto inner = cc->EvalAdd(
        cc->EvalMult(
            x,
            cc->EvalAdd(
                cc->EvalMult(
                    x,
                    cc->EvalAdd(cc->EvalMult(x, -20.0), 70.0)
                ),
                -84.0
            )
        ),
        35.0
    );
    return cc->EvalMult(x4, inner);
}

static std::vector<std::string> split_schedule(const char* raw_schedule) {
    std::vector<std::string> out;
    std::string s = raw_schedule == nullptr ? "" : std::string(raw_schedule);
    std::string lowered = s;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    lowered.erase(lowered.begin(), std::find_if(lowered.begin(), lowered.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    lowered.erase(std::find_if(lowered.rbegin(), lowered.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), lowered.end());
    if (lowered == "none" || lowered == "identity") {
        return out;
    }
    size_t start = 0;
    while (start <= s.size()) {
        size_t end = s.find(',', start);
        std::string part = s.substr(start, end == std::string::npos ? std::string::npos : end - start);
        part.erase(part.begin(), std::find_if(part.begin(), part.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        part.erase(std::find_if(part.rbegin(), part.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), part.end());
        if (!part.empty()) {
            out.push_back(part);
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    // An empty/blank schedule means NO selector-sharpen passes (same as "none").
    // This previously defaulted to a 4-pass smoothstep schedule
    // (smoothstep5 x3 + smoothstep7 ~= 9 extra multiplicative levels), which silently
    // fired for any logistic/tanh union lane that left its schedule unset -- exhausting
    // the depth-16 budget (DropLastElement). Selector sharpening is now strictly opt-in.
    return out;
}

static Ciphertext<DCRTPoly> apply_selector_schedule(const CryptoContext<DCRTPoly>& cc,
    Ciphertext<DCRTPoly> selector, const std::vector<std::string>& schedule) {
    for (const auto& mode : schedule) {
        if (mode == "smoothstep5") {
            selector = smoothstep5(cc, selector);
        } else if (mode == "smoothstep7") {
            selector = smoothstep7(cc, selector);
        } else {
            throw std::runtime_error("unsupported selector schedule stage: " + mode);
        }
    }
    return selector;
}

static Ciphertext<DCRTPoly> product_tree(const CryptoContext<DCRTPoly>& cc,
    std::vector<Ciphertext<DCRTPoly>> factors) {
    if (factors.empty()) {
        throw std::runtime_error("product tree requires at least one factor");
    }
    while (factors.size() > 1) {
        std::vector<Ciphertext<DCRTPoly>> next;
        next.reserve((factors.size() + 1) / 2);
        for (size_t i = 0; i + 1 < factors.size(); i += 2) {
            next.push_back(cc->EvalMult(factors[i], factors[i + 1]));
        }
        if (factors.size() % 2 == 1) {
            next.push_back(factors.back());
        }
        factors = std::move(next);
    }
    return factors[0];
}

static Ciphertext<DCRTPoly> broadcast_first_slot(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& ct, int slot_count, uint32_t batch_size) {
    std::vector<double> first_only(batch_size, 0.0);
    first_only[0] = 1.0;
    auto first_pt = cc->MakeCKKSPackedPlaintext(first_only);
    auto out = cc->EvalMult(ct, first_pt);
    for (int shift = 1; shift < slot_count; shift *= 2) {
        auto rotated = cc->EvalRotate(out, -shift);
        out = cc->EvalAdd(out, rotated);
    }
    return out;
}

static Ciphertext<DCRTPoly> broadcast_first_slot_bfv(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& ct, int slot_count, uint32_t batch_size) {
    std::vector<int64_t> first_only(batch_size, 0);
    first_only[0] = 1;
    auto out = cc->EvalMult(ct, cc->MakePackedPlaintext(first_only));
    for (int shift = 1; shift < slot_count; shift *= 2) {
        out = cc->EvalAdd(out, cc->EvalRotate(out, -shift));
    }
    return out;
}

// fold_dot_to_first_slot sums the first profile_dim slots of ct into slot 0 using
// positive power-of-two rotations — the minimal-key equivalent of EvalSum(ct, dim)
// for the dot product, using only the at-index keys minimal_rotation_indices generates.
static Ciphertext<DCRTPoly> fold_dot_to_first_slot(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& ct, int profile_dim) {
    auto acc = ct;
    for (int s = 1; s < profile_dim; s *= 2) {
        acc = cc->EvalAdd(acc, cc->EvalRotate(acc, s));
    }
    return acc;
}

static std::vector<int32_t> broadcast_rotation_indices(uint32_t batch_size) {
    std::vector<int32_t> indices;
    for (uint32_t shift = 1; shift < batch_size; shift *= 2) {
        indices.push_back(static_cast<int32_t>(shift));
        indices.push_back(-static_cast<int32_t>(shift));
    }
    return indices;
}

// minimal_rotation_indices returns the at-index rotation set a dimension-parameterized
// scorer needs: positive power-of-two shifts (< profile_dim) to fold a profile_dim-wide
// dot product into slot 0, plus negative power-of-two shifts (< payload_slot_count) to
// broadcast slot 0 across the candidate's payload bit-slots. Mirrors Go
// minimalRotationIndices; replaces the full-batch EvalSumKeyGen + broadcast set. The
// "< profile_dim" bound is load-bearing (must match fold_dot_to_first_slot in the scorer).
static std::vector<int32_t> minimal_rotation_indices(int profile_dim, int payload_slot_count) {
    std::vector<int32_t> indices;
    for (int s = 1; s < profile_dim; s *= 2) {
        indices.push_back(static_cast<int32_t>(s));
    }
    for (int s = 1; s < payload_slot_count; s *= 2) {
        indices.push_back(-static_cast<int32_t>(s));
    }
    return indices;
}

// eval_sum_only_indices is the chunked-union fold set: the positive power-of-two shifts
// (< profile_dim) that fold the profile_dim-wide dot product across the batch. It is the
// fold half of minimal_rotation_indices with no broadcast keys -- exactly the rotation
// set EvalSum needs at batch_size = next_pow2(profile_dim). Exposing it through
// GetMinimalRotationIndices lets the per-index b-only (CRS-seeded) keygen produce
// eval-sum-only keys with no client code change beyond selecting the eval-sum-only context.
static std::vector<int32_t> eval_sum_only_indices(int profile_dim) {
    std::vector<int32_t> indices;
    for (int s = 1; s < profile_dim; s *= 2) {
        indices.push_back(static_cast<int32_t>(s));
    }
    return indices;
}

static std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> clone_key_map(
    const std::map<usint, EvalKey<DCRTPoly>>& keys
) {
    return std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(keys);
}

static void merge_key_maps(
    const std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>>& into,
    const std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>>& from
) {
    for (const auto& item : *from) {
        (*into)[item.first] = item.second;
    }
}

static std::vector<double> package_bits_for_candidate(const int* candidate_packages,
    int candidate_index, int package_bytes, int payload_slot_count, uint32_t batch_size) {
    std::vector<double> bits(batch_size, 0.0);
    int available_bits = package_bytes * 8;
    int n_bits = std::min(payload_slot_count, available_bits);
    const int* pkg = candidate_packages + (static_cast<size_t>(candidate_index) * package_bytes);
    for (int bit_idx = 0; bit_idx < n_bits; bit_idx++) {
        int value = pkg[bit_idx / 8];
        int shift = 7 - (bit_idx % 8);
        bits[bit_idx] = ((value >> shift) & 1) ? 1.0 : 0.0;
    }
    return bits;
}

static ARESCryptoContext make_threshold_context(uint32_t batch_size, uint32_t depth,
    int scaling_mod_size, int first_mod_size, int parties) {
    if (parties < 2) {
        throw std::runtime_error("threshold context requires at least two parties");
    }
    ARESCryptoContext ctx{
        make_ckks_context(batch_size, depth, scaling_mod_size, first_mod_size),
        batch_size,
        {},
        {},
        nullptr,
        nullptr,
    };
    auto kp = ctx.cc->KeyGen();
    if (!kp.good()) {
        throw std::runtime_error("threshold key generation failed for lead party");
    }
    ctx.public_keys.push_back(kp.publicKey);
    ctx.secret_keys.push_back(kp.secretKey);
    for (int i = 1; i < parties; i++) {
        kp = ctx.cc->MultipartyKeyGen(ctx.public_keys.back());
        if (!kp.good()) {
            throw std::runtime_error("threshold key generation failed for participant");
        }
        ctx.public_keys.push_back(kp.publicKey);
        ctx.secret_keys.push_back(kp.secretKey);
    }
    return ctx;
}

static std::vector<double> threshold_decrypt_slots(ARESCryptoContext* ctx,
    const Ciphertext<DCRTPoly>& ct, int n_values) {
    if (ctx == nullptr || ctx->secret_keys.empty()) {
        throw std::runtime_error("threshold decrypt requires key shares");
    }
    std::vector<Ciphertext<DCRTPoly>> partials;
    partials.reserve(ctx->secret_keys.size());
    auto lead = ctx->cc->MultipartyDecryptLead({ct}, ctx->secret_keys[0]);
    if (lead.empty()) {
        throw std::runtime_error("threshold lead decrypt returned no partial");
    }
    partials.push_back(lead[0]);
    for (size_t i = 1; i < ctx->secret_keys.size(); i++) {
        auto main = ctx->cc->MultipartyDecryptMain({ct}, ctx->secret_keys[i]);
        if (main.empty()) {
            throw std::runtime_error("threshold participant decrypt returned no partial");
        }
        partials.push_back(main[0]);
    }
    Plaintext out;
    ctx->cc->MultipartyDecryptFusion(partials, &out);
    out->SetLength(static_cast<size_t>(n_values));
    auto slots = out->GetCKKSPackedValue();
    std::vector<double> values(static_cast<size_t>(n_values), 0.0);
    for (int i = 0; i < n_values && i < static_cast<int>(slots.size()); i++) {
        values[i] = slots[i].real();
    }
    return values;
}

static void rebuild_eval_mult_keys(ARESCryptoContext* ctx) {
    if (ctx->secret_keys.empty()) {
        throw std::runtime_error("cannot build eval-mult keys before threshold keygen");
    }
    if (ctx->secret_keys.size() == 1) {
        ctx->cc->EvalMultKeyGen(ctx->secret_keys[0]);
        return;
    }

    auto base = ctx->cc->KeySwitchGen(ctx->secret_keys[0], ctx->secret_keys[0]);
    auto joined = base;
    for (size_t i = 1; i < ctx->secret_keys.size(); i++) {
        auto share = ctx->cc->MultiKeySwitchGen(ctx->secret_keys[i], ctx->secret_keys[i], base);
        joined = ctx->cc->MultiAddEvalKeys(joined, share, ctx->public_keys[i]->GetKeyTag());
    }

    std::vector<EvalKey<DCRTPoly>> transformed;
    transformed.reserve(ctx->secret_keys.size());
    const std::string final_tag = ctx->public_keys.back()->GetKeyTag();
    for (const auto& sk : ctx->secret_keys) {
        transformed.push_back(ctx->cc->MultiMultEvalKey(sk, joined, final_tag));
    }

    auto combined = transformed[0];
    for (size_t i = 1; i < transformed.size(); i++) {
        combined = ctx->cc->MultiAddEvalMultKeys(combined, transformed[i], final_tag);
    }
    ctx->cc->InsertEvalMultKey({combined});
    ctx->eval_mult_base = joined;
}

static std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> rebuild_eval_sum_keys(ARESCryptoContext* ctx) {
    if (ctx->secret_keys.empty()) {
        throw std::runtime_error("cannot build eval-sum keys before threshold keygen");
    }
    ctx->cc->EvalSumKeyGen(ctx->secret_keys[0]);
    auto base = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(
        ctx->cc->GetEvalSumKeyMap(ctx->secret_keys[0]->GetKeyTag()));
    auto joined = base;
    for (size_t i = 1; i < ctx->secret_keys.size(); i++) {
        auto share = ctx->cc->MultiEvalSumKeyGen(ctx->secret_keys[i], base, ctx->public_keys[i]->GetKeyTag());
        joined = ctx->cc->MultiAddEvalSumKeys(joined, share, ctx->public_keys[i]->GetKeyTag());
    }
    ctx->cc->InsertEvalSumKey(joined);
    ctx->eval_sum_base = base;
    return joined;
}

template <typename T>
static int serialize_object(const T& obj, uint8_t** out_data, size_t* out_len) {
    if (out_data == nullptr || out_len == nullptr) {
        return 1;
    }
    std::stringstream os;
    Serial::Serialize(obj, os, SerType::BINARY);
    auto raw = os.str();
    auto* buf = reinterpret_cast<uint8_t*>(malloc(raw.size()));
    if (buf == nullptr && !raw.empty()) {
        return 1;
    }
    if (!raw.empty()) {
        memcpy(buf, raw.data(), raw.size());
    }
    *out_data = buf;
    *out_len = raw.size();
    return 0;
}

extern "C" {

CryptoContextHandle CreateCKKSContext(uint32_t ring_dim, double scaling_factor, uint32_t depth, uint32_t batch_size) {
    return CreateCKKSContextWithModuli(
        ring_dim,
        depth,
        infer_scaling_mod_size(scaling_factor),
        60,
        batch_size);
}

CryptoContextHandle CreateCKKSContextWithModuli(
    uint32_t ring_dim,
    uint32_t multiplicative_depth,
    uint32_t scaling_mod_size,
    uint32_t first_mod_size,
    uint32_t batch_size) {
    try {
        uint32_t bs = batch_size > 0 ? batch_size : (ring_dim >= 16 ? ring_dim / 2 : 8);
        auto* ctx = new ARESCryptoContext{
            make_ckks_context(
                bs,
                multiplicative_depth == 0 ? 2 : multiplicative_depth,
                static_cast<int>(scaling_mod_size),
                static_cast<int>(first_mod_size),
                ring_dim),
            bs,
            {},
            {},
            nullptr,
            nullptr,
        };
        return reinterpret_cast<CryptoContextHandle>(ctx);
    } catch (...) {
        return nullptr;
    }
}

CryptoContextHandle CreateBFVContext(uint32_t ring_dim, uint32_t multiplicative_depth,
    uint64_t plaintext_modulus, uint32_t batch_size) {
    try {
        uint32_t rd = ring_dim > 0 ? ring_dim : 8192;
        uint32_t depth = multiplicative_depth > 0 ? multiplicative_depth : 4;
        uint64_t p = plaintext_modulus > 0 ? plaintext_modulus : 65537;
        uint32_t bs = batch_size > 0 ? batch_size : (rd >= 16 ? rd / 2 : 8);
        auto* ctx = new ARESCryptoContext{
            make_bfv_context(rd, depth, p, bs),
            bs,
            {},
            {},
            nullptr,
            nullptr,
        };
        return reinterpret_cast<CryptoContextHandle>(ctx);
    } catch (...) {
        return nullptr;
    }
}

void FreeCryptoContext(CryptoContextHandle ctx) {
    if (ctx == nullptr) {
        return;
    }
    auto* c = reinterpret_cast<ARESCryptoContext*>(ctx);
    try {
        // OpenFHE stores eval keys in static maps keyed by the context tag. A
        // deleted wrapper does not evict those maps, so same-parameter contexts
        // can inherit stale keys and keep native memory resident after a session.
        if (c->cc) {
            lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalMultKeys(c->cc);
            lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalSumKeys(c->cc);
        }
    } catch (...) {
        // Destructors must not throw across the C ABI; still delete the wrapper.
    }
    delete c;
}

int OpenFHEContextCount(void) {
    return lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::GetContextCount();
}

void ReleaseAllOpenFHEContexts(void) {
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
}

void SetMinimalRotationKeys(CryptoContextHandle ctx, int profile_dim, int payload_slot_count) {
    if (ctx == nullptr) {
        return;
    }
    auto* c = reinterpret_cast<ARESCryptoContext*>(ctx);
    c->profile_dim = profile_dim;
    c->payload_slot_count = payload_slot_count;
    c->minimal_rotation_keys = true;
}

// SetEvalSumOnlyRotationKeys selects the chunked-fusion rotation set: the threshold
// eval-sum keygen produces ONLY the standard EvalSumKeyGen map (replicating, batch_size
// keys) and no broadcast at-index keys. The context must have been built with
// batch_size = next_pow2(profile_dim) so EvalSumKeyGen emits the profile_dim fold set.
void SetEvalSumOnlyRotationKeys(CryptoContextHandle ctx, int profile_dim) {
    if (ctx == nullptr) {
        return;
    }
    auto* c = reinterpret_cast<ARESCryptoContext*>(ctx);
    c->profile_dim = profile_dim;
    c->eval_sum_only = true;
}

int KeyGenFirst(CryptoContextHandle ctx, PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk) {
    try {
        if (out_pk == nullptr || out_sk == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto kp = c->cc->KeyGen();
        if (!kp.good()) {
            return 1;
        }
        c->public_keys.clear();
        c->secret_keys.clear();
        c->public_keys.push_back(kp.publicKey);
        c->secret_keys.push_back(kp.secretKey);
        *out_pk = reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{kp.publicKey});
        *out_sk = reinterpret_cast<SecretKeyShareHandle>(new ARESSecretKeyShare{kp.secretKey, true});
        return 0;
    } catch (...) {
        return 1;
    }
}

int KeyGenNext(CryptoContextHandle ctx, PublicKeyHandle prev_pk,
    PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk) {
    try {
        if (out_pk == nullptr || out_sk == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* prev = as_pk(prev_pk);
        auto kp = c->cc->MultipartyKeyGen(prev->pk);
        if (!kp.good()) {
            return 1;
        }
        c->public_keys.push_back(kp.publicKey);
        c->secret_keys.push_back(kp.secretKey);
        *out_pk = reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{kp.publicKey});
        *out_sk = reinterpret_cast<SecretKeyShareHandle>(new ARESSecretKeyShare{kp.secretKey, false});
        return 0;
    } catch (...) {
        return 1;
    }
}

int MultiAddPublicKeys(CryptoContextHandle ctx, PublicKeyHandle* pks, int n_keys, PublicKeyHandle* out_joint) {
    try {
        if (pks == nullptr || out_joint == nullptr || n_keys <= 0) {
            return 1;
        }
        (void)as_ctx(ctx);
        // KeyGenNext already returns the cumulative OpenFHE joint key, so the
        // final chained public key is the production encryption key.
        *out_joint = reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{as_pk(pks[n_keys - 1])->pk});
        return 0;
    } catch (...) {
        return 1;
    }
}

int SingleKeyEvalMultKeyGen(CryptoContextHandle ctx, SecretKeyShareHandle sk) {
    try {
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        c->cc->EvalMultKeyGen(s->sk);
        return 0;
    } catch (...) {
        return 1;
    }
}

int SingleKeyEvalMultKeyGenWithOutput(CryptoContextHandle ctx,
                                      SecretKeyShareHandle sk,
                                      EvalMultKeyHandle* out_key) {
    try {
        if (out_key == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        c->cc->EvalMultKeyGen(s->sk);
        const auto& keys = c->cc->GetEvalMultKeyVector(s->sk->GetKeyTag());
        if (keys.empty()) {
            return 1;
        }
        *out_key = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{keys.front()});
        return 0;
    } catch (...) {
        return 1;
    }
}

int GenEvalMultKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk, EvalMultKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        if (c->secret_keys.empty()) {
            c->secret_keys.push_back(s->sk);
        }
        if (c->eval_mult_base == nullptr) {
            rebuild_eval_mult_keys(c);
        }
        auto share = c->cc->KeySwitchGen(s->sk, s->sk);
        *out_share = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{share});
        return 0;
    } catch (...) {
        return 1;
    }
}
int GenRotKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk, RotKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        (void)as_sk(sk);
        auto* c = as_ctx(ctx);
        auto keys = c->eval_sum_base == nullptr ? rebuild_eval_sum_keys(c) : c->eval_sum_base;
        *out_share = reinterpret_cast<RotKeyHandle>(new ARESRotKey{keys});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalMultKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk, EvalMultKeyHandle* out_base) {
    HEAP_LOG("EvalMultKeyGenLead start");
    try {
        if (out_base == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        auto base = c->cc->KeySwitchGen(s->sk, s->sk);
        *out_base = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{base});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalMultKeySwitchShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle base, EvalMultKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        auto share = c->cc->MultiKeySwitchGen(s->sk, s->sk, as_eval_mult(base)->key);
        *out_share = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{share});
        return 0;
    } catch (...) {
        return 1;
    }
}

int CombineEvalMultSwitchShares(CryptoContextHandle ctx,
    PublicKeyHandle* pks, EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_joined) {
    try {
        if (pks == nullptr || shares == nullptr || out_joined == nullptr || n_shares <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto joined = as_eval_mult(shares[0])->key;
        for (int i = 1; i < n_shares; i++) {
            joined = c->cc->MultiAddEvalKeys(joined, as_eval_mult(shares[i])->key, as_pk(pks[i])->pk->GetKeyTag());
        }
        *out_joined = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{joined});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalMultKeyFinalShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle joined, PublicKeyHandle final_pk,
    EvalMultKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string final_tag = as_pk(final_pk)->pk->GetKeyTag();
        auto transformed = c->cc->MultiMultEvalKey(s->sk, as_eval_mult(joined)->key, final_tag);
        *out_share = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{transformed});
        return 0;
    } catch (...) {
        return 1;
    }
}

int CombineEvalMultFinalShares(CryptoContextHandle ctx, PublicKeyHandle final_pk,
    EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_final) {
    try {
        if (shares == nullptr || out_final == nullptr || n_shares <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        const std::string final_tag = as_pk(final_pk)->pk->GetKeyTag();
        auto combined = as_eval_mult(shares[0])->key;
        for (int i = 1; i < n_shares; i++) {
            combined = c->cc->MultiAddEvalMultKeys(combined, as_eval_mult(shares[i])->key, final_tag);
        }
        *out_final = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{combined});
        return 0;
    } catch (...) {
        return 1;
    }
}

int InsertEvalMultKey(CryptoContextHandle ctx, EvalMultKeyHandle key) {
    try {
        auto* c = as_ctx(ctx);
        // Clear any previously registered eval-mult keys for this context before
        // inserting. OpenFHE stores keys in a global map keyed by context ID; when
        // the same parameters produce the same context ID across multiple calls (e.g.
        // per-party loops in Phase-1c bound-check), a second insert would throw.
        // Clearing first makes InsertEvalMultKey idempotent for the same key material.
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalMultKeys(c->cc);
        c->cc->InsertEvalMultKey({as_eval_mult(key)->key});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalSumKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk, RotKeyHandle* out_base) {
    HEAP_LOG("EvalSumKeyGenLead start");
    try {
        if (out_base == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        if (c->eval_sum_only) {
            // Chunked fusion: replicating EvalSum map only (batch_size = profile_dim), no broadcast.
            c->cc->EvalSumKeyGen(s->sk);
        } else if (c->minimal_rotation_keys) {
            c->cc->EvalAtIndexKeyGen(s->sk,
                minimal_rotation_indices(c->profile_dim, c->payload_slot_count));
        } else {
            c->cc->EvalSumKeyGen(s->sk);
            c->cc->EvalAtIndexKeyGen(s->sk, broadcast_rotation_indices(c->batch_size));
        }
        auto keys = clone_key_map(c->cc->GetEvalAutomorphismKeyMap(s->sk->GetKeyTag()));
        *out_base = reinterpret_cast<RotKeyHandle>(new ARESRotKey{keys});
    HEAP_LOG("EvalSumKeyGenLead done");
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalSumKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk,
    RotKeyHandle* out_share) {
    HEAP_LOG("EvalSumKeyShare start");
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string key_tag = as_pk(own_pk)->pk->GetKeyTag();
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> share;
        if (c->eval_sum_only) {
            // Chunked fusion: replicating EvalSum share only, no broadcast.
            share = c->cc->MultiEvalSumKeyGen(s->sk, as_rot(base)->keys, key_tag);
        } else if (c->minimal_rotation_keys) {
            share = c->cc->MultiEvalAtIndexKeyGen(s->sk, as_rot(base)->keys,
                minimal_rotation_indices(c->profile_dim, c->payload_slot_count), key_tag);
        } else {
            share = c->cc->MultiEvalSumKeyGen(s->sk, as_rot(base)->keys, key_tag);
            auto rotate_share = c->cc->MultiEvalAtIndexKeyGen(s->sk, as_rot(base)->keys,
                broadcast_rotation_indices(c->batch_size), key_tag);
            merge_key_maps(share, rotate_share);
        }
        *out_share = reinterpret_cast<RotKeyHandle>(new ARESRotKey{share});
    HEAP_LOG("EvalSumKeyShare done");
        return 0;
    } catch (...) {
        return 1;
    }
}

// StreamedRotShareBytes generates a non-lead party's broadcast rotation-key share
// ONE INDEX AT A TIME against the lead's base map, serializing each index's key and
// freeing it before generating the next. Peak memory is therefore bounded to a
// single rotation key rather than the whole map — the memory-bounded keygen path
// for RAM-constrained clients (phones). The shares are NOT retained; only the total
// serialized size is returned (the caller streams them to its transport/sink).
int StreamedRotShareBytes(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk, unsigned long long* out_total_bytes) {
    try {
        if (out_total_bytes == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string key_tag = as_pk(own_pk)->pk->GetKeyTag();
        const auto& base_map = as_rot(base)->keys;
        unsigned long long total = 0;
        auto idx_set = c->minimal_rotation_keys
            ? minimal_rotation_indices(c->profile_dim, c->payload_slot_count)
            : broadcast_rotation_indices(c->batch_size);
        for (int32_t idx : idx_set) {
            std::vector<int32_t> one{idx};
            auto share = c->cc->MultiEvalAtIndexKeyGen(s->sk, base_map, one, key_tag);
            std::stringstream ss;
            Serial::Serialize(*share, ss, SerType::BINARY);
            total += static_cast<unsigned long long>(ss.str().size());
            // share + ss are freed at end of iteration -> peak bounded to one index.
        }
        *out_total_bytes = total;
        return 0;
    } catch (...) {
        return 1;
    }
}

// StreamedTwoPartyRotKeygenBytes generates a 2-party rotation key FULLY streamed:
// for each rotation index it generates the lead's base[idx], the participant's
// share[idx] against it, serializes both, clears the context's automorphism map,
// and frees — so peak memory is bounded to a SINGLE rotation index across BOTH
// parties (vs. holding the whole map). Returns total serialized bytes
// (lead base + participant share). The memory-bounded multiparty keygen path.
int StreamedTwoPartyRotKeygenBytes(CryptoContextHandle ctx,
    SecretKeyShareHandle sk_lead, SecretKeyShareHandle sk_part, PublicKeyHandle pk_part,
    unsigned long long* out_total_bytes) {
    try {
        if (out_total_bytes == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* sl = as_sk(sk_lead);
        auto* sp = as_sk(sk_part);
        const std::string lead_tag = sl->sk->GetKeyTag();
        const std::string part_tag = as_pk(pk_part)->pk->GetKeyTag();
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(lead_tag);
        unsigned long long total = 0;
        auto idx_set = c->minimal_rotation_keys
            ? minimal_rotation_indices(c->profile_dim, c->payload_slot_count)
            : broadcast_rotation_indices(c->batch_size);
        for (int32_t idx : idx_set) {
            std::vector<int32_t> one{idx};
            c->cc->EvalAtIndexKeyGen(sl->sk, one);
            auto base_i = clone_key_map(c->cc->GetEvalAutomorphismKeyMap(lead_tag));
            {
                std::stringstream ss;
                Serial::Serialize(*base_i, ss, SerType::BINARY);
                total += static_cast<unsigned long long>(ss.str().size());
            }
            auto share_i = c->cc->MultiEvalAtIndexKeyGen(sp->sk, base_i, one, part_tag);
            {
                std::stringstream ss;
                Serial::Serialize(*share_i, ss, SerType::BINARY);
                total += static_cast<unsigned long long>(ss.str().size());
            }
            lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(lead_tag);
        }
        *out_total_bytes = total;
        return 0;
    } catch (...) {
        return 1;
    }
}

// MeasureBOnlyRotShare checks whether the CRS-saving wire optimization is possible:
// for one rotation index it generates the lead's base key and a participant's share
// against it, tests whether the participant's a-vector equals the lead's (i.e. 'a'
// is shared across parties), and reports the full-key vs b-only serialized sizes.
// If a is shared, a participant need only transmit its b-vector (the server pairs it
// with the shared a), roughly halving the per-party upload.
int MeasureBOnlyRotShare(CryptoContextHandle ctx,
    SecretKeyShareHandle sk_lead, SecretKeyShareHandle sk_part, PublicKeyHandle pk_part,
    unsigned long long* out_full_bytes, unsigned long long* out_b_only_bytes, int* out_a_shared) {
    try {
        if (out_full_bytes == nullptr || out_b_only_bytes == nullptr || out_a_shared == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* sl = as_sk(sk_lead);
        auto* sp = as_sk(sk_part);
        const std::string lead_tag = sl->sk->GetKeyTag();
        const std::string part_tag = as_pk(pk_part)->pk->GetKeyTag();
        std::vector<int32_t> one{1};
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(lead_tag);
        c->cc->EvalAtIndexKeyGen(sl->sk, one);
        auto base_map = clone_key_map(c->cc->GetEvalAutomorphismKeyMap(lead_tag));
        auto share_map = c->cc->MultiEvalAtIndexKeyGen(sp->sk, base_map, one, part_tag);
        if (base_map->empty() || share_map->empty()) {
            return 2;
        }
        auto lead_key = base_map->begin()->second;
        auto part_key = share_map->begin()->second;
        const auto& la = lead_key->GetAVector();
        const auto& pa = part_key->GetAVector();
        bool shared = (la.size() == pa.size());
        for (size_t i = 0; shared && i < la.size(); i++) {
            if (!(la[i] == pa[i])) {
                shared = false;
            }
        }
        *out_a_shared = shared ? 1 : 0;
        {
            std::stringstream ss;
            Serial::Serialize(part_key, ss, SerType::BINARY);
            *out_full_bytes = static_cast<unsigned long long>(ss.str().size());
        }
        {
            std::stringstream ss;
            Serial::Serialize(part_key->GetBVector(), ss, SerType::BINARY);
            *out_b_only_bytes = static_cast<unsigned long long>(ss.str().size());
        }
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(lead_tag);
        return 0;
    } catch (...) {
        return 1;
    }
}

// ---- Production b-only rotation-key wire (CRS optimization) ----
// The rotation-key 'a'-vectors are byte-identical across parties (derived from
// shared public randomness), so each party transmits only its 'b'-vectors and the
// combiner rebuilds the full share from the shared 'a' + the party 'b'. No new
// crypto; ~50% wire saving. MeasureBOnlyRotShare proves the soundness/size.
int SerializeRotKeyBVectors(RotKeyHandle share, uint8_t** out_data, size_t* out_len) {
    try {
        auto* r = as_rot(share);
        std::map<usint, std::vector<DCRTPoly>> bmap;
        for (const auto& kv : *r->keys) {
            bmap[kv.first] = kv.second->GetBVector();
        }
        return serialize_object(bmap, out_data, out_len);
    } catch (...) {
        return 1;
    }
}

int SerializeRotKeyAVectors(RotKeyHandle share, uint8_t** out_data, size_t* out_len) {
    try {
        auto* r = as_rot(share);
        std::map<usint, std::vector<DCRTPoly>> amap;
        for (const auto& kv : *r->keys) {
            amap[kv.first] = kv.second->GetAVector();
        }
        return serialize_object(amap, out_data, out_len);
    } catch (...) {
        return 1;
    }
}

RotKeyHandle ReconstructRotKeyFromAB(CryptoContextHandle ctx,
    const uint8_t* a_data, size_t a_len, const uint8_t* b_data, size_t b_len) {
    try {
        auto* c = as_ctx(ctx);
        if (a_data == nullptr || b_data == nullptr || a_len == 0 || b_len == 0) {
            return nullptr;
        }
        std::map<usint, std::vector<DCRTPoly>> amap;
        std::map<usint, std::vector<DCRTPoly>> bmap;
        {
            std::string raw(reinterpret_cast<const char*>(a_data), a_len);
            std::stringstream is(raw);
            Serial::Deserialize(amap, is, SerType::BINARY);
        }
        {
            std::string raw(reinterpret_cast<const char*>(b_data), b_len);
            std::stringstream is(raw);
            Serial::Deserialize(bmap, is, SerType::BINARY);
        }
        auto keys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>();
        for (const auto& kv : bmap) {
            usint idx = kv.first;
            auto a_it = amap.find(idx);
            if (a_it == amap.end()) {
                return nullptr;
            }
            auto k = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(c->cc);
            k->SetAVector(a_it->second);
            k->SetBVector(kv.second);
            (*keys)[idx] = k;
        }
        return reinterpret_cast<RotKeyHandle>(new ARESRotKey{keys});
    } catch (...) {
        return nullptr;
    }
}

// Pre-deserialized A-vectors for cached b-only reconstruction.
struct ARESAVectors {
    std::map<usint, std::vector<DCRTPoly>> amap;
};

AVectorsHandle DeserializeAVectors(const uint8_t* a_data, size_t a_len) {
    try {
        if (a_data == nullptr || a_len == 0) return nullptr;
        auto* av = new ARESAVectors();
        std::string raw(reinterpret_cast<const char*>(a_data), a_len);
        std::stringstream is(raw);
        Serial::Deserialize(av->amap, is, SerType::BINARY);
        return av;
    } catch (...) {
        return nullptr;
    }
}

void FreeAVectors(AVectorsHandle h) {
    delete h;
}

RotKeyHandle ReconstructRotKeyFromAVectors(CryptoContextHandle ctx,
    AVectorsHandle a, const uint8_t* b_data, size_t b_len) {
    try {
        auto* c = as_ctx(ctx);
        if (a == nullptr || b_data == nullptr || b_len == 0) return nullptr;
        std::map<usint, std::vector<DCRTPoly>> bmap;
        {
            std::string raw(reinterpret_cast<const char*>(b_data), b_len);
            std::stringstream is(raw);
            Serial::Deserialize(bmap, is, SerType::BINARY);
        }
        auto keys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>();
        for (const auto& kv : bmap) {
            usint idx = kv.first;
            auto a_it = a->amap.find(idx);
            if (a_it == a->amap.end()) return nullptr;
            auto k = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(c->cc);
            k->SetAVector(a_it->second);
            k->SetBVector(kv.second);
            (*keys)[idx] = k;
        }
        return reinterpret_cast<RotKeyHandle>(new ARESRotKey{keys});
    } catch (...) {
        return nullptr;
    }
}

int CombineEvalSumKeys(CryptoContextHandle ctx,
    PublicKeyHandle* pks, RotKeyHandle* shares, int n_shares,
    RotKeyHandle* out_final) {
    try {
        if (pks == nullptr || shares == nullptr || out_final == nullptr || n_shares <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto joined = as_rot(shares[0])->keys;
        for (int i = 1; i < n_shares; i++) {
            joined = c->cc->MultiAddEvalAutomorphismKeys(joined, as_rot(shares[i])->keys, as_pk(pks[i])->pk->GetKeyTag());
        }
        *out_final = reinterpret_cast<RotKeyHandle>(new ARESRotKey{joined});
        return 0;
    } catch (...) {
        return 1;
    }
}

// EvalSumCombineStart / EvalSumCombineFold are the incremental form of
// CombineEvalSumKeys. CombineEvalSumKeys folds one share at a time but needs every
// share deserialized and resident at once; the incremental form lets a caller
// deserialize and free each share inside its own loop, so peak RAM is the
// accumulator plus one share instead of all N rotation-key maps. The folded result
// is byte-identical to CombineEvalSumKeys for the same (lead base, then participant
// shares) order.
RotKeyHandle EvalSumCombineStart(RotKeyHandle seed) {
    try {
        // Seed with the lead base (shares[0]); the fold below assigns fresh maps, so
        // the seed handle is never mutated, matching CombineEvalSumKeys' joined seed.
        return reinterpret_cast<RotKeyHandle>(new ARESRotKey{as_rot(seed)->keys});
    } catch (...) {
        return nullptr;
    }
}

int EvalSumCombineFold(CryptoContextHandle ctx, RotKeyHandle accum, PublicKeyHandle pk, RotKeyHandle share) {
    try {
        if (accum == nullptr || pk == nullptr || share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* a = as_rot(accum);
        a->keys = c->cc->MultiAddEvalAutomorphismKeys(a->keys, as_rot(share)->keys, as_pk(pk)->pk->GetKeyTag());
        return 0;
    } catch (...) {
        return 1;
    }
}

int MergeEvalSumKeyMaps(RotKeyHandle accum, RotKeyHandle next) {
    try {
        if (accum == nullptr || next == nullptr) {
            return 1;
        }
        auto* a = as_rot(accum);
        auto* n = as_rot(next);
        for (const auto& kv : *n->keys) {
            (*a->keys)[kv.first] = kv.second;
        }
        return 0;
    } catch (...) {
        return 1;
    }
}

int InsertEvalSumKey(CryptoContextHandle ctx, RotKeyHandle key) {
    try {
        auto* c = as_ctx(ctx);
        // Clear any previously registered eval-sum keys for this context before
        // inserting, mirroring the same idempotency fix applied to InsertEvalMultKey.
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalSumKeys(c->cc);
        c->cc->InsertEvalSumKey(as_rot(key)->keys);
        return 0;
    } catch (...) {
        return 1;
    }
}

int ClearEvalSumKeysForContext(CryptoContextHandle ctx) {
    try {
        auto* c = as_ctx(ctx);
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalSumKeys(c->cc);
        return 0;
    } catch (...) {
        return 1;
    }
}

int InsertEvalSumKeyAppend(CryptoContextHandle ctx, RotKeyHandle key) {
    try {
        auto* c = as_ctx(ctx);
        c->cc->InsertEvalSumKey(as_rot(key)->keys);
        return 0;
    } catch (...) {
        return 1;
    }
}

CiphertextHandle Encrypt(CryptoContextHandle ctx, PublicKeyHandle pk, double* values, int n_values) {
    try {
        if (values == nullptr || n_values <= 0) {
            return nullptr;
        }
        auto* c = as_ctx(ctx);
        auto* p = as_pk(pk);
        std::vector<double> packed(c->batch_size, 0.0);
        for (int i = 0; i < n_values && i < static_cast<int>(packed.size()); i++) {
            packed[i] = values[i];
        }
        auto pt = c->cc->MakeCKKSPackedPlaintext(packed);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->Encrypt(p->pk, pt)});
    } catch (...) {
        return nullptr;
    }
}

CiphertextHandle EncryptPackedInt(CryptoContextHandle ctx, PublicKeyHandle pk, int64_t* values, int n_values) {
    try {
        if (values == nullptr || n_values <= 0) {
            return nullptr;
        }
        auto* c = as_ctx(ctx);
        auto* p = as_pk(pk);
        std::vector<int64_t> packed(c->batch_size, 0);
        for (int i = 0; i < n_values && i < static_cast<int>(packed.size()); i++) {
            packed[i] = values[i];
        }
        auto pt = c->cc->MakePackedPlaintext(packed);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->Encrypt(p->pk, pt)});
    } catch (...) {
        return nullptr;
    }
}

// DecryptSingle: direct single-key Decrypt (not threshold). For use with
// standard (non-multiparty) key pairs from KeyGenFirst.
int DecryptSingle(CryptoContextHandle ctx, CiphertextHandle ct, SecretKeyShareHandle sk, double* out_values, int* out_n_values) {
    try {
        if (ct == nullptr || sk == nullptr || out_values == nullptr || out_n_values == nullptr || *out_n_values <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        Plaintext pt;
        c->cc->Decrypt(s->sk, as_ct(ct)->ct, &pt);
        int n = std::min(*out_n_values, static_cast<int>(pt->GetLength()));
        for (int i = 0; i < n; i++) {
            out_values[i] = pt->GetCKKSPackedValue()[i].real();
            if (std::isnan(out_values[i]) || std::isinf(out_values[i])) {
                out_values[i] = 0.0;
            }
        }
        *out_n_values = n;
        return 0;
    } catch (...) {
        return 1;
    }
}

int MultiDecMain(CryptoContextHandle ctx, CiphertextHandle ct, SecretKeyShareHandle sk, CiphertextHandle* out_partial) {
    try {
        if (out_partial == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* cipher = as_ct(ct);
        auto* share = as_sk(sk);
        std::vector<Ciphertext<DCRTPoly>> partials = share->lead
            ? c->cc->MultipartyDecryptLead({cipher->ct}, share->sk)
            : c->cc->MultipartyDecryptMain({cipher->ct}, share->sk);
        if (partials.empty()) {
            return 1;
        }
        *out_partial = reinterpret_cast<CiphertextHandle>(new ARESCiphertext{partials[0]});
        return 0;
    } catch (...) {
        return 1;
    }
}

int MultiDecFusion(CryptoContextHandle ctx, CiphertextHandle* partials, int n_partials, double* out_values, int* out_n_values) {
    try {
        if (partials == nullptr || out_values == nullptr || out_n_values == nullptr || n_partials <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.reserve(static_cast<size_t>(n_partials));
        for (int i = 0; i < n_partials; i++) {
            partial_vec.push_back(as_ct(partials[i])->ct);
        }
        Plaintext out;
        try { c->cc->MultipartyDecryptFusion(partial_vec, &out); } catch (const std::exception& e) { fprintf(stderr, "[ares] MultiDecFusion exception: %s\n", e.what()); fflush(stderr); throw; }
        int capacity = *out_n_values > 0 ? *out_n_values : static_cast<int>(c->batch_size);
        out->SetLength(static_cast<size_t>(capacity));
        auto slots = out->GetCKKSPackedValue();
        int count = std::min(capacity, static_cast<int>(slots.size()));
        for (int i = 0; i < count; i++) {
            out_values[i] = slots[i].real();
        }
        *out_n_values = count;
        return 0;
    } catch (const std::exception& ex) {
        fprintf(stderr, "[ares] MultiDecFusion error: %s\n", ex.what());
        fflush(stderr);
        return 1;
    } catch (...) {
        fprintf(stderr, "[ares] MultiDecFusion unknown error\n");
        fflush(stderr);
        return 1;
    }
}

int MultiDecFusionPackedInt(CryptoContextHandle ctx, CiphertextHandle* partials, int n_partials, int64_t* out_values, int* out_n_values) {
    try {
        if (partials == nullptr || out_values == nullptr || out_n_values == nullptr || n_partials <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.reserve(static_cast<size_t>(n_partials));
        for (int i = 0; i < n_partials; i++) {
            partial_vec.push_back(as_ct(partials[i])->ct);
        }
        Plaintext out;
        c->cc->MultipartyDecryptFusion(partial_vec, &out);
        int capacity = *out_n_values > 0 ? *out_n_values : static_cast<int>(c->batch_size);
        out->SetLength(static_cast<size_t>(capacity));
        auto slots = out->GetPackedValue();
        int count = std::min(capacity, static_cast<int>(slots.size()));
        for (int i = 0; i < count; i++) {
            out_values[i] = slots[i];
        }
        *out_n_values = count;
        return 0;
    } catch (const std::exception& ex) {
        fprintf(stderr, "[ares] MultiDecFusionPackedInt error: %s\n", ex.what());
        fflush(stderr);
        return 1;
    } catch (...) {
        fprintf(stderr, "[ares] MultiDecFusionPackedInt unknown error\n");
        fflush(stderr);
        return 1;
    }
}

CiphertextHandle EvalAdd(CryptoContextHandle ctx, CiphertextHandle a, CiphertextHandle b) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalAdd(as_ct(a)->ct, as_ct(b)->ct)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalMult(CryptoContextHandle ctx, CiphertextHandle a, CiphertextHandle b) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalMult(as_ct(a)->ct, as_ct(b)->ct)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalSum(CryptoContextHandle ctx, CiphertextHandle ct, int batch_size) {
    try {
        auto* c = as_ctx(ctx);
        int n = batch_size > 0 ? batch_size : static_cast<int>(c->batch_size);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalSum(as_ct(ct)->ct, n)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalMultConst(CryptoContextHandle ctx, CiphertextHandle ct, double scalar) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalMult(as_ct(ct)->ct, scalar)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalSub(CryptoContextHandle ctx, CiphertextHandle a, CiphertextHandle b) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalSub(as_ct(a)->ct, as_ct(b)->ct)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalChebyshevSign(CryptoContextHandle ctx, CiphertextHandle ct, int degree) {
    try {
        auto* c = as_ctx(ctx);
        auto sign = [](double x) -> double {
            return x >= 0.0 ? 1.0 : 0.0;
        };
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{
            c->cc->EvalChebyshevFunction(sign, as_ct(ct)->ct, -1.0, 1.0, static_cast<uint32_t>(std::max(3, degree)))
        });
    } catch (...) {
        return nullptr;
    }
}

CiphertextHandle EvalPolynomial(CryptoContextHandle ctx, CiphertextHandle ct, double* coeffs, int n_coeffs) {
    try {
        if (n_coeffs <= 0 || coeffs == nullptr) {
            return nullptr;
        }
        auto* c = as_ctx(ctx);
        std::vector<double> coefficients(coeffs, coeffs + n_coeffs);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{
            c->cc->EvalPoly(as_ct(ct)->ct, coefficients)
        });
    } catch (const std::exception& e) {
        std::cerr << "[openfhe] EvalPolynomial failed: " << e.what() << std::endl;
        return nullptr;
    } catch (...) {
        return nullptr;
    }
}

int EvalArgmax(CryptoContextHandle ctx,
               const CiphertextHandle* cts, int n_cts,
               const double* sharp_coeffs, int n_sharp_coeffs,
               CiphertextHandle* out_masks) {
    try {
        if (n_cts < 2 || cts == nullptr) return -1;
        if (n_sharp_coeffs < 2 || sharp_coeffs == nullptr) return -2;
        if (out_masks == nullptr) return -3;
        auto* c = as_ctx(ctx);
        std::vector<double> coeffs(sharp_coeffs, sharp_coeffs + n_sharp_coeffs);

        // Precompute sharp(cts[i] - cts[j]) once per ordered pair.
        // For i != j: pair[i][j] = p(cts[i] - cts[j]) ≈ 1 if cts[i] > cts[j], ≈ 0 otherwise.
        // mask[i] = ∏_{j != i} pair[i][j].
        //
        // Degree-1 optimisation: p(x) = c₀ + c₁·x is evaluated with level-free
        // EvalMultConst + EvalAdd (plaintext) — saves 1 multiplicative level vs
        // Horner form, which is the difference between n=5 and n=6 fitting at
        // ring 2¹⁴ / depth 4.
        bool deg1 = (coeffs.size() == 2);
        std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> pair(
            n_cts, std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(n_cts));
        for (int i = 0; i < n_cts; ++i) {
            for (int j = 0; j < n_cts; ++j) {
                if (i == j) continue;
                auto diff = c->cc->EvalSub(as_ct(cts[i])->ct, as_ct(cts[j])->ct);
                if (deg1) {
                    auto scaled = c->cc->EvalMult(diff, coeffs[1]);
                    auto constant = c->cc->MakeCKKSPackedPlaintext(
                        std::vector<double>(c->batch_size, coeffs[0]));
                    pair[i][j] = c->cc->EvalAdd(scaled, constant);
                } else {
                    pair[i][j] = c->cc->EvalPoly(diff, coeffs);
                }
            }
        }

        // Balanced product tree: for n_cts factors, depth = ceil(log2(n_cts-1)).
        // The sequential chain (acc=acc*next) would need n_cts-2 levels — with
        // a balanced tree, n=6 needs 3 levels instead of 4, which is the
        // difference between fitting ring 2^14 depth 4 or not.
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> masks(n_cts);
        for (int i = 0; i < n_cts; ++i) {
            std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> factors;
            factors.reserve(n_cts - 1);
            for (int j = 0; j < n_cts; ++j) {
                if (i != j) factors.push_back(pair[i][j]);
            }
            // Balanced reduce: pair up and multiply until one remains
            while (factors.size() > 1) {
                std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> next;
                next.reserve((factors.size() + 1) / 2);
                for (size_t k = 0; k < factors.size(); k += 2) {
                    if (k + 1 == factors.size()) {
                        next.push_back(factors[k]);
                    } else {
                        next.push_back(c->cc->EvalMult(factors[k], factors[k+1]));
                    }
                }
                factors = std::move(next);
            }
            masks[i] = factors[0];
        }

        for (int i = 0; i < n_cts; ++i) {
            out_masks[i] = reinterpret_cast<CiphertextHandle>(new ARESCiphertext{masks[i]});
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[openfhe] EvalArgmax failed: " << e.what() << std::endl;
        return -100;
    } catch (...) {
        return -101;
    }
}

int SerializeCiphertext(CiphertextHandle ct, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_ct(ct)->ct, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
int EncryptSerializedPayloadChunk(CryptoContextHandle ctx, PublicKeyHandle pk,
    const uint8_t* payload, size_t payload_len,
    size_t bit_offset, size_t chunk_size,
    uint8_t** out_data, size_t* out_len) {
    if (out_data == nullptr || out_len == nullptr) {
        return 1;
    }
    *out_data = nullptr;
    *out_len = 0;

    std::vector<double> values;
    try {
        auto* c = as_ctx(ctx);
        auto* p = as_pk(pk);
        if (payload == nullptr || payload_len == 0 || chunk_size == 0 ||
            chunk_size != c->batch_size || bit_offset % chunk_size != 0 ||
            payload_len > std::numeric_limits<size_t>::max() / 8) {
            return 1;
        }
        const size_t payload_bits = payload_len * 8;
        if (bit_offset > payload_bits || chunk_size > payload_bits - bit_offset ||
            p->pk->GetCryptoContext() != c->cc) {
            return 1;
        }

        values.resize(chunk_size);
        for (size_t i = 0; i < chunk_size; ++i) {
            const size_t bit = bit_offset + i;
            values[i] = static_cast<double>((payload[bit / 8] >> (7 - (bit % 8))) & 1U);
        }
        auto plaintext = c->cc->MakeCKKSPackedPlaintext(values);
        auto ciphertext = c->cc->Encrypt(p->pk, plaintext);
        const int rc = serialize_object(ciphertext, out_data, out_len);
        std::fill(values.begin(), values.end(), 0.0);
        return rc;
    } catch (...) {
        std::fill(values.begin(), values.end(), 0.0);
        return 1;
    }
}
int EncryptSerializedRepeatedScalarCKKS(CryptoContextHandle ctx, PublicKeyHandle pk,
    double value, uint8_t** out_data, size_t* out_len) {
    if (out_data == nullptr || out_len == nullptr) {
        return 1;
    }
    *out_data = nullptr;
    *out_len = 0;

    std::vector<double> values;
    try {
        auto* c = as_ctx(ctx);
        auto* p = as_pk(pk);
        if (c->batch_size == 0 || p->pk->GetCryptoContext() != c->cc) {
            return 1;
        }
        values.assign(c->batch_size, value);
        auto plaintext = c->cc->MakeCKKSPackedPlaintext(values);
        auto ciphertext = c->cc->Encrypt(p->pk, plaintext);
        const int rc = serialize_object(ciphertext, out_data, out_len);
        std::fill(values.begin(), values.end(), 0.0);
        return rc;
    } catch (...) {
        std::fill(values.begin(), values.end(), 0.0);
        return 1;
    }
}
int ComputeSerializedSquaredDistanceCKKS(CryptoContextHandle ctx,
    const uint8_t* origin_first, size_t origin_first_len,
    const uint8_t* origin_second, size_t origin_second_len,
    double local_first, double local_second,
    uint8_t** out_data, size_t* out_len) {
    if (out_data == nullptr || out_len == nullptr) {
        return 1;
    }
    *out_data = nullptr;
    *out_len = 0;

    std::vector<double> local_values;
    try {
        auto* c = as_ctx(ctx);
        if (origin_first == nullptr || origin_second == nullptr || origin_first_len == 0 ||
            origin_second_len == 0 || c->batch_size == 0) {
            return 1;
        }
        Ciphertext<DCRTPoly> first;
        Ciphertext<DCRTPoly> second;
        std::stringstream first_stream(std::string(reinterpret_cast<const char*>(origin_first), origin_first_len));
        std::stringstream second_stream(std::string(reinterpret_cast<const char*>(origin_second), origin_second_len));
        Serial::Deserialize(first, first_stream, SerType::BINARY);
        Serial::Deserialize(second, second_stream, SerType::BINARY);
        if (first == nullptr || second == nullptr || first->GetCryptoContext() != c->cc ||
            second->GetCryptoContext() != c->cc || first->GetKeyTag() != second->GetKeyTag()) {
            return 1;
        }

        local_values.assign(c->batch_size, local_first);
        auto local_first_pt = c->cc->MakeCKKSPackedPlaintext(local_values);
        std::fill(local_values.begin(), local_values.end(), local_second);
        auto local_second_pt = c->cc->MakeCKKSPackedPlaintext(local_values);
        auto first_delta = c->cc->EvalSub(first, local_first_pt);
        auto second_delta = c->cc->EvalSub(second, local_second_pt);
        auto first_square = c->cc->EvalMult(first_delta, first_delta);
        auto second_square = c->cc->EvalMult(second_delta, second_delta);
        auto distance = c->cc->EvalAdd(first_square, second_square);
        const int rc = serialize_object(distance, out_data, out_len);
        std::fill(local_values.begin(), local_values.end(), 0.0);
        return rc;
    } catch (...) {
        std::fill(local_values.begin(), local_values.end(), 0.0);
        return 1;
    }
}

int EncryptSerializedRepeatedScalarBFV(CryptoContextHandle ctx, PublicKeyHandle pk,
    int64_t value, uint8_t** out_data, size_t* out_len) {
    if (out_data == nullptr || out_len == nullptr) {
        return 1;
    }
    *out_data = nullptr;
    *out_len = 0;

    std::vector<int64_t> values;
    try {
        auto* c = as_ctx(ctx);
        auto* p = as_pk(pk);
        if (c->batch_size == 0 || p->pk->GetCryptoContext() != c->cc) {
            return 1;
        }
        values.assign(c->batch_size, value);
        auto plaintext = c->cc->MakePackedPlaintext(values);
        auto ciphertext = c->cc->Encrypt(p->pk, plaintext);
        const int rc = serialize_object(ciphertext, out_data, out_len);
        std::fill(values.begin(), values.end(), 0);
        return rc;
    } catch (...) {
        std::fill(values.begin(), values.end(), 0);
        return 1;
    }
}

int ComputeSerializedSquaredDistanceBFV(CryptoContextHandle ctx,
    const uint8_t* origin_first, size_t origin_first_len,
    const uint8_t* origin_second, size_t origin_second_len,
    int64_t local_first, int64_t local_second,
    uint8_t** out_data, size_t* out_len) {
    if (out_data == nullptr || out_len == nullptr) {
        return 1;
    }
    *out_data = nullptr;
    *out_len = 0;

    std::vector<int64_t> local_values;
    try {
        auto* c = as_ctx(ctx);
        if (origin_first == nullptr || origin_second == nullptr || origin_first_len == 0 ||
            origin_second_len == 0 || c->batch_size == 0) {
            return 1;
        }
        Ciphertext<DCRTPoly> first;
        Ciphertext<DCRTPoly> second;
        deserialize_from_memory(first, origin_first, origin_first_len);
        deserialize_from_memory(second, origin_second, origin_second_len);
        if (first == nullptr || second == nullptr || first->GetCryptoContext() != c->cc ||
            second->GetCryptoContext() != c->cc || first->GetKeyTag() != second->GetKeyTag()) {
            return 1;
        }

        local_values.assign(c->batch_size, local_first);
        auto local_first_pt = c->cc->MakePackedPlaintext(local_values);
        std::fill(local_values.begin(), local_values.end(), local_second);
        auto local_second_pt = c->cc->MakePackedPlaintext(local_values);
        auto first_delta = c->cc->EvalSub(first, local_first_pt);
        auto second_delta = c->cc->EvalSub(second, local_second_pt);
        auto first_square = c->cc->EvalMult(first_delta, first_delta);
        auto second_square = c->cc->EvalMult(second_delta, second_delta);
        auto distance = c->cc->EvalAdd(first_square, second_square);
        const int rc = serialize_object(distance, out_data, out_len);
        std::fill(local_values.begin(), local_values.end(), 0);
        return rc;
    } catch (...) {
        std::fill(local_values.begin(), local_values.end(), 0);
        return 1;
    }
}
int GetOpenFHEVersion(char* out_buf, int out_cap) {
    try {
        if (out_buf == nullptr || out_cap <= 0) {
            return 0;
        }
        std::string v = GetOPENFHEVersion();
        int n = static_cast<int>(v.size());
        if (n >= out_cap) {
            n = out_cap - 1;
        }
        std::memcpy(out_buf, v.data(), n);
        out_buf[n] = '\0';
        return n;
    } catch (...) {
        return 0;
    }
}

CiphertextHandle DeserializeCiphertext(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        auto* c = as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        Ciphertext<DCRTPoly> ct;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(ct, is, SerType::BINARY);
        // Verify the deserialized ciphertext is bound to the same
        // CryptoContext we're operating in. OpenFHE's global context
        // registry deduplicates contexts by parameter fingerprint;
        // a pointer mismatch here almost always means the serializer
        // and deserializer were linked against different OpenFHE
        // versions that resolve cyclotomic primes differently.
        if (ct->GetCryptoContext() != c->cc) {
            std::cerr << "[openfhe] DeserializeCiphertext: ciphertext's CryptoContext does not match local context "
                      << "(likely OpenFHE version skew between serializer and deserializer; "
                      << "linked OpenFHE version: " << GetOPENFHEVersion() << ")" << std::endl;
            return nullptr;
        }
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{ct});
    } catch (...) {
        return nullptr;
    }
}
int SerializePublicKey(PublicKeyHandle pk, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_pk(pk)->pk, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
PublicKeyHandle DeserializePublicKey(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        PublicKey<DCRTPoly> pk;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(pk, is, SerType::BINARY);
        return reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{pk});
    } catch (...) {
        return nullptr;
    }
}
int SerializeSecretKeyShare(SecretKeyShareHandle sk, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_sk(sk)->sk, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
SecretKeyShareHandle DeserializeSecretKeyShare(CryptoContextHandle ctx, uint8_t* data, size_t len, int lead) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        PrivateKey<DCRTPoly> sk;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(sk, is, SerType::BINARY);
        return reinterpret_cast<SecretKeyShareHandle>(new ARESSecretKeyShare{sk, lead != 0});
    } catch (...) {
        return nullptr;
    }
}
int SerializeEvalMultKey(EvalMultKeyHandle key, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_eval_mult(key)->key, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
EvalMultKeyHandle DeserializeEvalMultKey(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        EvalKey<DCRTPoly> key;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(key, is, SerType::BINARY);
        return reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{key});
    } catch (...) {
        return nullptr;
    }
}
int SerializeRotKey(RotKeyHandle key, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(*as_rot(key)->keys, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
RotKeyHandle DeserializeRotKey(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        std::map<usint, EvalKey<DCRTPoly>> keys;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(keys, is, SerType::BINARY);
        auto ptr = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(keys);
        return reinterpret_cast<RotKeyHandle>(new ARESRotKey{ptr});
    } catch (...) {
        return nullptr;
    }
}

void FreePublicKey(PublicKeyHandle pk) { delete reinterpret_cast<ARESPublicKey*>(pk); }
void FreeSecretKeyShare(SecretKeyShareHandle sk) { delete reinterpret_cast<ARESSecretKeyShare*>(sk); }
void FreeCiphertext(CiphertextHandle ct) { delete reinterpret_cast<ARESCiphertext*>(ct); }
void FreeEvalMultKey(EvalMultKeyHandle key) { delete reinterpret_cast<ARESEvalMultKey*>(key); }
void FreeRotKey(RotKeyHandle key) { delete reinterpret_cast<ARESRotKey*>(key); }

int ARESOpenFHESmoke(char* err, size_t err_len) {
    try {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(2);
        parameters.SetScalingModSize(50);
        parameters.SetFirstModSize(60);
        parameters.SetBatchSize(8);
        // Intentionally HEStd_NotSet: this is a fixed ring-256 toolchain self-test
        // (verifies the OpenFHE link + a trivial encrypt/mult/decrypt), never a real
        // session. A secure ring would defeat its purpose. Real contexts go through
        // make_ckks_context, which is secure-by-default (see ares_fhe_allow_insecure).
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 8);

        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);

        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        std::vector<double> values = {1.0, 2.0, 3.0, 4.0};
        auto pt = cc->MakeCKKSPackedPlaintext(values);
        auto ct = cc->Encrypt(keys.publicKey, pt);
        auto sq = cc->EvalMult(ct, ct);
        Plaintext out;
        cc->Decrypt(keys.secretKey, sq, &out);
        out->SetLength(values.size());
        auto slots = out->GetCKKSPackedValue();
        double got = 0.0;
        for (size_t i = 0; i < values.size() && i < slots.size(); i++) {
            got += slots[i].real();
        }
        if (std::fabs(got - 30.0) > 0.01) {
            set_error(err, err_len, "OpenFHE smoke dot product mismatch");
            return 1;
        }
        return 0;
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown OpenFHE smoke failure");
        return 1;
    }
}

int ARESScoreCandidatesCKKS(
    const double* initiator_profile,
    int profile_dim,
    int initiator_lat_q,
    int initiator_lon_q,
    const double* candidate_profiles,
    const int* candidate_lat_q,
    const int* candidate_lon_q,
    const int* candidate_brownies,
    int n_candidates,
    double alpha,
    double beta,
    double gamma,
    const char* distance_function,
    const char* comparator,
    int comparator_degree,
    double comparator_gain,
    double comparator_input_scale,
    double comparator_bound,
    const char* mask_mode,
    const char* selector_schedule,
    int scaling_mod_size,
    int first_mod_size,
    const int* candidate_packages,
    int package_bytes,
    int payload_slot_count,
    double* out_scores,
    double* out_mask_values,
    double* out_payload_values,
    int* out_winner_index,
    double* out_winner_score,
    char* err,
    size_t err_len
) {
    try {
        if (initiator_profile == nullptr || candidate_profiles == nullptr || candidate_packages == nullptr ||
            out_scores == nullptr || out_mask_values == nullptr || out_payload_values == nullptr ||
            out_winner_index == nullptr || out_winner_score == nullptr) {
            set_error(err, err_len, "null pointer passed to ARESScoreCandidatesCKKS");
            return 1;
        }
        if (profile_dim <= 0 || n_candidates <= 0) {
            set_error(err, err_len, "invalid profile_dim or n_candidates");
            return 1;
        }
        if (package_bytes <= 0 || payload_slot_count < package_bytes * 8) {
            set_error(err, err_len, "invalid package_bytes or payload_slot_count");
            return 1;
        }
        std::string mask_mode_value = mask_mode == nullptr ? "multiplicative" : std::string(mask_mode);
        if (mask_mode_value != "multiplicative") {
            set_error(err, err_len, "native OpenFHE scorer currently supports only multiplicative masks");
            return 1;
        }
        std::string comparator_value = comparator == nullptr ? "tanh_chebyshev" : std::string(comparator);
        if (comparator_value.empty()) {
            comparator_value = "tanh_chebyshev";
        }
        if (comparator_value != "tanh_chebyshev" && comparator_value != "logistic") {
            set_error(err, err_len, "native OpenFHE scorer supports tanh_chebyshev or logistic comparators");
            return 1;
        }
        if (comparator_degree <= 0) {
            comparator_degree = 27;
        }
        if (comparator_gain == 0.0) {
            comparator_gain = 100.0;
        }
        if (comparator_input_scale == 0.0) {
            comparator_input_scale = 0.5;
        }
        if (comparator_bound == 0.0) {
            comparator_bound = 0.5;
        }

        uint32_t batch_size = next_power_of_two(static_cast<uint32_t>(std::max(profile_dim, 32)));
        auto cc = make_ckks_context(batch_size, 3, scaling_mod_size, first_mod_size);

        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        std::vector<double> init_vec(batch_size, 0.0);
        for (int i = 0; i < profile_dim; i++) {
            init_vec[i] = initiator_profile[i];
        }
        auto init_pt = cc->MakeCKKSPackedPlaintext(init_vec);
        auto init_ct = cc->Encrypt(keys.publicKey, init_pt);

        bool sqrt_distance = distance_function != nullptr &&
            std::string(distance_function) == "polynomial_sqrt_approximation";
        int winner = -1;
        double winner_score = -std::numeric_limits<double>::infinity();

        for (int cand = 0; cand < n_candidates; cand++) {
            std::vector<double> cand_vec(batch_size, 0.0);
            const double* profile = candidate_profiles + (static_cast<size_t>(cand) * profile_dim);
            for (int j = 0; j < profile_dim; j++) {
                cand_vec[j] = profile[j];
            }
            auto cand_pt = cc->MakeCKKSPackedPlaintext(cand_vec);
            auto cand_ct = cc->Encrypt(keys.publicKey, cand_pt);
            auto prod_ct = cc->EvalMult(init_ct, cand_ct);
            Plaintext prod_pt;
            cc->Decrypt(keys.secretKey, prod_ct, &prod_pt);
            prod_pt->SetLength(profile_dim);
            auto prod_slots = prod_pt->GetCKKSPackedValue();
            double sim = 0.0;
            for (int j = 0; j < profile_dim && j < static_cast<int>(prod_slots.size()); j++) {
                sim += prod_slots[j].real();
            }

            double dlat = static_cast<double>(initiator_lat_q - candidate_lat_q[cand]);
            double dlon = static_cast<double>(initiator_lon_q - candidate_lon_q[cand]);
            double dist = dlat * dlat + dlon * dlon;
            if (sqrt_distance) {
                double x = dist;
                dist = 0.5 + x * (0.015 + x * (-1.2e-6 + x * 5.5e-11));
            }

            double score = -alpha * dist + (beta / 2.0) * sim + (beta / 2.0) +
                gamma * static_cast<double>(candidate_brownies[cand]);
            out_scores[cand] = score;
            if (winner < 0 || score > winner_score) {
                winner = cand;
                winner_score = score;
            }
        }

        uint32_t selector_batch = 8;
        uint32_t selector_depth = 30;
        auto selector_cc = make_ckks_context(selector_batch, selector_depth, scaling_mod_size, first_mod_size);
        auto selector_keys = selector_cc->KeyGen();
        selector_cc->EvalMultKeyGen(selector_keys.secretKey);

        std::vector<Ciphertext<DCRTPoly>> ct_scores;
        ct_scores.reserve(n_candidates);
        for (int i = 0; i < n_candidates; i++) {
            ct_scores.push_back(encrypt_repeated_scalar(selector_cc, selector_keys.publicKey, out_scores[i], selector_batch));
        }

        auto schedule = split_schedule(selector_schedule);
        std::vector<std::vector<Ciphertext<DCRTPoly>>> selectors(
            static_cast<size_t>(n_candidates),
            std::vector<Ciphertext<DCRTPoly>>(static_cast<size_t>(n_candidates))
        );
        for (int i = 0; i < n_candidates; i++) {
            selectors[i][i] = encrypt_repeated_scalar(selector_cc, selector_keys.publicKey, 1.0, selector_batch);
        }
        for (int i = 0; i < n_candidates; i++) {
            for (int j = i + 1; j < n_candidates; j++) {
                auto diff = selector_cc->EvalSub(ct_scores[i], ct_scores[j]);
                Ciphertext<DCRTPoly> sel_ij;
                if (comparator_value == "logistic") {
                    sel_ij = eval_logistic_chebyshev(
                        selector_cc,
                        diff,
                        comparator_input_scale,
                        comparator_gain,
                        comparator_bound,
                        comparator_degree
                    );
                } else {
                    sel_ij = eval_tanh_chebyshev(
                        selector_cc,
                        diff,
                        comparator_input_scale,
                        comparator_gain,
                        comparator_bound,
                        comparator_degree
                    );
                }
                sel_ij = apply_selector_schedule(selector_cc, sel_ij, schedule);
                auto one = encrypt_repeated_scalar(selector_cc, selector_keys.publicKey, 1.0, selector_batch);
                selectors[i][j] = sel_ij;
                selectors[j][i] = selector_cc->EvalSub(one, sel_ij);
            }
        }

        std::vector<double> mask_values(static_cast<size_t>(n_candidates), 0.0);
        for (int i = 0; i < n_candidates; i++) {
            std::vector<Ciphertext<DCRTPoly>> factors;
            factors.reserve(static_cast<size_t>(std::max(0, n_candidates - 1)));
            for (int j = 0; j < n_candidates; j++) {
                if (i == j) {
                    continue;
                }
                factors.push_back(selectors[i][j]);
            }
            auto mask_ct = product_tree(selector_cc, factors);
            mask_values[i] = decrypt_first_slot(selector_cc, selector_keys.secretKey, mask_ct);
            out_mask_values[i] = mask_values[i];
        }

        uint32_t payload_batch = next_power_of_two(static_cast<uint32_t>(std::max(payload_slot_count, 32)));
        auto payload_ctx = make_threshold_context(
            payload_batch,
            3,
            scaling_mod_size,
            first_mod_size,
            std::max(2, n_candidates + 1)
        );
        rebuild_eval_mult_keys(&payload_ctx);

        Ciphertext<DCRTPoly> fused_payload;
        bool have_payload = false;
        for (int i = 0; i < n_candidates; i++) {
            auto mask_ct = encrypt_repeated_scalar(payload_ctx.cc, payload_ctx.public_keys.back(), mask_values[i], payload_batch);
            auto bits = package_bits_for_candidate(candidate_packages, i, package_bytes, payload_slot_count, payload_batch);
            auto bits_pt = payload_ctx.cc->MakeCKKSPackedPlaintext(bits);
            auto bits_ct = payload_ctx.cc->Encrypt(payload_ctx.public_keys.back(), bits_pt);
            auto weighted = payload_ctx.cc->EvalMult(mask_ct, bits_ct);
            fused_payload = have_payload ? payload_ctx.cc->EvalAdd(fused_payload, weighted) : weighted;
            have_payload = true;
        }
        if (!have_payload) {
            set_error(err, err_len, "payload fusion produced no ciphertext");
            return 1;
        }

        auto payload_slots = threshold_decrypt_slots(&payload_ctx, fused_payload, payload_slot_count);
        for (int i = 0; i < payload_slot_count; i++) {
            out_payload_values[i] = i < static_cast<int>(payload_slots.size()) ? payload_slots[i] : 0.0;
        }

        *out_winner_index = winner;
        *out_winner_score = winner_score;
        return 0;
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown OpenFHE scoring failure");
        return 1;
    }
}

int ARESFullFusePayloadCKKS(
    CryptoContextHandle ctx_handle,
    uint32_t ring_dim,
    double scaling_factor,
    uint32_t depth,
    const uint8_t* initiator_ct,
    size_t initiator_ct_len,
    const uint8_t* candidate_ct_blob,
    const size_t* candidate_ct_lens,
    const int* candidate_lat_q,
    const int* candidate_lon_q,
    const int* candidate_brownies,
    int n_candidates,
    int profile_dim,
    int initiator_lat_q,
    int initiator_lon_q,
    double alpha,
    double beta,
    double gamma,
    const char* comparator,
    int comparator_degree,
    double comparator_gain,
    double comparator_input_scale,
    double comparator_bound,
    const char* selector_schedule,
    const uint8_t* eval_mult_key,
    size_t eval_mult_key_len,
    const uint8_t* eval_sum_key,
    size_t eval_sum_key_len,
    const int* candidate_packages,
    int package_bytes,
    int payload_slot_count,
    int minimal_rotation_keys,
    uint8_t** out_ct,
    size_t* out_ct_len,
    char* err,
    size_t err_len
) {
    try {
        const bool eval_sum_preinserted =
            ctx_handle != nullptr && (eval_sum_key == nullptr || eval_sum_key_len == 0);
        if (initiator_ct == nullptr || initiator_ct_len == 0 ||
            candidate_ct_blob == nullptr || candidate_ct_lens == nullptr ||
            candidate_lat_q == nullptr || candidate_lon_q == nullptr || candidate_brownies == nullptr ||
            eval_mult_key == nullptr || eval_mult_key_len == 0 ||
            (!eval_sum_preinserted && (eval_sum_key == nullptr || eval_sum_key_len == 0)) ||
            candidate_packages == nullptr || out_ct == nullptr || out_ct_len == nullptr) {
            set_error(err, err_len, "null pointer passed to ARESFullFusePayloadCKKS");
            return 1;
        }
        if (n_candidates <= 0 || profile_dim <= 0 || package_bytes <= 0 || payload_slot_count < package_bytes * 8) {
            set_error(err, err_len, "invalid full-fuse dimensions");
            return 1;
        }

        auto* existing_ctx = ctx_handle != nullptr ? as_ctx(ctx_handle) : nullptr;
        // Default full-fuse must match the context used by EncryptCKKSForContract
        // and threshold keygen. Compact payload-sized batches are valid only in
        // minimal-rotation mode, where all submitted artifacts are generated with
        // the same compact context.
        uint32_t batch_size = existing_ctx != nullptr
            ? existing_ctx->batch_size
            : (minimal_rotation_keys
                ? next_power_of_two(static_cast<uint32_t>(std::max(payload_slot_count, profile_dim)))
                : (ring_dim >= 16 ? ring_dim / 2 : 8));
        if (batch_size < static_cast<uint32_t>(payload_slot_count)) {
            set_error(err, err_len, "contract batch size too small for payload slots");
            return 1;
        }
        auto cc = (ctx_handle != nullptr)
            ? existing_ctx->cc
            : make_ckks_context(batch_size, depth == 0 ? 30 : depth, infer_scaling_mod_size(scaling_factor), 60, ring_dim);

        EvalKey<DCRTPoly> mult_key;
        {
            std::string raw(reinterpret_cast<const char*>(eval_mult_key), eval_mult_key_len);
            std::stringstream is(raw);
            Serial::Deserialize(mult_key, is, SerType::BINARY);
        }
        cc->InsertEvalMultKey({mult_key});
        if (!eval_sum_preinserted) {
            std::map<usint, EvalKey<DCRTPoly>> sum_keys;
            {
                std::string raw(reinterpret_cast<const char*>(eval_sum_key), eval_sum_key_len);
                std::stringstream is(raw);
                Serial::Deserialize(sum_keys, is, SerType::BINARY);
            }
            cc->InsertEvalSumKey(std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(sum_keys));
        }

        Ciphertext<DCRTPoly> init;
        {
            std::string raw(reinterpret_cast<const char*>(initiator_ct), initiator_ct_len);
            std::stringstream is(raw);
            Serial::Deserialize(init, is, SerType::BINARY);
        }
        if (init == nullptr || init->GetCryptoContext() != cc) {
            set_error(err, err_len, "initiator ciphertext context does not match scorer context");
            return 1;
        }
        const std::string collective_key_tag = init->GetKeyTag();
        std::vector<Ciphertext<DCRTPoly>> candidates;
        candidates.reserve(static_cast<size_t>(n_candidates));
        size_t offset = 0;
        for (int i = 0; i < n_candidates; i++) {
            size_t n = candidate_ct_lens[i];
            if (n == 0) {
                set_error(err, err_len, "candidate ciphertext length is zero");
                return 1;
            }
            Ciphertext<DCRTPoly> ct;
            std::string raw(reinterpret_cast<const char*>(candidate_ct_blob + offset), n);
            std::stringstream is(raw);
            Serial::Deserialize(ct, is, SerType::BINARY);
            if (ct == nullptr || ct->GetCryptoContext() != cc) {
                set_error(err, err_len, "candidate ciphertext context does not match scorer context");
                return 1;
            }
            if (ct->GetKeyTag() != collective_key_tag) {
                set_error(err, err_len, "candidate ciphertext key tag does not match initiator ciphertext");
                return 1;
            }
            candidates.push_back(ct);
            offset += n;
        }

        std::string comparator_value = comparator == nullptr ? "tanh_chebyshev" : std::string(comparator);
        if (comparator_value.empty()) {
            comparator_value = "tanh_chebyshev";
        }
        if (comparator_value != "tanh_chebyshev" && comparator_value != "logistic") {
            set_error(err, err_len, "full OpenFHE scorer supports tanh_chebyshev or logistic comparators");
            return 1;
        }
        if (comparator_degree <= 0) {
            comparator_degree = 27;
        }
        if (comparator_gain == 0.0) {
            comparator_gain = 100.0;
        }
        if (comparator_input_scale == 0.0) {
            comparator_input_scale = 0.5;
        }
        if (comparator_bound == 0.0) {
            comparator_bound = 0.5;
        }

        std::vector<Ciphertext<DCRTPoly>> ct_scores;
        ct_scores.reserve(static_cast<size_t>(n_candidates));
        for (int i = 0; i < n_candidates; i++) {
            auto prod = cc->EvalMult(init, candidates[i]);
            auto sim = minimal_rotation_keys
                ? fold_dot_to_first_slot(cc, prod, profile_dim)
                : cc->EvalSum(prod, profile_dim);
            sim = broadcast_first_slot(cc, sim, payload_slot_count, batch_size);
            double dlat = static_cast<double>(initiator_lat_q - candidate_lat_q[i]);
            double dlon = static_cast<double>(initiator_lon_q - candidate_lon_q[i]);
            double dist = dlat * dlat + dlon * dlon;
            auto score = cc->EvalMult(sim, beta / 2.0);
            score = cc->EvalAdd(score, (beta / 2.0) - alpha * dist + gamma * static_cast<double>(candidate_brownies[i]));
            ct_scores.push_back(score);
        }

        auto schedule = split_schedule(selector_schedule);
        std::vector<std::vector<Ciphertext<DCRTPoly>>> selectors(
            static_cast<size_t>(n_candidates),
            std::vector<Ciphertext<DCRTPoly>>(static_cast<size_t>(n_candidates))
        );
        for (int i = 0; i < n_candidates; i++) {
            selectors[i][i] = cc->EvalAdd(cc->EvalSub(ct_scores[i], ct_scores[i]), 1.0);
        }
        for (int i = 0; i < n_candidates; i++) {
            for (int j = i + 1; j < n_candidates; j++) {
                auto diff = cc->EvalSub(ct_scores[i], ct_scores[j]);
                Ciphertext<DCRTPoly> sel_ij;
                if (comparator_value == "logistic") {
                    sel_ij = eval_logistic_chebyshev(cc, diff, comparator_input_scale, comparator_gain, comparator_bound, comparator_degree);
                } else {
                    sel_ij = eval_tanh_chebyshev(cc, diff, comparator_input_scale, comparator_gain, comparator_bound, comparator_degree);
                }
                sel_ij = apply_selector_schedule(cc, sel_ij, schedule);
                auto one = cc->EvalAdd(cc->EvalSub(ct_scores[i], ct_scores[i]), 1.0);
                selectors[i][j] = sel_ij;
                selectors[j][i] = cc->EvalSub(one, sel_ij);
            }
        }

        Ciphertext<DCRTPoly> fused_payload;
        bool have_payload = false;
        for (int i = 0; i < n_candidates; i++) {
            std::vector<Ciphertext<DCRTPoly>> factors;
            factors.reserve(static_cast<size_t>(std::max(0, n_candidates - 1)));
            for (int j = 0; j < n_candidates; j++) {
                if (i != j) {
                    factors.push_back(selectors[i][j]);
                }
            }
            auto mask_ct = product_tree(cc, factors);
            auto bits = package_bits_for_candidate(candidate_packages, i, package_bytes, payload_slot_count, batch_size);
            auto bits_pt = cc->MakeCKKSPackedPlaintext(bits);
            auto weighted = cc->EvalMult(mask_ct, bits_pt);
            fused_payload = have_payload ? cc->EvalAdd(fused_payload, weighted) : weighted;
            have_payload = true;
        }
        if (!have_payload) {
            set_error(err, err_len, "full payload fusion produced no ciphertext");
            return 1;
        }
        if (serialize_object(fused_payload, out_ct, out_ct_len) != 0) {
            set_error(err, err_len, "serialize full fused payload failed");
            return 1;
        }
        return 0;
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown OpenFHE full-fuse failure");
        return 1;
    }
}

// package_chunk_bits returns chunk_size payload bits for one candidate's package
// starting at chunk_index*chunk_size, placed in slots [0, chunk_size). The chunked
// fusion aligns every chunk to slots [0, chunk_size) so it multiplies the EvalSum-
// replicated mask (also uniform across [0, chunk_size)) with no broadcast.
static std::vector<double> package_chunk_bits(const int* candidate_packages,
    int candidate_index, int package_bytes, int chunk_index, int chunk_size) {
    std::vector<double> bits(static_cast<size_t>(chunk_size), 0.0);
    const int total_bits = package_bytes * 8;
    const int start = chunk_index * chunk_size;
    const int* pkg = candidate_packages + (static_cast<size_t>(candidate_index) * package_bytes);
    for (int k = 0; k < chunk_size; k++) {
        const int bit_idx = start + k;
        if (bit_idx >= total_bits) break;
        const int value = pkg[bit_idx / 8];
        const int shift = 7 - (bit_idx % 8);
        bits[static_cast<size_t>(k)] = ((value >> shift) & 1) ? 1.0 : 0.0;
    }
    return bits;
}

// ARESChunkedFusePayloadCKKS is the server-blind fusion with crypto-lab's CHUNKED
// payload recovery -- the low-RSS default. Instead of broadcasting the scalar argmax
// mask across the whole payload in ONE ciphertext (which needs the negative broadcast
// rotation keys), it EvalSum-replicates the score/mask across the profile_dim batch
// (positive fold keys ONLY -- 7 vs 17 at dim 128 / 640-bit payload) and splits the
// payload into ceil(payload_slot_count/batch_size) chunks, fusing
// `sum_i mask_i * pkg_chunk_i` per chunk. Output: the n_chunks result ciphertexts
// serialized and concatenated into out_cts; out_chunk_lens[c] (caller-allocated,
// >= n_chunks) holds each chunk's serialized length; *out_n_chunks = chunk count.
// Each chunk holds the winner's chunk_size payload bits in slots [0, chunk_size);
// the caller threshold-decrypts each chunk and reassembles the 640-bit package.
static int chunkedFusePayloadCKKSImpl(
    CryptoContextHandle ctx_handle,
    uint32_t ring_dim,
    double scaling_factor,
    uint32_t depth,
    const uint8_t* initiator_ct,
    size_t initiator_ct_len,
    const uint8_t* candidate_ct_blob,
    const size_t* candidate_ct_lens,
    const int* candidate_lat_q,
    const int* candidate_lon_q,
    const int* candidate_brownies,
    const uint8_t* candidate_distance_ct_blob,
    size_t candidate_distance_ct_blob_len,
    const size_t* candidate_distance_ct_lens,
    int candidate_distance_ct_count,
    int n_candidates,
    int profile_dim,
    int initiator_lat_q,
    int initiator_lon_q,
    double alpha,
    double beta,
    double gamma,
    const char* comparator,
    int comparator_degree,
    double comparator_gain,
    double comparator_input_scale,
    double comparator_bound,
    const char* selector_schedule,
    const uint8_t* eval_mult_key,
    size_t eval_mult_key_len,
    const uint8_t* eval_sum_key,
    size_t eval_sum_key_len,
    const int* candidate_packages,
    int package_bytes,
    const uint8_t* candidate_payload_ct_blob,
    size_t candidate_payload_ct_blob_len,
    const size_t* candidate_payload_ct_lens,
    int candidate_payload_ct_count,
    int payload_slot_count,
    uint8_t** out_cts,
    size_t* out_cts_len,
    size_t* out_chunk_lens,
    int* out_n_chunks,
    char* err,
    size_t err_len
) {
    try {
        const bool plain_payload = candidate_packages != nullptr;
        const bool encrypted_payload = candidate_payload_ct_blob != nullptr ||
            candidate_payload_ct_lens != nullptr || candidate_payload_ct_count != 0;
        const bool raw_distance = candidate_lat_q != nullptr || candidate_lon_q != nullptr;
        const bool encrypted_distance = candidate_distance_ct_blob != nullptr ||
            candidate_distance_ct_lens != nullptr || candidate_distance_ct_count != 0;
        const bool eval_mult_preinserted =
            ctx_handle != nullptr && (eval_mult_key == nullptr || eval_mult_key_len == 0);
        const bool eval_sum_preinserted =
            ctx_handle != nullptr && (eval_sum_key == nullptr || eval_sum_key_len == 0);
        if (initiator_ct == nullptr || initiator_ct_len == 0 ||
            candidate_ct_blob == nullptr || candidate_ct_lens == nullptr ||
            candidate_brownies == nullptr ||
            (candidate_lat_q == nullptr) != (candidate_lon_q == nullptr) ||
            raw_distance == encrypted_distance ||
            (!eval_mult_preinserted && (eval_mult_key == nullptr || eval_mult_key_len == 0)) ||
            (!eval_sum_preinserted && (eval_sum_key == nullptr || eval_sum_key_len == 0)) ||
            plain_payload == encrypted_payload || out_cts == nullptr || out_cts_len == nullptr ||
            out_chunk_lens == nullptr || out_n_chunks == nullptr) {
            set_error(err, err_len, "invalid pointers or payload mode passed to chunked payload fusion");
            return 1;
        }
        if (n_candidates <= 0 || profile_dim <= 0 || payload_slot_count <= 0 ||
            (plain_payload && (package_bytes <= 0 || payload_slot_count < package_bytes * 8))) {
            set_error(err, err_len, "invalid chunked-fuse dimensions");
            return 1;
        }

        // Chunked: the scoring/payload batch is profile_dim-sized (matches the fold-only
        // 7-key rotation set), NOT max(payload, profile). The payload is split into chunks
        // of this batch instead of living in one wide ciphertext.
        const uint32_t batch_size = next_power_of_two(static_cast<uint32_t>(profile_dim));
        const int chunk_size = static_cast<int>(batch_size);
        const int n_chunks = (payload_slot_count + chunk_size - 1) / chunk_size;
        if (encrypted_payload && candidate_payload_ct_count != n_candidates * n_chunks) {
            set_error(err, err_len, "encrypted payload ciphertext count does not match candidate/chunk shape");
            return 1;
        }
        if (encrypted_payload && (candidate_payload_ct_blob == nullptr ||
            candidate_payload_ct_lens == nullptr || candidate_payload_ct_blob_len == 0)) {
            set_error(err, err_len, "encrypted payload ciphertext bytes and lengths are required");
            return 1;
        }
        if (encrypted_distance && (candidate_distance_ct_count != n_candidates ||
            candidate_distance_ct_blob == nullptr || candidate_distance_ct_lens == nullptr ||
            candidate_distance_ct_blob_len == 0)) {
            set_error(err, err_len, "encrypted distance ciphertext shape is invalid");
            return 1;
        }

        std::vector<size_t> payload_offsets;
        if (encrypted_payload) {
            payload_offsets.resize(static_cast<size_t>(candidate_payload_ct_count));
            size_t offset = 0;
            for (int i = 0; i < candidate_payload_ct_count; i++) {
                const size_t len = candidate_payload_ct_lens[i];
                if (len == 0 || offset > candidate_payload_ct_blob_len ||
                    len > candidate_payload_ct_blob_len - offset) {
                    set_error(err, err_len, "invalid encrypted payload ciphertext length");
                    return 1;
                }
                payload_offsets[static_cast<size_t>(i)] = offset;
                offset += len;
            }
            if (offset != candidate_payload_ct_blob_len) {
                set_error(err, err_len, "encrypted payload ciphertext blob length does not match lens");
                return 1;
            }
        }
        std::vector<size_t> distance_offsets;
        if (encrypted_distance) {
            distance_offsets.resize(static_cast<size_t>(candidate_distance_ct_count));
            size_t offset = 0;
            for (int i = 0; i < candidate_distance_ct_count; i++) {
                const size_t len = candidate_distance_ct_lens[i];
                if (len == 0 || offset > candidate_distance_ct_blob_len ||
                    len > candidate_distance_ct_blob_len - offset) {
                    set_error(err, err_len, "invalid encrypted distance ciphertext length");
                    return 1;
                }
                distance_offsets[static_cast<size_t>(i)] = offset;
                offset += len;
            }
            if (offset != candidate_distance_ct_blob_len) {
                set_error(err, err_len, "encrypted distance ciphertext blob length does not match lens");
                return 1;
            }
        }

        auto cc = (ctx_handle != nullptr)
            ? as_ctx(ctx_handle)->cc
            : make_ckks_context(batch_size, depth == 0 ? 30 : depth, infer_scaling_mod_size(scaling_factor), 60, ring_dim);

        if (!eval_mult_preinserted) {
            EvalKey<DCRTPoly> mult_key;
            {
                std::string raw(reinterpret_cast<const char*>(eval_mult_key), eval_mult_key_len);
                std::stringstream is(raw);
                Serial::Deserialize(mult_key, is, SerType::BINARY);
            }
            // Idempotent insert: OpenFHE caches eval-keys in a global map keyed by context
            // ID, so the same params across union-comparator calls collide. Clear first.
            lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalMultKeys(cc);
            cc->InsertEvalMultKey({mult_key});
        }
        if (!eval_sum_preinserted) {
            std::map<usint, EvalKey<DCRTPoly>> sum_keys;
            {
                std::string raw(reinterpret_cast<const char*>(eval_sum_key), eval_sum_key_len);
                std::stringstream is(raw);
                Serial::Deserialize(sum_keys, is, SerType::BINARY);
            }
            lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalSumKeys(cc);
            cc->InsertEvalSumKey(std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(sum_keys));
        }

        Ciphertext<DCRTPoly> init;
        {
            std::string raw(reinterpret_cast<const char*>(initiator_ct), initiator_ct_len);
            std::stringstream is(raw);
            Serial::Deserialize(init, is, SerType::BINARY);
        }
        if (init == nullptr || init->GetCryptoContext() != cc) {
            set_error(err, err_len, "initiator ciphertext context does not match scorer context");
            return 1;
        }
        const std::string collective_key_tag = init->GetKeyTag();
        std::vector<Ciphertext<DCRTPoly>> candidates;
        candidates.reserve(static_cast<size_t>(n_candidates));
        size_t offset = 0;
        for (int i = 0; i < n_candidates; i++) {
            size_t n = candidate_ct_lens[i];
            if (n == 0) {
                set_error(err, err_len, "candidate ciphertext length is zero");
                return 1;
            }
            Ciphertext<DCRTPoly> ct;
            std::string raw(reinterpret_cast<const char*>(candidate_ct_blob + offset), n);
            std::stringstream is(raw);
            Serial::Deserialize(ct, is, SerType::BINARY);
            if (ct == nullptr || ct->GetCryptoContext() != cc) {
                set_error(err, err_len, "candidate ciphertext context does not match scorer context");
                return 1;
            }
            if (ct->GetKeyTag() != collective_key_tag) {
                set_error(err, err_len, "candidate ciphertext key tag does not match initiator ciphertext");
                return 1;
            }
            candidates.push_back(ct);
            offset += n;
        }

        std::string comparator_value = comparator == nullptr ? "tanh_chebyshev" : std::string(comparator);
        if (comparator_value.empty()) comparator_value = "tanh_chebyshev";
        if (comparator_value != "tanh_chebyshev" && comparator_value != "logistic" && comparator_value != "selector") {
            set_error(err, err_len, "chunked scorer supports tanh_chebyshev, logistic, or selector comparators");
            return 1;
        }
        if (comparator_degree <= 0) comparator_degree = 27;
        if (comparator_gain == 0.0) comparator_gain = 100.0;
        if (comparator_input_scale == 0.0) comparator_input_scale = 0.5;
        if (comparator_bound == 0.0) comparator_bound = 0.5;

        // Score: EvalMult + EvalSum REPLICATES the dot product across the batch (fold keys
        // only) -- the chunked alternative to fold-to-slot-0 + broadcast. No broadcast keys.
        std::vector<Ciphertext<DCRTPoly>> ct_scores;
        ct_scores.reserve(static_cast<size_t>(n_candidates));
        for (int i = 0; i < n_candidates; i++) {
            auto prod = cc->EvalMult(init, candidates[i]);
            auto sim = cc->EvalSum(prod, profile_dim);
            auto score = cc->EvalMult(sim, beta / 2.0);
            if (encrypted_distance) {
                const size_t distance_len = candidate_distance_ct_lens[i];
                std::string raw(
                    reinterpret_cast<const char*>(candidate_distance_ct_blob + distance_offsets[static_cast<size_t>(i)]),
                    distance_len);
                std::stringstream is(raw);
                Ciphertext<DCRTPoly> distance;
                Serial::Deserialize(distance, is, SerType::BINARY);
                if (distance == nullptr || distance->GetCryptoContext() != cc ||
                    distance->GetKeyTag() != collective_key_tag) {
                    set_error(err, err_len, "encrypted distance ciphertext does not match scorer context or key");
                    return 1;
                }
                score = cc->EvalAdd(score, cc->EvalMult(distance, -alpha));
                score = cc->EvalAdd(score, (beta / 2.0) + gamma * static_cast<double>(candidate_brownies[i]));
            } else {
                double dlat = static_cast<double>(initiator_lat_q - candidate_lat_q[i]);
                double dlon = static_cast<double>(initiator_lon_q - candidate_lon_q[i]);
                double dist = dlat * dlat + dlon * dlon;
                score = cc->EvalAdd(score, (beta / 2.0) - alpha * dist + gamma * static_cast<double>(candidate_brownies[i]));
            }
            ct_scores.push_back(score);
        }

        auto schedule = split_schedule(selector_schedule);
        std::vector<std::vector<Ciphertext<DCRTPoly>>> selectors(
            static_cast<size_t>(n_candidates),
            std::vector<Ciphertext<DCRTPoly>>(static_cast<size_t>(n_candidates))
        );
        for (int i = 0; i < n_candidates; i++) {
            selectors[i][i] = cc->EvalAdd(cc->EvalSub(ct_scores[i], ct_scores[i]), 1.0);
        }
        for (int i = 0; i < n_candidates; i++) {
            for (int j = i + 1; j < n_candidates; j++) {
                auto diff = cc->EvalSub(ct_scores[i], ct_scores[j]);
                Ciphertext<DCRTPoly> sel_ij;
                if (comparator_value == "logistic") {
                    sel_ij = eval_logistic_chebyshev(cc, diff, comparator_input_scale, comparator_gain, comparator_bound, comparator_degree);
                } else if (comparator_value == "selector") {
                    // soft selector polynomial f(x)=0.5+0.1125x-0.00084375x^3 (crypto-lab ss base),
                    // with input_scale range control so large score margins stay in the poly's
                    // useful range (else the cubic saturates/inverts on big diffs).
                    auto sdiff = (std::fabs(comparator_input_scale - 1.0) > 1e-12)
                        ? cc->EvalMult(diff, comparator_input_scale) : diff;
                    auto x2 = cc->EvalMult(sdiff, sdiff);
                    auto inner = cc->EvalMult(x2, -0.00084375);
                    inner = cc->EvalAdd(inner, 0.1125);
                    auto prod = cc->EvalMult(inner, sdiff);
                    sel_ij = cc->EvalAdd(prod, 0.5);
                } else {
                    sel_ij = eval_tanh_chebyshev(cc, diff, comparator_input_scale, comparator_gain, comparator_bound, comparator_degree);
                }
                sel_ij = apply_selector_schedule(cc, sel_ij, schedule);
                auto one = cc->EvalAdd(cc->EvalSub(ct_scores[i], ct_scores[i]), 1.0);
                selectors[i][j] = sel_ij;
                selectors[j][i] = cc->EvalSub(one, sel_ij);
            }
        }

        // Per-candidate product mask (uniform across the batch, like the scores).
        std::vector<Ciphertext<DCRTPoly>> masks;
        masks.reserve(static_cast<size_t>(n_candidates));
        for (int i = 0; i < n_candidates; i++) {
            std::vector<Ciphertext<DCRTPoly>> factors;
            for (int j = 0; j < n_candidates; j++) {
                if (i != j) factors.push_back(selectors[i][j]);
            }
            masks.push_back(product_tree(cc, factors));
        }

        // Per-chunk fusion: every chunk reuses the SAME masks against that chunk's bits
        // (aligned to slots [0, chunk_size)). n_chunks result ciphertexts.
        std::string concat;
        for (int c = 0; c < n_chunks; c++) {
            Ciphertext<DCRTPoly> fused_chunk;
            bool have = false;
            for (int i = 0; i < n_candidates; i++) {
                Ciphertext<DCRTPoly> weighted;
                if (plain_payload) {
                    auto bits = package_chunk_bits(candidate_packages, i, package_bytes, c, chunk_size);
                    auto bits_pt = cc->MakeCKKSPackedPlaintext(bits);
                    weighted = cc->EvalMult(masks[i], bits_pt);
                } else {
                    const size_t index = static_cast<size_t>(i * n_chunks + c);
                    const size_t payload_len = candidate_payload_ct_lens[index];
                    std::string raw(
                        reinterpret_cast<const char*>(candidate_payload_ct_blob + payload_offsets[index]),
                        payload_len);
                    std::stringstream is(raw);
                    Ciphertext<DCRTPoly> payload_ct;
                    Serial::Deserialize(payload_ct, is, SerType::BINARY);
                    if (payload_ct == nullptr || payload_ct->GetCryptoContext() != cc) {
                        set_error(err, err_len, "encrypted payload ciphertext context does not match scorer context");
                        return 1;
                    }
                    if (payload_ct->GetKeyTag() != collective_key_tag) {
                        set_error(err, err_len, "encrypted payload ciphertext key tag does not match initiator ciphertext");
                        return 1;
                    }
                    // EvalMult clones both operands and calls OpenFHE's CKKS
                    // AdjustForMultInPlace, which jointly aligns levels and scales.
                    // Pre-reducing here repeats that expensive work once per level.
                    weighted = cc->EvalMult(masks[i], payload_ct);
                }
                fused_chunk = have ? cc->EvalAdd(fused_chunk, weighted) : weighted;
                have = true;
            }
            std::stringstream os;
            Serial::Serialize(fused_chunk, os, SerType::BINARY);
            std::string chunk_bytes = os.str();
            out_chunk_lens[c] = chunk_bytes.size();
            concat += chunk_bytes;
        }

        *out_n_chunks = n_chunks;
        *out_cts_len = concat.size();
        *out_cts = static_cast<uint8_t*>(malloc(concat.size()));
        if (*out_cts == nullptr) {
            set_error(err, err_len, "out-of-memory serializing chunked fused payload");
            return 1;
        }
        memcpy(*out_cts, concat.data(), concat.size());
        return 0;
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown OpenFHE chunked-fuse failure");
        return 1;
    }
}

int ARESChunkedFusePayloadCKKS(
    CryptoContextHandle ctx_handle, uint32_t ring_dim, double scaling_factor, uint32_t depth,
    const uint8_t* initiator_ct, size_t initiator_ct_len,
    const uint8_t* candidate_ct_blob, const size_t* candidate_ct_lens,
    const int* candidate_lat_q, const int* candidate_lon_q, const int* candidate_brownies,
    int n_candidates, int profile_dim, int initiator_lat_q, int initiator_lon_q,
    double alpha, double beta, double gamma, const char* comparator, int comparator_degree,
    double comparator_gain, double comparator_input_scale, double comparator_bound,
    const char* selector_schedule, const uint8_t* eval_mult_key, size_t eval_mult_key_len,
    const uint8_t* eval_sum_key, size_t eval_sum_key_len, const int* candidate_packages,
    int package_bytes, int payload_slot_count, uint8_t** out_cts, size_t* out_cts_len,
    size_t* out_chunk_lens, int* out_n_chunks, char* err, size_t err_len
) {
    return chunkedFusePayloadCKKSImpl(
        ctx_handle, ring_dim, scaling_factor, depth, initiator_ct, initiator_ct_len,
        candidate_ct_blob, candidate_ct_lens, candidate_lat_q, candidate_lon_q,
        candidate_brownies, nullptr, 0, nullptr, 0, n_candidates, profile_dim, initiator_lat_q, initiator_lon_q,
        alpha, beta, gamma, comparator, comparator_degree, comparator_gain,
        comparator_input_scale, comparator_bound, selector_schedule, eval_mult_key,
        eval_mult_key_len, eval_sum_key, eval_sum_key_len, candidate_packages, package_bytes,
        nullptr, 0, nullptr, 0, payload_slot_count, out_cts, out_cts_len, out_chunk_lens,
        out_n_chunks, err, err_len);
}

int ARESChunkedFuseEncryptedPayloadCKKS(
    CryptoContextHandle ctx_handle, uint32_t ring_dim, double scaling_factor, uint32_t depth,
    const uint8_t* initiator_ct, size_t initiator_ct_len,
    const uint8_t* candidate_ct_blob, const size_t* candidate_ct_lens,
    const int* candidate_lat_q, const int* candidate_lon_q, const int* candidate_brownies,
    int n_candidates, int profile_dim, int initiator_lat_q, int initiator_lon_q,
    double alpha, double beta, double gamma, const char* comparator, int comparator_degree,
    double comparator_gain, double comparator_input_scale, double comparator_bound,
    const char* selector_schedule, const uint8_t* eval_mult_key, size_t eval_mult_key_len,
    const uint8_t* eval_sum_key, size_t eval_sum_key_len,
    const uint8_t* candidate_payload_ct_blob, size_t candidate_payload_ct_blob_len,
    const size_t* candidate_payload_ct_lens, int candidate_payload_ct_count,
    int payload_slot_count, uint8_t** out_cts, size_t* out_cts_len, size_t* out_chunk_lens,
    int* out_n_chunks, char* err, size_t err_len
) {
    return chunkedFusePayloadCKKSImpl(
        ctx_handle, ring_dim, scaling_factor, depth, initiator_ct, initiator_ct_len,
        candidate_ct_blob, candidate_ct_lens, candidate_lat_q, candidate_lon_q,
        candidate_brownies, nullptr, 0, nullptr, 0, n_candidates, profile_dim, initiator_lat_q, initiator_lon_q,
        alpha, beta, gamma, comparator, comparator_degree, comparator_gain,
        comparator_input_scale, comparator_bound, selector_schedule, eval_mult_key,
        eval_mult_key_len, eval_sum_key, eval_sum_key_len, nullptr, 0,
        candidate_payload_ct_blob, candidate_payload_ct_blob_len, candidate_payload_ct_lens,
        candidate_payload_ct_count, payload_slot_count, out_cts, out_cts_len, out_chunk_lens,
        out_n_chunks, err, err_len);
}

int ARESChunkedFuseEncryptedInputsCKKS(
    CryptoContextHandle ctx_handle, uint32_t ring_dim, double scaling_factor, uint32_t depth,
    const uint8_t* initiator_ct, size_t initiator_ct_len,
    const uint8_t* candidate_ct_blob, const size_t* candidate_ct_lens,
    const int* candidate_brownies, int n_candidates, int profile_dim,
    double alpha, double beta, double gamma, const char* comparator, int comparator_degree,
    double comparator_gain, double comparator_input_scale, double comparator_bound,
    const char* selector_schedule, const uint8_t* eval_mult_key, size_t eval_mult_key_len,
    const uint8_t* eval_sum_key, size_t eval_sum_key_len,
    const uint8_t* candidate_distance_ct_blob, size_t candidate_distance_ct_blob_len,
    const size_t* candidate_distance_ct_lens, int candidate_distance_ct_count,
    const uint8_t* candidate_payload_ct_blob, size_t candidate_payload_ct_blob_len,
    const size_t* candidate_payload_ct_lens, int candidate_payload_ct_count,
    int payload_slot_count, uint8_t** out_cts, size_t* out_cts_len, size_t* out_chunk_lens,
    int* out_n_chunks, char* err, size_t err_len
) {
    return chunkedFusePayloadCKKSImpl(
        ctx_handle, ring_dim, scaling_factor, depth, initiator_ct, initiator_ct_len,
        candidate_ct_blob, candidate_ct_lens, nullptr, nullptr, candidate_brownies,
        candidate_distance_ct_blob, candidate_distance_ct_blob_len, candidate_distance_ct_lens,
        candidate_distance_ct_count, n_candidates, profile_dim, 0, 0,
        alpha, beta, gamma, comparator, comparator_degree, comparator_gain,
        comparator_input_scale, comparator_bound, selector_schedule, eval_mult_key,
        eval_mult_key_len, eval_sum_key, eval_sum_key_len, nullptr, 0,
        candidate_payload_ct_blob, candidate_payload_ct_blob_len, candidate_payload_ct_lens,
        candidate_payload_ct_count, payload_slot_count, out_cts, out_cts_len, out_chunk_lens,
        out_n_chunks, err, err_len);
}

static Plaintext bfv_repeated_plaintext(const CryptoContext<DCRTPoly>& cc,
    int64_t value, uint32_t batch_size) {
    return cc->MakePackedPlaintext(std::vector<int64_t>(batch_size, value));
}

struct BFVRepeatedPlaintextCache {
    BFVRepeatedPlaintextCache(const CryptoContext<DCRTPoly>& context, uint32_t batch)
        : cc(context), batch_size(batch) {}

    Plaintext get(int64_t value) {
        auto existing = repeated.find(value);
        if (existing != repeated.end()) {
            return existing->second;
        }
        auto inserted = repeated.emplace(
            value, cc->MakePackedPlaintext(std::vector<int64_t>(batch_size, value)));
        return inserted.first->second;
    }

    const CryptoContext<DCRTPoly>& cc;
    uint32_t batch_size;
    std::map<int64_t, Plaintext> repeated;
};

static Ciphertext<DCRTPoly> bfv_encrypted_constant_cached(
    const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& reference,
    int64_t value,
    BFVRepeatedPlaintextCache& cache) {
    auto zero = cc->EvalSub(reference, reference);
    auto plaintext = cache.get(value);
    return cc->EvalAdd(zero, plaintext);
}

static Ciphertext<DCRTPoly> bfv_mul_plain(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& ct, int64_t value, uint32_t batch_size) {
    return cc->EvalMult(ct, bfv_repeated_plaintext(cc, value, batch_size));
}

static Ciphertext<DCRTPoly> bfv_mul_plain_cached(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& ct, int64_t value, BFVRepeatedPlaintextCache& cache) {
    auto plaintext = cache.get(value);
    return cc->EvalMult(ct, plaintext);
}

static bool bfv_low_rss_mode() {
    const char* raw = getenv("ARES_BFV_PS_LOW_RSS");
    return raw == nullptr || raw[0] == '\0' || !(raw[0] == '0' && raw[1] == '\0');
}

static int bfv_ps_baby_steps(int degree) {
    const int fallback = std::max(2, static_cast<int>(std::sqrt(static_cast<double>(degree))) + 1);
    const char* raw = getenv("ARES_BFV_PS_BABY_STEPS");
    if (raw == nullptr || raw[0] == '\0') {
        return fallback;
    }
    char* end = nullptr;
    long parsed = std::strtol(raw, &end, 10);
    if (end == raw || parsed < 2 || parsed > degree + 1) {
        return fallback;
    }
    return static_cast<int>(parsed);
}

static std::vector<Ciphertext<DCRTPoly>> bfv_power_of_two_cache(
    const CryptoContext<DCRTPoly>& cc, const Ciphertext<DCRTPoly>& base, int max_exp) {
    std::vector<Ciphertext<DCRTPoly>> powers;
    if (max_exp <= 0) {
        return powers;
    }
    powers.push_back(base);
    for (int covered = 1; covered * 2 <= max_exp; covered *= 2) {
        powers.push_back(cc->EvalMult(powers.back(), powers.back()));
    }
    return powers;
}

static Ciphertext<DCRTPoly> bfv_power_from_binary(const CryptoContext<DCRTPoly>& cc,
    const std::vector<Ciphertext<DCRTPoly>>& powers, int exponent,
    const Ciphertext<DCRTPoly>& one) {
    if (exponent == 0) {
        return one;
    }
    std::vector<Ciphertext<DCRTPoly>> factors;
    for (int bit = 0; exponent > 0; exponent >>= 1, bit++) {
        if ((exponent & 1) != 0) {
            if (bit >= static_cast<int>(powers.size())) {
                throw std::runtime_error("BFV power cache is too small");
            }
            factors.push_back(powers[static_cast<size_t>(bit)]);
        }
    }
    return product_tree(cc, std::move(factors));
}

static Ciphertext<DCRTPoly> bfv_ps_eval(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& x, const std::vector<int64_t>& coefficients,
    BFVRepeatedPlaintextCache& cache) {
    if (coefficients.empty()) {
        throw std::runtime_error("BFV step polynomial is empty");
    }
    const int degree = static_cast<int>(coefficients.size()) - 1;
    if (degree == 0) {
        return bfv_encrypted_constant_cached(cc, x, coefficients[0], cache);
    }
    const int k = bfv_ps_baby_steps(degree);
    const int blocks = (degree + k) / k;

    std::vector<Ciphertext<DCRTPoly>> baby(static_cast<size_t>(k));
    baby[0] = bfv_encrypted_constant_cached(cc, x, 1, cache);
    baby[1] = x;
    for (int i = 2; i < k; i++) {
        const int left = i / 2;
        baby[static_cast<size_t>(i)] = cc->EvalMult(
            baby[static_cast<size_t>(left)], baby[static_cast<size_t>(i - left)]);
    }
    const auto xk = cc->EvalMult(baby[static_cast<size_t>(k / 2)],
        baby[static_cast<size_t>(k - k / 2)]);

    std::vector<Ciphertext<DCRTPoly>> giants;
    std::vector<Ciphertext<DCRTPoly>> giant_powers;
    const bool low_rss = bfv_low_rss_mode();
    if (low_rss) {
        giant_powers = bfv_power_of_two_cache(cc, xk, blocks - 1);
    } else {
        giants.resize(static_cast<size_t>(blocks));
        giants[0] = baby[0];
        if (blocks > 1) {
            giants[1] = xk;
        }
        for (int i = 2; i < blocks; i++) {
            const int left = i / 2;
            giants[static_cast<size_t>(i)] = cc->EvalMult(
                giants[static_cast<size_t>(left)], giants[static_cast<size_t>(i - left)]);
        }
    }

    Ciphertext<DCRTPoly> result;
    bool have_result = false;
    for (int block_index = 0; block_index < blocks; block_index++) {
        Ciphertext<DCRTPoly> block;
        bool have_block = false;
        for (int i = 0; i < k; i++) {
            const int coefficient_index = block_index * k + i;
            if (coefficient_index > degree) {
                break;
            }
            const int64_t coefficient = coefficients[static_cast<size_t>(coefficient_index)];
            if (coefficient == 0) {
                continue;
            }
            // Step-polynomial coefficients are high-cardinality. Keeping them
            // all in the plaintext cache retains a large working set, so each
            // coefficient plaintext is transient.
            auto term = bfv_mul_plain(cc, baby[static_cast<size_t>(i)], coefficient, cache.batch_size);
            block = have_block ? cc->EvalAdd(block, term) : term;
            have_block = true;
        }
        if (!have_block) {
            continue;
        }
        auto weighted = block;
        if (block_index != 0) {
            const auto factor = low_rss
                ? bfv_power_from_binary(cc, giant_powers, block_index, baby[0])
                : giants[static_cast<size_t>(block_index)];
            weighted = cc->EvalMult(factor, block);
        }
        result = have_result ? cc->EvalAdd(result, weighted) : weighted;
        have_result = true;
    }
    if (!have_result) {
        return bfv_encrypted_constant_cached(cc, x, 0, cache);
    }
    return result;
}

static void clear_ciphertexts(std::vector<Ciphertext<DCRTPoly>>& ciphertexts) {
    for (auto& ciphertext : ciphertexts) {
        ciphertext = nullptr;
    }
    std::vector<Ciphertext<DCRTPoly>>().swap(ciphertexts);
}

int ARESBlindFusePayloadBFV(
    uint32_t ring_dim, uint32_t multiplicative_depth, uint64_t plaintext_modulus,
    uint32_t batch_size, const uint8_t* eval_mult_key, size_t eval_mult_key_len,
    const uint8_t* eval_sum_key, size_t eval_sum_key_len, const uint8_t* initiator_ct,
    size_t initiator_ct_len, const uint8_t* const* candidate_profile_cts,
    const size_t* candidate_profile_ct_lens, const uint8_t* const* candidate_distance_cts,
    const size_t* candidate_distance_ct_lens, const uint8_t* const* candidate_payload_cts,
    const size_t* candidate_payload_ct_lens, const int* candidate_brownies,
    int n_candidates, int profile_dim, int64_t profile_weight, int64_t distance_weight,
    int64_t brownie_weight, int package_bytes, const int64_t* step_coeffs,
    int n_step_coeffs, uint8_t** out_ct, size_t* out_ct_len, char* err, size_t err_len) {
    try {
        if (eval_mult_key == nullptr || eval_sum_key == nullptr || initiator_ct == nullptr ||
            candidate_profile_cts == nullptr || candidate_profile_ct_lens == nullptr ||
            candidate_distance_cts == nullptr || candidate_distance_ct_lens == nullptr ||
            candidate_payload_cts == nullptr || candidate_payload_ct_lens == nullptr ||
            candidate_brownies == nullptr || step_coeffs == nullptr || out_ct == nullptr ||
            out_ct_len == nullptr) {
            set_error(err, err_len, "null pointer passed to ARESBlindFusePayloadBFV");
            return 1;
        }
        if (eval_mult_key_len == 0 || eval_sum_key_len == 0 || initiator_ct_len == 0 ||
            n_candidates < 2 || profile_dim <= 0 || package_bytes <= 0 ||
            n_step_coeffs <= 0 || package_bytes > static_cast<int>(batch_size)) {
            set_error(err, err_len, "invalid BFV blind fusion shape");
            return 1;
        }

        auto cc = make_bfv_context(ring_dim, multiplicative_depth, plaintext_modulus, batch_size);
        EvalKey<DCRTPoly> mult_key;
        deserialize_from_memory(mult_key, eval_mult_key, eval_mult_key_len);
        cc->InsertEvalMultKey({mult_key});
        mult_key = nullptr;
        std::map<usint, EvalKey<DCRTPoly>> sum_keys;
        deserialize_from_memory(sum_keys, eval_sum_key, eval_sum_key_len);
        cc->InsertEvalSumKey(std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(sum_keys));
        sum_keys.clear();

        Ciphertext<DCRTPoly> initiator;
        deserialize_from_memory(initiator, initiator_ct, initiator_ct_len);
        if (initiator == nullptr || initiator->GetCryptoContext() != cc) {
            set_error(err, err_len, "initiator ciphertext context does not match BFV scorer context");
            return 1;
        }
        const auto collective_key_tag = initiator->GetKeyTag();
        std::vector<int64_t> coefficients(step_coeffs, step_coeffs + n_step_coeffs);
        BFVRepeatedPlaintextCache plaintexts(cc, batch_size);

        std::vector<Ciphertext<DCRTPoly>> scores;
        scores.reserve(static_cast<size_t>(n_candidates));
        for (int i = 0; i < n_candidates; i++) {
            if (candidate_profile_cts[i] == nullptr || candidate_profile_ct_lens[i] == 0 ||
                candidate_distance_cts[i] == nullptr || candidate_distance_ct_lens[i] == 0 ||
                candidate_payload_cts[i] == nullptr || candidate_payload_ct_lens[i] == 0) {
                set_error(err, err_len, "empty BFV candidate ciphertext");
                return 1;
            }
            Ciphertext<DCRTPoly> profile;
            Ciphertext<DCRTPoly> distance;
            deserialize_from_memory(profile, candidate_profile_cts[i], candidate_profile_ct_lens[i]);
            deserialize_from_memory(distance, candidate_distance_cts[i], candidate_distance_ct_lens[i]);
            if (profile == nullptr || distance == nullptr || profile->GetCryptoContext() != cc ||
                distance->GetCryptoContext() != cc || profile->GetKeyTag() != collective_key_tag ||
                distance->GetKeyTag() != collective_key_tag) {
                set_error(err, err_len, "BFV candidate ciphertext context or key tag mismatch");
                return 1;
            }
            auto product = cc->EvalMult(initiator, profile);
            auto folded = fold_dot_to_first_slot(cc, product, profile_dim);
            auto score = broadcast_first_slot_bfv(cc, folded, package_bytes, batch_size);
            if (profile_weight != 1) {
                score = bfv_mul_plain_cached(cc, score, profile_weight, plaintexts);
            }
            if (distance_weight != 0) {
                auto weighted_distance = bfv_mul_plain_cached(cc, distance, distance_weight, plaintexts);
                score = cc->EvalAdd(score, weighted_distance);
            }
            const int64_t brownie_offset = brownie_weight * static_cast<int64_t>(candidate_brownies[i]);
            if (brownie_offset != 0) {
                auto brownie_plaintext = plaintexts.get(brownie_offset);
                score = cc->EvalAdd(score, brownie_plaintext);
            }
            scores.push_back(score);
        }
        initiator = nullptr;

        Ciphertext<DCRTPoly> fused;
        bool have_fused = false;
        for (int i = 0; i < n_candidates; i++) {
            std::vector<Ciphertext<DCRTPoly>> factors;
            factors.reserve(static_cast<size_t>(n_candidates - 1));
            for (int j = 0; j < n_candidates; j++) {
                if (i == j) {
                    continue;
                }
                auto difference = cc->EvalSub(scores[static_cast<size_t>(i)], scores[static_cast<size_t>(j)]);
                factors.push_back(bfv_ps_eval(cc, difference, coefficients, plaintexts));
            }
            auto mask = product_tree(cc, std::move(factors));
            Ciphertext<DCRTPoly> payload;
            deserialize_from_memory(payload, candidate_payload_cts[i], candidate_payload_ct_lens[i]);
            if (payload == nullptr || payload->GetCryptoContext() != cc ||
                payload->GetKeyTag() != collective_key_tag) {
                set_error(err, err_len, "BFV payload ciphertext context or key tag mismatch");
                return 1;
            }
            auto weighted_payload = cc->EvalMult(mask, payload);
            fused = have_fused ? cc->EvalAdd(fused, weighted_payload) : weighted_payload;
            have_fused = true;
        }
        clear_ciphertexts(scores);
        if (!have_fused) {
            set_error(err, err_len, "BFV blind fusion produced no payload");
            return 1;
        }
        return serialize_object(fused, out_ct, out_ct_len);
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown BFV blind fusion failure");
        return 1;
    }
}

// ── Scheme-switching argmin (CKKS→FHEW LUT, depth-independent, single-key only) ──

struct ARESLWESecretKey {
    LWEPrivateKey sk;
};

static ARESLWESecretKey* as_lwe(LWEPrivateKeyHandle handle) {
    return reinterpret_cast<ARESLWESecretKey*>(handle);
}

void FreeLWEPrivateKey(LWEPrivateKeyHandle key) {
    if (key) {
        delete as_lwe(key);
    }
}

int SchemeSwitchingArgmin(
    CryptoContextHandle ctx,
    PublicKeyHandle pk,
    SecretKeyShareHandle sk,
    CiphertextHandle packed_ct,
    uint32_t num_values,
    double scale_sign,
    CiphertextHandle* out_min,
    CiphertextHandle* out_argmin,
    char* err,
    size_t err_len
) {
    (void)err;
    (void)err_len;
    try {
        auto* c = as_ctx(ctx);
        auto* pub = as_pk(pk);
        auto* sec = as_sk(sk);
        auto* in_ct = as_ct(packed_ct);

        if (num_values < 2 || (num_values & (num_values - 1)) != 0) {
            if (err) snprintf(err, err_len, "num_values must be a power of two >= 2, got %u", num_values);
            return 1;
        }
        if (scale_sign <= 0.0) {
            scale_sign = 1.0;
        }

        // Enable scheme switching on this context (not enabled by default)
        c->cc->Enable(SCHEMESWITCH);

        // Build scheme-switching params: exact argmin via FHEW LUT
        SchSwchParams params;
        c->cc->SetParamsFromCKKSCryptocontext(params);
        params.SetSecurityLevelCKKS(HEStd_128_classic);
        params.SetSecurityLevelFHEW(STD128);
        params.SetNumSlotsCKKS(num_values);
        params.SetBatchSize(num_values);
        params.SetNumValues(num_values);
        params.SetComputeArgmin(true);
        params.SetOneHotEncoding(true);
        params.SetUseAltArgmin(false);
        uint32_t pLWE = 4;
        params.SetCtxtModSizeFHEWLargePrec(25);
        params.SetCtxtModSizeFHEWIntermedSwch(27);

        // Setup: creates FHEW context, returns LWE secret key
        auto lwesk = c->cc->EvalSchemeSwitchingSetup(params);

        // Generate switching keys (rotation, conjugation, switching) into the CKKS context
        KeyPair<DCRTPoly> kp;
        kp.publicKey = pub->pk;
        kp.secretKey = sec->sk;
        c->cc->EvalSchemeSwitchingKeyGen(kp, lwesk);

        // Run the exact argmin: returns [min_ciphertext, argmin_ciphertext]
        auto result = c->cc->EvalMinSchemeSwitching(
            in_ct->ct, pub->pk, num_values, num_values, pLWE, scale_sign);

        // EvalMinSchemeSwitching returns [min, argmin]. The argmin is one-hot
        // when oneHotEncoding=true (spanning num_values slots).
        if (result.size() < 2) {
            if (err) snprintf(err, err_len, "EvalMinSchemeSwitching returned %zu results, expected >=2", result.size());
            return 1;
        }

        *out_min = reinterpret_cast<CiphertextHandle>(new ARESCiphertext{result[0]});
        *out_argmin = reinterpret_cast<CiphertextHandle>(new ARESCiphertext{result[1]});
        return 0;
    } catch (const std::exception& ex) {
        if (err) snprintf(err, err_len, "scheme-switching argmin: %s", ex.what());
        return 1;
    } catch (...) {
        if (err) snprintf(err, err_len, "scheme-switching argmin: unknown error");
        return 1;
    }
}

} // extern "C"

// --- Streamed (per-index, memory-bounded) rotation keygen --------------------
// These generate one rotation index at a time, serialise it, and free the C++
// key before generating the next, so peak RAM is bounded to a single rotation
// key (~90 MB at ring 2^16) rather than the full map (~1.5 GB for 17 indices).
// The output is the standard serialised EvalKey map (byte-identical to the
// all-at-once EvalSumKeyGenLead / EvalSumKeyShare), so downstream code is
// unchanged — only peak memory differs.

int StreamedEvalSumKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle* out_base) {
    try {
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string tag = s->sk->GetKeyTag();
        auto idx_set = c->minimal_rotation_keys
            ? minimal_rotation_indices(c->profile_dim, c->payload_slot_count)
            : broadcast_rotation_indices(c->batch_size);
        if (idx_set.empty()) {
            *out_base = reinterpret_cast<RotKeyHandle>(
                new ARESRotKey{std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>()});
            return 0;
        }
        // Generate the first index.
        std::vector<int32_t> first{idx_set[0]};
        c->cc->EvalAtIndexKeyGen(s->sk, first);
        auto accum = clone_key_map(c->cc->GetEvalAutomorphismKeyMap(tag));
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(tag);
        // Generate and merge remaining indices one at a time.
        for (size_t i = 1; i < idx_set.size(); i++) {
            std::vector<int32_t> one{idx_set[i]};
            c->cc->EvalAtIndexKeyGen(s->sk, one);
            auto key_i = clone_key_map(c->cc->GetEvalAutomorphismKeyMap(tag));
            lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(
                tag);
            for (auto& kv : *key_i) {
                (*accum)[kv.first] = kv.second;
            }
        }
        *out_base = reinterpret_cast<RotKeyHandle>(new ARESRotKey{accum});
        return 0;
    } catch (...) { return 1; }
}

int StreamedEvalSumKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk, RotKeyHandle* out_share) {
    try {
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string key_tag = as_pk(own_pk)->pk->GetKeyTag();
        const auto& base_map = as_rot(base)->keys;
        auto idx_set = c->minimal_rotation_keys
            ? minimal_rotation_indices(c->profile_dim, c->payload_slot_count)
            : broadcast_rotation_indices(c->batch_size);
        if (idx_set.empty()) {
            *out_share = reinterpret_cast<RotKeyHandle>(
                new ARESRotKey{std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>()});
            return 0;
        }
        // Generate and merge indices one at a time.
        std::vector<int32_t> first{idx_set[0]};
        auto accum = c->cc->MultiEvalAtIndexKeyGen(s->sk, base_map, first, key_tag);
        for (size_t i = 1; i < idx_set.size(); i++) {
            std::vector<int32_t> one{idx_set[i]};
            auto key_i = c->cc->MultiEvalAtIndexKeyGen(s->sk, base_map, one, key_tag);
            for (auto& kv : *key_i) {
                (*accum)[kv.first] = kv.second;
            }
        }
        *out_share = reinterpret_cast<RotKeyHandle>(new ARESRotKey{accum});
        return 0;
    } catch (...) { return 1; }
}

// --- Per-index (never-merged) rotation key generation ----------------------
// Generate a single-index rotation key, clone it out of the context, and clear
// the context's automorphism map so the next call starts fresh. Peak memory is
// bounded to one key (~90 MB at ring=2^16). The caller loops over the index set
// and sends each key individually — the accumulator never grows on the client.

int GeneratePerIndexEvalSumKey(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    int32_t index, RotKeyHandle* out_key) {
    try {
        if (out_key == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        std::vector<int32_t> one{index};
        // Clear any pre-existing automorphism keys for this key tag FIRST. An earlier
        // EvalKeyRound1Lead leaves the lead's merged EvalSumBase (all fold indices) in the
        // global map under this same key tag; without this clear, GetEvalAutomorphismKeyMap
        // below folds that entire base into the single-index key, so the lead's a-vectors no
        // longer match the parties' single-index a-vectors and the b-only (shared-a)
        // reconstruction silently produces wrong eval-sum keys -> noisy scoring.
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(
            s->sk->GetKeyTag());
        c->cc->EvalAtIndexKeyGen(s->sk, one);
        auto keys = clone_key_map(
            c->cc->GetEvalAutomorphismKeyMap(s->sk->GetKeyTag()));
        lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::ClearEvalAutomorphismKeys(
            s->sk->GetKeyTag());
        *out_key = reinterpret_cast<RotKeyHandle>(new ARESRotKey{keys});
        return 0;
    } catch (...) { return 1; }
}

int GeneratePerIndexEvalSumShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle single_index_base, PublicKeyHandle own_pk,
    int32_t index, RotKeyHandle* out_share) {
    try {
        if (single_index_base == nullptr || own_pk == nullptr || out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string key_tag = as_pk(own_pk)->pk->GetKeyTag();
        std::vector<int32_t> one{index};
        auto share = c->cc->MultiEvalAtIndexKeyGen(
            s->sk, as_rot(single_index_base)->keys, one, key_tag);
        *out_share = reinterpret_cast<RotKeyHandle>(new ARESRotKey{share});
        return 0;
    } catch (...) { return 1; }
}

int GetMinimalRotationIndices(CryptoContextHandle ctx, int32_t* out, int32_t* count) {
    auto* c = as_ctx(ctx);
    auto idx_set = c->minimal_rotation_keys
        ? minimal_rotation_indices(c->profile_dim, c->payload_slot_count)
        : (c->eval_sum_only
            ? eval_sum_only_indices(c->profile_dim)
            : broadcast_rotation_indices(c->batch_size));
    if (out == nullptr) {
        *count = static_cast<int32_t>(idx_set.size());
        return 0;
    }
    int32_t n = std::min(*count, static_cast<int32_t>(idx_set.size()));
    for (int32_t i = 0; i < n; i++) out[i] = idx_set[i];
    *count = static_cast<int32_t>(idx_set.size());
    return 0;
}
