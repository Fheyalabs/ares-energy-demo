// SPDX-License-Identifier: Apache-2.0

#ifndef OPENFHE_WRAPPER_H
#define OPENFHE_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Opaque handle types
typedef void* CryptoContextHandle;
typedef void* PublicKeyHandle;
typedef void* SecretKeyShareHandle;
typedef void* EvalMultKeyHandle;
typedef void* RotKeyHandle;
typedef void* CiphertextHandle;
typedef void* PlaintextHandle;

// Context lifecycle
CryptoContextHandle CreateCKKSContext(
    uint32_t ring_dim,     // 32768
    double scaling_factor, // 2^52
    uint32_t depth,        // 12
    uint32_t batch_size    // 0 = ring_dim/2 (default), >0 = explicit batch
);
// CreateCKKSContextWithModuli is the explicit-parameter variant used when a
// signed contract carries both CKKS modulus sizes. It avoids deriving the
// first modulus from a legacy default.
CryptoContextHandle CreateCKKSContextWithModuli(
    uint32_t ring_dim,
    uint32_t multiplicative_depth,
    uint32_t scaling_mod_size,
    uint32_t first_mod_size,
    uint32_t batch_size
);
CryptoContextHandle CreateBFVContext(
    uint32_t ring_dim,
    uint32_t multiplicative_depth,
    uint64_t plaintext_modulus,
    uint32_t batch_size
);
void FreeCryptoContext(CryptoContextHandle ctx);
int OpenFHEContextCount(void);
void ReleaseAllOpenFHEContexts(void);
// SetMinimalRotationKeys opts a context into dimension-parameterized rotation-key
// generation: EvalSumKeyGenLead/Share emit only the at-index keys a profile_dim
// dot-product fold + a payload_slot_count broadcast need, instead of the full ring/2
// batch. Default (unset) keeps full-batch EvalSum + broadcast keygen.
void SetMinimalRotationKeys(CryptoContextHandle ctx, int profile_dim, int payload_slot_count);

// SetEvalSumOnlyRotationKeys opts a context into the chunked-fusion rotation set:
// the threshold eval-sum keygen produces ONLY the replicating EvalSumKeyGen map
// (batch_size = next_pow2(profile_dim) keys) and no broadcast at-index keys. Use with
// ARESChunkedFusePayloadCKKS, which folds via EvalSum (replicate), not broadcast.
void SetEvalSumOnlyRotationKeys(CryptoContextHandle ctx, int profile_dim);

// Threshold keygen (N-party)
int KeyGenFirst(CryptoContextHandle ctx,
    PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk);
int KeyGenNext(CryptoContextHandle ctx, PublicKeyHandle prev_pk,
    PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk);

// Combine all public keys into joint key
int MultiAddPublicKeys(CryptoContextHandle ctx,
    PublicKeyHandle* pks, int n_keys,
    PublicKeyHandle* out_joint);

// Eval key generation (each party contributes)
int GenEvalMultKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle* out_share);
int GenRotKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle* out_share);

int SingleKeyEvalMultKeyGen(CryptoContextHandle ctx, SecretKeyShareHandle sk);
// SingleKeyEvalMultKeyGenWithOutput generates the single-key relinearization
// key and returns it for serialization and transfer to a fresh evaluator
// context.
int SingleKeyEvalMultKeyGenWithOutput(CryptoContextHandle ctx,
    SecretKeyShareHandle sk, EvalMultKeyHandle* out_key);

int EvalMultKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle* out_base);
int EvalMultKeySwitchShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle base, EvalMultKeyHandle* out_share);
int CombineEvalMultSwitchShares(CryptoContextHandle ctx,
    PublicKeyHandle* pks, EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_joined);
int EvalMultKeyFinalShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle joined, PublicKeyHandle final_pk,
    EvalMultKeyHandle* out_share);
int CombineEvalMultFinalShares(CryptoContextHandle ctx, PublicKeyHandle final_pk,
    EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_final);
int InsertEvalMultKey(CryptoContextHandle ctx, EvalMultKeyHandle key);

int EvalSumKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle* out_base);
int EvalSumKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk,
    RotKeyHandle* out_share);
// Streamed (per-index) rotation-key generation: produces the same output as
// EvalSumKeyGenLead / EvalSumKeyShare but generates one index at a time,
// merging into an accumulator, so peak C++ memory is bounded to a single
// rotation key (~90 MB at ring 2^16) instead of the full map (~1.5 GB for
// 17 minimal indices).
int StreamedEvalSumKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle* out_base);
int StreamedEvalSumKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk,
    RotKeyHandle* out_share);
// Per-index (never-merged) keygen for client-side memory bounding.
// Per-index (never-merged) rotation key generation. Generate one index at a
// time, serialise it, and free before the next — peak memory is one key
// (~90 MB at ring=2^16). The client calls this in a loop and sends each key
// individually; it never holds a merged accumulator.
int GeneratePerIndexEvalSumKey(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    int32_t index, RotKeyHandle* out_key);
int GeneratePerIndexEvalSumShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle single_index_base, PublicKeyHandle own_pk,
    int32_t index, RotKeyHandle* out_share);

// GetMinimalRotationIndices writes the context's minimal rotation index set
// into out (up to *count entries) and sets *count to the total.
// Pass out=NULL to query the count only.
int GetMinimalRotationIndices(CryptoContextHandle ctx, int32_t* out, int32_t* count);

int StreamedRotShareBytes(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk, unsigned long long* out_total_bytes);
// Fully-streamed 2-party rotation keygen: lead base + participant share per index,
// peak bounded to a single rotation index across both parties.
int StreamedTwoPartyRotKeygenBytes(CryptoContextHandle ctx,
    SecretKeyShareHandle sk_lead, SecretKeyShareHandle sk_part, PublicKeyHandle pk_part,
    unsigned long long* out_total_bytes);
// Tests whether 'a' is shared across parties and measures full-key vs b-only
// serialized size, for the CRS wire optimization (transmit only b, rebuild a).
int MeasureBOnlyRotShare(CryptoContextHandle ctx,
    SecretKeyShareHandle sk_lead, SecretKeyShareHandle sk_part, PublicKeyHandle pk_part,
    unsigned long long* out_full_bytes, unsigned long long* out_b_only_bytes, int* out_a_shared);
// Production b-only rotation-key wire (the CRS optimization). The rotation-key
// 'a'-vectors are byte-identical across parties (shared CRS), so a party transmits
// only its 'b'-vectors and the combiner rebuilds the full share from the shared
// 'a' + the party 'b'. No new crypto. out_data is malloc'd; free it in Go.
int SerializeRotKeyBVectors(RotKeyHandle share, uint8_t** out_data, size_t* out_len);
int SerializeRotKeyAVectors(RotKeyHandle share, uint8_t** out_data, size_t* out_len);
RotKeyHandle ReconstructRotKeyFromAB(CryptoContextHandle ctx,
    const uint8_t* a_data, size_t a_len, const uint8_t* b_data, size_t b_len);

// Pre-deserialized A-vectors: the a-vectors are byte-identical across parties,
// so deserialize them ONCE per index and reuse for all N parties. This avoids
// ~85 redundant 45 MB C++ deserializations during a 6-party × 17-index combine.
typedef struct ARESAVectors ARESAVectors;
typedef ARESAVectors* AVectorsHandle;
AVectorsHandle DeserializeAVectors(const uint8_t* a_data, size_t a_len);
void FreeAVectors(AVectorsHandle h);
RotKeyHandle ReconstructRotKeyFromAVectors(CryptoContextHandle ctx,
    AVectorsHandle a, const uint8_t* b_data, size_t b_len);
int CombineEvalSumKeys(CryptoContextHandle ctx,
    PublicKeyHandle* pks, RotKeyHandle* shares, int n_shares,
    RotKeyHandle* out_final);
// Incremental eval-sum combine: fold shares one at a time (peak RAM = accumulator
// + one share, vs all N for CombineEvalSumKeys). Seed with the lead base, then fold
// each participant share; the result matches CombineEvalSumKeys.
RotKeyHandle EvalSumCombineStart(RotKeyHandle seed);
int EvalSumCombineFold(CryptoContextHandle ctx, RotKeyHandle accum, PublicKeyHandle pk, RotKeyHandle share);
int MergeEvalSumKeyMaps(RotKeyHandle accum, RotKeyHandle next);
int InsertEvalSumKey(CryptoContextHandle ctx, RotKeyHandle key);
int ClearEvalSumKeysForContext(CryptoContextHandle ctx);
int InsertEvalSumKeyAppend(CryptoContextHandle ctx, RotKeyHandle key);

// Encrypt/Decrypt
CiphertextHandle Encrypt(CryptoContextHandle ctx, PublicKeyHandle pk,
    double* values, int n_values);
CiphertextHandle EncryptPackedInt(CryptoContextHandle ctx, PublicKeyHandle pk,
    int64_t* values, int n_values);
int DecryptSingle(CryptoContextHandle ctx, CiphertextHandle ct,
    SecretKeyShareHandle sk, double* out_values, int* out_n_values);
int MultiDecMain(CryptoContextHandle ctx, CiphertextHandle ct,
    SecretKeyShareHandle sk, CiphertextHandle* out_partial);
int MultiDecFusion(CryptoContextHandle ctx,
    CiphertextHandle* partials, int n_partials,
    double* out_values, int* out_n_values);
int MultiDecFusionPackedInt(CryptoContextHandle ctx,
    CiphertextHandle* partials, int n_partials,
    int64_t* out_values, int* out_n_values);

// Homomorphic operations
CiphertextHandle EvalAdd(CryptoContextHandle ctx,
    CiphertextHandle a, CiphertextHandle b);
CiphertextHandle EvalMult(CryptoContextHandle ctx,
    CiphertextHandle a, CiphertextHandle b);
CiphertextHandle EvalSum(CryptoContextHandle ctx,
    CiphertextHandle ct, int batch_size);
CiphertextHandle EvalMultConst(CryptoContextHandle ctx,
    CiphertextHandle ct, double scalar);
CiphertextHandle EvalSub(CryptoContextHandle ctx,
    CiphertextHandle a, CiphertextHandle b);

// Chebyshev sign approximation for argmax
CiphertextHandle EvalChebyshevSign(CryptoContextHandle ctx,
    CiphertextHandle ct, int degree);

// Polynomial evaluation: applies p(x) = sum(coeffs[i] * x^i) slot-wise.
// coeffs is in ascending order (coeffs[0] is the constant term). The
// CryptoContext must have an eval-mult key registered for any
// polynomial with degree >= 2. Returns nullptr on failure.
CiphertextHandle EvalPolynomial(CryptoContextHandle ctx,
    CiphertextHandle ct, double* coeffs, int n_coeffs);

// EvalArgmax: composite argmax over N candidate ciphertexts using a
// caller-supplied sharpening polynomial.
//
// For each i ∈ [0, n_cts): mask[i] = ∏_{j != i} p(cts[i] - cts[j]),
// where p is the polynomial whose coefficients are passed in. The
// polynomial is expected to approximate a step function on
// [-1, 1] — positive inputs → ~1, negative → ~0. For inputs whose
// pairwise differences fall outside [-1, 1] the caller must scale
// them down before calling.
//
// On success returns 0 and writes n_cts new ciphertext handles to
// out_masks (caller frees with FreeCiphertext). On failure returns
// non-zero and out_masks is untouched.
int EvalArgmax(CryptoContextHandle ctx,
    const CiphertextHandle* cts, int n_cts,
    const double* sharp_coeffs, int n_sharp_coeffs,
    CiphertextHandle* out_masks);

// GetOpenFHEVersion writes the linked OpenFHE library version (e.g.
// "v1.5.1") into out_buf. Returns the number of bytes written, or 0
// on failure. out_buf must be at least 32 bytes.
int GetOpenFHEVersion(char* out_buf, int out_cap);

// DeserializeCiphertextErrCtxMismatch is returned via stderr log + a
// nullptr return when the deserialized ciphertext's embedded
// CryptoContext does not match the local ctx. Common cause: OpenFHE
// version skew between the process that serialized and the one
// deserializing.
#define ARES_ERR_CTX_MISMATCH (-200)

// Serialization
// Encrypt one fixed-size, MSB-first bit chunk of a serialized payload and return
// its ciphertext serialization. chunk_size must equal the context batch size;
// bit_offset and chunk_size are measured in bits. The caller frees out_data with
// free(3). This keeps payload bit packing in the native bridge so clients cannot
// diverge on byte ordering.
int EncryptSerializedPayloadChunk(CryptoContextHandle ctx, PublicKeyHandle pk,
    const uint8_t* payload, size_t payload_len,
    size_t bit_offset, size_t chunk_size,
    uint8_t** out_data, size_t* out_len);
// Encrypt one scalar repeated across the context batch and return its serialized
// CKKS ciphertext. The caller frees out_data with free(3).
int EncryptSerializedRepeatedScalarCKKS(CryptoContextHandle ctx, PublicKeyHandle pk,
    double value, uint8_t** out_data, size_t* out_len);
// Derive Enc((origin_first-local_first)^2 + (origin_second-local_second)^2)
// from two serialized repeated-scalar ciphertexts. The context must already
// contain the matching eval-mult key. The caller frees out_data with free(3).
int ComputeSerializedSquaredDistanceCKKS(CryptoContextHandle ctx,
    const uint8_t* origin_first, size_t origin_first_len,
    const uint8_t* origin_second, size_t origin_second_len,
    double local_first, double local_second,
    uint8_t** out_data, size_t* out_len);
// BFV counterparts use exact packed integers. The context must already contain
// the matching eval-mult key. The caller frees out_data with free(3).
int EncryptSerializedRepeatedScalarBFV(CryptoContextHandle ctx, PublicKeyHandle pk,
    int64_t value, uint8_t** out_data, size_t* out_len);
int ComputeSerializedSquaredDistanceBFV(CryptoContextHandle ctx,
    const uint8_t* origin_first, size_t origin_first_len,
    const uint8_t* origin_second, size_t origin_second_len,
    int64_t local_first, int64_t local_second,
    uint8_t** out_data, size_t* out_len);
int SerializeCiphertext(CiphertextHandle ct, uint8_t** out_data, size_t* out_len);
CiphertextHandle DeserializeCiphertext(CryptoContextHandle ctx,
    uint8_t* data, size_t len);
int SerializePublicKey(PublicKeyHandle pk, uint8_t** out_data, size_t* out_len);
PublicKeyHandle DeserializePublicKey(CryptoContextHandle ctx,
    uint8_t* data, size_t len);
int SerializeSecretKeyShare(SecretKeyShareHandle sk, uint8_t** out_data, size_t* out_len);
SecretKeyShareHandle DeserializeSecretKeyShare(CryptoContextHandle ctx,
    uint8_t* data, size_t len, int lead);
int SerializeEvalMultKey(EvalMultKeyHandle key, uint8_t** out_data, size_t* out_len);
EvalMultKeyHandle DeserializeEvalMultKey(CryptoContextHandle ctx,
    uint8_t* data, size_t len);
int SerializeRotKey(RotKeyHandle key, uint8_t** out_data, size_t* out_len);
RotKeyHandle DeserializeRotKey(CryptoContextHandle ctx,
    uint8_t* data, size_t len);

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
);

// ARESChunkedFusePayloadCKKS: server-blind fusion with crypto-lab CHUNKED payload
// recovery (the low-RSS default). EvalSum-replicates the mask across the profile_dim
// batch (fold keys only, no broadcast set) and splits the payload into
// ceil(payload_slot_count/batch_size) chunks. The n_chunks result ciphertexts are
// serialized and concatenated into *out_cts (length *out_cts_len); out_chunk_lens
// (caller-allocated, capacity >= max chunks) receives each chunk's serialized length;
// *out_n_chunks is the chunk count. Each chunk holds the winner's chunk_size payload
// bits in slots [0, chunk_size); the caller threshold-decrypts each and reassembles.
int ARESChunkedFusePayloadCKKS(
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
    uint8_t** out_cts,
    size_t* out_cts_len,
    size_t* out_chunk_lens,
    int* out_n_chunks,
    char* err,
    size_t err_len
);

// ARESChunkedFuseEncryptedPayloadCKKS is the ciphertext-only counterpart of
// ARESChunkedFusePayloadCKKS. candidate_payload_ct_blob contains exactly
// n_candidates * ceil(payload_slot_count / next_pow2(profile_dim)) serialized
// CKKS ciphertexts in candidate-major, then chunk-major order. The lens array
// has one entry per ciphertext. The scorer never receives source package bytes.
int ARESChunkedFuseEncryptedPayloadCKKS(
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
);

// ARESChunkedFuseEncryptedInputsCKKS accepts ciphertext-only candidate inputs:
// encrypted profile vectors, one encrypted squared distance per candidate, and
// encrypted payload chunks. It deliberately has no coordinate-array arguments.
int ARESChunkedFuseEncryptedInputsCKKS(
    CryptoContextHandle ctx_handle,
    uint32_t ring_dim,
    double scaling_factor,
    uint32_t depth,
    const uint8_t* initiator_ct,
    size_t initiator_ct_len,
    const uint8_t* candidate_ct_blob,
    const size_t* candidate_ct_lens,
    const int* candidate_brownies,
    int n_candidates,
    int profile_dim,
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
    const uint8_t* candidate_distance_ct_blob,
    size_t candidate_distance_ct_blob_len,
    const size_t* candidate_distance_ct_lens,
    int candidate_distance_ct_count,
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
);

// ARESBlindFusePayloadBFV evaluates the full BFV score from encrypted profile
// vectors and client-derived encrypted distances, applies the supplied exact
// step polynomial, and returns only a fused encrypted payload. It never
// decrypts candidate scores or accepts source coordinates.
int ARESBlindFusePayloadBFV(
    uint32_t ring_dim,
    uint32_t multiplicative_depth,
    uint64_t plaintext_modulus,
    uint32_t batch_size,
    const uint8_t* eval_mult_key,
    size_t eval_mult_key_len,
    const uint8_t* eval_sum_key,
    size_t eval_sum_key_len,
    const uint8_t* initiator_ct,
    size_t initiator_ct_len,
    const uint8_t* const* candidate_profile_cts,
    const size_t* candidate_profile_ct_lens,
    const uint8_t* const* candidate_distance_cts,
    const size_t* candidate_distance_ct_lens,
    const uint8_t* const* candidate_payload_cts,
    const size_t* candidate_payload_ct_lens,
    const int* candidate_brownies,
    int n_candidates,
    int profile_dim,
    int64_t profile_weight,
    int64_t distance_weight,
    int64_t brownie_weight,
    int package_bytes,
    const int64_t* step_coeffs,
    int n_step_coeffs,
    uint8_t** out_ct,
    size_t* out_ct_len,
    char* err,
    size_t err_len
);

typedef void* LWEPrivateKeyHandle;

// Scheme-switching argmin (CKKS→FHEW LUT, depth-independent, single-key only).
// Packs num_values keys into slots 0..num_values-1 of a single ciphertext,
// runs EvalMinSchemeSwitching (FHEW-based exact argmin), and returns
// [out_min, out_argmin] as two CKKS ciphertexts. out_argmin is one-hot over
// num_values slots. scale_sign is the scaling factor applied before switching
// to FHEW (default 1.0 if ≤ 0). num_values must be a power of two.
//
// On success returns 0. On failure returns non-zero and writes to err.
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
);

void FreeLWEPrivateKey(LWEPrivateKeyHandle key);

// Memory management
void FreePublicKey(PublicKeyHandle pk);
void FreeSecretKeyShare(SecretKeyShareHandle sk);
void FreeCiphertext(CiphertextHandle ct);
void FreeEvalMultKey(EvalMultKeyHandle key);
void FreeRotKey(RotKeyHandle key);

int ARESOpenFHESmoke(char* err, size_t err_len);

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
);

#ifdef __cplusplus
}
#endif

#endif // OPENFHE_WRAPPER_H
