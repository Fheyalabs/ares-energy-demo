// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	openfhe "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
)

type contractParamsJSON struct {
	Scheme         string  `json:"scheme,omitempty"`
	RingDim        uint32  `json:"ring_dim"`
	ScalingFactor  float64 `json:"scaling_factor,omitempty"`
	ScalingModSize int     `json:"scaling_mod_size,omitempty"`
	Depth          uint32  `json:"depth"`
}

type bfvContractParamsJSON struct {
	RingDim             uint32 `json:"ring_dim"`
	MultiplicativeDepth uint32 `json:"multiplicative_depth"`
	PlaintextModulus    uint64 `json:"plaintext_modulus"`
	BatchSize           int    `json:"batch_size,omitempty"`
}

type request struct {
	Op             string                `json:"op"`
	Params         contractParamsJSON    `json:"params"`
	BFVParams      bfvContractParamsJSON `json:"bfv_params,omitempty"`
	PrevPublicKey  string                `json:"prev_public_key,omitempty"`
	JointPublicKey string                `json:"joint_public_key,omitempty"`
	OwnPublicKey   string                `json:"own_public_key,omitempty"`
	FinalPublicKey string                `json:"final_public_key,omitempty"`
	EvalMultBase   string                `json:"eval_mult_base,omitempty"`
	EvalSumBase    string                `json:"eval_sum_base,omitempty"`
	EvalMultJoined string                `json:"eval_mult_joined,omitempty"`
	Values         []float64             `json:"values,omitempty"`
	IntValues      []int64               `json:"int_values,omitempty"`
	Ciphertext     string                `json:"ciphertext,omitempty"`
	SecretKeyShare string                `json:"secret_key_share,omitempty"`
	Lead           bool                  `json:"lead,omitempty"`
	Partials       []string              `json:"partials,omitempty"`
	NSlots         int                   `json:"n_slots,omitempty"`

	// combine_evalkey_round1 / combine_evalkey_round2 inputs.
	PublicKeys           []string `json:"public_keys,omitempty"`
	EvalMultRound1Shares []string `json:"eval_mult_round1_shares,omitempty"`
	EvalSumRound1Shares  []string `json:"eval_sum_round1_shares,omitempty"`
	EvalMultFinalShares  []string `json:"eval_mult_final_shares,omitempty"`
	EvalSumFinalKey      string   `json:"eval_sum_final_key,omitempty"`

	// b-only rotation-key wire: split a full eval-sum share into a/b, and
	// reconstruct the full share from the shared a + a party's b.
	EvalSumShare  string `json:"eval_sum_share,omitempty"`
	EvalSumShareA string `json:"eval_sum_share_a,omitempty"`
	EvalSumShareB string `json:"eval_sum_share_b,omitempty"`

	// Decomposable scoring primitives. See helperclient/scoring_ops.go.
	EvalKeys       string    `json:"eval_keys,omitempty"`
	CiphertextA    string    `json:"ciphertext_a,omitempty"`
	CiphertextB    string    `json:"ciphertext_b,omitempty"`
	Scalar         float64   `json:"scalar,omitempty"`
	Coefficients   []float64 `json:"coefficients,omitempty"`
	PolyLowerBound float64   `json:"poly_lower_bound,omitempty"`
	PolyUpperBound float64   `json:"poly_upper_bound,omitempty"`
	Ciphertexts    []string  `json:"ciphertexts,omitempty"`
}

type response struct {
	PublicKey          string    `json:"public_key,omitempty"`
	SecretKeyShare     string    `json:"secret_key_share,omitempty"`
	Lead               *bool     `json:"lead,omitempty"`
	Ciphertext         string    `json:"ciphertext,omitempty"`
	Partial            string    `json:"partial,omitempty"`
	Values             []float64 `json:"values,omitempty"`
	IntValues          []int64   `json:"int_values,omitempty"`
	EvalMultBase       string    `json:"eval_mult_base,omitempty"`
	EvalSumBase        string    `json:"eval_sum_base,omitempty"`
	EvalMultShare      string    `json:"eval_mult_share,omitempty"`
	EvalSumShare       string    `json:"eval_sum_share,omitempty"`
	EvalSumShareA      string    `json:"eval_sum_share_a,omitempty"`
	EvalSumShareB      string    `json:"eval_sum_share_b,omitempty"`
	EvalMultFinalShare string    `json:"eval_mult_final_share,omitempty"`

	// argmax returns a per-candidate mask ciphertext list.
	Ciphertexts []string `json:"ciphertexts,omitempty"`

	// combine_evalkey_round1 outputs the joined intermediate that
	// every participant signs in round 2, plus the final eval-sum key.
	EvalMultJoined string `json:"eval_mult_joined,omitempty"`
	EvalSumFinal   string `json:"eval_sum_final,omitempty"`

	// combine_evalkey_round2 outputs the joint eval-mult key.
	EvalMultFinal string `json:"eval_mult_final,omitempty"`

	// version returns the linked OpenFHE library version (e.g. "v1.5.1").
	Version string `json:"version,omitempty"`
}

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--daemon":
			fmt.Fprintf(os.Stderr, "openfhe-helper: linked OpenFHE version %s\n", openfhe.OpenFHEVersion())
			runDaemon()
			return
		case "--version", "-v":
			fmt.Println(openfhe.OpenFHEVersion())
			return
		}
	}

	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fail("decode request: %v", err)
	}
	res, err := run(req)
	if err != nil {
		fail("%v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fail("encode response: %v", err)
	}
}

// runDaemon reads newline-delimited JSON requests from stdin and writes
// envelope responses ({"result": ...} | {"error": "..."}) to stdout, one per
// line. Exits cleanly on EOF. Errors from individual ops are sent as
// envelopes; only protocol-level failures (bad JSON, write errors) terminate
// the process. Callers spawn one daemon per worker thread and reuse it across
// session calls to amortize OpenFHE library load and CryptoContext build.
func runDaemon() {
	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fail("decode request: %v", err)
		}
		envelope := struct {
			Result *response `json:"result,omitempty"`
			Error  string    `json:"error,omitempty"`
		}{}
		res, runErr := run(req)
		if runErr != nil {
			envelope.Error = runErr.Error()
		} else {
			envelope.Result = &res
		}
		if err := enc.Encode(envelope); err != nil {
			fail("encode response: %v", err)
		}
	}
}

func run(req request) (response, error) {
	params := req.Params.toContractParams()
	switch req.Op {
	case "version":
		return response{Version: openfhe.OpenFHEVersion()}, nil
	case "keygen_first":
		share, err := openfhe.DistributedKeyGenFirst(params)
		if err != nil {
			return response{}, err
		}
		return keyShareResponse(share), nil
	case "keygen_next":
		prev, err := decodeB64("prev_public_key", req.PrevPublicKey)
		if err != nil {
			return response{}, err
		}
		share, err := openfhe.DistributedKeyGenNext(params, prev)
		if err != nil {
			return response{}, err
		}
		return keyShareResponse(share), nil
	case "bfv_keygen_first":
		share, err := openfhe.BFVDistributedKeyGenFirst(req.BFVParams.toBFVContractParams())
		if err != nil {
			return response{}, err
		}
		return keyShareResponse(share), nil
	case "bfv_keygen_next":
		prev, err := decodeB64("prev_public_key", req.PrevPublicKey)
		if err != nil {
			return response{}, err
		}
		share, err := openfhe.BFVDistributedKeyGenNext(req.BFVParams.toBFVContractParams(), prev)
		if err != nil {
			return response{}, err
		}
		return keyShareResponse(share), nil
	case "encrypt_profile":
		joint, err := decodeB64("joint_public_key", req.JointPublicKey)
		if err != nil {
			return response{}, err
		}
		ct, err := openfhe.EncryptCKKSForContract(params, joint, req.Values)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(ct)}, nil
	case "bfv_encrypt_int_vector":
		joint, err := decodeB64("joint_public_key", req.JointPublicKey)
		if err != nil {
			return response{}, err
		}
		ct, err := openfhe.EncryptBFVForContract(req.BFVParams.toBFVContractParams(), joint, req.IntValues)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(ct)}, nil
	case "evalkey_round1_lead":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		round1, err := openfhe.EvalKeyRound1Lead(params, sk)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultBase: encodeB64(round1.EvalMultBase),
			EvalSumBase:  encodeB64(round1.EvalSumBase),
		}, nil
	case "bfv_evalkey_round1_lead":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		round1, err := openfhe.BFVEvalKeyRound1Lead(req.BFVParams.toBFVContractParams(), sk)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultBase: encodeB64(round1.EvalMultBase),
			EvalSumBase:  encodeB64(round1.EvalSumBase),
		}, nil
	case "evalkey_round1_participant":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		multBase, err := decodeB64("eval_mult_base", req.EvalMultBase)
		if err != nil {
			return response{}, err
		}
		sumBase, err := decodeB64("eval_sum_base", req.EvalSumBase)
		if err != nil {
			return response{}, err
		}
		ownPK, err := decodeB64("own_public_key", req.OwnPublicKey)
		if err != nil {
			return response{}, err
		}
		round1, err := openfhe.EvalKeyRound1Participant(params, sk, multBase, sumBase, ownPK)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultShare: encodeB64(round1.EvalMultSwitchShare),
			EvalSumShare:  encodeB64(round1.EvalSumShare),
		}, nil
	case "bfv_evalkey_round1_participant":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		multBase, err := decodeB64("eval_mult_base", req.EvalMultBase)
		if err != nil {
			return response{}, err
		}
		sumBase, err := decodeB64("eval_sum_base", req.EvalSumBase)
		if err != nil {
			return response{}, err
		}
		ownPK, err := decodeB64("own_public_key", req.OwnPublicKey)
		if err != nil {
			return response{}, err
		}
		round1, err := openfhe.BFVEvalKeyRound1Participant(req.BFVParams.toBFVContractParams(), sk, multBase, sumBase, ownPK)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultShare: encodeB64(round1.EvalMultSwitchShare),
			EvalSumShare:  encodeB64(round1.EvalSumShare),
		}, nil
	case "evalkey_round2_participant":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		joined, err := decodeB64("eval_mult_joined", req.EvalMultJoined)
		if err != nil {
			return response{}, err
		}
		finalPK, err := decodeB64("final_public_key", req.FinalPublicKey)
		if err != nil {
			return response{}, err
		}
		round2, err := openfhe.EvalKeyRound2Participant(params, sk, joined, finalPK, req.Lead)
		if err != nil {
			return response{}, err
		}
		return response{EvalMultFinalShare: encodeB64(round2.EvalMultFinalShare)}, nil
	case "bfv_evalkey_round2_participant":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		joined, err := decodeB64("eval_mult_joined", req.EvalMultJoined)
		if err != nil {
			return response{}, err
		}
		finalPK, err := decodeB64("final_public_key", req.FinalPublicKey)
		if err != nil {
			return response{}, err
		}
		round2, err := openfhe.BFVEvalKeyRound2Participant(req.BFVParams.toBFVContractParams(), sk, joined, finalPK, req.Lead)
		if err != nil {
			return response{}, err
		}
		return response{EvalMultFinalShare: encodeB64(round2.EvalMultFinalShare)}, nil
	case "partial_decrypt":
		ct, err := decodeB64("ciphertext", req.Ciphertext)
		if err != nil {
			return response{}, err
		}
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		partial, err := openfhe.PartialDecryptCKKSForContract(params, ct, sk, req.Lead)
		if err != nil {
			return response{}, err
		}
		return response{Partial: encodeB64(partial)}, nil
	case "bfv_partial_decrypt":
		ct, err := decodeB64("ciphertext", req.Ciphertext)
		if err != nil {
			return response{}, err
		}
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		partial, err := openfhe.PartialDecryptBFVForContract(req.BFVParams.toBFVContractParams(), ct, sk, req.Lead)
		if err != nil {
			return response{}, err
		}
		return response{Partial: encodeB64(partial)}, nil
	case "combine_evalkey_round1":
		pks, err := decodeB64Slice("public_keys", req.PublicKeys)
		if err != nil {
			return response{}, err
		}
		multShares, err := decodeB64Slice("eval_mult_round1_shares", req.EvalMultRound1Shares)
		if err != nil {
			return response{}, err
		}
		sumShares, err := decodeB64Slice("eval_sum_round1_shares", req.EvalSumRound1Shares)
		if err != nil {
			return response{}, err
		}
		combined, err := openfhe.CombineEvalKeyRound1(params, pks, multShares, sumShares)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultJoined: encodeB64(combined.EvalMultJoined),
			EvalSumFinal:   encodeB64(combined.EvalSumFinal),
		}, nil
	case "bfv_combine_evalkey_round1":
		pks, err := decodeB64Slice("public_keys", req.PublicKeys)
		if err != nil {
			return response{}, err
		}
		multShares, err := decodeB64Slice("eval_mult_round1_shares", req.EvalMultRound1Shares)
		if err != nil {
			return response{}, err
		}
		sumShares, err := decodeB64Slice("eval_sum_round1_shares", req.EvalSumRound1Shares)
		if err != nil {
			return response{}, err
		}
		combined, err := openfhe.BFVCombineEvalKeyRound1(req.BFVParams.toBFVContractParams(), pks, multShares, sumShares)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultJoined: encodeB64(combined.EvalMultJoined),
			EvalSumFinal:   encodeB64(combined.EvalSumFinal),
		}, nil
	case "combine_evalkey_round2":
		finalPK, err := decodeB64("final_public_key", req.FinalPublicKey)
		if err != nil {
			return response{}, err
		}
		finalShares, err := decodeB64Slice("eval_mult_final_shares", req.EvalMultFinalShares)
		if err != nil {
			return response{}, err
		}
		sumFinal, err := decodeB64("eval_sum_final_key", req.EvalSumFinalKey)
		if err != nil {
			return response{}, err
		}
		final, err := openfhe.CombineEvalKeyRound2(params, finalPK, finalShares, sumFinal)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultFinal: encodeB64(final.EvalMultFinal),
			EvalSumFinal:  encodeB64(final.EvalSumFinal),
		}, nil
	case "bfv_combine_evalkey_round2":
		finalPK, err := decodeB64("final_public_key", req.FinalPublicKey)
		if err != nil {
			return response{}, err
		}
		finalShares, err := decodeB64Slice("eval_mult_final_shares", req.EvalMultFinalShares)
		if err != nil {
			return response{}, err
		}
		sumFinal, err := decodeB64("eval_sum_final_key", req.EvalSumFinalKey)
		if err != nil {
			return response{}, err
		}
		final, err := openfhe.BFVCombineEvalKeyRound2(req.BFVParams.toBFVContractParams(), finalPK, finalShares, sumFinal)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultFinal: encodeB64(final.EvalMultFinal),
			EvalSumFinal:  encodeB64(final.EvalSumFinal),
		}, nil
	case "split_rot_share":
		full, err := decodeB64("eval_sum_share", req.EvalSumShare)
		if err != nil {
			return response{}, err
		}
		a, b, err := openfhe.SplitRotShareAB(params, full)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalSumShareA: encodeB64(a),
			EvalSumShareB: encodeB64(b),
		}, nil
	case "reconstruct_rot_share":
		a, err := decodeB64("eval_sum_share_a", req.EvalSumShareA)
		if err != nil {
			return response{}, err
		}
		b, err := decodeB64("eval_sum_share_b", req.EvalSumShareB)
		if err != nil {
			return response{}, err
		}
		full, err := openfhe.ReconstructRotShareAB(params, a, b)
		if err != nil {
			return response{}, err
		}
		return response{EvalSumShare: encodeB64(full)}, nil
	case "fuse_partials":
		partials := make([][]byte, 0, len(req.Partials))
		for i, raw := range req.Partials {
			partial, err := decodeB64(fmt.Sprintf("partials[%d]", i), raw)
			if err != nil {
				return response{}, err
			}
			partials = append(partials, partial)
		}
		values, err := openfhe.FuseCKKSPartialsForContract(params, partials, req.NSlots)
		if err != nil {
			return response{}, err
		}
		return response{Values: values}, nil
	case "bfv_fuse_partials_int":
		partials := make([][]byte, 0, len(req.Partials))
		for i, raw := range req.Partials {
			partial, err := decodeB64(fmt.Sprintf("partials[%d]", i), raw)
			if err != nil {
				return response{}, err
			}
			partials = append(partials, partial)
		}
		values, err := openfhe.FuseBFVPartialsForContract(req.BFVParams.toBFVContractParams(), partials, req.NSlots)
		if err != nil {
			return response{}, err
		}
		return response{IntValues: values}, nil
	case "bfv_eval_product_sum":
		evalMult, err := decodeB64("eval_keys", req.EvalKeys)
		if err != nil {
			return response{}, err
		}
		evalSum, err := decodeB64("eval_sum_final_key", req.EvalSumFinalKey)
		if err != nil {
			return response{}, err
		}
		ctA, err := decodeB64("ciphertext_a", req.CiphertextA)
		if err != nil {
			return response{}, err
		}
		ctB, err := decodeB64("ciphertext_b", req.CiphertextB)
		if err != nil {
			return response{}, err
		}
		out, err := openfhe.EvalProductSumBFVForContract(req.BFVParams.toBFVContractParams(), openfhe.EvalKeyFinal{
			EvalMultFinal: evalMult,
			EvalSumFinal:  evalSum,
		}, ctA, ctB, req.NSlots)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(out)}, nil
	case "eval_poly":
		evalKeys, err := decodeB64("eval_keys", req.EvalKeys)
		if err != nil {
			return response{}, err
		}
		ct, err := decodeB64("ciphertext", req.Ciphertext)
		if err != nil {
			return response{}, err
		}
		if len(req.Coefficients) == 0 {
			return response{}, errors.New("eval_poly requires coefficients")
		}
		result, err := openfhe.EvalPolyCKKSForContract(params, evalKeys, ct, req.Coefficients)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(result)}, nil
	case "eval_add":
		return runEvalBinary(req, params, openfhe.EvalAddCKKSForContract)
	case "eval_sub":
		return runEvalBinary(req, params, openfhe.EvalSubCKKSForContract)
	case "eval_mult":
		ctA, err := decodeB64("ciphertext_a", req.CiphertextA)
		if err != nil {
			return response{}, err
		}
		ctB, err := decodeB64("ciphertext_b", req.CiphertextB)
		if err != nil {
			return response{}, err
		}
		evalKey, err := decodeB64("eval_keys", req.EvalKeys)
		if err != nil {
			return response{}, err
		}
		out, err := openfhe.EvalMultCKKSForContract(params, evalKey, ctA, ctB)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(out)}, nil
	case "eval_const_mult":
		ct, err := decodeB64("ciphertext", req.Ciphertext)
		if err != nil {
			return response{}, err
		}
		out, err := openfhe.EvalConstMultCKKSForContract(params, ct, req.Scalar)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(out)}, nil
	case "argmax":
		evalKey, err := decodeB64("eval_keys", req.EvalKeys)
		if err != nil {
			return response{}, err
		}
		if len(req.Ciphertexts) < 2 {
			return response{}, errors.New("argmax requires at least 2 ciphertexts")
		}
		cts := make([][]byte, len(req.Ciphertexts))
		for i, raw := range req.Ciphertexts {
			ct, err := decodeB64(fmt.Sprintf("ciphertexts[%d]", i), raw)
			if err != nil {
				return response{}, err
			}
			cts[i] = ct
		}
		if len(req.Coefficients) < 2 {
			return response{}, errors.New("argmax requires sharpening coefficients (>= 2)")
		}
		masks, err := openfhe.EvalArgmaxCKKSForContract(params, evalKey, cts, req.Coefficients)
		if err != nil {
			return response{}, err
		}
		out := make([]string, len(masks))
		for i, m := range masks {
			out[i] = encodeB64(m)
		}
		return response{Ciphertexts: out}, nil
	default:
		return response{}, fmt.Errorf("unsupported op %q", req.Op)
	}
}

// runEvalBinary handles eval_add and eval_sub: both take two
// ciphertexts and no eval-mult key.
func runEvalBinary(
	req request,
	params openfhe.ContractParams,
	fn func(openfhe.ContractParams, []byte, []byte) ([]byte, error),
) (response, error) {
	ctA, err := decodeB64("ciphertext_a", req.CiphertextA)
	if err != nil {
		return response{}, err
	}
	ctB, err := decodeB64("ciphertext_b", req.CiphertextB)
	if err != nil {
		return response{}, err
	}
	out, err := fn(params, ctA, ctB)
	if err != nil {
		return response{}, err
	}
	return response{Ciphertext: encodeB64(out)}, nil
}

func (p contractParamsJSON) toContractParams() openfhe.ContractParams {
	scalingFactor := p.ScalingFactor
	if scalingFactor == 0 && p.ScalingModSize > 0 {
		scalingFactor = math.Ldexp(1, p.ScalingModSize)
	}
	return openfhe.ContractParams{
		RingDim:       p.RingDim,
		ScalingFactor: scalingFactor,
		Depth:         p.Depth,
	}
}

func (p bfvContractParamsJSON) toBFVContractParams() openfhe.BFVContractParams {
	return openfhe.BFVContractParams{
		RingDim:             p.RingDim,
		MultiplicativeDepth: p.MultiplicativeDepth,
		PlaintextModulus:    p.PlaintextModulus,
		BatchSize:           p.BatchSize,
	}
}

func keyShareResponse(share openfhe.DistributedKeyShare) response {
	lead := share.Lead
	return response{
		PublicKey:      encodeB64(share.PublicKey),
		SecretKeyShare: encodeB64(share.SecretKeyShare),
		Lead:           &lead,
	}
}

func decodeB64Slice(field string, values []string) ([][]byte, error) {
	out := make([][]byte, len(values))
	for i, v := range values {
		raw, err := decodeB64(fmt.Sprintf("%s[%d]", field, i), v)
		if err != nil {
			return nil, err
		}
		out[i] = raw
	}
	return out, nil
}

func decodeB64(field, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64: %w", field, err)
	}
	return out, nil
}

func encodeB64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
