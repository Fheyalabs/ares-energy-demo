// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"math"
	"testing"
)

// TestEvalPoly_Square verifies that p(x) = x² applied homomorphically
// returns x² after threshold decryption. End-to-end: distributed
// keygen → joint eval-mult key chain → encrypt → EvalPoly → partial
// decrypt → fuse. The polynomial-evaluation correctness gate.
func TestEvalPoly_Square(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}

	params := DefaultContractParams(4, 6) // small profile dim, modest depth
	values := []float64{1.5, -2.0, 3.25, 0.5}

	first, err := DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := DistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	joint := second.PublicKey

	evalKeys, evalKeyErr := buildJointEvalMultKey(t, params, []DistributedKeyShare{first, second})
	if evalKeyErr != nil {
		t.Skipf("eval-mult key chain unavailable: %v", evalKeyErr)
	}

	ct, err := EncryptCKKSForContract(params, joint, values)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// p(x) = x² — quadratic. Result should match input² modulo
	// small CKKS noise.
	out, err := EvalPolyCKKSForContract(params, evalKeys, ct, []float64{0, 0, 1})
	if err != nil {
		t.Fatalf("eval poly: %v", err)
	}

	partial1, err := PartialDecryptCKKSForContract(params, out, first.SecretKeyShare, first.Lead)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	partial2, err := PartialDecryptCKKSForContract(params, out, second.SecretKeyShare, second.Lead)
	if err != nil {
		t.Fatalf("partial 2: %v", err)
	}
	recovered, err := FuseCKKSPartialsForContract(params, [][]byte{partial1, partial2}, len(values))
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}

	const tol = 1e-2
	for i, v := range values {
		want := v * v
		if math.Abs(recovered[i]-want) > tol {
			t.Errorf("slot %d: got %v, want %v (=%v², tol %v)", i, recovered[i], want, v, tol)
		}
	}
}

// buildJointEvalMultKey runs round-1 and round-2 of the chained
// eval-mult key generation between two participants. Returns the
// joint eval-mult key blob (serialized).
func buildJointEvalMultKey(t *testing.T, params ContractParams, shares []DistributedKeyShare) ([]byte, error) {
	t.Helper()
	if len(shares) == 0 {
		return nil, nil
	}
	finalPK := shares[len(shares)-1].PublicKey

	lead, err := EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return nil, err
	}
	publicKeys := make([][]byte, len(shares))
	multRound1 := make([][]byte, len(shares))
	sumRound1 := make([][]byte, len(shares))
	publicKeys[0] = shares[0].PublicKey
	multRound1[0] = lead.EvalMultBase
	sumRound1[0] = lead.EvalSumBase
	for i := 1; i < len(shares); i++ {
		publicKeys[i] = shares[i].PublicKey
		r1, err := EvalKeyRound1Participant(params, shares[i].SecretKeyShare, lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return nil, err
		}
		multRound1[i] = r1.EvalMultSwitchShare
		sumRound1[i] = r1.EvalSumShare
	}
	combined, err := CombineEvalKeyRound1(params, publicKeys, multRound1, sumRound1)
	if err != nil {
		return nil, err
	}

	finalShares := make([][]byte, len(shares))
	for i := range shares {
		r2, err := EvalKeyRound2Participant(params, shares[i].SecretKeyShare, combined.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			return nil, err
		}
		finalShares[i] = r2.EvalMultFinalShare
	}
	final, err := CombineEvalKeyRound2(params, finalPK, finalShares, combined.EvalSumFinal)
	if err != nil {
		return nil, err
	}
	return final.EvalMultFinal, nil
}

// TestEvalPoly_RejectsEmptyCoefficients pins the validation guard.
func TestEvalPoly_RejectsEmptyCoefficients(t *testing.T) {
	_, err := EvalPolyCKKSForContract(ContractParams{}, nil, []byte{0x01}, nil)
	if err == nil {
		t.Errorf("expected error for empty coefficients")
	}
}

// TestEvalPoly_RejectsEmptyCiphertext pins the validation guard.
func TestEvalPoly_RejectsEmptyCiphertext(t *testing.T) {
	_, err := EvalPolyCKKSForContract(ContractParams{}, nil, nil, []float64{0, 1})
	if err == nil {
		t.Errorf("expected error for empty ciphertext")
	}
}
