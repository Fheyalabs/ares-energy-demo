// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"math"
	"testing"
)

// buildJointEvalKeys runs the two-round threshold eval-key protocol and
// returns the full bundle, including the rotation-key map that
// EvalAtIndex needs. The existing buildJointEvalMultKey helper in
// eval_poly_test.go returns only the eval-mult key.
func buildJointEvalKeys(t *testing.T, params ContractParams, shares []DistributedKeyShare) (EvalKeyFinal, error) {
	t.Helper()
	finalPK := shares[len(shares)-1].PublicKey

	lead, err := EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	pks := [][]byte{shares[0].PublicKey}
	multShares := [][]byte{lead.EvalMultBase}
	sumShares := [][]byte{lead.EvalSumBase}
	for i := 1; i < len(shares); i++ {
		r1, err := EvalKeyRound1Participant(params, shares[i].SecretKeyShare,
			lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return EvalKeyFinal{}, err
		}
		pks = append(pks, shares[i].PublicKey)
		multShares = append(multShares, r1.EvalMultSwitchShare)
		sumShares = append(sumShares, r1.EvalSumShare)
	}
	combined, err := CombineEvalKeyRound1(params, pks, multShares, sumShares)
	if err != nil {
		return EvalKeyFinal{}, err
	}

	var finalShares [][]byte
	for i, s := range shares {
		r2, err := EvalKeyRound2Participant(params, s.SecretKeyShare,
			combined.EvalMultJoined, finalPK, i == 0)
		if err != nil {
			return EvalKeyFinal{}, err
		}
		finalShares = append(finalShares, r2.EvalMultFinalShare)
	}
	return CombineEvalKeyRound2(params, finalPK, finalShares, combined.EvalSumFinal)
}

// EvalAtIndex(ct, 1) shifts slot i+1 into slot i. The pool clearing
// circuit uses index -1 to align E[k-1] against E[k] along the price
// axis; this test pins the direction convention both ways.
func TestEvalAtIndex_ShiftsSlots(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := DefaultContractParams(4, 4)
	kb := setupTwoParty(t, params)
	joint := kb.second.PublicKey

	keys, err := buildJointEvalKeys(t, params, []DistributedKeyShare{kb.first, kb.second})
	if err != nil {
		t.Skipf("eval-sum key chain unavailable: %v", err)
	}

	in := []float64{1, 2, 3, 4}
	ct, err := EncryptCKKSForContract(params, joint, in)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	left, err := EvalAtIndexCKKSForContract(params, keys.EvalSumFinal, ct, 1)
	if err != nil {
		t.Fatalf("rotate +1: %v", err)
	}
	got := recoverPlaintext(t, params, kb, left, len(in))
	if math.Abs(got[0]-2) > 1e-2 {
		t.Errorf("rotate(+1) slot 0 = %v, want 2", got[0])
	}
	if math.Abs(got[1]-3) > 1e-2 {
		t.Errorf("rotate(+1) slot 1 = %v, want 3", got[1])
	}

	right, err := EvalAtIndexCKKSForContract(params, keys.EvalSumFinal, ct, -1)
	if err != nil {
		t.Fatalf("rotate -1: %v", err)
	}
	got = recoverPlaintext(t, params, kb, right, len(in))
	if math.Abs(got[1]-1) > 1e-2 {
		t.Errorf("rotate(-1) slot 1 = %v, want 1", got[1])
	}
	if math.Abs(got[2]-2) > 1e-2 {
		t.Errorf("rotate(-1) slot 2 = %v, want 2", got[2])
	}
}

func TestEvalAtIndex_RejectsEmptyInputs(t *testing.T) {
	params := DefaultContractParams(4, 4)
	if _, err := EvalAtIndexCKKSForContract(params, []byte{1}, nil, 1); err == nil {
		t.Error("empty ciphertext: want error")
	}
	if _, err := EvalAtIndexCKKSForContract(params, nil, []byte{1}, 1); err == nil {
		t.Error("empty rotation key: want error")
	}
	if _, err := EvalAtIndexCKKSForContract(params, []byte{1}, []byte{1}, 0); err == nil {
		t.Error("zero index: want error")
	}
}
