// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"testing"
)

// TestEvalArgmax_PicksHighestScore verifies the composite argmax:
// 3 participants encrypt their (well-separated) scores; argmax with a
// degree-3 sharpening polynomial — mapped to [0, 1] indicator output —
// returns mask ciphertexts. After threshold decrypt, the participant
// with the highest score has the largest mask value.
func TestEvalArgmax_PicksHighestScore(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := DefaultContractParams(4, 10)
	kb := setupTwoParty(t, params)
	joint := kb.second.PublicKey

	// Three candidates with well-separated normalized scores. All
	// pairwise differences fall in (-1, 1) so the sharpening
	// polynomial's domain is honored.
	scores := []float64{0.5, -0.3, 0.0}
	expectedWinner := 0

	cts := make([][]byte, len(scores))
	for i, s := range scores {
		// Use a 1-slot vector for each candidate. (CKKS's batch
		// encoding requires at least 1 slot; we put the score in slot
		// 0 and pad with zeros to match the contract's batch size.)
		values := make([]float64, 4)
		values[0] = s
		ct, err := EncryptCKKSForContract(params, joint, values)
		if err != nil {
			t.Fatalf("encrypt candidate %d: %v", i, err)
		}
		cts[i] = ct
	}

	// (1.5x - 0.5x³ + 1) / 2  →  maps [-1, 1] sign output to a [0, 1]
	// indicator: 0.5 + 0.75x - 0.25x³.
	sharpen := []float64{0.5, 0.75, 0, -0.25}

	masks, err := EvalArgmaxCKKSForContract(params, kb.evalMult, cts, sharpen)
	if err != nil {
		t.Fatalf("argmax: %v", err)
	}
	if len(masks) != len(scores) {
		t.Fatalf("got %d masks, want %d", len(masks), len(scores))
	}

	maskValues := make([]float64, len(masks))
	for i, m := range masks {
		v := recoverPlaintext(t, params, kb, m, 4)
		maskValues[i] = v[0] // we put the score in slot 0
		t.Logf("score=%v → mask=%v", scores[i], maskValues[i])
	}

	winnerIdx := 0
	for i := 1; i < len(maskValues); i++ {
		if maskValues[i] > maskValues[winnerIdx] {
			winnerIdx = i
		}
	}
	if winnerIdx != expectedWinner {
		t.Errorf("argmax picked %d (mask=%v), want %d (mask=%v); all masks=%v",
			winnerIdx, maskValues[winnerIdx],
			expectedWinner, maskValues[expectedWinner],
			maskValues)
	}
}

func TestEvalArgmax_RejectsFewerThanTwoCandidates(t *testing.T) {
	_, err := EvalArgmaxCKKSForContract(ContractParams{}, []byte{1}, [][]byte{[]byte{1}}, []float64{0, 1})
	if err == nil {
		t.Errorf("expected error when fewer than 2 candidates")
	}
}

func TestEvalArgmax_RejectsMissingEvalKey(t *testing.T) {
	_, err := EvalArgmaxCKKSForContract(ContractParams{}, nil, [][]byte{[]byte{1}, []byte{2}}, []float64{0, 1})
	if err == nil {
		t.Errorf("expected error when eval-mult key is missing")
	}
}

func TestEvalArgmax_RejectsShortPolynomial(t *testing.T) {
	_, err := EvalArgmaxCKKSForContract(ContractParams{}, []byte{1}, [][]byte{[]byte{1}, []byte{2}}, []float64{0.5})
	if err == nil {
		t.Errorf("expected error when sharpening polynomial has < 2 coefficients")
	}
}
