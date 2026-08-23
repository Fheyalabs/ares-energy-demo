// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"math"
	"testing"
)

// twoPartyKeyBundle is the keygen + eval-mult-key result a binary-op
// test needs.
type twoPartyKeyBundle struct {
	first, second DistributedKeyShare
	evalMult      []byte
}

func setupTwoParty(t *testing.T, params ContractParams) twoPartyKeyBundle {
	t.Helper()
	first, err := DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := DistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	evalKey, err := buildJointEvalMultKey(t, params, []DistributedKeyShare{first, second})
	if err != nil {
		t.Skipf("eval-mult key chain unavailable: %v", err)
	}
	return twoPartyKeyBundle{first: first, second: second, evalMult: evalKey}
}

func recoverPlaintext(t *testing.T, params ContractParams, kb twoPartyKeyBundle, ct []byte, nSlots int) []float64 {
	t.Helper()
	p1, err := PartialDecryptCKKSForContract(params, ct, kb.first.SecretKeyShare, kb.first.Lead)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	p2, err := PartialDecryptCKKSForContract(params, ct, kb.second.SecretKeyShare, kb.second.Lead)
	if err != nil {
		t.Fatalf("partial 2: %v", err)
	}
	out, err := FuseCKKSPartialsForContract(params, [][]byte{p1, p2}, nSlots)
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}
	return out
}

func TestEvalAdd_EndToEnd(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := DefaultContractParams(4, 4)
	kb := setupTwoParty(t, params)
	joint := kb.second.PublicKey

	a := []float64{1.0, 2.0, 3.0, 4.0}
	b := []float64{0.5, -1.0, 1.5, 2.0}
	ctA, err := EncryptCKKSForContract(params, joint, a)
	if err != nil {
		t.Fatalf("encrypt a: %v", err)
	}
	ctB, err := EncryptCKKSForContract(params, joint, b)
	if err != nil {
		t.Fatalf("encrypt b: %v", err)
	}

	sum, err := EvalAddCKKSForContract(params, ctA, ctB)
	if err != nil {
		t.Fatalf("eval add: %v", err)
	}
	got := recoverPlaintext(t, params, kb, sum, len(a))
	for i := range a {
		want := a[i] + b[i]
		if math.Abs(got[i]-want) > 1e-3 {
			t.Errorf("slot %d: got %v, want %v", i, got[i], want)
		}
	}
}

func TestEvalSub_EndToEnd(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := DefaultContractParams(4, 4)
	kb := setupTwoParty(t, params)
	joint := kb.second.PublicKey

	a := []float64{5.0, 3.0, 7.0, 1.0}
	b := []float64{1.0, 1.5, 2.0, 0.5}
	ctA, _ := EncryptCKKSForContract(params, joint, a)
	ctB, _ := EncryptCKKSForContract(params, joint, b)

	diff, err := EvalSubCKKSForContract(params, ctA, ctB)
	if err != nil {
		t.Fatalf("eval sub: %v", err)
	}
	got := recoverPlaintext(t, params, kb, diff, len(a))
	for i := range a {
		want := a[i] - b[i]
		if math.Abs(got[i]-want) > 1e-3 {
			t.Errorf("slot %d: got %v, want %v", i, got[i], want)
		}
	}
}

func TestEvalMult_EndToEnd(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := DefaultContractParams(4, 6)
	kb := setupTwoParty(t, params)
	joint := kb.second.PublicKey

	a := []float64{2.0, 3.0, 0.5, -1.5}
	b := []float64{4.0, 0.25, 6.0, 2.0}
	ctA, _ := EncryptCKKSForContract(params, joint, a)
	ctB, _ := EncryptCKKSForContract(params, joint, b)

	prod, err := EvalMultCKKSForContract(params, kb.evalMult, ctA, ctB)
	if err != nil {
		t.Fatalf("eval mult: %v", err)
	}
	got := recoverPlaintext(t, params, kb, prod, len(a))
	for i := range a {
		want := a[i] * b[i]
		if math.Abs(got[i]-want) > 1e-2 {
			t.Errorf("slot %d: got %v, want %v", i, got[i], want)
		}
	}
}

func TestEvalConstMult_EndToEnd(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := DefaultContractParams(4, 4)
	kb := setupTwoParty(t, params)
	joint := kb.second.PublicKey

	a := []float64{1.0, 2.0, 3.5, -0.5}
	ctA, _ := EncryptCKKSForContract(params, joint, a)

	scaled, err := EvalConstMultCKKSForContract(params, ctA, 7.0)
	if err != nil {
		t.Fatalf("eval const mult: %v", err)
	}
	got := recoverPlaintext(t, params, kb, scaled, len(a))
	for i, v := range a {
		want := v * 7.0
		if math.Abs(got[i]-want) > 1e-3 {
			t.Errorf("slot %d: got %v, want %v", i, got[i], want)
		}
	}
}

func TestEvalMult_RejectsMissingKey(t *testing.T) {
	_, err := EvalMultCKKSForContract(ContractParams{}, nil, []byte{1}, []byte{1})
	if err == nil {
		t.Errorf("expected error when eval-mult key is missing")
	}
}

func TestEvalAdd_RejectsEmptyOperand(t *testing.T) {
	_, err := EvalAddCKKSForContract(ContractParams{}, nil, []byte{1})
	if err == nil {
		t.Errorf("expected error when ctA is empty")
	}
}
