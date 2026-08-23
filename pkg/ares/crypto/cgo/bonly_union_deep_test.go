//go:build openfhe

package cgo

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

// TestBOnlyUnionDeepCircuitRecovers exercises the full chunked-union scoring circuit
// (depth 16, the live openfhe_union config) with per-index b-only reconstructed
// eval-sum keys via ChunkedUnionScoreCKKSWithEvalSumRefs, then threshold-decrypts and
// recovers the winner package. This is the first real test of that path and the decisive
// reproduction for the live "approximation error too high" / opened=[-1 -1 -1] failure:
// if b-only keys are the cause, this fails in-process; if it passes, the bug is the
// Swift client's a/b vector generation rather than the reconstruction itself.
func TestBOnlyUnionDeepCircuitRecovers(t *testing.T) {
	const profileDim = 128
	ringDim := uint32(8192) // default: insecure-fast; ARES_UNION_SECURE_RING=1 -> live secure 2^15
	if os.Getenv("ARES_UNION_SECURE_RING") == "1" {
		ringDim = 32768
		// The package init() forces ARES_FHE_ALLOW_INSECURE=1; flip it off so this run
		// builds the real HEStd_128_classic modulus chain the live server uses.
		prev := os.Getenv("ARES_FHE_ALLOW_INSECURE")
		os.Setenv("ARES_FHE_ALLOW_INSECURE", "0")
		defer os.Setenv("ARES_FHE_ALLOW_INSECURE", prev)
	}
	params := ContractParams{
		RingDim:                 ringDim, // noise budget tracks depth+scale; secure 2^15 has the live modulus chain
		ScalingFactor:           float64(uint64(1) << 35),
		Depth:                   16,
		EvalSumOnlyRotationKeys: true,
		ProfileDim:              profileDim,
	}
	ctx, err := NewCryptoContext(params)
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	defer ctx.Close()

	shares := make([]DistributedKeyShare, 3)
	shares[0], err = DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	for i := 1; i < len(shares); i++ {
		shares[i], err = DistributedKeyGenNext(params, shares[i-1].PublicKey)
		if err != nil {
			t.Fatalf("keygen next %d: %v", i, err)
		}
	}

	// Per-index eval-sum keys, then b-only refs (a shared, b per party) -- exactly the
	// reconstruction the live server performs from the client's uploaded vectors.
	// EXACT live eval-mult round1: evalMultKeyGenLead + evalMultKeySwitchShare.
	evalMultBase, err := EvalMultKeyGenLeadWithContext(ctx, shares[0].SecretKeyShare)
	if err != nil {
		t.Fatalf("evalMultKeyGenLead: %v", err)
	}
	publicKeys := make([][]byte, len(shares))
	multRound1 := make([][]byte, len(shares))
	publicKeys[0] = shares[0].PublicKey
	multRound1[0] = evalMultBase
	for i := 1; i < len(shares); i++ {
		publicKeys[i] = shares[i].PublicKey
		switchShare, err := EvalMultKeySwitchShareWithContext(ctx, shares[i].SecretKeyShare, evalMultBase)
		if err != nil {
			t.Fatalf("evalMultKeySwitchShare %d: %v", i, err)
		}
		multRound1[i] = switchShare
	}

	// SINGULAR per-index eval-sum keygen -- exactly what the Swift client loops over
	// (GeneratePerIndexEvalSumKey/Share, one rotation index at a time), then split a/b.
	// This is the live path; the plural GeneratePerIndexEvalSumKeysWithContext was passing.
	foldIndices := []int32{1, 2, 4, 8, 16, 32, 64} // eval-sum-only fold set for profileDim 128
	bOnlyRefsByParty := make([][]IndexedEvalSumKeyRef, len(shares))
	for p := range shares {
		bOnlyRefsByParty[p] = make([]IndexedEvalSumKeyRef, 0, len(foldIndices))
	}
	bOnlyBlobs := make(map[string][]byte)
	for _, idx := range foldIndices {
		leadKey, err := GeneratePerIndexEvalSumKeyWithContext(ctx, shares[0].SecretKeyShare, idx)
		if err != nil {
			t.Fatalf("singular lead key idx %d: %v", idx, err)
		}
		a, bLead, err := SplitRotShareAB(params, leadKey)
		if err != nil {
			t.Fatalf("split lead idx %d: %v", idx, err)
		}
		aRef := fmt.Sprintf("idx-%d-a", idx)
		bLeadRef := fmt.Sprintf("p0-idx-%d-b", idx)
		bOnlyBlobs[aRef] = a
		bOnlyBlobs[bLeadRef] = bLead
		bOnlyRefsByParty[0] = append(bOnlyRefsByParty[0], IndexedEvalSumKeyRef{Index: int(idx), ARef: aRef, BRef: bLeadRef})
		for p := 1; p < len(shares); p++ {
			share, err := GeneratePerIndexEvalSumShareWithContext(ctx, shares[p].SecretKeyShare, leadKey, shares[p].PublicKey, idx)
			if err != nil {
				t.Fatalf("singular share party %d idx %d: %v", p, idx, err)
			}
			aP, bP, err := SplitRotShareAB(params, share)
			if err != nil {
				t.Fatalf("split party %d idx %d: %v", p, idx, err)
			}
			if !bytes.Equal(aP, a) {
				t.Fatalf("a-vectors differ party %d idx %d", p, idx)
			}
			bPRef := fmt.Sprintf("p%d-idx-%d-b", p, idx)
			bOnlyBlobs[bPRef] = bP
			bOnlyRefsByParty[p] = append(bOnlyRefsByParty[p], IndexedEvalSumKeyRef{Index: int(idx), ARef: aRef, BRef: bPRef})
		}
	}
	resolve := func(ref string) ([]byte, error) {
		blob, ok := bOnlyBlobs[ref]
		if !ok {
			return nil, fmt.Errorf("missing ref %s", ref)
		}
		return append([]byte(nil), blob...), nil
	}

	// Round-1 b-only combine -> eval-mult joined, then round-2 -> final eval-mult key.
	r1Combined, err := CombineEvalKeyRound1PerIndexLazy(params, publicKeys, multRound1, bOnlyRefsByParty, resolve)
	if err != nil {
		t.Fatalf("b-only round1 combine: %v", err)
	}
	finalPK := shares[len(shares)-1].PublicKey
	finalShares := make([][]byte, len(shares))
	for i := range shares {
		r2, err := EvalKeyRound2ParticipantWithContext(ctx, shares[i].SecretKeyShare, r1Combined.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			t.Fatalf("round2 participant %d: %v", i, err)
		}
		finalShares[i] = r2.EvalMultFinalShare
	}
	finalEval, err := CombineEvalKeyRound2WithContext(ctx, finalPK, finalShares, r1Combined.EvalSumFinal)
	if err != nil {
		t.Fatalf("round2 combine: %v", err)
	}

	// Initiator matches the winner candidate; loser is orthogonal.
	initProfile := make([]float64, profileDim)
	initProfile[0] = 1
	winnerProfile := make([]float64, profileDim)
	winnerProfile[0] = 1
	loserProfile := make([]float64, profileDim)
	loserProfile[1] = 1
	initCT, _ := EncryptCKKSForContract(params, finalPK, initProfile)
	winnerCT, _ := EncryptCKKSForContract(params, finalPK, winnerProfile)
	loserCT, _ := EncryptCKKSForContract(params, finalPK, loserProfile)

	winnerPackage := []int{0xA5, 0x5A, 0xC3, 0x3C}
	loserPackage := []int{0x11, 0x22, 0x33, 0x44}
	req := FullFuseRequest{
		InitiatorCiphertext:  initCT,
		CandidateCiphertexts: [][]byte{loserCT, winnerCT},
		CandidateLatQ:        []int{0, 0},
		CandidateLonQ:        []int{0, 0},
		CandidateBrownies:    []int{0, 0},
		CandidatePackages:    [][]int{loserPackage, winnerPackage},
		ProfileDim:           profileDim,
		Alpha:                0,
		Beta:                 1,
		Gamma:                0,
		EvalKeys:             EvalKeyFinal{EvalMultFinal: finalEval.EvalMultFinal},
		PackageBytes:         len(winnerPackage),
		PayloadSlotCount:     len(winnerPackage) * 8,
	}
	// Exact live CKKSRing32KUnionV1 lanes: note ComparatorInputScale is unset (0) in the
	// shipped profile, and bounds are 5/6 (not 1). This reproduces the live tuning.
	comparators := []UnionComparator{
		{ID: "tanh_g5_d13", Comparator: "tanh_chebyshev", Schedule: "none", Gain: 5, Bound: 6, InputScale: 0, Degree: 13},
		{ID: "logi_g4_b5_d13", Comparator: "logistic", Schedule: "none", Gain: 4, Bound: 5, InputScale: 0, Degree: 13},
		{ID: "logi_g3_b6_d13", Comparator: "logistic", Schedule: "none", Gain: 3, Bound: 6, InputScale: 0, Degree: 13},
	}

	perComp, err := ChunkedUnionScoreCKKSWithEvalSumRefs(params, req, comparators, 1, publicKeys, bOnlyRefsByParty, resolve)
	if err != nil {
		t.Fatalf("chunked union score (b-only): %v", err)
	}
	if len(perComp) != len(comparators) {
		t.Fatalf("unexpected perComp shape: %d comparators", len(perComp))
	}

	// Recover each lane's chunk 0 and report whether it decodes to the winner package
	// (live failure is opened=[-1 -1 -1] = every lane's fusion hits approximation error).
	opened := 0
	for c := range comparators {
		chunk := perComp[c][0]
		partials := make([][]byte, 0, len(shares))
		for _, share := range shares {
			partial, err := PartialDecryptCKKSForContract(params, chunk, share.SecretKeyShare, share.Lead)
			if err != nil {
				t.Fatalf("partial decrypt lane %s: %v", comparators[c].ID, err)
			}
			partials = append(partials, partial)
		}
		slots, err := FuseCKKSPartialsForContract(params, partials, len(winnerPackage)*8)
		if err != nil {
			t.Logf("lane %s: fusion FAILED (approximation error): %v", comparators[c].ID, err)
			continue
		}
		recovered := slotsToBytesForTest(slots, len(winnerPackage))
		match := bytes.Equal(recovered, intsToBytesForTest(winnerPackage))
		t.Logf("lane %s: recovered %x (want %x) match=%v", comparators[c].ID, recovered, intsToBytesForTest(winnerPackage), match)
		if match {
			opened++
		}
	}
	if opened == 0 {
		t.Fatalf("b-only union: no lane recovered the winner (reproduces live opened=[-1 -1 -1])")
	}
}
