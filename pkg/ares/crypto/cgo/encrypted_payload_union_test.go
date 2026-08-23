// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import "testing"

func TestChunkedUnionScoreEncryptedPayloadWithConcurrency(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}

	const profileDim = 8
	params := DefaultContractParams(profileDim, 12)
	params.EvalSumOnlyRotationKeys = true
	params.ProfileDim = profileDim

	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)
	jointPK := shares[len(shares)-1].PublicKey

	initCT, err := EncryptCKKSForContract(params, jointPK, []float64{1, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt initiator: %v", err)
	}
	candidateProfiles := [][]float64{
		{0, 1, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0},
	}
	candidateCTs := make([][]byte, len(candidateProfiles))
	for i, profile := range candidateProfiles {
		candidateCTs[i], err = EncryptCKKSForContract(params, jointPK, profile)
		if err != nil {
			t.Fatalf("encrypt candidate %d: %v", i, err)
		}
	}

	packages := [][]byte{{0x11}, {0xA5}}
	payloadCiphertexts := make([][][]byte, len(packages))
	for candidate, pkg := range packages {
		bits := make([]float64, 8)
		for bit := range bits {
			if pkg[bit/8]&(1<<uint(7-(bit%8))) != 0 {
				bits[bit] = 1
			}
		}
		ct, err := EncryptCKKSForContract(params, jointPK, bits)
		if err != nil {
			t.Fatalf("encrypt payload %d: %v", candidate, err)
		}
		payloadCiphertexts[candidate] = [][]byte{ct}
	}

	req := FullFuseRequest{
		InitiatorCiphertext:         initCT,
		CandidateCiphertexts:        candidateCTs,
		CandidateLatQ:               []int{0, 0},
		CandidateLonQ:               []int{0, 0},
		CandidateBrownies:           []int{0, 0},
		CandidatePayloadCiphertexts: payloadCiphertexts,
		ProfileDim:                  profileDim,
		Beta:                        1,
		EvalKeys:                    evalKeys,
		PayloadSlotCount:            8,
	}
	comparators := []UnionComparator{
		{ID: "lane-a", Comparator: "tanh_chebyshev", Schedule: "none", Gain: 40, InputScale: 1, Bound: 1, Degree: 7},
		{ID: "lane-b", Comparator: "tanh_chebyshev", Schedule: "none", Gain: 40, InputScale: 1, Bound: 1, Degree: 7},
	}

	lanes, err := ChunkedUnionScoreEncryptedPayloadCKKSWithConcurrency(params, req, comparators, 2)
	if err != nil {
		t.Fatalf("encrypted union score: %v", err)
	}
	if len(lanes) != len(comparators) {
		t.Fatalf("lane count = %d, want %d", len(lanes), len(comparators))
	}
	for lane, chunks := range lanes {
		if len(chunks) != 1 {
			t.Fatalf("lane %d chunk count = %d, want 1", lane, len(chunks))
		}
		partials := make([][]byte, 0, len(shares))
		for _, share := range shares {
			partial, err := PartialDecryptCKKSForContract(params, chunks[0], share.SecretKeyShare, share.Lead)
			if err != nil {
				t.Fatalf("lane %d partial decrypt: %v", lane, err)
			}
			partials = append(partials, partial)
		}
		slots, err := FuseCKKSPartialsForContract(params, partials, 8)
		if err != nil {
			t.Fatalf("lane %d fuse partials: %v", lane, err)
		}
		if recovered := slotsToBytesForTest(slots, 1); recovered[0] != packages[1][0] {
			t.Fatalf("lane %d recovered %x, want %x", lane, recovered, packages[1])
		}
	}
}
