// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"math"
	"reflect"
	"testing"
)

func TestEncryptedSquaredDistanceCKKSContractRoundTrip(t *testing.T) {
	const profileDim = 8
	params := DefaultContractParams(profileDim, 6)
	params.EvalSumOnlyRotationKeys = true
	params.ProfileDim = profileDim

	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)
	jointPK := shares[len(shares)-1].PublicKey

	originFirst, err := EncryptRepeatedScalarCKKSForContract(params, jointPK, 10)
	if err != nil {
		t.Fatalf("encrypt origin first: %v", err)
	}
	originSecond, err := EncryptRepeatedScalarCKKSForContract(params, jointPK, 20)
	if err != nil {
		t.Fatalf("encrypt origin second: %v", err)
	}
	distance, err := EncryptedSquaredDistanceCKKSForContract(
		params, evalKeys.EvalMultFinal, originFirst, originSecond, 7, 24,
	)
	if err != nil {
		t.Fatalf("encrypted squared distance: %v", err)
	}

	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, distance, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt: %v", err)
		}
		partials = append(partials, partial)
	}
	slots, err := FuseCKKSPartialsForContract(params, partials, profileDim)
	if err != nil {
		t.Fatalf("fuse distance partials: %v", err)
	}
	for index, slot := range slots {
		if math.Abs(slot-25) > 0.1 {
			t.Fatalf("slot %d = %.6f, want 25", index, slot)
		}
	}
}

func TestChunkedFuseEncryptedInputsUsesDistanceCiphertexts(t *testing.T) {
	const profileDim = 8
	params := DefaultContractParams(profileDim, 12)
	params.EvalSumOnlyRotationKeys = true
	params.ProfileDim = profileDim

	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)
	jointPK := shares[len(shares)-1].PublicKey

	profile := []float64{1, 0, 0, 0, 0, 0, 0, 0}
	initiator, err := EncryptCKKSForContract(params, jointPK, profile)
	if err != nil {
		t.Fatalf("encrypt initiator profile: %v", err)
	}
	candidateCiphertexts := make([][]byte, 2)
	for i := range candidateCiphertexts {
		candidateCiphertexts[i], err = EncryptCKKSForContract(params, jointPK, profile)
		if err != nil {
			t.Fatalf("encrypt candidate profile %d: %v", i, err)
		}
	}

	originFirst, err := EncryptRepeatedScalarCKKSForContract(params, jointPK, 10)
	if err != nil {
		t.Fatalf("encrypt origin first: %v", err)
	}
	originSecond, err := EncryptRepeatedScalarCKKSForContract(params, jointPK, 20)
	if err != nil {
		t.Fatalf("encrypt origin second: %v", err)
	}
	farDistance, err := EncryptedSquaredDistanceCKKSForContract(
		params, evalKeys.EvalMultFinal, originFirst, originSecond, 7, 24,
	)
	if err != nil {
		t.Fatalf("encrypt far distance: %v", err)
	}
	nearDistance, err := EncryptedSquaredDistanceCKKSForContract(
		params, evalKeys.EvalMultFinal, originFirst, originSecond, 10, 20,
	)
	if err != nil {
		t.Fatalf("encrypt near distance: %v", err)
	}

	packages := [][]byte{{0xA5}, {0x5A}}
	payloadCiphertexts := make([][][]byte, len(packages))
	for candidate, pkg := range packages {
		bits := make([]float64, 8)
		for bit := range bits {
			bits[bit] = float64((pkg[bit/8] >> uint(7-(bit%8))) & 1)
		}
		payloadCiphertexts[candidate] = make([][]byte, 1)
		payloadCiphertexts[candidate][0], err = EncryptCKKSForContract(params, jointPK, bits)
		if err != nil {
			t.Fatalf("encrypt payload %d: %v", candidate, err)
		}
	}

	req := EncryptedInputFuseRequest{
		InitiatorCiphertext:          initiator,
		CandidateCiphertexts:         candidateCiphertexts,
		CandidateDistanceCiphertexts: [][]byte{farDistance, nearDistance},
		CandidateBrownies:            []int{0, 0},
		CandidatePayloadCiphertexts:  payloadCiphertexts,
		ProfileDim:                   profileDim,
		Alpha:                        0.01,
		Beta:                         1,
		Comparator:                   "tanh_chebyshev",
		ComparatorDegree:             7,
		ComparatorGain:               40,
		ComparatorScale:              1,
		ComparatorBound:              1,
		SelectorSchedule:             "none",
		EvalKeys:                     evalKeys,
		PayloadSlotCount:             8,
	}
	chunks, err := ChunkedFuseEncryptedInputsCKKS(params, req)
	if err != nil {
		t.Fatalf("chunked encrypted input fusion: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("chunk count = %d, want 1", len(chunks))
	}

	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, chunks[0], share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt: %v", err)
		}
		partials = append(partials, partial)
	}
	slots, err := FuseCKKSPartialsForContract(params, partials, 8)
	if err != nil {
		t.Fatalf("fuse partials: %v", err)
	}
	if recovered := slotsToBytesForTest(slots, 1); recovered[0] != packages[1][0] {
		t.Fatalf("recovered %x, want closest candidate package %x", recovered, packages[1])
	}

	comparators := []UnionComparator{
		{ID: "lane-a", Comparator: "tanh_chebyshev", Schedule: "none", Gain: 40, InputScale: 1, Bound: 1, Degree: 7},
		{ID: "lane-b", Comparator: "tanh_chebyshev", Schedule: "none", Gain: 40, InputScale: 1, Bound: 1, Degree: 7},
	}
	lanes, err := ChunkedUnionScoreEncryptedInputsCKKSWithConcurrency(params, req, comparators, 2)
	if err != nil {
		t.Fatalf("encrypted input union: %v", err)
	}
	if len(lanes) != len(comparators) {
		t.Fatalf("lane count = %d, want %d", len(lanes), len(comparators))
	}
	for lane, laneChunks := range lanes {
		if len(laneChunks) != 1 {
			t.Fatalf("lane %d chunk count = %d, want 1", lane, len(laneChunks))
		}
		partials := make([][]byte, 0, len(shares))
		for _, share := range shares {
			partial, err := PartialDecryptCKKSForContract(params, laneChunks[0], share.SecretKeyShare, share.Lead)
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
			t.Fatalf("lane %d recovered %x, want closest candidate package %x", lane, recovered, packages[1])
		}
	}

	requestType := reflect.TypeOf(EncryptedInputFuseRequest{})
	for _, forbidden := range []string{"InitiatorLatQ", "InitiatorLonQ", "CandidateLatQ", "CandidateLonQ", "CandidatePackages"} {
		if _, present := requestType.FieldByName(forbidden); present {
			t.Fatalf("encrypted input request exposes forbidden plaintext field %q", forbidden)
		}
	}
	missingDistance := req
	missingDistance.CandidateDistanceCiphertexts = missingDistance.CandidateDistanceCiphertexts[:1]
	if _, err := ChunkedFuseEncryptedInputsCKKS(params, missingDistance); err == nil {
		t.Fatal("encrypted input fusion accepted an incomplete distance ciphertext set")
	}
	foreignShares := distributedSharesForTest(t, params, 3)
	foreignEvalKeys := distributedEvalKeysForTest(t, params, foreignShares)
	foreignPK := foreignShares[len(foreignShares)-1].PublicKey
	foreignFirst, err := EncryptRepeatedScalarCKKSForContract(params, foreignPK, 10)
	if err != nil {
		t.Fatalf("encrypt foreign origin first: %v", err)
	}
	foreignSecond, err := EncryptRepeatedScalarCKKSForContract(params, foreignPK, 20)
	if err != nil {
		t.Fatalf("encrypt foreign origin second: %v", err)
	}
	foreignDistance, err := EncryptedSquaredDistanceCKKSForContract(
		params, foreignEvalKeys.EvalMultFinal, foreignFirst, foreignSecond, 10, 20,
	)
	if err != nil {
		t.Fatalf("encrypt foreign distance: %v", err)
	}
	foreignKey := req
	foreignKey.CandidateDistanceCiphertexts = [][]byte{farDistance, foreignDistance}
	if _, err := ChunkedFuseEncryptedInputsCKKS(params, foreignKey); err == nil {
		t.Fatal("encrypted input fusion accepted a foreign-key distance ciphertext")
	}
}
