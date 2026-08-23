// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"math"
	"strings"
	"testing"
)

func TestDistributedKeygenCiphertextContractRoundTrip(t *testing.T) {
	params := DefaultContractParams(8, 4)
	first, err := DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("first keygen share: %v", err)
	}
	second, err := DistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("second keygen share: %v", err)
	}
	third, err := DistributedKeyGenNext(params, second.PublicKey)
	if err != nil {
		t.Fatalf("third keygen share: %v", err)
	}

	profile := []float64{1.0, 0.5, -0.25, 0.125}
	ct, err := EncryptCKKSForContract(params, third.PublicKey, profile)
	if err != nil {
		t.Fatalf("encrypt profile ciphertext: %v", err)
	}
	partials := make([][]byte, 0, 3)
	for _, share := range []DistributedKeyShare{first, second, third} {
		partial, err := PartialDecryptCKKSForContract(params, ct, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	got, err := FuseCKKSPartialsForContract(params, partials, len(profile))
	if err != nil {
		t.Fatalf("fuse partials: %v", err)
	}
	if len(got) != len(profile) {
		t.Fatalf("fused slots = %d, want %d", len(got), len(profile))
	}
	for i, want := range profile {
		if math.Abs(got[i]-want) > 0.01 {
			t.Fatalf("slot %d = %.6f, want %.6f (all slots=%v)", i, got[i], want, got)
		}
	}
}

func TestDistributedEvalKeysSupportCiphertextDotProduct(t *testing.T) {
	params := DefaultContractParams(8, 6)
	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)

	left := []float64{1.0, 2.0, 3.0, 4.0}
	right := []float64{0.5, -1.0, 0.25, 2.0}
	leftCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, left)
	if err != nil {
		t.Fatalf("encrypt left: %v", err)
	}
	rightCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, right)
	if err != nil {
		t.Fatalf("encrypt right: %v", err)
	}
	dotCT, err := EvalProductSumForContract(params, evalKeys, leftCT, rightCT, len(left))
	if err != nil {
		t.Fatalf("evaluate encrypted dot product: %v", err)
	}

	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, dotCT, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	got, err := FuseCKKSPartialsForContract(params, partials, 1)
	if err != nil {
		t.Fatalf("fuse dot partials: %v", err)
	}
	want := 0.0
	for i := range left {
		want += left[i] * right[i]
	}
	if math.Abs(got[0]-want) > 0.05 {
		t.Fatalf("dot = %.6f, want %.6f", got[0], want)
	}
}

func TestFullFusePayloadUsesSubmittedCiphertexts(t *testing.T) {
	params := DefaultContractParams(32, 12)
	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)

	initProfile := []float64{1, 0, 0, 0}
	loserProfile := []float64{0, 1, 0, 0}
	winnerProfile := []float64{1, 0, 0, 0}
	initCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, initProfile)
	if err != nil {
		t.Fatalf("encrypt initiator profile: %v", err)
	}
	loserCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, loserProfile)
	if err != nil {
		t.Fatalf("encrypt loser profile: %v", err)
	}
	winnerCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, winnerProfile)
	if err != nil {
		t.Fatalf("encrypt winner profile: %v", err)
	}

	loserPackage := []int{0x11, 0x22, 0x33, 0x44}
	winnerPackage := []int{0xA5, 0x5A, 0xC3, 0x3C}
	ctWinner, err := FullFusePayloadCKKS(params, FullFuseRequest{
		InitiatorCiphertext:  initCT,
		InitiatorLatQ:        0,
		InitiatorLonQ:        0,
		CandidateCiphertexts: [][]byte{loserCT, winnerCT},
		CandidateLatQ:        []int{0, 0},
		CandidateLonQ:        []int{0, 0},
		CandidateBrownies:    []int{0, 0},
		CandidatePackages:    [][]int{loserPackage, winnerPackage},
		ProfileDim:           len(initProfile),
		Alpha:                0,
		Beta:                 1,
		Gamma:                0,
		Comparator:           "tanh_chebyshev",
		ComparatorDegree:     7,
		ComparatorGain:       40,
		ComparatorScale:      1,
		ComparatorBound:      1,
		SelectorSchedule:     "none",
		EvalKeys:             evalKeys,
		PackageBytes:         len(winnerPackage),
		PayloadSlotCount:     len(winnerPackage) * 8,
	})
	if err != nil {
		t.Fatalf("full fuse payload: %v", err)
	}
	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, ctWinner, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	slots, err := FuseCKKSPartialsForContract(params, partials, len(winnerPackage)*8)
	if err != nil {
		t.Fatalf("fuse full payload partials: %v", err)
	}
	recovered := slotsToBytesForTest(slots, len(winnerPackage))
	for i, want := range winnerPackage {
		if recovered[i] != byte(want) {
			t.Fatalf("recovered package %x, want %x (slots=%v)", recovered, intsToBytesForTest(winnerPackage), slots[:8])
		}
	}
}

func TestFullFusePayloadMinimalRotationKeys(t *testing.T) {
	params := DefaultContractParams(32, 12)
	params.MinimalRotationKeys = true
	params.ProfileDim = 4
	params.PayloadSlotCount = 32

	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)

	initProfile := []float64{1, 0, 0, 0}
	loserProfile := []float64{0, 1, 0, 0}
	winnerProfile := []float64{1, 0, 0, 0}
	initCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, initProfile)
	if err != nil {
		t.Fatalf("encrypt initiator profile: %v", err)
	}
	loserCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, loserProfile)
	if err != nil {
		t.Fatalf("encrypt loser profile: %v", err)
	}
	winnerCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, winnerProfile)
	if err != nil {
		t.Fatalf("encrypt winner profile: %v", err)
	}

	loserPackage := []int{0x11, 0x22, 0x33, 0x44}
	winnerPackage := []int{0xA5, 0x5A, 0xC3, 0x3C}
	ctWinner, err := FullFusePayloadCKKS(params, FullFuseRequest{
		InitiatorCiphertext:  initCT,
		CandidateCiphertexts: [][]byte{loserCT, winnerCT},
		CandidateLatQ:        []int{0, 0},
		CandidateLonQ:        []int{0, 0},
		CandidateBrownies:    []int{0, 0},
		CandidatePackages:    [][]int{loserPackage, winnerPackage},
		ProfileDim:           len(initProfile),
		Alpha:                0,
		Beta:                 1,
		Gamma:                0,
		Comparator:           "tanh_chebyshev",
		ComparatorDegree:     7,
		ComparatorGain:       40,
		ComparatorScale:      1,
		ComparatorBound:      1,
		SelectorSchedule:     "none",
		EvalKeys:             evalKeys,
		PackageBytes:         len(winnerPackage),
		PayloadSlotCount:     len(winnerPackage) * 8,
		MinimalRotationKeys:  true,
	})
	if err != nil {
		t.Fatalf("minimal full fuse payload: %v", err)
	}
	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, ctWinner, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	slots, err := FuseCKKSPartialsForContract(params, partials, len(winnerPackage)*8)
	if err != nil {
		t.Fatalf("fuse minimal payload partials: %v", err)
	}
	recovered := slotsToBytesForTest(slots, len(winnerPackage))
	for i, want := range winnerPackage {
		if recovered[i] != byte(want) {
			t.Fatalf("minimal-mode recovered %x, want %x (slots=%v)",
				recovered, intsToBytesForTest(winnerPackage), slots[:8])
		}
	}
}

// TestChunkedFusePayloadEvalSumOnly validates the chunked server-blind fusion on the
// eval-sum-only (7-fold-key, no broadcast) rotation set at n=6 parties: EvalSum-replicate
// scoring + per-chunk Σ mask·pkg recovers the winner's package across all chunks.
// Run with ARES_FHE_ALLOW_INSECURE=1 (small test ring).
func TestChunkedFusePayloadEvalSumOnly(t *testing.T) {
	const profileDim = 8
	const nParties = 6
	params := DefaultContractParams(profileDim, 12)
	params.EvalSumOnlyRotationKeys = true
	params.ProfileDim = profileDim

	shares := distributedSharesForTest(t, params, nParties)
	evalKeys := distributedEvalKeysForTest(t, params, shares)
	jointPK := shares[len(shares)-1].PublicKey

	// Seeded cohort: candidate 2 == initiator (cosine 1, clear winner); others orthogonal.
	initProfile := []float64{1, 0, 0, 0, 0, 0, 0, 0}
	candProfiles := [][]float64{
		{0, 1, 0, 0, 0, 0, 0, 0},
		{0, 0, 1, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0},
	}
	const winnerIdx = 2
	nCands := len(candProfiles)

	initCT, err := EncryptCKKSForContract(params, jointPK, initProfile)
	if err != nil {
		t.Fatalf("encrypt initiator: %v", err)
	}
	candCTs := make([][]byte, nCands)
	for i := range candProfiles {
		candCTs[i], err = EncryptCKKSForContract(params, jointPK, candProfiles[i])
		if err != nil {
			t.Fatalf("encrypt candidate %d: %v", i, err)
		}
	}

	packages := [][]int{
		{0x11, 0x22, 0x33, 0x44},
		{0x55, 0x66, 0x77, 0x88},
		{0xA5, 0x5A, 0xC3, 0x3C}, // winner package
	}
	packageBytes := len(packages[0])
	payloadSlots := packageBytes * 8

	chunks, err := ChunkedFusePayloadCKKS(params, FullFuseRequest{
		InitiatorCiphertext:  initCT,
		CandidateCiphertexts: candCTs,
		CandidateLatQ:        make([]int, nCands),
		CandidateLonQ:        make([]int, nCands),
		CandidateBrownies:    make([]int, nCands),
		CandidatePackages:    packages,
		ProfileDim:           profileDim,
		Alpha:                0,
		Beta:                 1,
		Gamma:                0,
		Comparator:           "tanh_chebyshev",
		ComparatorDegree:     7,
		ComparatorGain:       40,
		ComparatorScale:      1,
		ComparatorBound:      1,
		SelectorSchedule:     "none",
		EvalKeys:             evalKeys,
		PackageBytes:         packageBytes,
		PayloadSlotCount:     payloadSlots,
	})
	if err != nil {
		t.Fatalf("chunked fuse payload: %v", err)
	}

	chunkSize := 1
	for chunkSize < profileDim {
		chunkSize <<= 1
	}
	wantChunks := (payloadSlots + chunkSize - 1) / chunkSize
	if len(chunks) != wantChunks {
		t.Fatalf("got %d chunks, want %d (chunkSize=%d)", len(chunks), wantChunks, chunkSize)
	}

	// Threshold-decrypt each chunk and reassemble its chunk_size bits in order.
	allBits := make([]float64, 0, len(chunks)*chunkSize)
	for c, chunk := range chunks {
		partials := make([][]byte, 0, nParties)
		for _, share := range shares {
			partial, err := PartialDecryptCKKSForContract(params, chunk, share.SecretKeyShare, share.Lead)
			if err != nil {
				t.Fatalf("partial decrypt chunk %d lead=%v: %v", c, share.Lead, err)
			}
			partials = append(partials, partial)
		}
		slots, err := FuseCKKSPartialsForContract(params, partials, chunkSize)
		if err != nil {
			t.Fatalf("fuse chunk %d: %v", c, err)
		}
		allBits = append(allBits, slots...)
	}

	recovered := slotsToBytesForTest(allBits, packageBytes)
	want := packages[winnerIdx]
	for i := range want {
		if recovered[i] != byte(want[i]) {
			t.Fatalf("chunked recovered %x, want %x (winner=%d, chunks=%d)",
				recovered, intsToBytesForTest(want), winnerIdx, len(chunks))
		}
	}
}

func TestChunkedFuseEncryptedPayloadEvalSumOnly(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	const profileDim = 8
	const nParties = 3
	params := DefaultContractParams(profileDim, 12)
	params.EvalSumOnlyRotationKeys = true
	params.ProfileDim = profileDim

	shares := distributedSharesForTest(t, params, nParties)
	evalKeys := distributedEvalKeysForTest(t, params, shares)
	jointPK := shares[len(shares)-1].PublicKey

	initCT, err := EncryptCKKSForContract(params, jointPK, []float64{1, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt initiator: %v", err)
	}
	candidateProfiles := [][]float64{
		{0, 1, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0}, // winner
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
	for i, pkg := range packages {
		bits := make([]float64, 8)
		for bit := 0; bit < len(bits); bit++ {
			if pkg[bit/8]&(1<<uint(7-(bit%8))) != 0 {
				bits[bit] = 1
			}
		}
		payloadCiphertexts[i] = make([][]byte, 1)
		payloadCiphertexts[i][0], err = EncryptCKKSForContract(params, jointPK, bits)
		if err != nil {
			t.Fatalf("encrypt candidate payload %d: %v", i, err)
		}
	}

	chunks, err := ChunkedFuseEncryptedPayloadCKKS(params, FullFuseRequest{
		InitiatorCiphertext:         initCT,
		CandidateCiphertexts:        candidateCTs,
		CandidateLatQ:               []int{0, 0},
		CandidateLonQ:               []int{0, 0},
		CandidateBrownies:           []int{0, 0},
		CandidatePayloadCiphertexts: payloadCiphertexts,
		ProfileDim:                  profileDim,
		Beta:                        1,
		Comparator:                  "tanh_chebyshev",
		ComparatorDegree:            7,
		ComparatorGain:              40,
		ComparatorScale:             1,
		ComparatorBound:             1,
		SelectorSchedule:            "none",
		EvalKeys:                    evalKeys,
		PayloadSlotCount:            8,
	})
	if err != nil {
		t.Fatalf("chunked encrypted payload fusion: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("chunk count = %d, want 1", len(chunks))
	}

	partials := make([][]byte, 0, nParties)
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
		t.Fatalf("recovered encrypted payload %x, want %x", recovered, packages[1])
	}
}

func TestChunkedFuseEncryptedPayloadRejectsMixedPayloadModes(t *testing.T) {
	_, err := ChunkedFuseEncryptedPayloadCKKS(ContractParams{}, FullFuseRequest{
		InitiatorCiphertext:         []byte{1},
		CandidateCiphertexts:        [][]byte{{1}},
		CandidateLatQ:               []int{0},
		CandidateLonQ:               []int{0},
		CandidateBrownies:           []int{0},
		CandidatePackages:           [][]int{{0xA5}},
		CandidatePayloadCiphertexts: [][][]byte{{{1}}},
		ProfileDim:                  8,
		PayloadSlotCount:            8,
		EvalKeys:                    EvalKeyFinal{EvalMultFinal: []byte{1}, EvalSumFinal: []byte{1}},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot include plaintext") {
		t.Fatalf("mixed payload mode error = %v, want plaintext-mode rejection", err)
	}
}

func TestChunkedFuseEncryptedPayloadRejectsInvalidChunkShape(t *testing.T) {
	_, err := ChunkedFuseEncryptedPayloadCKKS(ContractParams{}, FullFuseRequest{
		InitiatorCiphertext:         []byte{1},
		CandidateCiphertexts:        [][]byte{{1}},
		CandidateLatQ:               []int{0},
		CandidateLonQ:               []int{0},
		CandidateBrownies:           []int{0},
		CandidatePayloadCiphertexts: [][][]byte{{{1}}},
		ProfileDim:                  8,
		PayloadSlotCount:            16,
		EvalKeys:                    EvalKeyFinal{EvalMultFinal: []byte{1}, EvalSumFinal: []byte{1}},
	})
	if err == nil || !strings.Contains(err.Error(), "chunk count") {
		t.Fatalf("invalid chunk shape error = %v, want chunk-count rejection", err)
	}
}

func TestChunkedFuseEncryptedPayloadRejectsEmptyChunk(t *testing.T) {
	_, err := ChunkedFuseEncryptedPayloadCKKS(ContractParams{}, FullFuseRequest{
		InitiatorCiphertext:         []byte{1},
		CandidateCiphertexts:        [][]byte{{1}},
		CandidateLatQ:               []int{0},
		CandidateLonQ:               []int{0},
		CandidateBrownies:           []int{0},
		CandidatePayloadCiphertexts: [][][]byte{{nil}},
		ProfileDim:                  8,
		PayloadSlotCount:            8,
		EvalKeys:                    EvalKeyFinal{EvalMultFinal: []byte{1}, EvalSumFinal: []byte{1}},
	})
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty chunk error = %v, want empty-chunk rejection", err)
	}
}

func TestChunkedFusePlaintextPayloadRejectsEncryptedChunks(t *testing.T) {
	_, err := ChunkedFusePayloadCKKS(ContractParams{}, FullFuseRequest{
		CandidatePayloadCiphertexts: [][][]byte{{{1}}},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot also include encrypted") {
		t.Fatalf("plaintext mode with encrypted chunks error = %v, want mixed-mode rejection", err)
	}
}

func TestChunkedFuseEncryptedPayloadRejectsForeignContext(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := DefaultContractParams(8, 12)
	params.EvalSumOnlyRotationKeys = true
	params.ProfileDim = 8
	shares := distributedSharesForTest(t, params, 2)
	evalKeys := distributedEvalKeysForTest(t, params, shares)
	jointPK := shares[len(shares)-1].PublicKey

	initCT, err := EncryptCKKSForContract(params, jointPK, []float64{1, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt initiator: %v", err)
	}
	candidateCT, err := EncryptCKKSForContract(params, jointPK, []float64{1, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt candidate: %v", err)
	}

	foreignParams := params
	foreignFirst, err := DistributedKeyGenFirst(foreignParams)
	if err != nil {
		t.Fatalf("foreign keygen first: %v", err)
	}
	foreignSecond, err := DistributedKeyGenNext(foreignParams, foreignFirst.PublicKey)
	if err != nil {
		t.Fatalf("foreign keygen second: %v", err)
	}
	foreignPayload, err := EncryptCKKSForContract(foreignParams, foreignSecond.PublicKey, []float64{1, 0, 1, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt foreign payload: %v", err)
	}

	_, err = ChunkedFuseEncryptedPayloadCKKS(params, FullFuseRequest{
		InitiatorCiphertext:         initCT,
		CandidateCiphertexts:        [][]byte{candidateCT, candidateCT},
		CandidateLatQ:               []int{0, 0},
		CandidateLonQ:               []int{0, 0},
		CandidateBrownies:           []int{0, 0},
		CandidatePayloadCiphertexts: [][][]byte{{foreignPayload}, {foreignPayload}},
		ProfileDim:                  8,
		Beta:                        1,
		Comparator:                  "tanh_chebyshev",
		ComparatorDegree:            7,
		ComparatorGain:              40,
		ComparatorScale:             1,
		ComparatorBound:             1,
		EvalKeys:                    evalKeys,
		PayloadSlotCount:            8,
	})
	if err == nil || !strings.Contains(err.Error(), "key tag") {
		t.Fatalf("foreign encrypted payload key-tag error = %v, want key-tag rejection", err)
	}
}

func TestCryptoContextCloseClearsInsertedEvalKeys(t *testing.T) {
	const profileDim = 8
	params := DefaultContractParams(profileDim, 6)
	params.EvalSumOnlyRotationKeys = true
	params.ProfileDim = profileDim
	shares := distributedSharesForTest(t, params, 2)
	evalKeys := distributedEvalKeysForTest(t, params, shares)
	jointPK := shares[len(shares)-1].PublicKey

	initCT, err := EncryptCKKSForContract(params, jointPK, []float64{1, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt initiator: %v", err)
	}
	candCT, err := EncryptCKKSForContract(params, jointPK, []float64{1, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt candidate: %v", err)
	}
	otherCT, err := EncryptCKKSForContract(params, jointPK, []float64{0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt other candidate: %v", err)
	}

	req := FullFuseRequest{
		InitiatorCiphertext:  initCT,
		CandidateCiphertexts: [][]byte{candCT, otherCT},
		CandidateLatQ:        []int{0, 0},
		CandidateLonQ:        []int{0, 0},
		CandidateBrownies:    []int{0, 0},
		CandidatePackages:    [][]int{{0xA5}, {0x5A}},
		ProfileDim:           profileDim,
		Beta:                 1,
		Comparator:           "tanh_chebyshev",
		ComparatorDegree:     7,
		ComparatorGain:       40,
		ComparatorScale:      1,
		ComparatorBound:      1,
		SelectorSchedule:     "none",
		EvalKeys:             evalKeys,
		PackageBytes:         1,
		PayloadSlotCount:     8,
	}

	ctx, err := NewCryptoContext(params)
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	if _, err := ChunkedFusePayloadCKKSWithContext(ctx, req); err != nil {
		ctx.Close()
		t.Fatalf("priming chunked fuse: %v", err)
	}
	ctx.Close()

	fresh, err := NewCryptoContext(params)
	if err != nil {
		t.Fatalf("new fresh context: %v", err)
	}
	defer fresh.Close()

	req.EvalKeys = EvalKeyFinal{}
	if _, err := ChunkedFusePayloadCKKSWithContext(fresh, req); err == nil {
		t.Fatal("chunked fuse with a fresh context and no eval keys unexpectedly succeeded; Close left stale OpenFHE eval keys behind")
	}
}

func TestReleaseOpenFHEGlobalContextsClearsFactoryCache(t *testing.T) {
	const profileDim = 8
	params := DefaultContractParams(profileDim, 6)
	ctx, err := NewCryptoContext(params)
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	ctx.Close()

	if got := OpenFHEContextCount(); got == 0 {
		t.Fatal("expected OpenFHE factory to retain the created context before explicit release")
	}
	ReleaseOpenFHEGlobalContexts()
	if got := OpenFHEContextCount(); got != 0 {
		t.Fatalf("OpenFHE context count after release = %d, want 0", got)
	}
}

func slotsToBytesForTest(slots []float64, n int) []byte {
	out := make([]byte, n)
	for bit := 0; bit < n*8 && bit < len(slots); bit++ {
		if slots[bit] >= 0.5 {
			out[bit/8] |= 1 << uint(7-(bit%8))
		}
	}
	return out
}

func intsToBytesForTest(values []int) []byte {
	out := make([]byte, len(values))
	for i, value := range values {
		out[i] = byte(value)
	}
	return out
}

func distributedSharesForTest(t *testing.T, params ContractParams, n int) []DistributedKeyShare {
	t.Helper()
	shares := make([]DistributedKeyShare, n)
	var err error
	shares[0], err = DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("first keygen share: %v", err)
	}
	for i := 1; i < n; i++ {
		shares[i], err = DistributedKeyGenNext(params, shares[i-1].PublicKey)
		if err != nil {
			t.Fatalf("keygen share %d: %v", i, err)
		}
	}
	return shares
}

func distributedEvalKeysForTest(t *testing.T, params ContractParams, shares []DistributedKeyShare) EvalKeyFinal {
	t.Helper()
	lead, err := EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		t.Fatalf("eval-key round1 lead: %v", err)
	}
	publicKeys := make([][]byte, len(shares))
	multRound1 := make([][]byte, len(shares))
	sumRound1 := make([][]byte, len(shares))
	publicKeys[0] = shares[0].PublicKey
	multRound1[0] = lead.EvalMultBase
	sumRound1[0] = lead.EvalSumBase
	for i := 1; i < len(shares); i++ {
		publicKeys[i] = shares[i].PublicKey
		round1, err := EvalKeyRound1Participant(params, shares[i].SecretKeyShare, lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			t.Fatalf("eval-key round1 participant %d: %v", i, err)
		}
		multRound1[i] = round1.EvalMultSwitchShare
		sumRound1[i] = round1.EvalSumShare
	}
	combinedRound1, err := CombineEvalKeyRound1(params, publicKeys, multRound1, sumRound1)
	if err != nil {
		t.Fatalf("combine eval-key round1: %v", err)
	}

	finalShares := make([][]byte, len(shares))
	finalPK := shares[len(shares)-1].PublicKey
	for i := range shares {
		round2, err := EvalKeyRound2Participant(params, shares[i].SecretKeyShare, combinedRound1.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			t.Fatalf("eval-key round2 participant %d: %v", i, err)
		}
		finalShares[i] = round2.EvalMultFinalShare
	}
	final, err := CombineEvalKeyRound2(params, finalPK, finalShares, combinedRound1.EvalSumFinal)
	if err != nil {
		t.Fatalf("combine eval-key round2: %v", err)
	}
	return final
}
