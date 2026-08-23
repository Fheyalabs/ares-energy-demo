// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"reflect"
	"testing"
)

func TestEncryptedSquaredDistanceBFVContractRoundTrip(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	evalKeys := buildBFVEvalKeysForTest(t, params, first, second)
	originFirst, err := EncryptRepeatedScalarBFVForContract(params, second.PublicKey, 10)
	if err != nil {
		t.Fatalf("encrypt origin first: %v", err)
	}
	originSecond, err := EncryptRepeatedScalarBFVForContract(params, second.PublicKey, 20)
	if err != nil {
		t.Fatalf("encrypt origin second: %v", err)
	}
	distance, err := EncryptedSquaredDistanceBFVForContract(
		params, evalKeys.EvalMultFinal, originFirst, originSecond, 7, 24,
	)
	if err != nil {
		t.Fatalf("encrypted squared distance: %v", err)
	}
	p0, err := PartialDecryptBFVForContract(params, distance, first.SecretKeyShare, true)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := PartialDecryptBFVForContract(params, distance, second.SecretKeyShare, false)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	got, err := FuseBFVPartialsForContract(params, [][]byte{p0, p1}, params.BatchSize)
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}
	for index, value := range got {
		if value != 25 {
			t.Fatalf("slot %d = %d, want 25", index, value)
		}
	}
}

func TestBFVBlindFuseRequestDoesNotExposeCoordinates(t *testing.T) {
	requestType := reflect.TypeOf(BFVBlindFuseRequest{})
	for _, forbidden := range []string{"InitiatorLatQ", "InitiatorLonQ", "CandidateLatQ", "CandidateLonQ"} {
		if _, present := requestType.FieldByName(forbidden); present {
			t.Fatalf("BFV blind fuse request exposes plaintext coordinate field %q", forbidden)
		}
	}
}

func TestBlindFusePayloadBFVUsesEncryptedDistances(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	ReleaseOpenFHEGlobalContexts()
	t.Cleanup(ReleaseOpenFHEGlobalContexts)
	t.Setenv("ARES_FHE_ALLOW_INSECURE", "1")
	t.Setenv("ARES_BFV_PS_LOW_RSS", "1")
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 12,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	evalKeys := buildBFVEvalKeysForTest(t, params, first, second)
	initiator, err := EncryptBFVForContract(params, second.PublicKey, []int64{1, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt initiator profile: %v", err)
	}
	candidateA, err := EncryptBFVForContract(params, second.PublicKey, []int64{1, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt candidate A profile: %v", err)
	}
	candidateB, err := EncryptBFVForContract(params, second.PublicKey, []int64{3, 0, 0, 0})
	if err != nil {
		t.Fatalf("encrypt candidate B profile: %v", err)
	}
	payloadA, err := EncryptBFVForContract(params, second.PublicKey, []int64{11, 12, 13, 14})
	if err != nil {
		t.Fatalf("encrypt payload A: %v", err)
	}
	payloadB, err := EncryptBFVForContract(params, second.PublicKey, []int64{21, 22, 23, 24})
	if err != nil {
		t.Fatalf("encrypt payload B: %v", err)
	}
	originFirst, err := EncryptRepeatedScalarBFVForContract(params, second.PublicKey, 10)
	if err != nil {
		t.Fatalf("encrypt origin first: %v", err)
	}
	originSecond, err := EncryptRepeatedScalarBFVForContract(params, second.PublicKey, 20)
	if err != nil {
		t.Fatalf("encrypt origin second: %v", err)
	}
	distanceA, err := EncryptedSquaredDistanceBFVForContract(params, evalKeys.EvalMultFinal, originFirst, originSecond, 10, 20)
	if err != nil {
		t.Fatalf("derive distance A: %v", err)
	}
	distanceB, err := EncryptedSquaredDistanceBFVForContract(params, evalKeys.EvalMultFinal, originFirst, originSecond, 11, 20)
	if err != nil {
		t.Fatalf("derive distance B: %v", err)
	}
	fused, err := BlindFusePayloadBFVForContract(params, BFVBlindFuseRequest{
		InitiatorCiphertext:          initiator,
		CandidateProfileCiphertexts:  [][]byte{candidateA, candidateB},
		CandidateDistanceCiphertexts: [][]byte{distanceA, distanceB},
		CandidatePayloadCiphertexts:  [][]byte{payloadA, payloadB},
		CandidateBrownies:            []int{0, 0},
		ProfileDim:                   4,
		ProfileWeight:                1,
		DistanceWeight:               -1,
		PackageBytes:                 4,
		EvalKeys:                     evalKeys,
		StepCoefficients:             stepCoefficientsForBFVTest(2),
	})
	if err != nil {
		t.Fatalf("blind fuse: %v", err)
	}
	if OpenFHEContextCount() == 0 {
		t.Fatal("blind fusion did not create an OpenFHE context")
	}
	ReleaseOpenFHEGlobalContexts()
	if got := OpenFHEContextCount(); got != 0 {
		t.Fatalf("OpenFHE context count after blind-fusion release = %d, want 0", got)
	}
	p0, err := PartialDecryptBFVForContract(params, fused, first.SecretKeyShare, true)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := PartialDecryptBFVForContract(params, fused, second.SecretKeyShare, false)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	got, err := FuseBFVPartialsForContract(params, [][]byte{p0, p1}, 4)
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}
	want := []int64{21, 22, 23, 24}
	for index, value := range want {
		if got[index] != value {
			t.Fatalf("payload slot %d = %d, want %d (all slots %v)", index, got[index], value, got)
		}
	}
}

func TestBFVPackedIntThresholdRoundTrip(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	ct, err := EncryptBFVForContract(params, second.PublicKey, []int64{-3, 0, 42, 65536})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	p0, err := PartialDecryptBFVForContract(params, ct, first.SecretKeyShare, true)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := PartialDecryptBFVForContract(params, ct, second.SecretKeyShare, false)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	got, err := FuseBFVPartialsForContract(params, [][]byte{p0, p1}, 4)
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}
	want := []int64{-3, 0, 42, -1}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slot %d = %d, want %d (all slots %v)", i, got[i], want[i], got)
		}
	}
}

func TestBFVEvalKeyRounds(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	r1Lead, err := BFVEvalKeyRound1Lead(params, first.SecretKeyShare)
	if err != nil {
		t.Fatalf("round1 lead: %v", err)
	}
	r1Part, err := BFVEvalKeyRound1Participant(params, second.SecretKeyShare, r1Lead.EvalMultBase, r1Lead.EvalSumBase, second.PublicKey)
	if err != nil {
		t.Fatalf("round1 participant: %v", err)
	}
	r1, err := BFVCombineEvalKeyRound1(params,
		[][]byte{first.PublicKey, second.PublicKey},
		[][]byte{r1Lead.EvalMultBase, r1Part.EvalMultSwitchShare},
		[][]byte{r1Lead.EvalSumBase, r1Part.EvalSumShare},
	)
	if err != nil {
		t.Fatalf("combine round1: %v", err)
	}
	r20, err := BFVEvalKeyRound2Participant(params, first.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, true)
	if err != nil {
		t.Fatalf("round2 lead: %v", err)
	}
	r21, err := BFVEvalKeyRound2Participant(params, second.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, false)
	if err != nil {
		t.Fatalf("round2 participant: %v", err)
	}
	final, err := BFVCombineEvalKeyRound2(params, second.PublicKey, [][]byte{r20.EvalMultFinalShare, r21.EvalMultFinalShare}, r1.EvalSumFinal)
	if err != nil {
		t.Fatalf("combine round2: %v", err)
	}
	if len(final.EvalMultFinal) == 0 || len(final.EvalSumFinal) == 0 {
		t.Fatalf("empty final eval keys: %+v", final)
	}
}

func TestBFVEvalKeyRound1LazyRefs(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	r1Lead, err := BFVEvalKeyRound1Lead(params, first.SecretKeyShare)
	if err != nil {
		t.Fatalf("round1 lead: %v", err)
	}
	r1Part, err := BFVEvalKeyRound1Participant(params, second.SecretKeyShare, r1Lead.EvalMultBase, r1Lead.EvalSumBase, second.PublicKey)
	if err != nil {
		t.Fatalf("round1 participant: %v", err)
	}

	refs := []string{"lead", "participant"}
	resolved := make([]string, 0, len(refs))
	lazy, err := BFVCombineEvalKeyRound1Lazy(params,
		[][]byte{first.PublicKey, second.PublicKey},
		[][]byte{r1Lead.EvalMultBase, r1Part.EvalMultSwitchShare},
		refs,
		func(ref string) ([]byte, error) {
			resolved = append(resolved, ref)
			switch ref {
			case "lead":
				return r1Lead.EvalSumBase, nil
			case "participant":
				return r1Part.EvalSumShare, nil
			default:
				t.Fatalf("unexpected eval-sum ref %q", ref)
				return nil, nil
			}
		},
	)
	if err != nil {
		t.Fatalf("lazy combine round1: %v", err)
	}
	if len(lazy.EvalMultJoined) == 0 || len(lazy.EvalSumFinal) == 0 {
		t.Fatalf("empty lazy round1 result: %+v", lazy)
	}
	if len(resolved) != 2 || resolved[0] != "lead" || resolved[1] != "participant" {
		t.Fatalf("resolved refs = %v, want [lead participant]", resolved)
	}
}

func TestBFVEvalKeyRound1PerIndexLazyRefs(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	r1Lead, err := BFVEvalKeyRound1Lead(params, first.SecretKeyShare)
	if err != nil {
		t.Fatalf("round1 lead: %v", err)
	}
	r1Part, err := BFVEvalKeyRound1Participant(params, second.SecretKeyShare, r1Lead.EvalMultBase, r1Lead.EvalSumBase, second.PublicKey)
	if err != nil {
		t.Fatalf("round1 participant: %v", err)
	}

	resolved := make([]string, 0, 2)
	perIndex, err := BFVCombineEvalKeyRound1PerIndexLazy(params,
		[][]byte{first.PublicKey, second.PublicKey},
		[][]byte{r1Lead.EvalMultBase, r1Part.EvalMultSwitchShare},
		[][]IndexedEvalSumKeyRef{
			{{Index: 1, Ref: "lead"}},
			{{Index: 1, Ref: "participant"}},
		},
		func(ref string) ([]byte, error) {
			resolved = append(resolved, ref)
			switch ref {
			case "lead":
				return r1Lead.EvalSumBase, nil
			case "participant":
				return r1Part.EvalSumShare, nil
			default:
				t.Fatalf("unexpected eval-sum ref %q", ref)
				return nil, nil
			}
		},
	)
	if err != nil {
		t.Fatalf("per-index lazy combine round1: %v", err)
	}
	if len(perIndex.EvalMultJoined) == 0 || len(perIndex.EvalSumFinal) == 0 {
		t.Fatalf("empty per-index round1 result: %+v", perIndex)
	}
	if len(resolved) != 2 || resolved[0] != "lead" || resolved[1] != "participant" {
		t.Fatalf("resolved refs = %v, want [lead participant]", resolved)
	}
}

func TestBFVEvalProductSum(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	evalKeys := buildBFVEvalKeysForTest(t, params, first, second)
	left, err := EncryptBFVForContract(params, second.PublicKey, []int64{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("encrypt left: %v", err)
	}
	right, err := EncryptBFVForContract(params, second.PublicKey, []int64{5, 6, 7, 8})
	if err != nil {
		t.Fatalf("encrypt right: %v", err)
	}
	dot, err := EvalProductSumBFVForContract(params, evalKeys, left, right, 4)
	if err != nil {
		t.Fatalf("eval product sum: %v", err)
	}
	p0, err := PartialDecryptBFVForContract(params, dot, first.SecretKeyShare, true)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := PartialDecryptBFVForContract(params, dot, second.SecretKeyShare, false)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	got, err := FuseBFVPartialsForContract(params, [][]byte{p0, p1}, 1)
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}
	if got[0] != 70 {
		t.Fatalf("dot = %d, want 70", got[0])
	}
}

func buildBFVEvalKeysForTest(t *testing.T, params BFVContractParams, first, second DistributedKeyShare) EvalKeyFinal {
	t.Helper()
	r1Lead, err := BFVEvalKeyRound1Lead(params, first.SecretKeyShare)
	if err != nil {
		t.Fatalf("round1 lead: %v", err)
	}
	r1Part, err := BFVEvalKeyRound1Participant(params, second.SecretKeyShare, r1Lead.EvalMultBase, r1Lead.EvalSumBase, second.PublicKey)
	if err != nil {
		t.Fatalf("round1 participant: %v", err)
	}
	r1, err := BFVCombineEvalKeyRound1(params,
		[][]byte{first.PublicKey, second.PublicKey},
		[][]byte{r1Lead.EvalMultBase, r1Part.EvalMultSwitchShare},
		[][]byte{r1Lead.EvalSumBase, r1Part.EvalSumShare},
	)
	if err != nil {
		t.Fatalf("combine round1: %v", err)
	}
	r20, err := BFVEvalKeyRound2Participant(params, first.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, true)
	if err != nil {
		t.Fatalf("round2 lead: %v", err)
	}
	r21, err := BFVEvalKeyRound2Participant(params, second.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, false)
	if err != nil {
		t.Fatalf("round2 participant: %v", err)
	}
	final, err := BFVCombineEvalKeyRound2(params, second.PublicKey, [][]byte{r20.EvalMultFinalShare, r21.EvalMultFinalShare}, r1.EvalSumFinal)
	if err != nil {
		t.Fatalf("combine round2: %v", err)
	}
	return final
}

func stepCoefficientsForBFVTest(bits int) []int64 {
	const modulus int64 = 65537
	maxDifference := (1 << bits) - 1
	xs := make([]int64, 0, 2*maxDifference+1)
	ys := make([]int64, 0, 2*maxDifference+1)
	for difference := -maxDifference; difference <= maxDifference; difference++ {
		x := int64(difference)
		if x < 0 {
			x += modulus
		}
		xs = append(xs, x)
		if difference > 0 {
			ys = append(ys, 1)
		} else {
			ys = append(ys, 0)
		}
	}

	master := []int64{1}
	for _, x := range xs {
		next := make([]int64, len(master)+1)
		for index, coefficient := range master {
			next[index] = modBFVTest(next[index]-x*coefficient, modulus)
			next[index+1] = modBFVTest(next[index+1]+coefficient, modulus)
		}
		master = next
	}
	result := make([]int64, len(xs))
	for point, x := range xs {
		if ys[point] == 0 {
			continue
		}
		descending := make([]int64, len(master))
		for index := range master {
			descending[index] = master[len(master)-1-index]
		}
		quotientDescending := make([]int64, len(descending)-1)
		var carry int64
		for index := 0; index < len(descending)-1; index++ {
			carry = modBFVTest(descending[index]+carry*x, modulus)
			quotientDescending[index] = carry
		}
		quotient := make([]int64, len(quotientDescending))
		for index := range quotientDescending {
			quotient[index] = quotientDescending[len(quotientDescending)-1-index]
		}
		var denominator int64
		for index := len(quotient) - 1; index >= 0; index-- {
			denominator = modBFVTest(denominator*x+quotient[index], modulus)
		}
		coefficient := modBFVTest(ys[point]*powModBFVTest(denominator, modulus-2, modulus), modulus)
		for index, value := range quotient {
			result[index] = modBFVTest(result[index]+coefficient*value, modulus)
		}
	}
	return result
}

func modBFVTest(value, modulus int64) int64 {
	value %= modulus
	if value < 0 {
		value += modulus
	}
	return value
}

func powModBFVTest(base, exponent, modulus int64) int64 {
	result := int64(1)
	base = modBFVTest(base, modulus)
	for exponent > 0 {
		if exponent&1 == 1 {
			result = result * base % modulus
		}
		base = base * base % modulus
		exponent >>= 1
	}
	return result
}
