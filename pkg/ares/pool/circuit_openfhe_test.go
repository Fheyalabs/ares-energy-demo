// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package pool

import (
	"math"
	"testing"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// testEnv is a two-party threshold CKKS context plus the handle the
// circuit runs against.
//
// Ring 8192 (not 1024) because the circuit is ~7 levels deep: at
// ScalingFactor 2^50 the modulus chain is 60 + 7*50 = 410 bits, and a
// tiny ring produces enough approximation error to smear the one-hot.
// The insecure opt-out in insecure_optout_test.go is what lets the
// bridge accept it; Task 6 measures the secure ring properly.
type testEnv struct {
	handle fhecalib.ContextHandle
	params cgo.ContractParams
	first  cgo.DistributedKeyShare
	second cgo.DistributedKeyShare
}

func newTestEnv(t *testing.T, ringDim, depth uint32) *testEnv {
	t.Helper()
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	cp := cgo.ContractParams{
		RingDim:       ringDim,
		ScalingFactor: float64(uint64(1) << 50),
		Depth:         depth,
	}
	first, err := cgo.DistributedKeyGenFirst(cp)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := cgo.DistributedKeyGenNext(cp, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	keys, err := buildJointEvalKeys(cp, []cgo.DistributedKeyShare{first, second})
	if err != nil {
		t.Skipf("eval-key chain unavailable: %v", err)
	}
	h := fhecalib.NewContextHandle(helperclient.ContractParams{
		RingDim:        ringDim,
		ScalingFactor:  cp.ScalingFactor,
		ScalingModSize: 50,
		Depth:          depth,
	}, keys, second.PublicKey)
	return &testEnv{handle: h, params: cp, first: first, second: second}
}

// decrypt threshold-decrypts a ciphertext produced under this env.
func (e *testEnv) decrypt(t *testing.T, ct []byte, nSlots int) []float64 {
	t.Helper()
	p1, err := cgo.PartialDecryptCKKSForContract(e.params, ct, e.first.SecretKeyShare, e.first.Lead)
	if err != nil {
		t.Fatalf("partial decrypt 1: %v", err)
	}
	p2, err := cgo.PartialDecryptCKKSForContract(e.params, ct, e.second.SecretKeyShare, e.second.Lead)
	if err != nil {
		t.Fatalf("partial decrypt 2: %v", err)
	}
	out, err := cgo.FuseCKKSPartialsForContract(e.params, [][]byte{p1, p2}, nSlots)
	if err != nil {
		t.Fatalf("fuse partials: %v", err)
	}
	return out
}

// buildJointEvalKeys runs the two-round threshold eval-key protocol and
// returns the bundle, including the rotation-key map EvalAtIndex needs.
func buildJointEvalKeys(params cgo.ContractParams, shares []cgo.DistributedKeyShare) (cgo.EvalKeyFinal, error) {
	finalPK := shares[len(shares)-1].PublicKey

	lead, err := cgo.EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return cgo.EvalKeyFinal{}, err
	}
	pks := [][]byte{shares[0].PublicKey}
	multShares := [][]byte{lead.EvalMultBase}
	sumShares := [][]byte{lead.EvalSumBase}
	for i := 1; i < len(shares); i++ {
		r1, err := cgo.EvalKeyRound1Participant(params, shares[i].SecretKeyShare,
			lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return cgo.EvalKeyFinal{}, err
		}
		pks = append(pks, shares[i].PublicKey)
		multShares = append(multShares, r1.EvalMultSwitchShare)
		sumShares = append(sumShares, r1.EvalSumShare)
	}
	combined, err := cgo.CombineEvalKeyRound1(params, pks, multShares, sumShares)
	if err != nil {
		return cgo.EvalKeyFinal{}, err
	}

	var finalShares [][]byte
	for i, s := range shares {
		r2, err := cgo.EvalKeyRound2Participant(params, s.SecretKeyShare,
			combined.EvalMultJoined, finalPK, i == 0)
		if err != nil {
			return cgo.EvalKeyFinal{}, err
		}
		finalShares = append(finalShares, r2.EvalMultFinalShare)
	}
	return cgo.CombineEvalKeyRound2(params, finalPK, finalShares, combined.EvalSumFinal)
}

// The homomorphic circuit must select the same clearing bucket as the
// plaintext oracle. This is the correctness gate for spec §3.3.
func TestEvalClearing_MatchesOracle(t *testing.T) {
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{
		{Slot: 0, PriceCt: 0.75, Quantity: 4},
		{Slot: 1, PriceCt: 1.50, Quantity: 2},
	})
	dem := mustEncode(t, EncodeDemand, g, []Offer{
		{Slot: 0, PriceCt: 1.75, Quantity: 4},
		{Slot: 1, PriceCt: 1.75, Quantity: 2},
	})
	want, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}

	env := newTestEnv(t, 8192, 8)
	h := env.handle

	ctS, err := h.Encrypt(sup)
	if err != nil {
		t.Fatalf("encrypt supply: %v", err)
	}
	ctD, err := h.Encrypt(dem)
	if err != nil {
		t.Fatalf("encrypt demand: %v", err)
	}

	out, err := EvalClearing(h, g, ClearingInputs{Supply: ctS, Demand: ctD},
		LogisticCoeffs(13, 4.0), 8.0)
	if err != nil {
		t.Fatalf("EvalClearing: %v", err)
	}

	step := env.decrypt(t, out.Step, g.Len())
	got := DecodeCrossing(g, step)
	for slot := range want {
		if got[slot] != want[slot].Bucket {
			t.Errorf("slot %d: circuit bucket %d, oracle bucket %d (step %v)",
				slot, got[slot], want[slot].Bucket, step[slot*g.NumBuckets:(slot+1)*g.NumBuckets])
		}
	}
}

// The three rationing scalars must be readable at the clearing bucket,
// otherwise participants cannot compute their own allocation
// (spec §4.5 Break 3).
func TestEvalClearing_RationingScalars(t *testing.T) {
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{
		{Slot: 0, PriceCt: 0.25, Quantity: 4},
		{Slot: 0, PriceCt: 0.75, Quantity: 6},
	})
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 2.0, Quantity: 5}})
	want, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}

	env := newTestEnv(t, 8192, 8)
	h := env.handle
	ctS, err := h.Encrypt(sup)
	if err != nil {
		t.Fatalf("encrypt supply: %v", err)
	}
	ctD, err := h.Encrypt(dem)
	if err != nil {
		t.Fatalf("encrypt demand: %v", err)
	}

	out, err := EvalClearing(h, g, ClearingInputs{Supply: ctS, Demand: ctD},
		LogisticCoeffs(13, 4.0), 16.0)
	if err != nil {
		t.Fatalf("EvalClearing: %v", err)
	}

	got := DecodeClearing(g,
		env.decrypt(t, out.Step, g.Len()),
		env.decrypt(t, out.OneHot, g.Len()),
		env.decrypt(t, out.SupplyAt, g.Len()),
		env.decrypt(t, out.SupplyPrevAt, g.Len()),
		env.decrypt(t, out.DemandAt, g.Len()),
	)

	const tol = 0.5
	w, gt := want[0], got[0]
	if gt.Bucket != w.Bucket {
		t.Fatalf("Bucket = %d, want %d", gt.Bucket, w.Bucket)
	}
	for _, c := range []struct {
		name      string
		got, want float64
	}{
		{"Supply", gt.Supply, w.Supply},
		{"SupplyPrev", gt.SupplyPrev, w.SupplyPrev},
		{"Demand", gt.Demand, w.Demand},
		{"Cleared", gt.Cleared, w.Cleared},
	} {
		if c.got < c.want-tol || c.got > c.want+tol {
			t.Errorf("%s = %v, want %v (tol %v)", c.name, c.got, c.want, tol)
		}
	}
	// Ratios are dimensionless, so they should land much tighter.
	const ratioTol = 0.05
	if math.Abs(gt.MarginalRatio-w.MarginalRatio) > ratioTol {
		t.Errorf("MarginalRatio = %v, want %v", gt.MarginalRatio, w.MarginalRatio)
	}
	if math.Abs(gt.InframarginalRatio-w.InframarginalRatio) > ratioTol {
		t.Errorf("InframarginalRatio = %v, want %v", gt.InframarginalRatio, w.InframarginalRatio)
	}
}

func TestLogisticCoeffs_IsOddAndCentred(t *testing.T) {
	coeffs := LogisticCoeffs(13, 4.0)
	if len(coeffs) != 14 {
		t.Fatalf("len = %d, want 14", len(coeffs))
	}
	if coeffs[0] != 0.5 {
		t.Errorf("constant term = %v, want 0.5 (crossing at x=0)", coeffs[0])
	}
	for i := 2; i < len(coeffs); i += 2 {
		if coeffs[i] != 0 {
			t.Errorf("even coefficient %d = %v, want 0", i, coeffs[i])
		}
	}
}

func TestDecodeOneHot_PicksArgmaxPerSlot(t *testing.T) {
	g := testGrid()
	v := make([]float64, g.Len())
	v[g.Index(0, 3)] = 0.9
	v[g.Index(0, 2)] = 0.1
	v[g.Index(1, 6)] = 0.8
	got := DecodeOneHot(g, v)
	if got[0] != 3 {
		t.Errorf("slot 0 = %d, want 3", got[0])
	}
	if got[1] != 6 {
		t.Errorf("slot 1 = %d, want 6", got[1])
	}
}

func TestDecodeOneHot_NoClearingWhenFlat(t *testing.T) {
	g := testGrid()
	got := DecodeOneHot(g, make([]float64, g.Len()))
	for slot, k := range got {
		if k != NoClearing {
			t.Errorf("slot %d = %d, want NoClearing", slot, k)
		}
	}
}

// Regression: the crossing is not always the largest step in the
// aggregate curve. Here a large elastic seller sits well above the
// crossing, so its step dwarfs the true one — DecodeOneHot's argmax
// picks the wrong bucket and DecodeCrossing must not.
func TestDecodeCrossing_NotTheLargestStep(t *testing.T) {
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{
		{Slot: 0, PriceCt: 0.50, Quantity: 2},  // true crossing here
		{Slot: 0, PriceCt: 1.50, Quantity: 40}, // much bigger step, far above
	})
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 1.75, Quantity: 2}})
	want, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}

	env := newTestEnv(t, 8192, PinnedDepth)
	h := env.handle
	ctS, err := h.Encrypt(sup)
	if err != nil {
		t.Fatalf("encrypt supply: %v", err)
	}
	ctD, err := h.Encrypt(dem)
	if err != nil {
		t.Fatalf("encrypt demand: %v", err)
	}

	// Scale to roughly 2x the largest |E| so the comparator argument stays
	// in [-0.5, 0.5] and the degree-13 series stays in its trusted domain.
	out, err := EvalClearing(h, g, ClearingInputs{Supply: ctS, Demand: ctD},
		LogisticCoeffs(13, 4.0), 84.0)
	if err != nil {
		t.Fatalf("EvalClearing: %v", err)
	}

	gotCross := DecodeCrossing(g, env.decrypt(t, out.Step, g.Len()))
	if gotCross[0] != want[0].Bucket {
		t.Errorf("DecodeCrossing = %d, want %d", gotCross[0], want[0].Bucket)
	}
	gotArgmax := DecodeOneHot(g, env.decrypt(t, out.OneHot, g.Len()))
	t.Logf("crossing=%d (correct), one-hot argmax=%d, oracle=%d",
		gotCross[0], gotArgmax[0], want[0].Bucket)
}

// envDecrypt is decrypt without t.Fatalf, for probes that need to
// distinguish "did not decrypt" from "test failed".
func envDecrypt(e *testEnv, ct []byte, nSlots int) ([]float64, error) {
	p1, err := cgo.PartialDecryptCKKSForContract(e.params, ct, e.first.SecretKeyShare, e.first.Lead)
	if err != nil {
		return nil, err
	}
	p2, err := cgo.PartialDecryptCKKSForContract(e.params, ct, e.second.SecretKeyShare, e.second.Lead)
	if err != nil {
		return nil, err
	}
	return cgo.FuseCKKSPartialsForContract(e.params, [][]byte{p1, p2}, nSlots)
}
