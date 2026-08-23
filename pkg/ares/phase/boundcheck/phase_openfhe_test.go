// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package boundcheck_test

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// buildN2Context provisions an n=2 threshold CKKS context for the bound-check
// phase round test. It returns:
//   - the cgo.ContractParams used for all crypto ops
//   - the two DistributedKeyShare values (shares[0] is lead)
//   - the combined EvalKeyFinal (eval-mult + eval-sum)
//   - the joint public key bytes (shares[1].PublicKey, i.e. the final key in the chain)
//   - a fhecalib.ContextHandle backed by the real cgo bridge
func buildN2Context(t *testing.T) (
	params cgo.ContractParams,
	shares [2]cgo.DistributedKeyShare,
	evalKeys cgo.EvalKeyFinal,
	jointPK []byte,
	handle fhecalib.ContextHandle,
) {
	t.Helper()

	// Dim=8 requires ringDim >= 16 slots, but we set to 1<<14 for adequate
	// depth budget (depth=1 confirmed by NormCircuit calibration test).
	params = cgo.DefaultContractParams(8, 2)
	params.RingDim = 1 << 14

	first, err := cgo.DistributedKeyGenFirst(params)
	if err != nil {
		t.Skipf("keygen first: %v", err)
	}
	second, err := cgo.DistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Skipf("keygen next: %v", err)
	}
	shares[0] = first
	shares[1] = second

	// Build the eval-key chain (same as buildJointEvalMultN2 in fhecalib).
	finalPK := second.PublicKey
	lead, err := cgo.EvalKeyRound1Lead(params, first.SecretKeyShare)
	if err != nil {
		t.Skipf("evalkey round1 lead: %v", err)
	}
	pks := [][]byte{first.PublicKey, second.PublicKey}
	r1Participant, err := cgo.EvalKeyRound1Participant(params, second.SecretKeyShare,
		lead.EvalMultBase, lead.EvalSumBase, second.PublicKey)
	if err != nil {
		t.Skipf("evalkey round1 participant: %v", err)
	}
	mr1 := [][]byte{lead.EvalMultBase, r1Participant.EvalMultSwitchShare}
	sr1 := [][]byte{lead.EvalSumBase, r1Participant.EvalSumShare}
	combined, err := cgo.CombineEvalKeyRound1(params, pks, mr1, sr1)
	if err != nil {
		t.Skipf("combine evalkey round1: %v", err)
	}
	r2First, err := cgo.EvalKeyRound2Participant(params, first.SecretKeyShare,
		combined.EvalMultJoined, finalPK, true /* lead */)
	if err != nil {
		t.Skipf("evalkey round2 first: %v", err)
	}
	r2Second, err := cgo.EvalKeyRound2Participant(params, second.SecretKeyShare,
		combined.EvalMultJoined, finalPK, false /* not lead */)
	if err != nil {
		t.Skipf("evalkey round2 second: %v", err)
	}
	final, err := cgo.CombineEvalKeyRound2(params, finalPK,
		[][]byte{r2First.EvalMultFinalShare, r2Second.EvalMultFinalShare},
		combined.EvalSumFinal)
	if err != nil {
		t.Skipf("combine evalkey round2: %v", err)
	}
	evalKeys = final
	jointPK = second.PublicKey

	hcParams := helperclient.ContractParams{
		RingDim:        params.RingDim,
		Depth:          params.Depth,
		ScalingModSize: 50,
	}
	handle = fhecalib.NewContextHandle(hcParams, evalKeys, jointPK)
	return
}

// unitNormVec returns a unit-norm 8-vector (‖v‖² = 1).
func unitNormVec() []float64 {
	dim := 8
	v := make([]float64, dim)
	for i := range v {
		v[i] = 1.0 / math.Sqrt(float64(dim))
	}
	return v
}

// inflatedVec returns an inflated 8-vector with ‖v‖² ≈ 4.0 (2 × unit-norm).
// nu = 4.0 - 1.01 = 2.99 > NuHard(1.25) → SeverityHard.
func inflatedVec() []float64 {
	v := unitNormVec()
	for i := range v {
		v[i] *= 2.0
	}
	return v
}

// partialMapForParty builds the JSON-encoded partial-decrypt map that one
// participant (identified by its secret key share and lead flag) produces for
// ALL check ciphertexts in checkCTs. The map is keyed by the checked party
// name. partiesOrder is the session's participants list; the caller passes
// lead=true only for participants[0].
func partialMapForParty(
	t *testing.T,
	params cgo.ContractParams,
	sk []byte,
	lead bool,
	checkCTs map[string][]byte,
	partiesOrder []string,
) []byte {
	t.Helper()
	m := make(map[string][]byte, len(checkCTs))
	for _, checkedParty := range partiesOrder {
		ct := checkCTs[checkedParty]
		partial, err := cgo.PartialDecryptCKKSForContract(params, ct, sk, lead)
		if err != nil {
			t.Fatalf("PartialDecryptCKKSForContract for checked party %q: %v", checkedParty, err)
		}
		m[checkedParty] = partial
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal partial map: %v", err)
	}
	return raw
}

// TestPhaseRound_RealFHE_P0OK_P1Violates is the canonical correctness test for
// the N-party quorum fuse path. With n=2 and a real OpenFHE backend:
//
//   - p0 encrypts a unit-norm 8-vector (‖x‖² ≈ 1.0) → should be in-bound.
//   - p1 encrypts a 2× inflated vector (‖x‖² ≈ 4.0) → nu≈2.99 > NuHard(1.25) → SeverityHard.
//
// Exit is expected to call handler.OnViolation for p1 with SeverityHard
// and return an error wrapping phase.ErrAppAttributable. p0 must NOT be
// flagged.
//
// Lead designation: participants = ["p0","p1"]; p0 is lead (lead=true) and
// p1 is follower (lead=false), mirroring the deterministic rule in the
// package doc. The partialMapForParty helper enforces this.
func TestPhaseRound_RealFHE_P0OK_P1Violates(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}

	params, shares, evalKeys, jointPK, handle := buildN2Context(t)

	// Fuse closure: binds cgoParams for real threshold decryption.
	fuseFn := func(partials [][]byte, nSlots int) ([]float64, error) {
		return cgo.FuseCKKSPartialsForContract(params, partials, nSlots)
	}

	const dim = 8
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: dim}
	handler := &captureHandler{}

	phaseParams := boundcheck.DefaultParams()
	ph := boundcheck.NewPhaseWithCrypto(
		circuit, handler, phaseParams,
		defaults.StateScoring, defaults.StateDecrypting,
		handle, fuseFn,
	)

	parties := []string{"p0", "p1"}

	// Encrypt inputs under the joint public key.
	encP0, err := cgo.EncryptCKKSForContract(params, jointPK, unitNormVec())
	if err != nil {
		t.Fatalf("encrypt p0: %v", err)
	}
	encP1, err := cgo.EncryptCKKSForContract(params, jointPK, inflatedVec())
	if err != nil {
		t.Fatalf("encrypt p1: %v", err)
	}

	ctx := phase.NewSessionContext("real-fhe-test")
	ctx.Set(defaults.CtxParticipants, parties)
	ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{
		"p0": encP0,
		"p1": encP1,
	})
	ctx.Set(boundcheck.CtxInputDim, dim)
	ctx.Set(boundcheck.CtxEvalKeyBundle, evalKeys.EvalMultFinal)
	ctx.Set(boundcheck.CtxJointPublicKey, jointPK)

	// Enter: computes enc_check for p0 and p1 via the norm circuit.
	if err := ph.Enter(ctx); err != nil {
		t.Fatalf("Enter: %v", err)
	}
	checkCTs, ok := phase.TryGet[map[string][]byte](ctx, boundcheck.CtxBoundCheckCiphers)
	if !ok {
		t.Fatal("CtxBoundCheckCiphers not set after Enter")
	}
	if len(checkCTs) != 2 {
		t.Fatalf("expected 2 check ciphertexts, got %d", len(checkCTs))
	}

	// Each party partial-decrypts BOTH check ciphertexts.
	// p0 = participants[0] → lead=true; p1 = participants[1] → lead=false.
	p0PartialMap := partialMapForParty(t, params, shares[0].SecretKeyShare, true, checkCTs, parties)
	p1PartialMap := partialMapForParty(t, params, shares[1].SecretKeyShare, false, checkCTs, parties)

	if err := ph.OnMessage(ctx, boundcheck.MsgBoundPartial, "p0", p0PartialMap); err != nil {
		t.Fatalf("OnMessage p0: %v", err)
	}
	if err := ph.OnMessage(ctx, boundcheck.MsgBoundPartial, "p1", p1PartialMap); err != nil {
		t.Fatalf("OnMessage p1: %v", err)
	}
	if !ph.CheckComplete(ctx) {
		t.Fatal("CheckComplete must be true after both parties submitted")
	}

	// Exit: fuse, classify, invoke handler, return error.
	exitErr := ph.Exit(ctx)
	if exitErr == nil {
		t.Fatal("Exit must return error when p1 is out-of-bound")
	}
	if !errors.Is(exitErr, phase.ErrAppAttributable) {
		t.Errorf("Exit error must wrap ErrAppAttributable; got %v", exitErr)
	}

	// Handler must have been called exactly once, for p1 with SeverityHard.
	// ‖inflated‖² ≈ 4.0 (2× unit-norm); bound Hi=1.01;
	// nu = 4.0 - 1.01 ≈ 2.99 > NuHard(1.25) → SeverityHard.
	if len(handler.calls) == 0 {
		t.Fatal("ViolationHandler.OnViolation was not called")
	}
	foundP1 := false
	for _, c := range handler.calls {
		if c.party == "p0" {
			t.Errorf("handler called for p0 (in-bound); nu=%.6f sev=%v", c.nu, c.sev)
		}
		if c.party == "p1" {
			foundP1 = true
			if c.sev != boundcheck.SeverityHard {
				t.Errorf("p1 violation severity = %v, want SeverityHard (nu=%.6f)", c.sev, c.nu)
			}
		}
	}
	if !foundP1 {
		t.Errorf("ViolationHandler not called for p1; calls = %v", handler.calls)
	}
	t.Logf("TestPhaseRound_RealFHE_P0OK_P1Violates: Exit error = %v, handler calls = %+v", exitErr, handler.calls)
}

// TestPhaseRound_RealFHE_BothOK confirms that when both parties submit
// unit-norm vectors, Exit returns nil and the handler is never invoked.
func TestPhaseRound_RealFHE_BothOK(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}

	params, shares, evalKeys, jointPK, handle := buildN2Context(t)

	fuseFn := func(partials [][]byte, nSlots int) ([]float64, error) {
		return cgo.FuseCKKSPartialsForContract(params, partials, nSlots)
	}

	const dim = 8
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: dim}
	handler := &captureHandler{}
	phaseParams := boundcheck.DefaultParams()

	ph := boundcheck.NewPhaseWithCrypto(
		circuit, handler, phaseParams,
		defaults.StateScoring, defaults.StateDecrypting,
		handle, fuseFn,
	)

	parties := []string{"p0", "p1"}

	// Both parties encrypt unit-norm vectors.
	encP0, err := cgo.EncryptCKKSForContract(params, jointPK, unitNormVec())
	if err != nil {
		t.Fatalf("encrypt p0: %v", err)
	}
	encP1, err := cgo.EncryptCKKSForContract(params, jointPK, unitNormVec())
	if err != nil {
		t.Fatalf("encrypt p1: %v", err)
	}

	ctx := phase.NewSessionContext("real-fhe-both-ok")
	ctx.Set(defaults.CtxParticipants, parties)
	ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{
		"p0": encP0,
		"p1": encP1,
	})
	ctx.Set(boundcheck.CtxInputDim, dim)
	ctx.Set(boundcheck.CtxEvalKeyBundle, evalKeys.EvalMultFinal)
	ctx.Set(boundcheck.CtxJointPublicKey, jointPK)

	if err := ph.Enter(ctx); err != nil {
		t.Fatalf("Enter: %v", err)
	}
	checkCTs, ok := phase.TryGet[map[string][]byte](ctx, boundcheck.CtxBoundCheckCiphers)
	if !ok {
		t.Fatal("CtxBoundCheckCiphers not set after Enter")
	}

	p0PartialMap := partialMapForParty(t, params, shares[0].SecretKeyShare, true, checkCTs, parties)
	p1PartialMap := partialMapForParty(t, params, shares[1].SecretKeyShare, false, checkCTs, parties)

	_ = ph.OnMessage(ctx, boundcheck.MsgBoundPartial, "p0", p0PartialMap)
	_ = ph.OnMessage(ctx, boundcheck.MsgBoundPartial, "p1", p1PartialMap)

	if exitErr := ph.Exit(ctx); exitErr != nil {
		t.Fatalf("Exit must return nil when all parties are in-bound; got %v", exitErr)
	}
	if len(handler.calls) != 0 {
		t.Fatalf("handler must not be called on all-in-bound; calls = %+v", handler.calls)
	}
	t.Logf("TestPhaseRound_RealFHE_BothOK: all parties passed bound check")
}
