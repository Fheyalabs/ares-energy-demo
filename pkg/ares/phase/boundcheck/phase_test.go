// SPDX-License-Identifier: Apache-2.0

package boundcheck_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeContextHandle satisfies fhecalib.ContextHandle with canned responses.
// Every method returns the same cannedCT bytes regardless of input — the
// orchestration tests only verify that the check ciphertext map is populated,
// not that the bytes are cryptographically meaningful.
type fakeContextHandle struct {
	cannedCT []byte
}

func (h *fakeContextHandle) Params() helperclient.ContractParams {
	return helperclient.ContractParams{RingDim: 1024, Depth: 2}
}
func (h *fakeContextHandle) EvalMult(ctA, ctB []byte) ([]byte, error) {
	return h.cannedCT, nil
}
func (h *fakeContextHandle) EvalSubConst(ct []byte, vals []float64) ([]byte, error) {
	return h.cannedCT, nil
}
func (h *fakeContextHandle) EvalProductSum(ctLeft, ctRight []byte, nSlots int) ([]byte, error) {
	return h.cannedCT, nil
}

// captureHandler records every OnViolation call for assertions.
type captureHandler struct {
	calls []violationCall
}

type violationCall struct {
	party string
	nu    float64
	sev   boundcheck.Severity
}

func (h *captureHandler) OnViolation(_ *phase.SessionContext, party string, nu float64, sev boundcheck.Severity) error {
	h.calls = append(h.calls, violationCall{party: party, nu: nu, sev: sev})
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newCtx builds a populated SessionContext for the bound-check phase.
func newCtx(parties []string, encInputs map[string][]byte, dim int) *phase.SessionContext {
	ctx := phase.NewSessionContext("test-session")
	ctx.Set(defaults.CtxParticipants, parties)
	ctx.Set(boundcheck.CtxEncryptedInputs, encInputs)
	ctx.Set(boundcheck.CtxInputDim, dim)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("fake-eval-key"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("fake-joint-pk"))
	return ctx
}

// newStubPhase returns a stub-mode Phase with nil handle/fuse.
func newStubPhase(circuit boundcheck.BoundCircuit, handler boundcheck.ViolationHandler, p boundcheck.Params) *boundcheck.Phase {
	return boundcheck.NewPhase(circuit, handler, p, defaults.StateScoring, defaults.StateDecrypting)
}

// newRealPhase returns a real-mode Phase wired with the given fake crypto seams.
func newRealPhase(
	circuit boundcheck.BoundCircuit,
	handler boundcheck.ViolationHandler,
	p boundcheck.Params,
	handle *fakeContextHandle,
	fuse func([][]byte, int) ([]float64, error),
) *boundcheck.Phase {
	return boundcheck.NewPhaseWithCrypto(
		circuit, handler, p,
		defaults.StateScoring, defaults.StateDecrypting,
		handle, fuse,
	)
}

// makePartialMap builds a JSON-encoded map[string][]byte for the given parties,
// associating each party with the supplied partial blob. This reflects the
// N-party quorum shape: each sender partial-decrypts EVERY check ciphertext
// and replies with a map keyed by checkedParty.
// discriminant is prepended to each blob so the fake fuse can route by it.
func makePartialMap(parties []string, discriminant []byte) []byte {
	m := make(map[string][]byte, len(parties))
	for _, p := range parties {
		blob := append(append([]byte(nil), discriminant...), []byte(p)...)
		m[p] = blob
	}
	raw, _ := json.Marshal(m)
	return raw
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestPhase_Enter_PopulatesBoundCheckCiphers verifies that Enter computes a
// check ciphertext entry for every party in CtxEncryptedInputs and stores
// them all in CtxBoundCheckCiphers (uniform per-party guarantee).
func TestPhase_Enter_PopulatesBoundCheckCiphers(t *testing.T) {
	cannedCT := []byte("fake-check-ct")
	handle := &fakeContextHandle{cannedCT: cannedCT}
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		return []float64{1.0}, nil // irrelevant for Enter test
	}

	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	p := newRealPhase(circuit, nil, boundcheck.DefaultParams(), handle, fakeFuse)

	parties := []string{"alice", "bob", "carol"}
	encInputs := map[string][]byte{
		"alice": []byte("enc-alice"),
		"bob":   []byte("enc-bob"),
		"carol": []byte("enc-carol"),
	}
	ctx := newCtx(parties, encInputs, 4)

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("Enter: %v", err)
	}

	checks, ok := phase.TryGet[map[string][]byte](ctx, boundcheck.CtxBoundCheckCiphers)
	if !ok {
		t.Fatal("CtxBoundCheckCiphers not set after Enter")
	}
	// Assert an entry for every party.
	for _, party := range parties {
		if _, found := checks[party]; !found {
			t.Errorf("CtxBoundCheckCiphers missing entry for party %q", party)
		}
	}
	// No extra entries.
	if len(checks) != len(parties) {
		t.Errorf("CtxBoundCheckCiphers has %d entries, want %d", len(checks), len(parties))
	}
}

// TestPhase_CheckComplete_QuorumGating verifies that CheckComplete is false
// until all N participants have submitted MsgBoundPartial (N-of-N quorum).
func TestPhase_CheckComplete_QuorumGating(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	parties := []string{"a", "b"}
	ctx := newCtx(parties, map[string][]byte{"a": []byte("x"), "b": []byte("y")}, 4)

	if p.CheckComplete(ctx) {
		t.Fatal("CheckComplete must be false with 0/2 partials")
	}

	// Each party sends a JSON partial map covering both check ciphertexts.
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "a", makePartialMap(parties, []byte("pa-")))
	if p.CheckComplete(ctx) {
		t.Fatal("CheckComplete must be false with 1/2 partials")
	}

	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "b", makePartialMap(parties, []byte("pb-")))
	if !p.CheckComplete(ctx) {
		t.Fatal("CheckComplete must be true with 2/2 partials")
	}
}

// TestPhase_Exit_ViolationCallsHandlerAndAborts checks that when the fake
// fuse returns an out-of-bound value for one party's quorum of partials, Exit:
//   - calls the ViolationHandler with that party's name, nu, and sev;
//   - returns an error that errors.Is(err, phase.ErrAppAttributable) == true.
//
// The fake fuse discriminates by the first byte of the FIRST partial blob in
// the quorum: 'v' prefix → out-of-bound; any other → in-bound. Since
// participants order determines which sender's partial comes first, and the
// partial for the violating party ("bob") includes discriminant bytes, the
// fake signals the violation via the lead partial's content.
func TestPhase_Exit_ViolationCallsHandlerAndAborts(t *testing.T) {
	violatorParty := "bob"
	inBoundValue := 1.0  // norm 1.0 is within [0.99, 1.01]
	outBoundValue := 5.0 // far outside [0.99, 1.01] -> hard violation

	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	params := boundcheck.DefaultParams()
	handler := &captureHandler{}

	// Fuse discriminates by the first byte of the first partial blob:
	// 'v' prefix -> violating -> out-of-bound; else in-bound.
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		if len(partials) > 0 && len(partials[0]) > 0 && partials[0][0] == 'v' {
			return []float64{outBoundValue}, nil
		}
		return []float64{inBoundValue}, nil
	}

	handle := &fakeContextHandle{cannedCT: []byte("ct")}
	p := newRealPhase(circuit, handler, params, handle, fakeFuse)

	parties := []string{"alice", violatorParty} // alice is participants[0] (lead)
	ctx := newCtx(parties, map[string][]byte{"alice": []byte("x"), violatorParty: []byte("y")}, 4)

	_ = p.Enter(ctx)

	// alice (lead, participants[0]) sends partial maps:
	// - for "alice": discriminant 'a' -> in-bound
	// - for "bob": discriminant 'a' -> in-bound (alice's partial of bob's ct is also 'a')
	// bob sends partial maps:
	// - for "alice": discriminant 'a' -> in-bound (bob's partial of alice's ct)
	// - for "bob": discriminant 'v' -> out-of-bound (bob's partial of bob's ct)
	//
	// When Exit assembles partials for "bob":
	//   partialsForBob = [alice's blob for "bob", bob's blob for "bob"]
	//   alice's blob for "bob" = 'a' + "bob" -> first byte 'a' -> in-bound via fuse... BUT
	//   we need the FIRST partial (from participants[0]=alice) to have 'v' for bob.
	//
	// To signal a violation for "bob", we make alice's partial for "bob" start with 'v':
	aliceMap := map[string][]byte{
		"alice": []byte("alice-partial-of-alice"), // 'a' -> in-bound
		"bob":   []byte("violating-partial-of-bob"), // 'v' -> out-of-bound
	}
	alicePayload, _ := json.Marshal(aliceMap)

	bobMap := map[string][]byte{
		"alice": []byte("bob-partial-of-alice"), // 'b' -> in-bound
		"bob":   []byte("bob-partial-of-bob"),   // 'b' -> in-bound (alice's partial drives the signal)
	}
	bobPayload, _ := json.Marshal(bobMap)

	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "alice", alicePayload)
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, violatorParty, bobPayload)

	err := p.Exit(ctx)
	if err == nil {
		t.Fatal("Exit must return error on violation")
	}
	if !errors.Is(err, phase.ErrAppAttributable) {
		t.Errorf("Exit error must wrap ErrAppAttributable; got %v", err)
	}

	// Handler must have been called at least once.
	if len(handler.calls) == 0 {
		t.Fatal("ViolationHandler.OnViolation was not called")
	}
	// At least one call must be for the violating party.
	found := false
	for _, c := range handler.calls {
		if c.party == violatorParty {
			found = true
			if c.sev == boundcheck.SeverityOK {
				t.Errorf("handler called with SeverityOK for violating party; sev=%v", c.sev)
			}
		}
	}
	if !found {
		t.Errorf("handler not called for violating party %q; calls = %v", violatorParty, handler.calls)
	}
}

// TestPhase_Exit_AllInBound_NoHandlerNoError verifies that when all parties
// submit in-bound values, Exit returns nil and the ViolationHandler is never
// invoked.
func TestPhase_Exit_AllInBound_NoHandlerNoError(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	params := boundcheck.DefaultParams()
	handler := &captureHandler{}

	// Fuse always returns in-bound value.
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		return []float64{1.0}, nil // 1.0 is within [0.99, 1.01]
	}

	handle := &fakeContextHandle{cannedCT: []byte("ct")}
	p := newRealPhase(circuit, handler, params, handle, fakeFuse)

	parties := []string{"alice", "bob"}
	ctx := newCtx(parties, map[string][]byte{"alice": []byte("x"), "bob": []byte("y")}, 4)

	_ = p.Enter(ctx)
	// Each party sends a JSON partial map covering both check ciphertexts.
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "alice", makePartialMap(parties, []byte("pa-")))
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "bob", makePartialMap(parties, []byte("pb-")))

	if err := p.Exit(ctx); err != nil {
		t.Fatalf("Exit must return nil for all-in-bound; got %v", err)
	}
	if len(handler.calls) != 0 {
		t.Fatalf("ViolationHandler must not be called on all-in-bound; calls = %v", handler.calls)
	}
}

// TestPhase_Invariant5_DimRefusal checks that Enter returns a non-nil error
// for CtxInputDim == 0 and CtxInputDim == 1 (invariant #5).
func TestPhase_Invariant5_DimRefusal(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 2}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	for _, dim := range []int{0, 1} {
		ctx := phase.NewSessionContext("dim-test")
		ctx.Set(defaults.CtxParticipants, []string{"a"})
		ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{"a": []byte("x")})
		ctx.Set(boundcheck.CtxInputDim, dim)
		ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("key"))
		ctx.Set(boundcheck.CtxJointPublicKey, []byte("pk"))

		if err := p.Enter(ctx); err == nil {
			t.Errorf("Enter with dim=%d must return error (invariant #5)", dim)
		}
	}
}

// TestPhase_Invariant5_Dim2_OK confirms that dim >= 2 passes Enter without
// error in stub mode.
func TestPhase_Invariant5_Dim2_OK(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 2}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	ctx := phase.NewSessionContext("dim-ok")
	ctx.Set(defaults.CtxParticipants, []string{"a"})
	ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{"a": []byte("x")})
	ctx.Set(boundcheck.CtxInputDim, 2)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("key"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("pk"))

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("Enter with dim=2 must not error; got %v", err)
	}
}

// TestPhase_Invariant2_OneCircuit documents the structural single-circuit
// invariant: Phase has exactly one circuit field, enforced by the constructor
// signature. This is a runtime constructor test — the real enforcement is the
// single `circuit` field on Phase; a constructor change to accept multiple
// circuits would fail here at compile time.
func TestPhase_Invariant2_OneCircuit(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	p := boundcheck.NewPhase(circuit, nil, boundcheck.DefaultParams(), defaults.StateScoring, defaults.StateDecrypting)
	if p == nil {
		t.Fatal("NewPhase with one BoundCircuit must return non-nil Phase")
	}
	if p.Name() != "bound-check" {
		t.Errorf("Name() = %q, want %q", p.Name(), "bound-check")
	}
}

// TestPhase_Metadata confirms the phase metadata contract.
func TestPhase_Metadata(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	p := boundcheck.NewPhase(circuit, nil, boundcheck.DefaultParams(), defaults.StateScoring, defaults.StateDecrypting)

	if p.Lifetime() != phase.LifetimePerSession {
		t.Errorf("Lifetime = %v, want LifetimePerSession", p.Lifetime())
	}
	if p.RunsAt() != phase.RunsAtInline {
		t.Errorf("RunsAt = %v, want RunsAtInline", p.RunsAt())
	}
	if p.EntryState() != defaults.StateScoring {
		t.Errorf("EntryState = %q, want SCORING", p.EntryState())
	}
	if p.ExitState() != defaults.StateDecrypting {
		t.Errorf("ExitState = %q, want DECRYPTING", p.ExitState())
	}
	if p.InternalStates() != nil {
		t.Errorf("InternalStates must be nil")
	}
	consumed := p.ConsumedMessageTypes()
	if len(consumed) != 1 || consumed[0] != boundcheck.MsgBoundPartial {
		t.Errorf("ConsumedMessageTypes = %v, want [%q]", consumed, boundcheck.MsgBoundPartial)
	}
}

// TestPhase_Exit_MissingPartial_BlamesWithholdingSender verifies that when a
// sender's MsgBoundPartial map omits another party's entry, Exit:
//   - calls ViolationHandler with the WITHHOLDING SENDER's identity (not the
//     checked party whose ciphertext could not be assembled), with SeverityHard;
//   - returns an error that errors.Is(err, phase.ErrAppAttributable) == true.
func TestPhase_Exit_MissingPartial_BlamesWithholdingSender(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	params := boundcheck.DefaultParams()
	handler := &captureHandler{}

	// Fuse always succeeds — it should not be called for the incomplete quorum.
	fuseCallCount := 0
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		fuseCallCount++
		return []float64{1.0}, nil
	}

	handle := &fakeContextHandle{cannedCT: []byte("ct")}
	p := newRealPhase(circuit, handler, params, handle, fakeFuse)

	parties := []string{"alice", "bob", "carol"}
	ctx := newCtx(parties, map[string][]byte{
		"alice": []byte("enc-alice"),
		"bob":   []byte("enc-bob"),
		"carol": []byte("enc-carol"),
	}, 4)

	_ = p.Enter(ctx)

	// alice sends a complete map covering all three checked parties.
	aliceMap := map[string][]byte{
		"alice": []byte("alice-partial-of-alice"),
		"bob":   []byte("alice-partial-of-bob"),
		"carol": []byte("alice-partial-of-carol"),
	}
	alicePayload, _ := json.Marshal(aliceMap)

	// bob sends a map that OMITS "carol" — bob is the withholding sender.
	bobMap := map[string][]byte{
		"alice": []byte("bob-partial-of-alice"),
		"bob":   []byte("bob-partial-of-bob"),
		// "carol" intentionally absent
	}
	bobPayload, _ := json.Marshal(bobMap)

	// carol sends a complete map.
	carolMap := map[string][]byte{
		"alice": []byte("carol-partial-of-alice"),
		"bob":   []byte("carol-partial-of-bob"),
		"carol": []byte("carol-partial-of-carol"),
	}
	carolPayload, _ := json.Marshal(carolMap)

	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "alice", alicePayload)
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "bob", bobPayload)
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "carol", carolPayload)

	err := p.Exit(ctx)
	if err == nil {
		t.Fatal("Exit must return error when a sender withholds a partial")
	}
	if !errors.Is(err, phase.ErrAppAttributable) {
		t.Errorf("Exit error must wrap ErrAppAttributable; got %v", err)
	}

	// Handler must have been called for the WITHHOLDING SENDER ("bob"),
	// not for "carol" (the checked party whose quorum was incomplete).
	if len(handler.calls) == 0 {
		t.Fatal("ViolationHandler.OnViolation was not called")
	}
	foundBob := false
	foundCarol := false
	for _, c := range handler.calls {
		if c.party == "bob" {
			foundBob = true
			if c.sev != boundcheck.SeverityHard {
				t.Errorf("withholding sender bob: want SeverityHard, got %v", c.sev)
			}
		}
		if c.party == "carol" {
			foundCarol = true
		}
	}
	if !foundBob {
		t.Errorf("handler not called for withholding sender %q; calls = %v", "bob", handler.calls)
	}
	if foundCarol {
		t.Errorf("handler must NOT be called for checked party %q (victim, not violator); calls = %v", "carol", handler.calls)
	}
}

// TestPhase_Enter_EmitsCheckCommitments verifies that Enter (real mode)
// populates CtxBoundCheckCommitments with the correct binding digest for
// every party. The expected digest is computed independently as:
//
//	inner = SHA256(enc_x_i)
//	commitment_i = SHA256(enc_check_i ‖ inner ‖ session_id)
//
// The test uses a fakeContextHandle whose cannedCT is the enc_check value
// returned for every party, and asserts exact equality for two parties.
func TestPhase_Enter_EmitsCheckCommitments(t *testing.T) {
	const sessionID = "test-session-commit-001"
	cannedCT := []byte("canned-enc-check-bytes")
	handle := &fakeContextHandle{cannedCT: cannedCT}
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		return []float64{1.0}, nil
	}

	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	p := newRealPhase(circuit, nil, boundcheck.DefaultParams(), handle, fakeFuse)

	parties := []string{"alice", "bob"}
	encInputs := map[string][]byte{
		"alice": []byte("enc-input-alice"),
		"bob":   []byte("enc-input-bob"),
	}

	ctx := phase.NewSessionContext(sessionID)
	ctx.Set(defaults.CtxParticipants, parties)
	ctx.Set(boundcheck.CtxEncryptedInputs, encInputs)
	ctx.Set(boundcheck.CtxInputDim, 4)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("fake-eval-key"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("fake-joint-pk"))

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("Enter: %v", err)
	}

	commitments, ok := phase.TryGet[map[string][]byte](ctx, boundcheck.CtxBoundCheckCommitments)
	if !ok {
		t.Fatal("CtxBoundCheckCommitments not set after Enter")
	}
	if len(commitments) != len(parties) {
		t.Errorf("CtxBoundCheckCommitments has %d entries, want %d", len(commitments), len(parties))
	}

	// Independently recompute the expected commitment for each party and
	// assert byte-for-byte equality. enc_check is cannedCT for all parties
	// (fakeContextHandle returns the same bytes regardless of input).
	for _, party := range parties {
		encX := encInputs[party]
		inner := sha256.Sum256(encX)
		h := sha256.New()
		h.Write(cannedCT)
		h.Write(inner[:])
		h.Write([]byte(sessionID))
		want := h.Sum(nil)

		got, found := commitments[party]
		if !found {
			t.Errorf("CtxBoundCheckCommitments missing entry for party %q", party)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("party %q: commitment mismatch\n  got  %x\n  want %x", party, got, want)
		}
	}
}

// TestPhase_Enter_DimMismatch asserts that Enter returns a permanent error
// when CtxInputDim does not match the circuit's Dim().
func TestPhase_Enter_DimMismatch(t *testing.T) {
	// Circuit expects dim=4; session provides dim=8 — mismatch must be rejected.
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	ctx := phase.NewSessionContext("dim-mismatch-test")
	ctx.Set(defaults.CtxParticipants, []string{"a"})
	ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{"a": []byte("x")})
	ctx.Set(boundcheck.CtxInputDim, 8) // 8 != circuit.Dim()=4
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("key"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("pk"))

	err := p.Enter(ctx)
	if err == nil {
		t.Fatal("Enter must return error when CtxInputDim != circuit.Dim()")
	}
	if !errors.Is(err, phase.ErrPermanent) {
		t.Errorf("dim-mismatch error must wrap ErrPermanent; got %v", err)
	}
}

// TestPhase_StubMode_EnterExitNoop confirms that stub mode (nil handle and
// fuse) leaves CtxBoundCheckCiphers absent and Exit returns nil regardless
// of accumulated partials. This is the compose-time structural test mode.
func TestPhase_StubMode_EnterExitNoop(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, NDim: 4}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	parties := []string{"a", "b"}
	ctx := newCtx(parties, map[string][]byte{"a": []byte("x"), "b": []byte("y")}, 4)

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("stub Enter: %v", err)
	}
	// CtxBoundCheckCiphers must NOT be set in stub mode.
	if ctx.Has(boundcheck.CtxBoundCheckCiphers) {
		t.Error("stub Enter must not set CtxBoundCheckCiphers")
	}

	// Accumulate partials to reach quorum.
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "a", makePartialMap(parties, []byte("pa")))
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "b", makePartialMap(parties, []byte("pb")))
	if !p.CheckComplete(ctx) {
		t.Fatal("stub CheckComplete must be true after N-of-N partials")
	}

	if err := p.Exit(ctx); err != nil {
		t.Fatalf("stub Exit must return nil; got %v", err)
	}
}
