// SPDX-License-Identifier: Apache-2.0

package rideshare

import (
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestBeginSession_InitialState verifies that BeginSession places
// the new session in the runner's declared initial state and
// returns a SessionContext keyed by the session ID.
func TestBeginSession_InitialState(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	ctx, err := r.BeginSession("ride-1", "cohort-A")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if ctx.SessionID != "ride-1" {
		t.Errorf("ctx.SessionID = %q, want %q", ctx.SessionID, "ride-1")
	}
	if ctx.CohortID != "cohort-A" {
		t.Errorf("ctx.CohortID = %q, want %q", ctx.CohortID, "cohort-A")
	}
	s, ok := r.CurrentState("ride-1")
	if !ok {
		t.Fatalf("CurrentState: session not tracked")
	}
	if s != StateInvite {
		t.Errorf("CurrentState = %q, want %q", s, StateInvite)
	}
}

// TestBeginSession_DuplicateRejected verifies that BeginSession with
// the same sessionID twice is rejected (sessions are tracked by ID).
func TestBeginSession_DuplicateRejected(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("dup", ""); err != nil {
		t.Fatalf("first BeginSession: %v", err)
	}
	if _, err := r.BeginSession("dup", ""); err == nil {
		t.Fatalf("expected duplicate BeginSession to fail")
	}
}

// TestBeginSession_EmptyIDRejected ensures empty sessionIDs are
// rejected at BeginSession time (the runner needs a non-empty key
// to track per-session state).
func TestBeginSession_EmptyIDRejected(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("", ""); err == nil {
		t.Fatalf("expected empty sessionID to be rejected")
	}
}

// TestAdvanceToState_WalksFullPipeline drives a session through
// every state of the ride-share pipeline. With stub Enter/Exit
// hooks, AdvanceToState should reach each target state without
// error and stop cleanly at Settle.
func TestAdvanceToState_WalksFullPipeline(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("walk", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	targets := []phase.SessionState{
		StateKeygen, StateSubmit, StateScore, StateDecrypt, StateSettle,
	}
	for _, target := range targets {
		if err := r.AdvanceToState("walk", target); err != nil {
			t.Fatalf("AdvanceToState(%q): %v", target, err)
		}
		got, _ := r.CurrentState("walk")
		if got != target {
			t.Errorf("after AdvanceToState(%q): CurrentState = %q", target, got)
		}
	}
}

// TestAdvanceToState_NoOpAtTarget confirms AdvanceToState returns
// nil immediately when the session is already in the target state.
func TestAdvanceToState_NoOpAtTarget(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("noop", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if err := r.AdvanceToState("noop", StateInvite); err != nil {
		t.Fatalf("AdvanceToState to current: %v", err)
	}
}

// TestAdvanceToState_UnknownSession verifies that AdvanceToState
// for an untracked sessionID returns an error rather than silently
// creating tracking state.
func TestAdvanceToState_UnknownSession(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	err = r.AdvanceToState("ghost", StateSubmit)
	if err == nil {
		t.Fatalf("expected AdvanceToState on untracked session to fail")
	}
}

// TestHandleMessage_RejectsUnknownType verifies that a message type
// the current phase does not consume returns an error and does not
// advance state.
func TestHandleMessage_RejectsUnknownType(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("msg-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	// PhaseInvite consumes no messages — every msgType rejects.
	_, err = r.HandleMessage("msg-1", "ride.bid", "driver-1", nil)
	if err == nil {
		t.Fatalf("expected HandleMessage to reject ride.bid in Invite state")
	}
	if !strings.Contains(err.Error(), "ride-invite") {
		t.Errorf("error %q does not mention current phase 'ride-invite'", err.Error())
	}
}

// TestHandleMessage_WrongPhaseForMessageType: at StateKeygen, the
// pipeline accepts ride.keygen.share but not ride.bid (which
// belongs to PhaseSubmit's next state).
func TestHandleMessage_WrongPhaseForMessageType(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("wrong", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if err := r.AdvanceToState("wrong", StateKeygen); err != nil {
		t.Fatalf("AdvanceToState(Keygen): %v", err)
	}
	if _, err := r.HandleMessage("wrong", "ride.bid", "rider", nil); err == nil {
		t.Fatalf("expected ride.bid to be rejected in Keygen state")
	}
}

// TestHandleMessage_UntrackedSession verifies HandleMessage on an
// unknown session returns an error.
func TestHandleMessage_UntrackedSession(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	_, err = r.HandleMessage("nobody", "ride.bid", "x", nil)
	if err == nil {
		t.Fatalf("expected HandleMessage on untracked session to fail")
	}
}

// TestEndSession_RemovesTracking confirms EndSession releases
// the runner's tracker so future HandleMessage / CurrentState
// calls treat the session as unknown.
func TestEndSession_RemovesTracking(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("end", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	r.EndSession("end")
	if _, ok := r.CurrentState("end"); ok {
		t.Errorf("CurrentState should report untracked after EndSession")
	}
	if _, err := r.HandleMessage("end", "ride.bid", "x", nil); err == nil {
		t.Errorf("expected HandleMessage after EndSession to fail")
	}
}

// TestPhaseForState_TerminalNotClaimed: StateNone (terminal) is
// not claimed by any phase.
func TestPhaseForState_TerminalNotClaimed(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, ok := r.PhaseForState(phase.StateNone); ok {
		t.Errorf("PhaseForState(StateNone) should be false")
	}
	if _, ok := r.PhaseForState("RIDE_BOGUS"); ok {
		t.Errorf("PhaseForState on unknown state should be false")
	}
}

// TestConsumedMessageTypes_AreDistinctPerPhase pins the message
// routing surface: each consumer phase owns its own types and they
// do not overlap with another phase's claim.
func TestConsumedMessageTypes_AreDistinctPerPhase(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	seen := map[string]string{}
	for _, p := range r.Phases() {
		for _, t := range p.ConsumedMessageTypes() {
			if other, dup := seen[t]; dup {
				if other != p.Name() {
					// fail the test
					reportCollision(p.Name(), other, t)
				}
			}
			seen[t] = p.Name()
		}
	}
	for _, want := range []string{"ride.keygen.share", "ride.bid", "ride.decrypt.partial"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("no phase consumes %q", want)
		}
	}
}

func reportCollision(a, b, msg string) {
	panic("ride-share phases " + a + " and " + b + " both claim message type " + msg)
}

// TestPhaseLifetimes verifies all ride-share phases are
// per-session — ride share has no cohort or persistent state.
func TestPhaseLifetimes(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	for _, p := range r.Phases() {
		if p.Lifetime() != phase.LifetimePerSession {
			t.Errorf("phase %q has Lifetime %q, want per-session",
				p.Name(), p.Lifetime())
		}
		if p.RunsAt() != phase.RunsAtInline {
			t.Errorf("phase %q has RunsAt %q, want inline",
				p.Name(), p.RunsAt())
		}
	}
}

// TestCryptoContract_DepthMinTooHigh: substitute a Score phase that
// requires depth_min=20. Invite emits depth=12; the runner must
// reject the composition.
func TestCryptoContract_DepthMinTooHigh(t *testing.T) {
	_, err := phase.Compose(
		NewPhaseInvite(),
		NewPhaseKeygen(),
		NewPhaseSubmit(),
		&deepScorePhase{},
		NewPhaseDecrypt(),
		NewPhaseSettle(),
	)
	if err == nil {
		t.Fatalf("expected runner to reject Score requiring depth_min=20 against Invite's depth=12")
	}
	if !strings.Contains(err.Error(), "depth_min") {
		t.Errorf("error %q does not mention depth_min constraint", err.Error())
	}
}

// deepScorePhase is a clone of PhaseScore demanding depth_min=20.
type deepScorePhase struct{}

func (deepScorePhase) Name() string                         { return "ride-score-deep" }
func (deepScorePhase) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (deepScorePhase) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (deepScorePhase) EntryState() phase.SessionState       { return StateScore }
func (deepScorePhase) ExitState() phase.SessionState        { return StateDecrypt }
func (deepScorePhase) InternalStates() []phase.SessionState { return nil }
func (deepScorePhase) ConsumedMessageTypes() []string       { return nil }
func (deepScorePhase) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:   {TypeName: "[]string", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 20}},
		CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxBids:           {TypeName: "RideShareBids", Required: true},
	}
}
func (deepScorePhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxWinner: {TypeName: "[]byte"}}
}
func (deepScorePhase) Enter(*phase.SessionContext) error { return nil }
func (deepScorePhase) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (deepScorePhase) CheckComplete(*phase.SessionContext) bool { return false }
func (deepScorePhase) Exit(*phase.SessionContext) error         { return nil }

// TestMissingProducerRejected: drop PhaseKeygen, the pipeline that
// needs CollectivePK / SecretShares / EvalKeys should fail to
// validate.
func TestMissingProducerRejected(t *testing.T) {
	_, err := phase.Compose(
		NewPhaseInvite(),
		// Keygen removed.
		NewPhaseSubmit(),
		NewPhaseScore(),
		NewPhaseDecrypt(),
		NewPhaseSettle(),
	)
	if err == nil {
		t.Fatalf("expected runner to reject pipeline missing PhaseKeygen")
	}
}

// TestDuplicatePhaseNameRejected: two phases with the same Name
// should be refused.
func TestDuplicatePhaseNameRejected(t *testing.T) {
	_, err := phase.Compose(
		NewPhaseInvite(),
		NewPhaseInvite(), // duplicate name "ride-invite"
		NewPhaseKeygen(),
		NewPhaseSubmit(),
		NewPhaseScore(),
		NewPhaseDecrypt(),
		NewPhaseSettle(),
	)
	if err == nil {
		t.Fatalf("expected duplicate-name pipeline to be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error %q does not mention 'duplicate'", err.Error())
	}
}

// TestInviteProvidesContractWithDepth12 pins the ride-share contract
// at depth=12 (between auction depth=10 and Fheya depth=30) — a
// regression here probably means someone tuned the circuit.
func TestInviteProvidesContractWithDepth12(t *testing.T) {
	p := NewPhaseInvite()
	got := p.Provides()[CtxCryptoContract]
	if got.Constraints["depth"] != 12 {
		t.Errorf("Invite Provides depth = %v, want 12", got.Constraints["depth"])
	}
}
