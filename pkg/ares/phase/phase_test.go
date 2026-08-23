// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"errors"
	"strings"
	"testing"
)

// --- mock phase used by the runner tests --------------------------------

// mockPhase is a fully configurable Phase implementation for tests.
// Every interface method delegates to a struct field so individual
// tests can construct exactly the phase shape they need without
// defining new types.
type mockPhase struct {
	name      string
	lifetime  Lifetime
	runsAt    RunsAt
	entry     SessionState
	exit      SessionState
	internals []SessionState
	messages  []string
	requires  ContextSchema
	provides  ContextSchema
	enterErr  error
	exitErr   error
	onMsgErr  error
	completeAfterN int // CheckComplete returns true after N OnMessage calls
	enterFn   func(ctx *SessionContext)
	exitFn    func(ctx *SessionContext)
	onMsgFn   func(ctx *SessionContext, msgType, from string, payload []byte)
	// runtime counters used by tests
	enterCount int
	exitCount  int
	msgCount   int
}

func (m *mockPhase) Name() string                   { return m.name }
func (m *mockPhase) Lifetime() Lifetime             { return m.lifetime }
func (m *mockPhase) RunsAt() RunsAt                 { return m.runsAt }
func (m *mockPhase) EntryState() SessionState       { return m.entry }
func (m *mockPhase) ExitState() SessionState        { return m.exit }
func (m *mockPhase) InternalStates() []SessionState { return m.internals }
func (m *mockPhase) ConsumedMessageTypes() []string { return m.messages }
func (m *mockPhase) Requires() ContextSchema        { return m.requires }
func (m *mockPhase) Provides() ContextSchema        { return m.provides }

func (m *mockPhase) Enter(ctx *SessionContext) error {
	m.enterCount++
	if m.enterFn != nil {
		m.enterFn(ctx)
	}
	return m.enterErr
}

func (m *mockPhase) OnMessage(ctx *SessionContext, msgType, from string, payload []byte) error {
	m.msgCount++
	if m.onMsgFn != nil {
		m.onMsgFn(ctx, msgType, from, payload)
	}
	return m.onMsgErr
}

func (m *mockPhase) CheckComplete(ctx *SessionContext) bool {
	if m.completeAfterN <= 0 {
		return true
	}
	return m.msgCount >= m.completeAfterN
}

func (m *mockPhase) Exit(ctx *SessionContext) error {
	m.exitCount++
	if m.exitFn != nil {
		m.exitFn(ctx)
	}
	return m.exitErr
}

// --- SessionContext tests ---------------------------------------------

func TestSessionContext_GetSetHasKeys(t *testing.T) {
	ctx := NewSessionContext("sess-1")
	if ctx.Has("missing") {
		t.Fatalf("empty context should not Has missing key")
	}
	ctx.Set("a", 42)
	ctx.Set("b", "hello")

	if !ctx.Has("a") {
		t.Errorf("expected Has(a) = true")
	}
	v, ok := ctx.Get("a")
	if !ok || v.(int) != 42 {
		t.Errorf("Get(a) = %v, %v, want 42, true", v, ok)
	}
	keys := ctx.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys() returned %d entries, want 2: %v", len(keys), keys)
	}
}

func TestSessionContext_MustGetTryGet(t *testing.T) {
	ctx := NewSessionContext("sess-1")
	ctx.Set("score", 3.14)
	if v := MustGet[float64](ctx, "score"); v != 3.14 {
		t.Errorf("MustGet returned %v, want 3.14", v)
	}
	if v, ok := TryGet[float64](ctx, "score"); !ok || v != 3.14 {
		t.Errorf("TryGet returned %v, %v, want 3.14, true", v, ok)
	}
	if _, ok := TryGet[string](ctx, "score"); ok {
		t.Errorf("TryGet[string] of a float64 key should be false")
	}
	defer func() {
		if recover() == nil {
			t.Errorf("MustGet of missing key should panic")
		}
	}()
	MustGet[int](ctx, "missing")
}

// --- SessionRunner construction tests --------------------------------

func TestNewSessionRunner_RejectsEmpty(t *testing.T) {
	if _, err := Compose(); err == nil {
		t.Errorf("expected error for empty phase list")
	}
}

func TestNewSessionRunner_RejectsDuplicateName(t *testing.T) {
	a := &mockPhase{name: "dup", runsAt: RunsAtInline, entry: "S1", exit: "S2", messages: []string{"m"}}
	b := &mockPhase{name: "dup", runsAt: RunsAtInline, entry: "S2", exit: StateNone, messages: []string{"m"}}
	_, err := Compose(a, b)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestNewSessionRunner_RejectsDisconnectedChain(t *testing.T) {
	a := &mockPhase{name: "a", runsAt: RunsAtInline, entry: "S1", exit: "S2", messages: []string{"m"}}
	b := &mockPhase{name: "b", runsAt: RunsAtInline, entry: "S3", exit: StateNone, messages: []string{"m"}}
	_, err := Compose(a, b)
	if err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected disconnected-chain error, got %v", err)
	}
}

func TestNewSessionRunner_RejectsUnsatisfiedRequires(t *testing.T) {
	a := &mockPhase{
		name:    "consumer",
		runsAt:  RunsAtInline,
		entry:   "S1",
		exit:    StateNone,
		messages: []string{"m"},
		requires: ContextSchema{"crypto_ctx": {TypeName: "Foo", Required: true}},
	}
	_, err := Compose(a)
	if err == nil || !strings.Contains(err.Error(), "no preceding phase provides") {
		t.Fatalf("expected unsatisfied-requires error, got %v", err)
	}
}

func TestNewSessionRunner_AcceptsSatisfiedConstraintChain(t *testing.T) {
	keygen := &mockPhase{
		name:     "keygen",
		runsAt:   RunsAtInline,
		entry:    "S1",
		exit:     "S2",
		messages: []string{"keygen.share"},
		provides: ContextSchema{
			"crypto_ctx": {
				TypeName:    "OpenFHEContract",
				Required:    false,
				Constraints: map[string]any{"depth": 30, "ring_dim": 4096},
			},
		},
	}
	scoring := &mockPhase{
		name:     "scoring",
		runsAt:   RunsAtInline,
		entry:    "S2",
		exit:     StateNone,
		messages: []string{"submit.distance"},
		requires: ContextSchema{
			"crypto_ctx": {
				TypeName:    "OpenFHEContract",
				Required:    true,
				Constraints: map[string]any{"depth_min": 20, "ring_dim_min": 2048},
			},
		},
	}
	r, err := Compose(keygen, scoring)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if r.InitialState() != "S1" {
		t.Errorf("InitialState = %q, want S1", r.InitialState())
	}
}

func TestNewSessionRunner_RejectsInsufficientDepth(t *testing.T) {
	keygen := &mockPhase{
		name:   "keygen",
		runsAt: RunsAtInline,
		entry:  "S1",
		exit:   "S2",
		messages: []string{"k"},
		provides: ContextSchema{
			"crypto_ctx": {
				TypeName:    "OpenFHEContract",
				Constraints: map[string]any{"depth": 6},
			},
		},
	}
	scoring := &mockPhase{
		name:   "scoring",
		runsAt: RunsAtInline,
		entry:  "S2",
		exit:   StateNone,
		messages: []string{"s"},
		requires: ContextSchema{
			"crypto_ctx": {
				TypeName:    "OpenFHEContract",
				Required:    true,
				Constraints: map[string]any{"depth_min": 20},
			},
		},
	}
	_, err := Compose(keygen, scoring)
	if err == nil || !strings.Contains(err.Error(), "depth_min") {
		t.Fatalf("expected insufficient-depth error, got %v", err)
	}
}

func TestNewSessionRunner_RejectsAmbiguousEntryState(t *testing.T) {
	a := &mockPhase{name: "a", runsAt: RunsAtInline, entry: "S1", exit: "S2", messages: []string{"m"}}
	b := &mockPhase{name: "b", runsAt: RunsAtInline, entry: "S1", exit: StateNone, messages: []string{"m"}}
	_, err := Compose(a, b)
	if err == nil || !strings.Contains(err.Error(), "claimed by both") {
		t.Fatalf("expected ambiguous-entry-state error, got %v", err)
	}
}

// --- SessionRunner runtime tests --------------------------------------

func TestRunner_TrivialThreePhasePipelineRunsEndToEnd(t *testing.T) {
	a := &mockPhase{
		name:           "register",
		runsAt:         RunsAtInline,
		entry:          "REGISTER",
		exit:           "SUBMIT",
		messages:       []string{"hello"},
		completeAfterN: 1,
		provides: ContextSchema{
			"pseudonym": {TypeName: "string"},
		},
		onMsgFn: func(ctx *SessionContext, msgType, from string, payload []byte) {
			ctx.Set("pseudonym", from)
		},
	}
	b := &mockPhase{
		name:           "submit",
		runsAt:         RunsAtInline,
		entry:          "SUBMIT",
		exit:           "RESULT",
		messages:       []string{"data"},
		completeAfterN: 1,
		requires:       ContextSchema{"pseudonym": {TypeName: "string", Required: true}},
		provides:       ContextSchema{"score": {TypeName: "int"}},
		onMsgFn: func(ctx *SessionContext, msgType, from string, payload []byte) {
			ctx.Set("score", len(payload))
		},
	}
	c := &mockPhase{
		name:           "result",
		runsAt:         RunsAtInline,
		entry:          "RESULT",
		exit:           StateNone,
		messages:       []string{"ack"},
		completeAfterN: 1,
		requires:       ContextSchema{"score": {TypeName: "int", Required: true}},
	}

	r, err := Compose(a, b, c)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx, err := r.BeginSession("session-1", "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if a.enterCount != 1 {
		t.Errorf("phase a Enter count = %d, want 1", a.enterCount)
	}

	// Phase a consumes "hello".
	advanced, err := r.HandleMessage("session-1", "hello", "alice", nil)
	if err != nil {
		t.Fatalf("HandleMessage(hello): %v", err)
	}
	if !advanced {
		t.Errorf("expected pipeline to advance after a's only message")
	}
	if a.exitCount != 1 {
		t.Errorf("phase a Exit count = %d, want 1", a.exitCount)
	}
	if b.enterCount != 1 {
		t.Errorf("phase b Enter count = %d, want 1", b.enterCount)
	}
	if ps, _ := ctx.Get("pseudonym"); ps != "alice" {
		t.Errorf("expected pseudonym alice, got %v", ps)
	}

	if state, _ := r.CurrentState("session-1"); state != "SUBMIT" {
		t.Errorf("after a, state = %q, want SUBMIT", state)
	}

	advanced, err = r.HandleMessage("session-1", "data", "alice", []byte("xyz"))
	if err != nil {
		t.Fatalf("HandleMessage(data): %v", err)
	}
	if !advanced {
		t.Errorf("expected pipeline to advance after b's only message")
	}
	if score, _ := ctx.Get("score"); score != 3 {
		t.Errorf("expected score 3, got %v", score)
	}

	if state, _ := r.CurrentState("session-1"); state != "RESULT" {
		t.Errorf("after b, state = %q, want RESULT", state)
	}

	advanced, err = r.HandleMessage("session-1", "ack", "alice", nil)
	if err != nil {
		t.Fatalf("HandleMessage(ack): %v", err)
	}
	if !advanced {
		t.Errorf("expected pipeline to terminate after c's only message")
	}
	if state, _ := r.CurrentState("session-1"); state != StateNone {
		t.Errorf("after c, state = %q, want StateNone", state)
	}

	r.EndSession("session-1")
	if _, ok := r.CurrentState("session-1"); ok {
		t.Errorf("session should be gone after EndSession")
	}
}

func TestRunner_RejectsWrongMessageType(t *testing.T) {
	a := &mockPhase{
		name:           "a",
		runsAt:         RunsAtInline,
		entry:          "S1",
		exit:           StateNone,
		messages:       []string{"expected"},
		completeAfterN: 1,
	}
	r, err := Compose(a)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if _, err := r.BeginSession("s", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	_, err = r.HandleMessage("s", "unexpected", "from", nil)
	if err == nil || !strings.Contains(err.Error(), "does not consume") {
		t.Errorf("expected does-not-consume error, got %v", err)
	}
}

func TestRunner_BubblesPhaseErrors(t *testing.T) {
	a := &mockPhase{
		name:           "a",
		runsAt:         RunsAtInline,
		entry:          "S1",
		exit:           StateNone,
		messages:       []string{"m"},
		onMsgErr:       errors.New("boom"),
		completeAfterN: 1,
	}
	r, err := Compose(a)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if _, err := r.BeginSession("s", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if _, err := r.HandleMessage("s", "m", "from", nil); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected boom propagated, got %v", err)
	}
}

func TestPhaseForState_FindsInternalStates(t *testing.T) {
	a := &mockPhase{
		name:      "a",
		runsAt:    RunsAtInline,
		entry:     "S1",
		exit:      "S2",
		internals: []SessionState{"S1_SUB"},
		messages:  []string{"m"},
		completeAfterN: 1,
	}
	b := &mockPhase{
		name:           "b",
		runsAt:         RunsAtInline,
		entry:          "S2",
		exit:           StateNone,
		messages:       []string{"m2"},
		completeAfterN: 1,
	}
	r, err := Compose(a, b)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if p, ok := r.PhaseForState("S1_SUB"); !ok || p.Name() != "a" {
		t.Errorf("PhaseForState(S1_SUB) = %v, %v; want phase a", p, ok)
	}
	if p, ok := r.PhaseForState("S1"); !ok || p.Name() != "a" {
		t.Errorf("PhaseForState(S1) = %v, %v; want phase a", p, ok)
	}
}

func TestAdvanceToState_TreatsInternalAsNoOp(t *testing.T) {
	a := &mockPhase{
		name:      "a",
		runsAt:    RunsAtInline,
		entry:     "S1",
		exit:      "S2",
		internals: []SessionState{"S1_SUB"},
		messages:  []string{"m"},
		completeAfterN: 1,
	}
	b := &mockPhase{
		name:           "b",
		runsAt:         RunsAtInline,
		entry:          "S2",
		exit:           StateNone,
		messages:       []string{"m2"},
		completeAfterN: 1,
	}
	r, err := Compose(a, b)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if _, err := r.BeginSession("s", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if err := r.AdvanceToState("s", "S1_SUB"); err != nil {
		t.Errorf("AdvanceToState(S1_SUB) should be a no-op for internal state, got: %v", err)
	}
	state, _ := r.CurrentState("s")
	if state != "S1" {
		t.Errorf("session moved off S1 unexpectedly: now at %q", state)
	}
	// Phase a should NOT have called Exit yet.
	if a.exitCount != 0 {
		t.Errorf("phase a Exit called %d times during internal-state advance, want 0", a.exitCount)
	}
}

func TestRunner_NonInlinePhaseDoesNotClaimState(t *testing.T) {
	// A registration-time phase provides crypto_ctx out of band. The
	// inline scoring phase requires it. Validation should accept the
	// composition.
	keyBundle := &mockPhase{
		name:     "cohort-keygen",
		runsAt:   RunsAtRegistration,
		lifetime: LifetimePerCohort,
		// No EntryState / ExitState / messages.
		provides: ContextSchema{
			"crypto_ctx": {TypeName: "KeyBundle"},
		},
	}
	scoring := &mockPhase{
		name:           "scoring",
		runsAt:         RunsAtInline,
		entry:          "SCORE",
		exit:           StateNone,
		messages:       []string{"bid"},
		completeAfterN: 1,
		requires:       ContextSchema{"crypto_ctx": {TypeName: "KeyBundle", Required: true}},
	}
	if _, err := Compose(keyBundle, scoring); err != nil {
		t.Errorf("expected non-inline + inline composition to validate, got %v", err)
	}
}
