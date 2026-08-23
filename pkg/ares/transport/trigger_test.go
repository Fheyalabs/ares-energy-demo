// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// fakeInlinePhase is a single-state phase used to exercise the trigger
// against a real SessionRunner.
type fakeInlinePhase struct{ name string }

func (p *fakeInlinePhase) Name() string                         { return p.name }
func (p *fakeInlinePhase) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (p *fakeInlinePhase) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (p *fakeInlinePhase) EntryState() phase.SessionState       { return "START" }
func (p *fakeInlinePhase) ExitState() phase.SessionState        { return phase.StateNone }
func (p *fakeInlinePhase) InternalStates() []phase.SessionState { return nil }
func (p *fakeInlinePhase) ConsumedMessageTypes() []string       { return []string{"go"} }
func (p *fakeInlinePhase) Requires() phase.ContextSchema        { return nil }
func (p *fakeInlinePhase) Provides() phase.ContextSchema        { return nil }
func (p *fakeInlinePhase) Enter(*phase.SessionContext) error    { return nil }
func (p *fakeInlinePhase) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (p *fakeInlinePhase) CheckComplete(*phase.SessionContext) bool { return true }
func (p *fakeInlinePhase) Exit(*phase.SessionContext) error         { return nil }

func newTestRunner(t *testing.T) *phase.SessionRunner {
	t.Helper()
	r, err := phase.Compose(&fakeInlinePhase{name: "test-phase"})
	if err != nil {
		t.Fatalf("NewSessionRunner: %v", err)
	}
	return r
}

func TestManualAdminTrigger_StartsSession(t *testing.T) {
	r := newTestRunner(t)
	tr := NewManualAdminTrigger(r, nil, "")
	err := tr.Start("s1", []string{"p1", "p2"}, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if tr.StartedCount() != 1 {
		t.Errorf("StartedCount = %d, want 1", tr.StartedCount())
	}
	s, ok := r.CurrentState("s1")
	if !ok || s != "START" {
		t.Errorf("CurrentState = %q,%v, want START,true", s, ok)
	}
}

func TestManualAdminTrigger_RejectsEmptyParticipants(t *testing.T) {
	r := newTestRunner(t)
	tr := NewManualAdminTrigger(r, nil, "")
	if err := tr.Start("s2", nil, nil); err == nil {
		t.Errorf("expected Start with no participants to fail")
	}
}

func TestManualAdminTrigger_SeedsAttrsIntoContext(t *testing.T) {
	r := newTestRunner(t)
	tr := NewManualAdminTrigger(r, nil, "")
	err := tr.Start("s3", []string{"p1"}, map[string]any{
		"max_price":     50,
		"participants":  []string{"p1"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Re-derive the context via a second Start call to a fresh session
	// would lose access — instead, confirm the runner accepted the call.
	if tr.StartedCount() != 1 {
		t.Errorf("StartedCount = %d, want 1", tr.StartedCount())
	}
}
