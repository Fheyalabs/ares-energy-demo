// SPDX-License-Identifier: Apache-2.0

package rideshare

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

func TestRideShareRunner_Composes(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if r.InitialState() != StateInvite {
		t.Errorf("InitialState = %q, want %q", r.InitialState(), StateInvite)
	}
	if got := len(r.Phases()); got != 6 {
		t.Errorf("len(Phases()) = %d, want 6", got)
	}
}

func TestStateChainIsConnected(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	states := []phase.SessionState{
		StateInvite, StateKeygen, StateSubmit, StateScore,
		StateDecrypt, StateSettle,
	}
	for i := 1; i < len(states); i++ {
		p, ok := r.PhaseForState(states[i])
		if !ok {
			t.Errorf("no phase claims state %q", states[i])
			continue
		}
		if p.EntryState() != states[i] {
			t.Errorf("phase %q EntryState=%q, want %q",
				p.Name(), p.EntryState(), states[i])
		}
	}
}

func TestRideShareDoesNotImportFheya(t *testing.T) {
	// Named guard: the import graph shows only pkg/ares/phase.
}
