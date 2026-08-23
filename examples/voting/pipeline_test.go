// SPDX-License-Identifier: Apache-2.0

package voting

import (
	"encoding/json"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// TestPipeline_Composes verifies the voting runner validates at
// construction time.
func TestPipeline_Composes(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if got, want := r.InitialState(), defaults.StateInviting; got != want {
		t.Errorf("InitialState = %q, want %q", got, want)
	}
}

// TestTally_PicksLargestWeightedChoice exercises PhaseTally directly.
// Three voters, weights 1, 2, 1.5; choices 0, 1, 1 — choice 1 wins
// with weight 3.5.
func TestTally_PicksLargestWeightedChoice(t *testing.T) {
	ctx := phase.NewSessionContext("test")
	ctx.Set(CtxVoteBallots, map[string]Ballot{
		"voter-a": {Voter: "voter-a", Choice: 0, Weight: 1.0},
		"voter-b": {Voter: "voter-b", Choice: 1, Weight: 2.0},
		"voter-c": {Voter: "voter-c", Choice: 1, Weight: 1.5},
	})
	if err := (PhaseTally{}).Enter(ctx); err != nil {
		t.Fatalf("PhaseTally.Enter: %v", err)
	}
	tally := phase.MustGet[Tally](ctx, CtxVoteTally)
	if tally.WinnerChoice != 1 {
		t.Errorf("winner = %d, want 1", tally.WinnerChoice)
	}
	if tally.WinnerWeight != 3.5 {
		t.Errorf("winning weight = %v, want 3.5", tally.WinnerWeight)
	}
	if tally.TotalBallots != 3 {
		t.Errorf("total ballots = %d, want 3", tally.TotalBallots)
	}
}

// TestSettle_EmitsHashedTranscript verifies PhaseSettle wraps the
// tally in a hash-tagged JSON envelope.
func TestSettle_EmitsHashedTranscript(t *testing.T) {
	ctx := phase.NewSessionContext("test")
	ctx.Set(CtxVoteTally, Tally{
		Totals:       map[int]float64{1: 3.5, 0: 1.0},
		TotalBallots: 3,
		WinnerChoice: 1,
		WinnerWeight: 3.5,
	})
	if err := (PhaseSettle{}).Enter(ctx); err != nil {
		t.Fatalf("PhaseSettle.Enter: %v", err)
	}
	raw := phase.MustGet[[]byte](ctx, CtxVoteTranscript)
	var env struct {
		Tally json.RawMessage `json:"tally"`
		Hash  string          `json:"hash"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode transcript: %v", err)
	}
	if len(env.Hash) != 64 {
		t.Errorf("hash = %q (len %d), want 64-char hex", env.Hash, len(env.Hash))
	}
	if len(env.Tally) == 0 {
		t.Errorf("tally body empty")
	}
}
