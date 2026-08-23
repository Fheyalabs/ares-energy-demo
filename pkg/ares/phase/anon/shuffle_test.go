// SPDX-License-Identifier: Apache-2.0

package anon_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/anon"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

func TestPhaseGShuffle_CompletesAfterAllPeelers(t *testing.T) {
	p := anon.NewPhaseGShuffle()
	if p.EntryState() != defaults.StateGossip || p.ExitState() != defaults.StateVerifying {
		t.Fatalf("arc = %s->%s, want GOSSIP->VERIFYING", p.EntryState(), p.ExitState())
	}

	ctx := phase.NewSessionContext("s1")
	ctx.Set(anon.CtxParticipants, []string{"p1", "p2", "p3"}) // N-1 = 3 peelers

	if p.CheckComplete(ctx) {
		t.Fatal("should not be complete before any peel")
	}
	// Each of the 3 peelers forwards exactly once.
	for _, peeler := range []string{"p1", "p2", "p3"} {
		if err := p.OnMessage(ctx, anon.MsgPeelForward, peeler, []byte("batch")); err != nil {
			t.Fatalf("OnMessage(%s): %v", peeler, err)
		}
	}
	if !p.CheckComplete(ctx) {
		t.Fatal("should be complete after all peelers forwarded")
	}
}

func TestPhaseGShuffle_DuplicatePeelerDoesNotDoubleCount(t *testing.T) {
	p := anon.NewPhaseGShuffle()
	ctx := phase.NewSessionContext("s1")
	ctx.Set(anon.CtxParticipants, []string{"p1", "p2"})
	_ = p.OnMessage(ctx, anon.MsgPeelForward, "p1", []byte("b"))
	_ = p.OnMessage(ctx, anon.MsgPeelForward, "p1", []byte("b-again"))
	if p.CheckComplete(ctx) {
		t.Fatal("one distinct peeler must not satisfy a 2-peeler quorum")
	}
}
