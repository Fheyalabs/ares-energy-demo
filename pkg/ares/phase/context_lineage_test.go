// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestSessionContext_LineageDAG_ReturnsAppendedNodes(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	producer := &byteProducerPhase{
		name:    "producer",
		entry:   "S1",
		exit:    "S2",
		outKey:  "CtxBytes",
		payload: []byte("p"),
	}
	terminator := &noopPhase{name: "term", entry: "S2", exit: phase.StateNone}
	runner, _ := phase.ComposeWith(
		[]phase.Phase{producer, terminator},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	ctx, _ := runner.BeginSession("sess-1", "")
	_ = runner.AdvanceToState("sess-1", "S2")

	count := 0
	for range ctx.LineageDAG() {
		count++
	}
	if count == 0 {
		t.Error("LineageDAG() returned no nodes; expected at least one auto-committed Provides output")
	}
}

func TestSessionContext_LineageDAG_EmptyWhenLineageDisabled(t *testing.T) {
	// Compose-built runner: ctx.LineageDAG() yields nothing.
	runner, _ := phase.Compose(noopPhase{name: "n", entry: "S1", exit: phase.StateNone})
	ctx, _ := runner.BeginSession("sess-1", "")
	for range ctx.LineageDAG() {
		t.Error("LineageDAG() yielded a node on a Compose-built runner")
	}
}
