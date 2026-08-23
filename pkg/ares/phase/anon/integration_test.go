// SPDX-License-Identifier: Apache-2.0

package anon_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/anon"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// seedPhase is a trivial test provider that seeds CtxParticipants so the
// VERIFYING-arc verify phase's Required input is satisfied at compose
// time (the runner rejects a Required key with no preceding provider).
// It occupies INVITING -> VERIFYING and sets the participant list in
// Enter. CtxParticipants is []string (not []byte), so it is not
// lineage-auto-committed.
type seedPhase struct{ parties []string }

func (seedPhase) Name() string                         { return "seed" }
func (seedPhase) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (seedPhase) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (seedPhase) EntryState() phase.SessionState       { return defaults.StateInviting }
func (seedPhase) ExitState() phase.SessionState        { return defaults.StateVerifying }
func (seedPhase) InternalStates() []phase.SessionState { return nil }
func (seedPhase) ConsumedMessageTypes() []string       { return nil }
func (seedPhase) Requires() phase.ContextSchema        { return nil }
func (seedPhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{anon.CtxParticipants: {TypeName: "[]string"}}
}
func (p seedPhase) Enter(ctx *phase.SessionContext) error {
	ctx.Set(anon.CtxParticipants, p.parties)
	return nil
}
func (seedPhase) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (seedPhase) CheckComplete(*phase.SessionContext) bool                      { return true }
func (seedPhase) Exit(*phase.SessionContext) error                              { return nil }

// runShuffle performs the client-side onion shuffle across n participants
// and returns them. Asserts every peeler identifies its own item.
// (Crypto correctness; no runner involved.)
func runShuffle(t *testing.T, n int) []*anon.Participant {
	t.Helper()
	seed := []byte("integration-seed")
	parts := make([]*anon.Participant, n)
	pubs := make([][]byte, n)
	for i := 0; i < n; i++ {
		p, err := anon.NewParticipant(seed, n, i)
		if err != nil {
			t.Fatalf("participant %d: %v", i, err)
		}
		parts[i] = p
		pubs[i] = p.SlotPub
	}
	batch := make([][]byte, n)
	memos := make([][]byte, n)
	for i := 0; i < n; i++ {
		o, memo, err := parts[i].BuildOnion(pubs, i)
		if err != nil {
			t.Fatalf("build onion %d: %v", i, err)
		}
		batch[i], memos[i] = o, memo
	}
	for k := 0; k < n; k++ {
		peeled, own, err := parts[k].Peel(memos[k], batch)
		if err != nil {
			t.Fatalf("peel %d: %v", k, err)
		}
		if own < 0 {
			t.Fatalf("peeler %d did not find its own item", k)
		}
		batch = peeled
	}
	return parts
}

// verifyRunner builds a lineage-enabled runner [seed -> PhaseGVerify(terminal)]
// and advances it to the VERIFYING arc, ready to accept slot submissions.
func verifyRunner(t *testing.T, sessionID string, parties []string) (*phase.SessionRunner, *phase.SessionContext) {
	t.Helper()
	local, _ := sign.NewEd25519Signer()
	verifier, _ := sign.NewEd25519Signer()
	runner, err := phase.ComposeWith(
		[]phase.Phase{
			seedPhase{parties: parties},
			// Terminal exit (StateNone): no downstream phase, so the
			// verify phase ends the session when its quorum completes.
			anon.NewPhaseGVerify(phase.StateNone),
		},
		phase.WithSigner(local),
		phase.WithPeerVerifiers(map[string]sign.Signer{"ed25519": verifier}),
	)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	ctx, err := runner.BeginSession(sessionID, "")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Walk from the seed phase (INVITING) into the verify phase (VERIFYING).
	if err := runner.AdvanceToState(sessionID, defaults.StateVerifying); err != nil {
		t.Fatalf("advance to VERIFYING: %v", err)
	}
	return runner, ctx
}

func TestIntegration_ShuffleThenVerifiedSubmissions(t *testing.T) {
	const n = 5
	parts := runShuffle(t, n)

	parties := make([]string, n)
	for i := range parties {
		parties[i] = fmt.Sprintf("party-%d", i)
	}
	runner, ctx := verifyRunner(t, "sess-int", parties)

	// Each participant submits its ephemeral-signed slot node; each is
	// verified by the runner before the phase observes it.
	for i, p := range parts {
		payload, node, err := p.SlotSubmission("sess-int")
		if err != nil {
			t.Fatalf("submission %d: %v", i, err)
		}
		if _, err := runner.HandleLineageMessage("sess-int", anon.MsgSlotSubmit, parties[i], payload, &node); err != nil {
			t.Fatalf("verify submission %d: %v", i, err)
		}
	}

	// Quorum reached -> verify phase Exited (auto-committing the
	// assembled list) -> terminal exit ended the session.
	if state, ok := runner.CurrentState("sess-int"); ok && state != phase.StateNone {
		t.Fatalf("state after submissions = %q, want terminal (StateNone)", state)
	}

	// The assembled slot list is committed to the session lineage DAG.
	var assembledNode *lineage.DAGNode
	submissionHashes := make(map[lineage.NodeRef]bool)
	for node := range ctx.LineageDAG() {
		if node.Role == anon.CtxAssembledSlotList {
			n := node
			assembledNode = &n
		}
		if node.Role == anon.RoleSlotSubmission {
			submissionHashes[node.Hash] = true
		}
	}
	if assembledNode == nil {
		t.Fatal("assembled slot list not committed to lineage")
	}

	// The assembled-list node must have exactly n parent edges, one per
	// slot-submission node.
	if len(assembledNode.Parents) != n {
		t.Fatalf("assembled-list node has %d parent(s), want %d (one per submission)", len(assembledNode.Parents), n)
	}
	if len(submissionHashes) != n {
		t.Fatalf("found %d slot-submission node(s) in lineage DAG, want %d", len(submissionHashes), n)
	}
	parentSet := make(map[lineage.NodeRef]bool, len(assembledNode.Parents))
	for _, ref := range assembledNode.Parents {
		parentSet[ref] = true
	}
	for ref := range submissionHashes {
		if !parentSet[ref] {
			t.Errorf("slot-submission node %x is not a parent of the assembled-list node", ref)
		}
	}
}

func TestIntegration_TamperedSubmissionRejected(t *testing.T) {
	const n = 3
	parts := runShuffle(t, n)
	runner, _ := verifyRunner(t, "sess-tamper", []string{"a", "b", "c"})

	payload, node, err := parts[0].SlotSubmission("sess-tamper")
	if err != nil {
		t.Fatalf("submission: %v", err)
	}
	tampered := append([]byte(nil), payload...)
	tampered[0] ^= 0xFF // flip a byte; the node no longer binds the payload

	_, err = runner.HandleLineageMessage("sess-tamper", anon.MsgSlotSubmit, "a", tampered, &node)
	var me *lineage.MismatchError
	if !errors.As(err, &me) || me.Field != "PayloadHash" {
		t.Fatalf("want *MismatchError{PayloadHash}, got: %v", err)
	}
}
