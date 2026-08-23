// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"context"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestRunner_PostExit_AutoCommitsProvidesBytes(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	// Two-phase pipeline: producer writes a []byte output during
	// Exit; framework auto-commits it after Exit returns.
	producer := &byteProducerPhase{
		name:    "producer",
		entry:   "S1",
		exit:    "S2",
		outKey:  "CtxBytes",
		payload: []byte("auto-committed-payload"),
	}
	terminator := &noopPhase{name: "term", entry: "S2", exit: phase.StateNone}

	runner, err := phase.ComposeWith(
		[]phase.Phase{producer, terminator},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	if err != nil {
		t.Fatalf("ComposeWith: %v", err)
	}
	if _, err := runner.BeginSession("sess-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if err := runner.AdvanceToState("sess-1", "S2"); err != nil {
		t.Fatalf("AdvanceToState: %v", err)
	}

	// Walk the store; expect at least one node with role matching
	// the producer's Provides key.
	ctx := context.Background()
	found := false
	for node, err := range store.WalkSession(ctx, "sess-1") {
		if err != nil {
			t.Fatalf("WalkSession: %v", err)
		}
		if node.PhaseID == "producer" && node.Role == "CtxBytes" {
			found = true
			// PayloadHash matches the producer's bytes.
			want := lineage.HashPayload([]byte("auto-committed-payload"))
			if node.PayloadHash != want {
				t.Errorf("PayloadHash = %x, want %x", node.PayloadHash, want)
			}
		}
	}
	if !found {
		t.Error("expected an auto-committed node for producer.CtxBytes; got none")
	}
}

func TestRunner_PostExit_RespectsNoLineageOptOut(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	producer := &byteProducerPhase{
		name:    "producer",
		entry:   "S1",
		exit:    "S2",
		outKey:  "CtxBytes",
		payload: []byte("not committed"),
		optOut:  true,
	}
	terminator := &noopPhase{name: "term", entry: "S2", exit: phase.StateNone}
	runner, _ := phase.ComposeWith(
		[]phase.Phase{producer, terminator},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	runner.BeginSession("sess-1", "")
	_ = runner.AdvanceToState("sess-1", "S2")

	ctx := context.Background()
	for node, err := range store.WalkSession(ctx, "sess-1") {
		if err != nil {
			t.Fatalf("WalkSession: %v", err)
		}
		if node.PhaseID == "producer" && node.Role == "CtxBytes" {
			t.Error("output marked NoLineage was committed anyway")
		}
	}
}

func TestRunner_PostExit_ParentChainResolves(t *testing.T) {
	// Two phases where the second declares Requires on the first's
	// output. After both phases run, the second phase's auto-commit
	// should reference the first phase's commit as parent.
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	producer := &byteProducerPhase{
		name:    "p1",
		entry:   "S1",
		exit:    "S2",
		outKey:  "CtxBytes",
		payload: []byte("phase-1 output"),
	}
	consumer := &byteConsumerPhase{
		name:          "p2",
		entry:         "S2",
		exit:          "S3",
		inKey:         "CtxBytes",
		outKey:        "CtxDerivedBytes",
		derivePayload: func(in []byte) []byte { return append([]byte("derived:"), in...) },
	}
	terminator := &noopPhase{name: "term", entry: "S3", exit: phase.StateNone}
	runner, err := phase.ComposeWith(
		[]phase.Phase{producer, consumer, terminator},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	if err != nil {
		t.Fatalf("ComposeWith: %v", err)
	}
	runner.BeginSession("sess-1", "")
	// Advance to terminator's entry: p1.Exit + commit, p2.Exit + commit,
	// then halt at S3 (no need to drive terminator).
	if err := runner.AdvanceToState("sess-1", "S3"); err != nil {
		t.Fatalf("AdvanceToState: %v", err)
	}

	ctx := context.Background()
	var consumerNode *lineage.DAGNode
	for node, err := range store.WalkSession(ctx, "sess-1") {
		if err != nil {
			t.Fatalf("WalkSession: %v", err)
		}
		if node.PhaseID == "p2" {
			n := node
			consumerNode = &n
		}
	}
	if consumerNode == nil {
		t.Fatal("consumer phase did not produce a commit")
	}
	if len(consumerNode.Parents) != 1 {
		t.Errorf("consumer node has %d parents, want 1", len(consumerNode.Parents))
	}
}

// byteProducerPhase writes a single []byte value to context during
// Exit so the runner's post-Exit auto-commit hook has something to
// commit.
type byteProducerPhase struct {
	name        string
	entry, exit phase.SessionState
	outKey      string
	payload     []byte
	optOut      bool
}

func (p *byteProducerPhase) Name() string                                                    { return p.name }
func (p *byteProducerPhase) Lifetime() phase.Lifetime                                        { return phase.LifetimePerSession }
func (p *byteProducerPhase) RunsAt() phase.RunsAt                                            { return phase.RunsAtInline }
func (p *byteProducerPhase) EntryState() phase.SessionState                                  { return p.entry }
func (p *byteProducerPhase) ExitState() phase.SessionState                                   { return p.exit }
func (p *byteProducerPhase) ConsumedMessageTypes() []string                                  { return nil }
func (p *byteProducerPhase) InternalStates() []phase.SessionState                            { return nil }
func (p *byteProducerPhase) Requires() phase.ContextSchema                                   { return nil }
func (p *byteProducerPhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		p.outKey: {TypeName: "[]byte", NoLineage: p.optOut},
	}
}
func (p *byteProducerPhase) Enter(*phase.SessionContext) error                               { return nil }
func (p *byteProducerPhase) OnMessage(*phase.SessionContext, string, string, []byte) error  { return nil }
func (p *byteProducerPhase) CheckComplete(*phase.SessionContext) bool                        { return true }
func (p *byteProducerPhase) Exit(ctx *phase.SessionContext) error {
	ctx.Set(p.outKey, p.payload)
	return nil
}

// byteConsumerPhase reads inKey, transforms it, writes to outKey.
type byteConsumerPhase struct {
	name          string
	entry, exit   phase.SessionState
	inKey, outKey string
	derivePayload func([]byte) []byte
}

func (p *byteConsumerPhase) Name() string                                                    { return p.name }
func (p *byteConsumerPhase) Lifetime() phase.Lifetime                                        { return phase.LifetimePerSession }
func (p *byteConsumerPhase) RunsAt() phase.RunsAt                                            { return phase.RunsAtInline }
func (p *byteConsumerPhase) EntryState() phase.SessionState                                  { return p.entry }
func (p *byteConsumerPhase) ExitState() phase.SessionState                                   { return p.exit }
func (p *byteConsumerPhase) ConsumedMessageTypes() []string                                  { return nil }
func (p *byteConsumerPhase) InternalStates() []phase.SessionState                            { return nil }
func (p *byteConsumerPhase) Requires() phase.ContextSchema {
	return phase.ContextSchema{p.inKey: {TypeName: "[]byte", Required: true}}
}
func (p *byteConsumerPhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{p.outKey: {TypeName: "[]byte"}}
}
func (p *byteConsumerPhase) Enter(*phase.SessionContext) error                               { return nil }
func (p *byteConsumerPhase) OnMessage(*phase.SessionContext, string, string, []byte) error  { return nil }
func (p *byteConsumerPhase) CheckComplete(*phase.SessionContext) bool                        { return true }
func (p *byteConsumerPhase) Exit(ctx *phase.SessionContext) error {
	in, _ := ctx.Get(p.inKey)
	if b, ok := in.([]byte); ok {
		ctx.Set(p.outKey, p.derivePayload(b))
	}
	return nil
}
