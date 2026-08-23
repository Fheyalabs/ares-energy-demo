// SPDX-License-Identifier: Apache-2.0

package anon

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"
import "github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"

// PhaseGShuffle sequences the onion-shuffle gossip round
// (GOSSIP -> VERIFYING). It accepts each participant's initial onion
// and counts peel-forward rounds, completing once every non-initiator
// peeler has forwarded once. It does no cryptography itself — the
// onion build/peel runs client-side via pkg/ares/onion (see
// Participant) and the relay forwards opaque batches, so the
// orchestrator never sees the slot->participant mapping.
type PhaseGShuffle struct{}

func NewPhaseGShuffle() *PhaseGShuffle { return &PhaseGShuffle{} }

func (PhaseGShuffle) Name() string                         { return "anon-g-shuffle" }
func (PhaseGShuffle) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (PhaseGShuffle) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (PhaseGShuffle) EntryState() phase.SessionState       { return defaults.StateGossip }
func (PhaseGShuffle) ExitState() phase.SessionState        { return defaults.StateVerifying }
func (PhaseGShuffle) InternalStates() []phase.SessionState { return nil }
func (PhaseGShuffle) ConsumedMessageTypes() []string {
	return []string{MsgOnionBatch, MsgPeelForward}
}
func (PhaseGShuffle) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxParticipants: {TypeName: "[]string", Required: true}}
}
func (PhaseGShuffle) Provides() phase.ContextSchema {
	// int marker, not []byte -> not auto-committed to lineage.
	return phase.ContextSchema{CtxPeelRounds: {TypeName: "int"}}
}
func (PhaseGShuffle) Enter(*phase.SessionContext) error { return nil }

func (PhaseGShuffle) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	switch msgType {
	case MsgOnionBatch:
		phase.AccumulateMessage(ctx, bucketOnions, from, payload)
	case MsgPeelForward:
		// AccumulateMessage keys by sender, so a peeler forwarding
		// twice does not double-count toward the quorum.
		phase.AccumulateMessage(ctx, bucketPeels, from, payload)
	}
	return nil
}

func (PhaseGShuffle) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketPeels, len(participants))
}

func (PhaseGShuffle) Exit(ctx *phase.SessionContext) error {
	ctx.Set(CtxPeelRounds, len(phase.AccumulatedMessages(ctx, bucketPeels)))
	return nil
}
