// SPDX-License-Identifier: Apache-2.0

package voting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/anon"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// PhaseInvite opens a voting session. The orchestrator picks the
// eligible voter set and emits a `vote.invitation` frame to each.
// Identical shape to `defaults.Phase1aSessionInitiation` — the only
// difference is the message type and that no crypto contract is
// declared (plaintext keygen carries no CKKS parameters).
type PhaseInvite struct{}

func NewPhaseInvite() *PhaseInvite { return &PhaseInvite{} }

func (PhaseInvite) Name() string                                              { return "vote-invitation" }
func (PhaseInvite) Lifetime() phase.Lifetime                                  { return phase.LifetimePerSession }
func (PhaseInvite) RunsAt() phase.RunsAt                                      { return phase.RunsAtInline }
func (PhaseInvite) EntryState() phase.SessionState                            { return defaults.StateInviting }
func (PhaseInvite) ExitState() phase.SessionState                             { return defaults.StateLocked }
func (PhaseInvite) ConsumedMessageTypes() []string                            { return nil }
func (PhaseInvite) InternalStates() []phase.SessionState                      { return nil }
func (PhaseInvite) Requires() phase.ContextSchema                             { return nil }
func (PhaseInvite) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxVoteParticipants:      {TypeName: "[]string"},
		defaults.CtxParticipants: {TypeName: "[]string"},
		anon.CtxParticipants:     {TypeName: "[]string"},
	}
}
func (PhaseInvite) Enter(*phase.SessionContext) error                               { return nil }
func (PhaseInvite) OnMessage(*phase.SessionContext, string, string, []byte) error   { return nil }
func (PhaseInvite) CheckComplete(*phase.SessionContext) bool                        { return true }
func (PhaseInvite) Exit(*phase.SessionContext) error                                { return nil }

// PhaseSubmitVote accumulates one `vote.ballot` from each participant.
// Wire shape:
//
//	{"choice": 1, "weight": 1.5}
//
// The voter's identity is taken from the WS pseudonym, not the
// payload (preventing cross-voter ballot stuffing under the same
// account).
//
// entryState defaults to GOSSIP; when the shuffle phases are composed
// ahead of it, the pipeline re-points it to SUBMITTING.
type PhaseSubmitVote struct {
	entryState phase.SessionState
}

// NewPhaseSubmitVote returns a submit phase entering at GOSSIP (the
// no-shuffle pipeline). Use NewPhaseSubmitVoteAt to re-point it.
func NewPhaseSubmitVote() *PhaseSubmitVote {
	return &PhaseSubmitVote{entryState: defaults.StateGossip}
}

// NewPhaseSubmitVoteAt returns a submit phase entering at the given
// state (used when the onion-shuffle arc precedes it).
func NewPhaseSubmitVoteAt(entry phase.SessionState) *PhaseSubmitVote {
	return &PhaseSubmitVote{entryState: entry}
}

func (PhaseSubmitVote) Name() string                         { return "vote-submit" }
func (PhaseSubmitVote) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (PhaseSubmitVote) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (p PhaseSubmitVote) EntryState() phase.SessionState     { return p.entryState }
func (PhaseSubmitVote) ExitState() phase.SessionState        { return defaults.StateScoring }
func (PhaseSubmitVote) ConsumedMessageTypes() []string       { return []string{"vote.ballot"} }
func (PhaseSubmitVote) InternalStates() []phase.SessionState { return nil }
func (PhaseSubmitVote) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxVoteParticipants: {TypeName: "[]string", Required: true},
	}
}
func (PhaseSubmitVote) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxVoteBallots: {TypeName: "map[string]Ballot"},
	}
}
func (PhaseSubmitVote) Enter(*phase.SessionContext) error { return nil }
func (PhaseSubmitVote) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketBallots, from, payload)
	return nil
}
func (PhaseSubmitVote) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxVoteParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketBallots, len(participants))
}
func (PhaseSubmitVote) Exit(ctx *phase.SessionContext) error {
	raw := phase.AccumulatedMessages(ctx, bucketBallots)
	parsed := make(map[string]Ballot, len(raw))
	for voter, payload := range raw {
		var b struct {
			Choice int     `json:"choice"`
			Weight float64 `json:"weight"`
		}
		if err := json.Unmarshal(payload, &b); err != nil {
			return fmt.Errorf("PhaseSubmitVote: decode ballot from %s: %w", voter, err)
		}
		if b.Weight <= 0 {
			b.Weight = 1.0
		}
		parsed[voter] = Ballot{Voter: voter, Choice: b.Choice, Weight: b.Weight}
	}
	ctx.Set(CtxVoteBallots, parsed)
	return nil
}

// PhaseTally sums weights per choice and picks the largest. This is
// the voting equivalent of an FHE app's PhaseArgmax — same pipeline
// arc (SCORING -> DECRYPTING) but plaintext math.
type PhaseTally struct{}

func NewPhaseTally() *PhaseTally { return &PhaseTally{} }

func (PhaseTally) Name() string                         { return "vote-tally" }
func (PhaseTally) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (PhaseTally) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (PhaseTally) EntryState() phase.SessionState       { return defaults.StateScoring }
func (PhaseTally) ExitState() phase.SessionState        { return defaults.StateDecrypting }
func (PhaseTally) ConsumedMessageTypes() []string       { return nil }
func (PhaseTally) InternalStates() []phase.SessionState { return nil }
func (PhaseTally) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxVoteBallots: {TypeName: "map[string]Ballot", Required: true},
	}
}
func (PhaseTally) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxVoteTally: {TypeName: "Tally"},
	}
}
func (PhaseTally) Enter(ctx *phase.SessionContext) error {
	ballots := phase.MustGet[map[string]Ballot](ctx, CtxVoteBallots)
	totals := make(map[int]float64)
	for _, b := range ballots {
		totals[b.Choice] += b.Weight
	}
	// Deterministic winner pick: highest weight, ties broken by
	// lowest choice index.
	choices := make([]int, 0, len(totals))
	for k := range totals {
		choices = append(choices, k)
	}
	sort.Ints(choices)
	winner := choices[0]
	for _, c := range choices[1:] {
		if totals[c] > totals[winner] {
			winner = c
		}
	}
	ctx.Set(CtxVoteTally, Tally{
		Totals:       totals,
		TotalBallots: len(ballots),
		WinnerChoice: winner,
		WinnerWeight: totals[winner],
	})
	return nil
}
func (PhaseTally) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseTally) CheckComplete(*phase.SessionContext) bool                      { return true }
func (PhaseTally) Exit(*phase.SessionContext) error                              { return nil }

// PhaseSettle emits a signed transcript carrying the tally. Closely
// mirrors `sealed_bid_auction.PhaseSettlement` shape: synchronous
// Enter that writes a transcript artifact, ExitState terminal.
type PhaseSettle struct{}

func NewPhaseSettle() *PhaseSettle { return &PhaseSettle{} }

func (PhaseSettle) Name() string                         { return "vote-settle" }
func (PhaseSettle) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (PhaseSettle) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (PhaseSettle) EntryState() phase.SessionState       { return defaults.StateDecrypting }
func (PhaseSettle) ExitState() phase.SessionState        { return phase.StateNone }
func (PhaseSettle) ConsumedMessageTypes() []string       { return nil }
func (PhaseSettle) InternalStates() []phase.SessionState { return nil }
func (PhaseSettle) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxVoteTally: {TypeName: "Tally", Required: true},
	}
}
func (PhaseSettle) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxVoteTranscript: {TypeName: "[]byte"},
	}
}
func (PhaseSettle) Enter(ctx *phase.SessionContext) error {
	tally := phase.MustGet[Tally](ctx, CtxVoteTally)
	body, err := json.Marshal(tally)
	if err != nil {
		return fmt.Errorf("PhaseSettle: marshal tally: %w", err)
	}
	// Transcript shape: {"tally": <json>, "hash": <sha256 hex>}.
	// The hash is a stand-in for a real signature scheme; production
	// applications swap this for HMAC, Ed25519, or a TEE attestation.
	sum := sha256.Sum256(body)
	transcript, _ := json.Marshal(map[string]any{
		"tally": json.RawMessage(body),
		"hash":  hex.EncodeToString(sum[:]),
	})
	ctx.Set(CtxVoteTranscript, transcript)
	return nil
}
func (PhaseSettle) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseSettle) CheckComplete(*phase.SessionContext) bool                      { return true }
func (PhaseSettle) Exit(*phase.SessionContext) error                              { return nil }
