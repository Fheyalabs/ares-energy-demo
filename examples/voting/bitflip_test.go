// SPDX-License-Identifier: Apache-2.0

package voting_test

import (
	"encoding/json"
	"errors"
	"testing"

	voting "github.com/Fheyalabs/ares-core/examples/voting"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestBitflip_DetectedAtEveryLineageStage exercises the voting
// pipeline's one lineage-protected message type (vote.ballot). To
// demonstrate position-independent bitflip detection the same stage
// is exercised with the bit flipped at multiple byte positions.
//
// Voting demonstrates that SC-10 protects ANY byte payload — these
// ballots are plaintext (no FHE), but the framework's Merkle DAG
// binding still detects tampering between voter and tally.
func TestBitflip_DetectedAtEveryLineageStage(t *testing.T) {
	basePayload, _ := json.Marshal(map[string]any{
		"choice":  "option-A",
		"voter":   "voter-1",
		"version": 1,
	})

	type variant struct {
		name   string
		flipFn func(b []byte)
	}
	variants := []variant{
		{name: "flip byte 0", flipFn: func(b []byte) { b[0] ^= 0x01 }},
		{name: "flip middle byte", flipFn: func(b []byte) { b[len(b)/2] ^= 0x80 }},
		{name: "flip last byte", flipFn: func(b []byte) { b[len(b)-1] ^= 0x01 }},
		{name: "flip choice value (changes 'option-A' → 'option-' + flipped)",
			flipFn: func(b []byte) {
				// Find 'A' in "option-A" and flip its low bit (→ '@').
				for i := range b {
					if b[i] == 'A' {
						b[i] ^= 0x01
						return
					}
				}
				t.Fatalf("payload lacked the 'A' marker")
			}},
	}

	for _, v := range variants {
		v := v
		t.Run("vote.ballot at GOSSIP ("+v.name+")", func(t *testing.T) {
			election, _ := sign.NewEd25519Signer()
			voter, _ := sign.NewEd25519Signer()
			peers := map[string]sign.Signer{sign.Ed25519Algorithm: voter}

			runner, err := voting.PipelineWithLineage(election, peers)
			if err != nil {
				t.Fatalf("PipelineWithLineage: %v", err)
			}
			sessionID := "vote-bitflip-" + v.name
			ctx, err := runner.BeginSession(sessionID, "")
			if err != nil {
				t.Fatalf("BeginSession: %v", err)
			}
			ctx.Set(voting.CtxVoteParticipants, []string{"voter-1", "voter-2", "voter-3"})
			ctx.Set(defaults.CtxParticipants, []string{"voter-1", "voter-2", "voter-3"})

			// Advance past Invite + PlaintextKeygen so PhaseSubmitVote
			// is the active phase consuming vote.ballot.
			if err := runner.AdvanceToState(sessionID, defaults.StateGossip); err != nil {
				t.Fatalf("advance to GOSSIP: %v", err)
			}
			if s, _ := runner.CurrentState(sessionID); s != phase.SessionState(defaults.StateGossip) {
				t.Fatalf("state = %q want GOSSIP", s)
			}

			node, err := lineage.Commit(sessionID, "vote-submit", "ballot-voter-1", basePayload, nil, voter)
			if err != nil {
				t.Fatalf("lineage.Commit: %v", err)
			}

			tampered := append([]byte{}, basePayload...)
			v.flipFn(tampered)
			t.Logf("base=%q tampered=%q", string(basePayload), string(tampered))

			_, err = runner.HandleLineageMessage(sessionID, "vote.ballot", "voter-1", tampered, &node)
			if err == nil {
				t.Fatalf("%s: expected *MismatchError, got nil", v.name)
			}
			var me *lineage.MismatchError
			if !errors.As(err, &me) {
				t.Fatalf("%s: expected *MismatchError, got %T: %v", v.name, err, err)
			}
			if me.Field != "PayloadHash" {
				t.Errorf("%s: MismatchError.Field = %q, want %q", v.name, me.Field, "PayloadHash")
			}
		})
	}
}
