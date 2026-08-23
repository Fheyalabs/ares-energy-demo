// SPDX-License-Identifier: Apache-2.0

package voting_test

import (
	"fmt"
	"testing"

	"github.com/Fheyalabs/ares-core/examples/voting"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestVoting_PipelineWithShuffle_Composes verifies the shuffle-enabled
// voting pipeline composes without error and the shuffle arc
// (GOSSIP -> VERIFYING -> SUBMITTING) is wired ahead of ballot
// submission.
func TestVoting_PipelineWithShuffle_Composes(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	verifier, _ := sign.NewEd25519Signer()
	runner, err := voting.PipelineWithShuffle(signer, map[string]sign.Signer{"ed25519": verifier})
	if err != nil {
		t.Fatalf("PipelineWithShuffle: %v", err)
	}
	// PhaseGShuffle must claim GOSSIP; PhaseGVerify must claim VERIFYING.
	if _, ok := runner.PhaseForState(defaults.StateGossip); !ok {
		t.Fatal("no phase claims GOSSIP (shuffle not wired)")
	}
	if _, ok := runner.PhaseForState(defaults.StateVerifying); !ok {
		t.Fatal("no phase claims VERIFYING (verify not wired)")
	}
	// The ballot submit phase now claims SUBMITTING.
	if _, ok := runner.PhaseForState(defaults.StateSubmitting); !ok {
		t.Fatal("no phase claims SUBMITTING (submit not re-pointed)")
	}
	_ = fmt.Sprint(runner.Phases()) // smoke
}
