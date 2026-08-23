// SPDX-License-Identifier: Apache-2.0

package voting_test

import (
	"encoding/json"
	"errors"
	"testing"

	voting "github.com/Fheyalabs/ares-core/examples/voting"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestVoting_TamperedBallot_DetectedByLineage(t *testing.T) {
	authority, _ := sign.NewEd25519Signer()
	voter, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: voter}

	runner, err := voting.PipelineWithLineage(authority, peers)
	if err != nil {
		t.Fatalf("PipelineWithLineage: %v", err)
	}
	if _, err := runner.BeginSession("election-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	ballot := map[string]any{
		"candidate": "alice",
		"weight":    1,
	}
	payload, _ := json.Marshal(ballot)
	node, _ := lineage.Commit("election-1", "voting-submit", "ballot-voter-1", payload, nil, voter)

	// Election authority tampers — switches candidate to "bob".
	tampered := []byte(`{"candidate":"bob","weight":1}`)
	_, err = runner.HandleLineageMessage("election-1", "vote.ballot", "voter-1", tampered, &node)
	if err == nil {
		t.Fatal("expected tamper rejection")
	}
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if me.Field != "PayloadHash" {
		t.Errorf("MismatchError.Field = %q, want %q", me.Field, "PayloadHash")
	}
}
