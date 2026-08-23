// SPDX-License-Identifier: Apache-2.0

package lineage_test

import (
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Confirms the design's load-bearing assumption: a DAGNode signed by
// an ephemeral, single-use signer verifies against a verifier map keyed
// only by algorithm (NOT by producer identity). This is what lets a
// slot submission be signed by a per-slot ephemeral key without leaking
// the slot->identity mapping to verifiers.
func TestEphemeralSigner_VerifiesViaSelfDescribingProducer(t *testing.T) {
	ephemeral, err := sign.NewEd25519Signer() // stand-in for a per-slot key
	if err != nil {
		t.Fatalf("new ephemeral signer: %v", err)
	}

	payload := []byte("slot_dk_pub||slot_index=3")
	node, err := lineage.Commit("session-1", "slot-submit", "slot-submission", payload, nil, ephemeral)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The verifier map holds a DIFFERENT ed25519 signer — it provides
	// only the scheme's Verify implementation; the producer pubkey
	// travels on the node.
	otherVerifier, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("new verifier signer: %v", err)
	}
	verifiers := map[string]sign.Signer{"ed25519": otherVerifier}

	if err := lineage.Verify(node, payload, verifiers); err != nil {
		t.Fatalf("verify with self-describing producer should pass, got: %v", err)
	}
}

func TestEphemeralSigner_TamperedPayloadFails(t *testing.T) {
	ephemeral, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("new ephemeral signer: %v", err)
	}
	node, err := lineage.Commit("session-1", "slot-submit", "slot-submission", []byte("orig"), nil, ephemeral)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	verifiers := map[string]sign.Signer{"ed25519": ephemeral}

	err = lineage.Verify(node, []byte("TAMPERED"), verifiers)
	var me *lineage.MismatchError
	if !errors.As(err, &me) || me.Field != "PayloadHash" {
		t.Fatalf("want *MismatchError{Field:PayloadHash}, got: %v", err)
	}
}
