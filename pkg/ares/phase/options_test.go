// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestComposeOptions_AllConstructorsReturnNonNil(t *testing.T) {
	// Compile-time/runtime check: each With* helper returns a
	// non-nil ComposeOption.
	store := lineage.NewInMemoryStore()
	signer, _ := sign.NewEd25519Signer()
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	hook := func(ev phase.LineageFailureEvent) {}

	for name, opt := range map[string]phase.ComposeOption{
		"WithStore":              phase.WithStore(store),
		"WithSigner":             phase.WithSigner(signer),
		"WithPeerVerifiers":      phase.WithPeerVerifiers(verifiers),
		"WithLineageFailureHook": phase.WithLineageFailureHook(hook),
	} {
		if opt == nil {
			t.Errorf("%s returned nil ComposeOption", name)
		}
	}
}

func TestLineageFailureEvent_FieldsAccessible(t *testing.T) {
	ev := phase.LineageFailureEvent{
		Kind:       "mismatch-confirmed",
		SessionID:  "s",
		PhaseID:    "p",
		Role:       "r",
		Attributee: "pubkey-bytes",
		DAGNodes:   nil,
	}
	if ev.Kind != "mismatch-confirmed" {
		t.Error("Kind not set")
	}
	if ev.SessionID != "s" {
		t.Error("SessionID not set")
	}
}
