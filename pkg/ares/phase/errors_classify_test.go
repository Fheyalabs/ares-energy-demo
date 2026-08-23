// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestErrorClassification_PublicAPI confirms framework-level errors
// returned from the public SessionRunner API carry the documented
// sentinel so apps can branch retry / penalty / report-bug policy
// via errors.Is(err, phase.ErrXxx).
//
// Coverage:
//   - Compose with no phases       → ErrPermanent
//   - ComposeWith missing Signer   → ErrPermanent
//   - BeginSession empty sessionID → ErrPermanent
//   - BeginSession dup sessionID   → ErrPermanent
//   - HandleMessage on unknown session    → ErrPermanent
//   - HandleMessage wrong message type    → ErrPermanent
//   - AdvanceToState on unknown session   → ErrPermanent
//   - HandleLineageMessage tampered bytes → ErrAppAttributable
//   - HandleLineageMessage no node (v2)   → ErrPermanent
//
// ErrFrameworkBug is harder to trigger from a test (it represents
// "should never happen" defensive paths) so it has dedicated
// targeted assertions in errors_test.go via direct wrap testing.
func TestErrorClassification_PublicAPI(t *testing.T) {
	t.Run("Compose with no phases", func(t *testing.T) {
		_, err := phase.Compose()
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("ComposeWith missing Signer", func(t *testing.T) {
		_, err := phase.ComposeWith([]phase.Phase{noopPhase{name: "n", entry: "S", exit: phase.StateNone}})
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("BeginSession empty sessionID", func(t *testing.T) {
		runner, _ := phase.Compose(noopPhase{name: "n", entry: "S", exit: phase.StateNone})
		_, err := runner.BeginSession("", "")
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("BeginSession duplicate sessionID", func(t *testing.T) {
		runner, _ := phase.Compose(noopPhase{name: "n", entry: "S", exit: phase.StateNone})
		runner.BeginSession("dup", "")
		_, err := runner.BeginSession("dup", "")
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("HandleMessage unknown session", func(t *testing.T) {
		runner, _ := phase.Compose(noopPhase{name: "n", entry: "S", exit: phase.StateNone})
		_, err := runner.HandleMessage("nope", "x.y", "p1", []byte{})
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("HandleMessage wrong msg type", func(t *testing.T) {
		runner, _ := phase.Compose(noopPhase{name: "n", entry: "S", exit: phase.StateNone, consumes: []string{"a"}})
		runner.BeginSession("w", "")
		_, err := runner.HandleMessage("w", "b", "p1", []byte{})
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("AdvanceToState unknown session", func(t *testing.T) {
		runner, _ := phase.Compose(noopPhase{name: "n", entry: "S", exit: phase.StateNone})
		err := runner.AdvanceToState("nope", "S2")
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("HandleLineageMessage no node (v2 frame missing Lineage)", func(t *testing.T) {
		signer, _ := sign.NewEd25519Signer()
		peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
		runner, _ := phase.ComposeWith(
			[]phase.Phase{noopPhase{name: "n", entry: "S", exit: phase.StateNone, consumes: []string{"x"}}},
			phase.WithSigner(signer),
			phase.WithPeerVerifiers(peers),
		)
		runner.BeginSession("s", "")
		_, err := runner.HandleLineageMessage("s", "x", "p1", []byte("p"), nil)
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
	t.Run("HandleLineageMessage tampered bytes (canonical app-attributable case)", func(t *testing.T) {
		signer, _ := sign.NewEd25519Signer()
		peer, _ := sign.NewEd25519Signer()
		peers := map[string]sign.Signer{sign.Ed25519Algorithm: peer}
		runner, _ := phase.ComposeWith(
			[]phase.Phase{noopPhase{name: "n", entry: "S", exit: phase.StateNone, consumes: []string{"x"}}},
			phase.WithSigner(signer),
			phase.WithPeerVerifiers(peers),
		)
		runner.BeginSession("s", "")
		node, _ := lineage.Commit("s", "n", "r", []byte("good"), nil, peer)
		_, err := runner.HandleLineageMessage("s", "x", "p1", []byte("BAD"), &node)
		mustBeSentinel(t, err, phase.ErrAppAttributable)
		// Underlying typed error still recoverable via errors.As.
		var me *lineage.MismatchError
		if !errors.As(err, &me) {
			t.Errorf("underlying *lineage.MismatchError unavailable via errors.As: %v", err)
		}
	})
	t.Run("BuildMismatchClaim on Compose-built runner", func(t *testing.T) {
		runner, _ := phase.Compose(noopPhase{name: "n", entry: "S", exit: phase.StateNone})
		_, err := runner.BuildMismatchClaim("s", "p", "r", errors.New("x"))
		mustBeSentinel(t, err, phase.ErrPermanent)
	})
}

func mustBeSentinel(t *testing.T, err, sentinel error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err %v not classified by sentinel %v", err, sentinel)
	}
}
