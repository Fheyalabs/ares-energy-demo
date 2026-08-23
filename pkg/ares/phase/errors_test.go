// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestSentinels_AreDistinct confirms the 4 sentinels don't satisfy
// errors.Is against each other — branching on one sentinel never
// accidentally matches another. (Two sentinels backed by the same
// errors.New value would be a critical app-attribution bug.)
func TestSentinels_AreDistinct(t *testing.T) {
	sentinels := map[string]error{
		"Transient":       phase.ErrTransient,
		"Permanent":       phase.ErrPermanent,
		"AppAttributable": phase.ErrAppAttributable,
		"FrameworkBug":    phase.ErrFrameworkBug,
	}
	for name, s := range sentinels {
		for otherName, other := range sentinels {
			if name == otherName {
				continue
			}
			if errors.Is(s, other) {
				t.Errorf("%s incorrectly satisfies errors.Is(_, %s) — sentinels must be distinct", name, otherName)
			}
		}
	}
}

// TestSentinels_WrappedErrorsClassify confirms the canonical usage
// pattern works: phase.ErrXxx wrapped via fmt.Errorf("%w: ...")
// classifies via errors.Is even through nested wraps, while the
// typed underlying error remains accessible via errors.As.
func TestSentinels_WrappedErrorsClassify(t *testing.T) {
	mismatch := &lineage.MismatchError{Field: "PayloadHash"}
	wrapped := fmt.Errorf("%w: lineage verify on phase %q output %q: %w",
		phase.ErrAppAttributable, "phase-x", "ct_out", mismatch)
	doublyWrapped := fmt.Errorf("HandleLineageMessage: %w", wrapped)

	if !errors.Is(doublyWrapped, phase.ErrAppAttributable) {
		t.Error("nested wrap broke errors.Is(_, ErrAppAttributable)")
	}
	if errors.Is(doublyWrapped, phase.ErrTransient) {
		t.Error("doubly-wrapped err incorrectly satisfies errors.Is(_, ErrTransient)")
	}

	var me *lineage.MismatchError
	if !errors.As(doublyWrapped, &me) {
		t.Error("nested wrap broke errors.As(_, **lineage.MismatchError)")
	}
	if me == nil || me.Field != "PayloadHash" {
		t.Errorf("recovered MismatchError = %+v, want Field=PayloadHash", me)
	}
}

// TestSentinels_BranchOnRetryability documents the canonical app-side
// retry/fail-fast branching pattern.
func TestSentinels_BranchOnRetryability(t *testing.T) {
	transientErr := fmt.Errorf("%w: store.Append: connection refused", phase.ErrTransient)
	permanentErr := fmt.Errorf("%w: missing required context key %q", phase.ErrPermanent, "ct_in")

	shouldRetry := func(err error) bool {
		return errors.Is(err, phase.ErrTransient)
	}
	if !shouldRetry(transientErr) {
		t.Error("transient err should signal retry")
	}
	if shouldRetry(permanentErr) {
		t.Error("permanent err should NOT signal retry")
	}
}
