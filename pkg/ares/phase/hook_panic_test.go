// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestFireFailureHook_PanicLoggedToWriter confirms that when an
// app-registered LineageFailureFn panics, the recover() does NOT
// silently swallow the panic — it writes a single descriptive log
// line including the session/phase/role/kind context to the
// hook-panic writer.
//
// Pre-v0.4.1 behavior: panic silently swallowed.
// v0.4.1 behavior:    panic still recovered (runner doesn't crash),
//                     but a log line is emitted to stderr (or the
//                     configured writer) so the misbehavior is
//                     observable at runtime.
func TestFireFailureHook_PanicLoggedToWriter(t *testing.T) {
	var buf bytes.Buffer
	prev := phase.SetHookPanicLog(&buf)
	defer phase.SetHookPanicLog(prev)

	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	hook := func(ev phase.LineageFailureEvent) {
		panic("intentional test panic in hook")
	}

	runner, err := phase.ComposeWith(
		[]phase.Phase{noopPhase{name: "n", entry: "S1", exit: phase.StateNone}},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
		phase.WithLineageFailureHook(hook),
	)
	if err != nil {
		t.Fatalf("ComposeWith: %v", err)
	}
	if _, err := runner.BeginSession("hook-panic-sess", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	// Triggering ReportFalseLineageClaim drives the hook through the
	// fireFailureHook path; the registered hook will panic.
	wrongClaim, err := runner.BuildMismatchClaim("hook-panic-sess", "phase-x", "role-y",
		&lineage.MismatchError{Field: "PayloadHash"})
	if err != nil {
		t.Fatalf("BuildMismatchClaim: %v", err)
	}

	// Should NOT panic out to the test goroutine. If it did, this
	// line would never execute.
	runner.ReportFalseLineageClaim("hook-panic-sess", wrongClaim)

	logged := buf.String()
	if logged == "" {
		t.Fatal("expected hook-panic log line, got empty buffer")
	}
	// Spot-check that the canonical context fields made it into the
	// log line. The claim's Role is "mismatch-claim" (hardcoded by
	// BuildMismatchClaim regardless of the role argument passed in —
	// flagged separately as a godoc-audit follow-up); the input
	// "role-y" we passed is discarded by the current API.
	for _, want := range []string{
		"LineageFailureHook panic",
		"hook-panic-sess",
		"phase-x",
		"mismatch-claim",
		"mismatch-false-claim",
		"intentional test panic in hook",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log missing %q\nfull: %s", want, logged)
		}
	}
}

// TestSetHookPanicLog_DiscardSilencesOutput confirms apps can opt
// out of the stderr log by routing the panic writer to io.Discard
// (e.g., production deployments piping panics through their own
// observability stack).
func TestSetHookPanicLog_DiscardSilencesOutput(t *testing.T) {
	var buf bytes.Buffer
	prev := phase.SetHookPanicLog(&buf)
	defer phase.SetHookPanicLog(prev)

	// Buffer was set; now redirect to nowhere.
	phase.SetHookPanicLog(&silentWriter{})
	t.Cleanup(func() { phase.SetHookPanicLog(&buf) })

	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	hook := func(ev phase.LineageFailureEvent) { panic("nope") }
	runner, _ := phase.ComposeWith(
		[]phase.Phase{noopPhase{name: "n", entry: "S1", exit: phase.StateNone}},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
		phase.WithLineageFailureHook(hook),
	)
	runner.BeginSession("hook-silent-sess", "")
	claim, _ := runner.BuildMismatchClaim("hook-silent-sess", "p", "r", &lineage.MismatchError{Field: "PayloadHash"})
	runner.ReportFalseLineageClaim("hook-silent-sess", claim)

	if buf.Len() != 0 {
		t.Errorf("expected silent writer to absorb panic log, got %d bytes in buf: %s", buf.Len(), buf.String())
	}
}

// silentWriter is a Write-blackhole used to confirm SetHookPanicLog
// can route output away from the previous destination.
type silentWriter struct{}

func (silentWriter) Write(p []byte) (int, error) { return len(p), nil }
