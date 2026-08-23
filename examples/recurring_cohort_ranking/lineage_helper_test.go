// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cohort

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestFormationPipelineWithLineageAndHelper_TamperRejected mirrors the
// stub-mode TestCohortFormation_TamperedKeygenShare_DetectedByLineage
// but builds the formation runner with helper-backed PhaseCohortKeygen.
// Validates the helper+lineage combined wiring on the cohort
// formation pipeline.
func TestFormationPipelineWithLineageAndHelper_TamperRejected(t *testing.T) {
	binary := buildHelperBinary(t)
	defer os.Remove(binary)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := helperclient.Start(ctx, binary)
	if err != nil {
		t.Fatalf("helper start: %v", err)
	}
	defer client.Close()

	orchestrator, _ := sign.NewEd25519Signer()
	participant, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: participant}

	formation, err := FormationPipelineWithLineageAndHelper(client, store, orchestrator, peers)
	if err != nil {
		t.Fatalf("FormationPipelineWithLineageAndHelper: %v", err)
	}
	if _, err := formation.BeginSession("cohort-helper-w22", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	share := map[string]string{"share_ct": hex.EncodeToString([]byte("participant-keygen-share"))}
	payload, _ := json.Marshal(share)
	node, err := lineage.Commit("cohort-helper-w22", "cohort-keygen", "share-participant-1", payload, nil, participant)
	if err != nil {
		t.Fatalf("lineage.Commit: %v", err)
	}

	tampered := []byte(`{"share_ct":"deadbeef"}`)
	_, err = formation.HandleLineageMessage("cohort-helper-w22", "cohort.keygen.share", "p1", tampered, &node)
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

// TestWeeklyPipelineWithLineageAndHelper_ConstructorContract confirms
// the helper-backed weekly constructor accepts the same Store as the
// formation pipeline (for cross-runner DAG resolution) and that it
// surfaces the same standalone-uncomposable behavior as the stub-mode
// WeeklyPipelineWithLineage (PhasePreSharedKeyLookup needs caller-
// seeded keys, which Compose-time validation can't satisfy).
func TestWeeklyPipelineWithLineageAndHelper_ConstructorContract(t *testing.T) {
	binary := buildHelperBinary(t)
	defer os.Remove(binary)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := helperclient.Start(ctx, binary)
	if err != nil {
		t.Fatalf("helper start: %v", err)
	}
	defer client.Close()

	signer, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	store := lineage.NewInMemoryStore()
	sharpening := helperclient.EvalPolyParams{
		Coefficients: []float64{0.5, 0.75, 0, -0.25},
		LowerBound:   -1, UpperBound: 1,
	}

	// Formation constructs cleanly with the shared store.
	if _, err := FormationPipelineWithLineageAndHelper(client, store, signer, peers); err != nil {
		t.Errorf("FormationPipelineWithLineageAndHelper: %v", err)
	}

	// Weekly is standalone-uncomposable BY DESIGN — same contract as
	// the non-helper, non-lineage WeeklyPipeline. The constructor
	// must surface a composition error.
	_, err = WeeklyPipelineWithLineageAndHelper(client, sharpening, store, signer, peers)
	if err == nil {
		t.Error("WeeklyPipelineWithLineageAndHelper should fail standalone (matches WeeklyPipeline behavior)")
	}
}

func buildHelperBinary(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		root = filepath.Dir(root)
	}
	binary, err := os.CreateTemp("", "openfhe-contract-helper-*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	binary.Close()
	cmd := exec.Command("go", "build", "-tags", "openfhe", "-o", binary.Name(),
		"./cmd/openfhe-contract-helper")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(binary.Name())
		t.Skipf("helper build failed (missing OpenFHE?): %s", out)
	}
	return binary.Name()
}
