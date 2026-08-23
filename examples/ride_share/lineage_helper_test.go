// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package rideshare

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

// TestPipelineWithLineageAndHelper_TamperRejected proves the v0.4.0
// lineage verify-before-dispatch path remains intact for the ride
// share app when the runner is built with helper-mode phases. Mirrors
// the stub-mode TestRideShare_TamperedBid_DetectedByLineage from
// tamper_test.go.
func TestPipelineWithLineageAndHelper_TamperRejected(t *testing.T) {
	binary := buildHelperBinary(t)
	defer os.Remove(binary)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := helperclient.Start(ctx, binary)
	if err != nil {
		t.Fatalf("helper start: %v", err)
	}
	defer client.Close()

	dispatcher, _ := sign.NewEd25519Signer()
	driver, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: driver}

	sharpening := helperclient.EvalPolyParams{
		Coefficients: []float64{0.5, 0.75, 0, -0.25},
		LowerBound:   -1, UpperBound: 1,
	}
	runner, err := PipelineWithLineageAndHelper(client, sharpening, dispatcher, peers)
	if err != nil {
		t.Fatalf("PipelineWithLineageAndHelper: %v", err)
	}
	if _, err := runner.BeginSession("ride-helper-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	bid := map[string]string{
		"price_ct":     hex.EncodeToString([]byte("driver-bid-price")),
		"proximity_ct": hex.EncodeToString([]byte("driver-bid-prox")),
	}
	payload, _ := json.Marshal(bid)
	node, err := lineage.Commit("ride-helper-1", "rideshare-submit", "bid-driver-1", payload, nil, driver)
	if err != nil {
		t.Fatalf("lineage.Commit: %v", err)
	}

	tampered := []byte(`{"price_ct":"deadbeef","proximity_ct":"00"}`)
	_, err = runner.HandleLineageMessage("ride-helper-1", "ride.bid", "driver-1", tampered, &node)
	if err == nil {
		t.Fatal("expected lineage rejection")
	}
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if me.Field != "PayloadHash" {
		t.Errorf("MismatchError.Field = %q, want %q", me.Field, "PayloadHash")
	}
}

// buildHelperBinary builds the openfhe-contract-helper subprocess for
// the duration of one test. Skips the test if the build fails (no
// OpenFHE locally).
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
