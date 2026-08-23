// SPDX-License-Identifier: Apache-2.0

package rideshare_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	rideshare "github.com/Fheyalabs/ares-core/examples/ride_share"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestRideShare_TamperedBid_DetectedByLineage(t *testing.T) {
	dispatcher, _ := sign.NewEd25519Signer()
	driver, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: driver}

	runner, err := rideshare.PipelineWithLineage(dispatcher, peers)
	if err != nil {
		t.Fatalf("PipelineWithLineage: %v", err)
	}
	if _, err := runner.BeginSession("ride-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	bid := map[string]string{
		"price_ct":     hex.EncodeToString([]byte("driver-bid-price")),
		"proximity_ct": hex.EncodeToString([]byte("driver-bid-prox")),
	}
	payload, _ := json.Marshal(bid)
	node, _ := lineage.Commit("ride-1", "rideshare-submit", "bid-driver-1", payload, nil, driver)

	// Tamper attempt: same lineage node, different bytes (server-relay
	// substitution).
	tampered := []byte(`{"price_ct":"deadbeef","proximity_ct":"00"}`)
	_, err = runner.HandleLineageMessage("ride-1", "ride.bid", "driver-1", tampered, &node)
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
