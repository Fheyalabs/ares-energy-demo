// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package auction

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestPipelineWithLineageAndHelper_TamperRejected proves the v0.4.0
// lineage verify-before-dispatch path remains intact when the runner
// is built with helper-mode phases. Same shape as the stub-mode
// tamper smoke (auction_test.TestAuction_TamperedBid_DetectedByLineage)
// but with PipelineWithLineageAndHelper instead of PipelineWithLineage.
//
// This is the only checked-in test that exercises the combined
// "real FHE phase wiring" + "SC-10 ciphertext lineage" path. It
// proves the constructor's argument plumbing is correct and that
// the runner's HandleLineageMessage middleware rejects tampered
// bytes regardless of whether downstream phases are stub or helper
// backed.
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

	auctioneer, _ := sign.NewEd25519Signer()
	bidder, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: bidder}

	sharpening := helperclient.EvalPolyParams{
		Coefficients: []float64{0.5, 0.75, 0, -0.25},
		LowerBound:   -1, UpperBound: 1,
	}
	runner, err := PipelineWithLineageAndHelper(client, sharpening, auctioneer, peers)
	if err != nil {
		t.Fatalf("PipelineWithLineageAndHelper: %v", err)
	}
	if _, err := runner.BeginSession("auction-helper-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	bid := map[string]string{"bid_ct": hex.EncodeToString([]byte("bidder-encrypted-100"))}
	payload, _ := json.Marshal(bid)
	node, err := lineage.Commit("auction-helper-1", "auction-scalar-bid", "bid-bidder-1", payload, nil, bidder)
	if err != nil {
		t.Fatalf("lineage.Commit: %v", err)
	}

	tampered := []byte(`{"bid_ct":"deadbeef"}`)
	_, err = runner.HandleLineageMessage("auction-helper-1", "auction.bid", "bidder-1", tampered, &node)
	if err == nil {
		t.Fatal("expected lineage rejection of tampered bid")
	}
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if me.Field != "PayloadHash" {
		t.Errorf("MismatchError.Field = %q, want %q", me.Field, "PayloadHash")
	}
}

// TestPipelineWithLineageAndHelper_GoodCommitAccepted proves the
// happy path: an untampered, properly-signed bid commit is accepted
// by HandleLineageMessage and the node lands in the runner's DAG.
// Counterpart to the tamper test above.
func TestPipelineWithLineageAndHelper_GoodCommitAccepted(t *testing.T) {
	binary := buildHelperBinary(t)
	defer os.Remove(binary)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := helperclient.Start(ctx, binary)
	if err != nil {
		t.Fatalf("helper start: %v", err)
	}
	defer client.Close()

	auctioneer, _ := sign.NewEd25519Signer()
	bidder, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: bidder}

	sharpening := helperclient.EvalPolyParams{
		Coefficients: []float64{0.5, 0.75, 0, -0.25},
		LowerBound:   -1, UpperBound: 1,
	}
	runner, err := PipelineWithLineageAndHelper(client, sharpening, auctioneer, peers)
	if err != nil {
		t.Fatalf("PipelineWithLineageAndHelper: %v", err)
	}
	sctx, err := runner.BeginSession("auction-helper-2", "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	// Confirm the runner is lineage-enabled (Compose-built runners
	// return an empty LineageDAG seq).
	dag := sctx.LineageDAG()
	if dag == nil {
		t.Fatal("expected non-nil LineageDAG on ComposeWith-built runner")
	}

	// Seed the minimal context PhaseScalarBid expects and advance the
	// session into AUCTION_BIDDING (PhaseScalarBid's entry state).
	sctx.Set(CtxAuctionParticipants, []string{"bidder-1", "bidder-2", "bidder-3"})
	sctx.Set(CtxAuctionCryptoContract, map[string]any{
		"ring_dim": 2048, "depth": 10, "scaling_mod_size": 40,
	})
	if err := runner.AdvanceToState("auction-helper-2", StateAuctionBidding); err != nil {
		t.Fatalf("advance to BIDDING: %v", err)
	}

	bid := map[string]string{"bid_ct": hex.EncodeToString([]byte("bidder-encrypted-50"))}
	payload, _ := json.Marshal(bid)
	node, err := lineage.Commit("auction-helper-2", "auction-scalar-bid", "bid-bidder-1", payload, nil, bidder)
	if err != nil {
		t.Fatalf("lineage.Commit: %v", err)
	}

	// Submit the bid + matching payload bytes. Only 1 of 3 bidders
	// has submitted so quorum won't trip; the assertion is that
	// lineage verification PASSED, the dispatch reached
	// PhaseScalarBid.OnMessage, and the node was persisted.
	_, err = runner.HandleLineageMessage("auction-helper-2", "auction.bid", "bidder-1", payload, &node)
	if err != nil {
		t.Fatalf("HandleLineageMessage (good): %v", err)
	}

	// Walk the session DAG and confirm our node was committed.
	found := false
	for n := range sctx.LineageDAG() {
		if n.Hash == node.Hash {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("committed node %x not present in LineageDAG after HandleLineageMessage", node.Hash[:8])
	}
}
