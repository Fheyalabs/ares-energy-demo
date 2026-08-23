// SPDX-License-Identifier: Apache-2.0

package auction_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	auction "github.com/Fheyalabs/ares-core/examples/sealed_bid_auction"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Seed Phase ScalarBid's pre-conditions on the SessionContext so
// HandleLineageMessage can route the bid to the phase. The minimal
// seeding mirrors what the production trigger would set.
const (
	ctxAuctionParticipants    = "auction_participants"
	ctxAuctionCollectivePK    = "auction_collective_pk"
	ctxAuctionCryptoContract  = "auction_crypto_ctx"
)

func TestAuction_TamperedBid_DetectedByLineage(t *testing.T) {
	auctioneer, _ := sign.NewEd25519Signer()
	bidder1, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: bidder1}

	runner, err := auction.PipelineWithLineage(auctioneer, peers)
	if err != nil {
		t.Fatalf("PipelineWithLineage: %v", err)
	}
	if _, err := runner.BeginSession("auction-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	// Construct a signed bid commitment.
	bid := map[string]string{"bid_ct": hex.EncodeToString([]byte("bidder-1-encrypted-100"))}
	payload, _ := json.Marshal(bid)
	node, _ := lineage.Commit("auction-1", "auction-scalar-bid", "bid-bidder-1", payload, nil, bidder1)

	// Server-relay tamper: same lineage node, different bytes.
	tampered := []byte(`{"bid_ct":"deadbeef"}`)
	_, err = runner.HandleLineageMessage("auction-1", "auction.bid", "bidder-1", tampered, &node)
	if err == nil {
		t.Fatal("expected lineage rejection of tampered bid")
	}
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Errorf("expected *MismatchError wrapped in returned error, got %T: %v", err, err)
	}
	if me != nil && me.Field != "PayloadHash" {
		t.Errorf("MismatchError.Field = %q, want %q", me.Field, "PayloadHash")
	}
}
