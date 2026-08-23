// SPDX-License-Identifier: Apache-2.0

package auction_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	auction "github.com/Fheyalabs/ares-core/examples/sealed_bid_auction"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestBitflip_DetectedAtEveryLineageStage iterates across every
// lineage-protected message type in the auction pipeline and asserts
// that a single-bit flip in the payload bytes is rejected with
// *lineage.MismatchError{Field:"PayloadHash"} at every stage.
//
// "At every stage" matters: it's not enough that lineage detects a
// tamper at the bid stage; the SC-10 claim is that EVERY phase
// boundary that the framework auto-binds is protected. This test
// proves that for the auction.
//
// Each subtest builds a fresh PipelineWithLineage runner, drives it
// to the target state by submitting upstream messages via the legacy
// HandleMessage path (which bypasses lineage verification — that's
// fine, we don't care about the upstream commits, only about the
// final stage), constructs a properly-signed lineage commit for the
// target message, flips a single bit somewhere in the payload, and
// dispatches via HandleLineageMessage.
//
// The bit-flip index varies across stages (byte 0, middle byte, last
// byte) to demonstrate the rejection is position-independent.
func TestBitflip_DetectedAtEveryLineageStage(t *testing.T) {
	const sessionID = "auction-bitflip"
	participants := []string{"bidder-1", "bidder-2", "bidder-3"}

	type stage struct {
		name    string
		msgType string
		from    string
		phaseID string
		role    string
		target  phase.SessionState
		payload []byte
		flipFn  func([]byte) int // returns flipped index
	}

	stages := []stage{
		{
			name:    "auction.keygen.share at AUCTION_LOCKED (flip byte 0)",
			msgType: "auction.keygen.share",
			from:    "bidder-1",
			phaseID: "auction-keygen",
			role:    "share-bidder-1",
			target:  auction.StateAuctionLocked,
			payload: mustJSON(t, map[string]string{
				"share_ct": hex.EncodeToString([]byte("bidder-1-real-keygen-share")),
			}),
			flipFn: func(_ []byte) int { return 0 },
		},
		{
			name:    "auction.bid at AUCTION_BIDDING (flip middle byte)",
			msgType: "auction.bid",
			from:    "bidder-1",
			phaseID: "auction-scalar-bid",
			role:    "bid-bidder-1",
			target:  auction.StateAuctionBidding,
			payload: mustJSON(t, map[string]string{
				"bid_ct": hex.EncodeToString([]byte("bidder-1-encrypted-scalar-bid-100")),
			}),
			flipFn: func(b []byte) int { return len(b) / 2 },
		},
		{
			name:    "auction.decrypt.partial at AUCTION_DECRYPTING (flip last byte)",
			msgType: "auction.decrypt.partial",
			from:    "bidder-1",
			phaseID: "auction-threshold-decrypt",
			role:    "partial-bidder-1",
			target:  auction.StateAuctionDecrypting,
			payload: mustJSON(t, map[string]string{
				"partial_ct": hex.EncodeToString([]byte("bidder-1-partial-decrypt-share")),
			}),
			flipFn: func(b []byte) int { return len(b) - 1 },
		},
	}

	for _, s := range stages {
		s := s
		t.Run(s.name, func(t *testing.T) {
			auctioneer, _ := sign.NewEd25519Signer()
			bidder, _ := sign.NewEd25519Signer()
			peers := map[string]sign.Signer{sign.Ed25519Algorithm: bidder}

			runner, err := auction.PipelineWithLineage(auctioneer, peers)
			if err != nil {
				t.Fatalf("PipelineWithLineage: %v", err)
			}
			ctx, err := runner.BeginSession(sessionID, "")
			if err != nil {
				t.Fatalf("BeginSession: %v", err)
			}
			ctx.Set(auction.CtxAuctionParticipants, participants)
			ctx.Set(auction.CtxAuctionCryptoContract, map[string]any{
				"depth": 30, "ring_dim": 16384, "scaling_mod_size": 40,
			})

			driveAuctionTo(t, runner, sessionID, participants, s.target)

			// Construct a properly-signed lineage commit for the target
			// payload, then flip one bit and submit.
			node, err := lineage.Commit(sessionID, s.phaseID, s.role, s.payload, nil, bidder)
			if err != nil {
				t.Fatalf("lineage.Commit: %v", err)
			}
			tampered := append([]byte{}, s.payload...)
			idx := s.flipFn(tampered)
			tampered[idx] ^= 0x01
			t.Logf("flipped bit at byte %d (of %d): %q → %q",
				idx, len(tampered), s.payload[idx:idx+1], tampered[idx:idx+1])

			_, err = runner.HandleLineageMessage(sessionID, s.msgType, s.from, tampered, &node)
			if err == nil {
				t.Fatalf("%s: expected *MismatchError, got nil (bitflip undetected!)", s.name)
			}
			var me *lineage.MismatchError
			if !errors.As(err, &me) {
				t.Fatalf("%s: expected *MismatchError, got %T: %v", s.name, err, err)
			}
			if me.Field != "PayloadHash" {
				t.Errorf("%s: MismatchError.Field = %q, want %q", s.name, me.Field, "PayloadHash")
			}
		})
	}
}

// driveAuctionTo advances the runner from its current state to
// target by submitting upstream messages via the legacy HandleMessage
// path (which bypasses lineage verification — fine, we don't care
// about upstream commits in this test).
func driveAuctionTo(t *testing.T, runner *phase.SessionRunner, sessionID string, participants []string, target phase.SessionState) {
	t.Helper()
	current, _ := runner.CurrentState(sessionID)
	if current == target {
		return
	}
	// Always start by advancing past Invitation to LOCKED.
	if err := runner.AdvanceToState(sessionID, auction.StateAuctionLocked); err != nil {
		t.Fatalf("advance to LOCKED: %v", err)
	}
	if target == auction.StateAuctionLocked {
		return
	}
	// Drive keygen.share → BIDDING.
	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "auction.keygen.share", p, []byte("s-"+p)); err != nil {
			t.Fatalf("drive keygen.share from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != auction.StateAuctionBidding {
		t.Fatalf("after keygen drive: state=%q want BIDDING", s)
	}
	if target == auction.StateAuctionBidding {
		return
	}
	// Drive bids → SCORING → (PhaseArgmax auto-advances) → DECRYPTING.
	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "auction.bid", p, []byte("b-"+p)); err != nil {
			t.Fatalf("drive bid from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != auction.StateAuctionDecrypting {
		t.Fatalf("after bid drive: state=%q want DECRYPTING", s)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
