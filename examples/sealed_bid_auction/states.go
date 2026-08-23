// SPDX-License-Identifier: Apache-2.0

// Package auction is a worked example showing how to build a
// non-Fheya application on top of the ARES framework. The auction
// has N bidders, each submits one encrypted scalar bid amount, the
// server runs encrypted argmax to identify the winner, threshold
// decryption reveals only the winning bid amount and the winning
// bidder's pseudonym, and a signed settlement transcript closes the
// session. There is no Phase D back-channel.
//
// The package is intentionally self-contained: it does not import
// pkg/ares/phase/defaults (which carries Fheya-shaped phase shapes
// like onion shuffling and ECIES winner packages — concepts the
// auction does not need). It depends only on pkg/ares/phase for the
// abstraction primitives. This is the proof that the framework is
// genuinely a framework: a second application composes its own
// pipeline from scratch using only the public Phase / SessionRunner
// interfaces.
//
// Compared to the Fheya default pipeline:
//
//	defaults pipeline (Fheya):    Phase1a → Phase0a → PhaseG → PhaseG2 → Phase1b → Phase2 → Phase3 → PhaseD
//	auction pipeline:             Invitation → Keygen → ScalarBid → Argmax → Decrypt → Settlement
//
// Auction skips onion-shuffle (PhaseG) and verification (PhaseG.2)
// because slot anonymity is not required — the winning bidder's
// identity is intentionally revealed in the settlement transcript.
// Phase D is replaced by a single-shot Settlement phase that emits a
// signed transcript and terminates.
package auction

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// SessionState labels for the auction pipeline. Distinct from the
// Fheya defaults so the two pipelines could in principle run in the
// same process without colliding.
const (
	StateAuctionInviting   phase.SessionState = "AUCTION_INVITING"
	StateAuctionLocked     phase.SessionState = "AUCTION_LOCKED"
	StateAuctionBidding    phase.SessionState = "AUCTION_BIDDING"
	StateAuctionScoring    phase.SessionState = "AUCTION_SCORING"
	StateAuctionDecrypting phase.SessionState = "AUCTION_DECRYPTING"
	StateAuctionSettled    phase.SessionState = "AUCTION_SETTLED"
)

// Context keys for the auction. Distinct names (CtxAuction*) so the
// auction's context schema does not overlap with the Fheya defaults
// package's key strings. The framework treats keys as opaque
// strings; the namespacing is purely for our sanity.
const (
	// CtxParticipants holds the ordered pseudonyms of the N
	// bidders. Provided by Invitation; consumed by everything
	// downstream.
	CtxAuctionParticipants = "auction.participants"

	// CtxAuctionCryptoContract pins the CKKS parameters. Because
	// argmax is much shallower than the Fheya selector chain, the
	// auction can run at depth=10 (vs 30 for Fheya), shrinking
	// keygen cost meaningfully.
	CtxAuctionCryptoContract = "auction.crypto_ctx"

	// CtxAuctionCollectivePublicKey holds the joint CKKS public
	// key after Keygen.
	CtxAuctionCollectivePublicKey = "auction.collective_pk"

	// CtxAuctionSecretShares holds threshold secret-key shares
	// indexed by bidder pseudonym. Used in Decrypt.
	CtxAuctionSecretShares = "auction.secret_shares"

	// CtxAuctionEvalKeys holds the collective evaluation keys
	// needed by Argmax's homomorphic comparator.
	CtxAuctionEvalKeys = "auction.eval_keys"

	// CtxAuctionBids holds the encrypted scalar bid ciphertexts,
	// indexed by bidder pseudonym. Provided by ScalarBid;
	// consumed by Argmax.
	CtxAuctionBids = "auction.bids"

	// CtxAuctionCipherWinnerBid holds the encrypted (winning_bid,
	// winner_id) tuple emitted by Argmax. Consumed by Decrypt.
	CtxAuctionCipherWinnerBid = "auction.ct_winner_bid"

	// CtxAuctionWinnerBid holds the cleartext (winning_bid,
	// winner_id) tuple after threshold decryption. Consumed by
	// Settlement.
	CtxAuctionWinnerBid = "auction.winner_bid"

	// CtxAuctionSettlement holds the signed settlement transcript
	// (winning_bid, winner_id, signed by the auctioneer).
	CtxAuctionSettlement = "auction.settlement"

	// Accumulator bucket keys — used internally by phase OnMessage
	// hooks to track which participants have submitted. Not part of
	// the cross-phase context schema; phases produce CtxAuction* keys
	// instead.
	bucketKeygenShares    = "auction.bucket.keygen_shares"
	bucketScalarBids      = "auction.bucket.scalar_bids"
	bucketDecryptPartials = "auction.bucket.decrypt_partials"
)
