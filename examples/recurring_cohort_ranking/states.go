// SPDX-License-Identifier: Apache-2.0

// Package cohort demonstrates the amortized-keygen
// fast path: the same N participants form a long-lived cohort and
// run MANY sessions against one collective key bundle. Keygen is
// done once at cohort formation; every subsequent session skips
// it entirely and completes in sub-minute wall-clock. This is the
// single biggest performance lever for repeat-participant use
// cases (weekly rankings, recurring auctions, league seasons).
//
// Two runners:
//
//   CohortFormationRunner — runs ONCE per cohort lifecycle:
//     FormCohort → ThresholdKeygen → CohortSealed
//
//   WeeklyRankingSessionRunner — runs per session, ~no-keygen:
//     Invite → PreSharedKeygen → SubmitRating → Argmax → Decrypt → Settle
//
// Cohorts can be rotated: after N sessions or T days, run
// CohortFormationRunner again with a new cohort_id and the old
// key bundle goes stale.
//
// Like examples/sealed_bid_auction, this package imports only
// pkg/ares/phase and pkg/ares/phase/keygen — not
// pkg/ares/phase/defaults. Distinct states, distinct context
// keys, distinct pipeline.
package cohort

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Cohort formation states.
const (
	StateCohortForming  phase.SessionState = "COHORT_FORMING"
	StateCohortKeygen   phase.SessionState = "COHORT_KEYGEN"
	StateCohortSealed   phase.SessionState = "COHORT_SEALED"
)

// Per-session ranking states.
const (
	StateRankingInviting  phase.SessionState = "RANKING_INVITING"
	StateRankingLocked    phase.SessionState = "RANKING_LOCKED"
	StateRankingBidding   phase.SessionState = "RANKING_BIDDING"
	StateRankingScoring   phase.SessionState = "RANKING_SCORING"
	StateRankingDecrypt   phase.SessionState = "RANKING_DECRYPT"
	StateRankingSettled   phase.SessionState = "RANKING_SETTLED"
)

// Session context keys.
const (
	CtxParticipants     = "ranking.participants"
	CtxCohortID         = "ranking.cohort_id"
	CtxCryptoContract   = "ranking.crypto_ctx"
	CtxCollectivePK     = "ranking.collective_pk"
	CtxSecretShares     = "ranking.secret_shares"
	CtxEvalKeys         = "ranking.eval_keys"
	CtxRatings          = "ranking.ratings"
	CtxWinnerRating     = "ranking.ct_winner"
	CtxWinner           = "ranking.winner"
	CtxTranscript       = "ranking.transcript"

	// Accumulator bucket keys.
	bucketCohortKeygenShares = "cohort.bucket.keygen_shares"
	bucketRatings            = "ranking.bucket.ratings"
	bucketDecryptPartials    = "ranking.bucket.decrypt_partials"
)
