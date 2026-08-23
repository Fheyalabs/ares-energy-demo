// SPDX-License-Identifier: Apache-2.0

// Package voting is a worked example showing how to build a non-FHE
// application on top of the ARES framework. Voters submit signed
// weighted ballots; the orchestrator tallies the weighted sum and
// publishes a signed transcript with the result.
//
// The pipeline reuses the default state vocabulary (INVITING, LOCKED,
// GOSSIP, SCORING, DECRYPTING, BROADCASTING) so it can drop in
// keygen.PlaintextKeygen (which owns LOCKED -> GOSSIP) unchanged.
// There is no cryptographic privacy beyond transport-layer signing —
// this example exists to demonstrate that the ARES phase-composition
// machinery works for protocols whose scoring shape is "sum the
// inputs" rather than "FHE argmax of encrypted scores".
//
// Pipeline:
//
//	PhaseInvite      INVITING     -> LOCKED         (server-side, defaults shape)
//	keygen.Plaintext LOCKED       -> GOSSIP         (no-crypto keygen)
//	PhaseSubmitVote  GOSSIP       -> SCORING        (accumulate ballots)
//	PhaseTally       SCORING      -> DECRYPTING     (compute weighted sum)
//	PhaseSettle      DECRYPTING   -> (terminal / StateNone)   (emit signed transcript)
package voting

// SessionContext keys produced and consumed by the voting pipeline.
const (
	CtxVoteParticipants = "vote.participants"
	CtxVoteBallots      = "vote.ballots"    // map[string]Ballot
	CtxVoteTally        = "vote.tally"      // Tally
	CtxVoteTranscript   = "vote.transcript" // signed transcript bytes
)

// Bucket name for accumulated WS ballots inside SessionContext.
const bucketBallots = "vote.bucket.ballots"

// Ballot is one voter's submission. Weight allows weighted voting
// (e.g. share-weighted governance). Choice is the integer choice
// index — the application defines what each index means.
type Ballot struct {
	Voter  string  `json:"voter"`
	Choice int     `json:"choice"`
	Weight float64 `json:"weight"`
}

// Tally is the result of summing weighted choices. WinnerChoice is
// the choice with the largest weighted sum.
type Tally struct {
	Totals       map[int]float64 `json:"totals"` // choice -> sum(weights)
	TotalBallots int             `json:"total_ballots"`
	WinnerChoice int             `json:"winner_choice"`
	WinnerWeight float64         `json:"winner_weight"`
}
