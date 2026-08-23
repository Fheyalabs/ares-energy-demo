// SPDX-License-Identifier: Apache-2.0

// Package rideshare demonstrates an inDrive-style ride-sharing
// application on ARES: one rider and N drivers submit encrypted
// bids reflecting price and location. ARES computes a composite
// score (price × proximity) under FHE and reveals only the
// winning (driver, rider, agreed_price) tuple via threshold
// decryption. Losing bids and precise locations are never exposed.
//
// Participants:
//   - One rider: submits (max_price, pickup_lat, pickup_lon)
//   - N drivers: each submits (ask_price, current_lat, current_lon)
//
// Scoring: for each driver,
//   price_fitness  = max(0, 1 - ask_price / rider_max_price)
//   distance       = haversine(driver_pos, rider_pos)
//   proximity      = max(0, 1 - distance / max_radius)
//   score          = alpha * price_fitness + beta * proximity
//
// The highest-scoring driver wins. The winner package carries
// (agreed_price, driver_pseudonym, rider_pseudonym).
//
// As with all ARES examples, phase bodies are declared as stubs —
// the crypto, WS transport, and OpenFHE helper calls are replaced
// by the runtime wiring in a real deployment. The framework proves
// that the phase composition is correct, the context chain is
// satisfied, and the state machine is connected.
//
// Depends only on pkg/ares/phase.
package rideshare

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

const (
	StateInvite     phase.SessionState = "RIDE_INVITE"
	StateKeygen     phase.SessionState = "RIDE_KEYGEN"
	StateSubmit     phase.SessionState = "RIDE_SUBMIT"
	StateScore      phase.SessionState = "RIDE_SCORE"
	StateDecrypt    phase.SessionState = "RIDE_DECRYPT"
	StateSettle     phase.SessionState = "RIDE_SETTLE"
)

const (
	CtxParticipants   = "ride.participants"
	CtxRoles          = "ride.roles"
	CtxCryptoContract = "ride.crypto_ctx"
	CtxCollectivePK   = "ride.collective_pk"
	CtxSecretShares   = "ride.secret_shares"
	CtxEvalKeys       = "ride.eval_keys"
	CtxBids           = "ride.bids"
	CtxWinner         = "ride.ct_winner"
	CtxResult         = "ride.result"
	CtxSettlement     = "ride.settlement"

	// Accumulator bucket keys.
	bucketKeygenShares    = "ride.bucket.keygen_shares"
	bucketBids            = "ride.bucket.bids"
	bucketDecryptPartials = "ride.bucket.decrypt_partials"
)
