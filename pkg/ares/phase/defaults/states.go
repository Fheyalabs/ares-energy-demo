// SPDX-License-Identifier: Apache-2.0

// Package defaults provides generic phase implementations the ARES
// framework ships out of the box. Each phase corresponds to one arc
// of the canonical session state machine:
//
//	Phase 1a — Session Initiation          (INVITING   → LOCKED)
//	Phase 0a — Threshold Keygen            (LOCKED     → GOSSIP)
//	Phase 3  — Threshold Decrypt           (DECRYPTING → BROADCASTING)
//
// Generic-shape state labels (LOCKED, KEYGEN, GOSSIP, VERIFYING,
// SUBMITTING, SCORING, DECRYPTING, BROADCASTING, CLOSED) are also
// declared here so app authors can compose pipelines that include
// the GOSSIP / VERIFYING / SUBMITTING arcs even though no default
// phase claims those states yet. Applications supply the missing
// phases (input submission, scoring, post-result) themselves; see
// `examples/sealed_bid_auction/`, `examples/ride_share/`, and
// `examples/recurring_cohort_ranking/` for full pipelines.
//
// Phases that were historically named for an ARES-as-matchmaking
// reading (encrypted profile submit, FHE cosine scoring, anonymous
// post-result broadcast, onion shuffle, verification) live in
// application repositories, not here. The framework deliberately
// ships no opinionated default runner — applications compose their
// own pipeline via `phase.Compose(...)`.
package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// SessionState labels covering the canonical state-machine arcs.
// Applications may use the subset their pipeline traverses.
const (
	StateInviting     phase.SessionState = "INVITING"
	StateLocked       phase.SessionState = "LOCKED"
	// StateKeygen is an internal sub-state of Phase 0a — the
	// engine transitions LOCKED → KEYGEN on the first
	// KeyShareSubmitted event and accumulates remaining keyshare
	// and eval-round events within KEYGEN before transitioning
	// to GOSSIP on KeygenComplete. Phase 0a declares KEYGEN as
	// an InternalState so PhaseForState / AdvanceToState treat
	// it as "still inside Phase 0a" rather than a missing phase.
	StateKeygen       phase.SessionState = "KEYGEN"
	StateGossip       phase.SessionState = "GOSSIP"
	StateVerifying    phase.SessionState = "VERIFYING"
	StateSubmitting   phase.SessionState = "SUBMITTING"
	StateScoring      phase.SessionState = "SCORING"
	StateDecrypting   phase.SessionState = "DECRYPTING"
	StateBroadcasting phase.SessionState = "BROADCASTING"
	StateClosed       phase.SessionState = "CLOSED"
)

// SessionContext key names used by the framework's generic default
// phases. Applications may reference these directly when composing
// pipelines that include Phase 1a, Phase 0a, or Phase 3, and add
// their own keys for app-specific phases.
const (
	// CtxParticipants holds the ordered list of participant
	// pseudonyms for the session. Typically provided by Phase 1a;
	// consumed by every later phase.
	CtxParticipants = "participants"

	// CtxCryptoContract holds the FHE / CKKS parameter contract
	// (ring_dim, depth, scaling_mod_size, ...). Typically provided
	// by Phase 0a or by an out-of-band cohort-keygen phase.
	CtxCryptoContract = "crypto_ctx"

	// CtxCollectivePublicKey holds the joint public key after
	// threshold keygen. Provided by Phase 0a; consumed by phases
	// that encrypt under the session key.
	CtxCollectivePublicKey = "collective_pk"

	// CtxSecretShares holds per-participant threshold secret key
	// shares. Provided by Phase 0a; consumed by Phase 3 for
	// partial decrypt.
	CtxSecretShares = "secret_shares"

	// CtxEvalKeys holds the collective evaluation keys (eval-mult,
	// eval-sum) needed for homomorphic operations in the scoring
	// phase. Provided by Phase 0a.
	CtxEvalKeys = "eval_keys"

	// CtxResultCiphertext holds the scorer's emitted result
	// ciphertext — the FHE-evaluated output that Phase 3 will
	// threshold-decrypt. Provided by the app's scoring phase;
	// consumed by Phase 3.
	CtxResultCiphertext = "result_ct"

	// CtxResultBytes holds the threshold-decrypted plaintext result
	// recovered from CtxResultCiphertext. Provided by Phase 3;
	// consumed by the app's post-result phase (if any).
	CtxResultBytes = "result_bytes"
)
