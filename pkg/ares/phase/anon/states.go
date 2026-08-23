// SPDX-License-Identifier: Apache-2.0

package anon

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Context keys produced/consumed by the shuffle phases.
const (
	// CtxParticipants is the []string of non-initiator participant
	// identifiers (pseudonyms) in the session. Required input.
	CtxParticipants = "anon.participants"

	// CtxPeelRounds is the int count of completed peel-forward rounds.
	// Internal progress marker (not []byte, so not auto-committed).
	CtxPeelRounds = "anon.peel_rounds"

	// CtxAssembledSlotList is the []byte canonical encoding of the
	// ordered slot list (slot_index -> slot_dk_pub) produced by
	// PhaseGVerify. Auto-committed to lineage with the submission
	// nodes as parents.
	CtxAssembledSlotList = "anon.assembled_slot_list"
)

// RoleSlotSubmission is the lineage role assigned to each participant's
// ephemeral-key-signed slot-submission DAG node. Used by both
// Participant.SlotSubmission (sender side) and PhaseGVerify (receiver
// side) to identify submission nodes when building parent edges.
const RoleSlotSubmission = "slot-submission"

// WebSocket message types the shuffle phases consume.
const (
	// MsgOnionBatch carries a participant's initial onion (built for
	// the full peel order, including self). One per participant.
	MsgOnionBatch = "onion.batch"

	// MsgPeelForward carries a peeler's post-peel, post-shuffle batch
	// forwarded toward the next peeler. One per peeler per round.
	MsgPeelForward = "onion.peel_forward"

	// MsgSlotSubmit carries one participant's (slot_index, slot_dk_pub)
	// submission, signed by that slot's ephemeral key. One per
	// participant.
	MsgSlotSubmit = "slot.submit"
)

// internal accumulation buckets.
const (
	bucketOnions = "anon.bucket.onions"
	bucketPeels  = "anon.bucket.peels"
	bucketSlots  = "anon.bucket.slots"
)

// AccumulatedOnions returns a shallow copy of the per-participant onion
// payloads accumulated under the onion.batch bucket for the session.
// The map key is the participant pseudonym; the value is the raw JSON
// payload bytes of their onion.batch submission.
//
// External packages (e.g. a transport relay) should call this instead of
// reading the bucket key directly — the bucket name is an internal
// implementation detail of this package.
//
// Returns an empty (non-nil) map if no onion.batch messages have been
// received yet.
func AccumulatedOnions(ctx *phase.SessionContext) map[string][]byte {
	return phase.AccumulatedMessages(ctx, bucketOnions)
}
