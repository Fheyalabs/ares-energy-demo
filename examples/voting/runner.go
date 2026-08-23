// SPDX-License-Identifier: Apache-2.0

package voting

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/anon"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/keygen"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Pipeline builds the voting SessionRunner:
//
//	Invite -> PlaintextKeygen -> SubmitVote -> Tally -> Settle
//
// No FHE; PlaintextKeygen is a documented no-op that fills the
// LOCKED -> GOSSIP arc without producing crypto material. Use this
// example as a template for applications whose threat model trusts
// the orchestrator (regulated governance, internal voting, etc.).
func Pipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvite(),
		keygen.NewPlaintextKeygen(),
		NewPhaseSubmitVote(),
		NewPhaseTally(),
		NewPhaseSettle(),
	)
}

// PipelineWithLineage builds the voting pipeline with SC-10
// ciphertext lineage enabled. Ballots are not FHE-encrypted in
// this example (PlaintextKeygen topology) but lineage still binds
// each ballot's bytes to its submitter — preventing the election
// authority from swapping ballots between collection and tally.
// Demonstrates SC-10 is useful for non-FHE ARES apps too: the
// binding is over byte payloads, not over cryptographic objects
// specifically.
func PipelineWithLineage(signer sign.Signer, peerVerifiers map[string]sign.Signer) (*phase.SessionRunner, error) {
	return phase.ComposeWith(
		[]phase.Phase{
			NewPhaseInvite(),
			keygen.NewPlaintextKeygen(),
			NewPhaseSubmitVote(),
			NewPhaseTally(),
			NewPhaseSettle(),
		},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peerVerifiers),
		phase.WithStore(lineage.NewInMemoryStore()),
	)
}

// PipelineWithShuffle builds the voting pipeline with inter-participant
// slot anonymity: an onion-shuffle gossip round runs between keygen and
// ballot submission so the election authority cannot link an
// anonymized slot to the voter who produced it. Demonstrates the
// generic pkg/ares/phase/anon primitive on a non-FHE app.
//
// Arc: Invite -> PlaintextKeygen -> Shuffle(GOSSIP->VERIFYING)
//
//	-> Verify(VERIFYING->SUBMITTING) -> SubmitVote(SUBMITTING->SCORING)
//	-> Tally -> Settle.
func PipelineWithShuffle(signer sign.Signer, peerVerifiers map[string]sign.Signer) (*phase.SessionRunner, error) {
	return phase.ComposeWith(
		[]phase.Phase{
			NewPhaseInvite(),
			keygen.NewPlaintextKeygen(),
			anon.NewPhaseGShuffle(),
			anon.NewPhaseGVerify(defaults.StateSubmitting),
			NewPhaseSubmitVoteAt(defaults.StateSubmitting),
			NewPhaseTally(),
			NewPhaseSettle(),
		},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peerVerifiers),
		phase.WithStore(lineage.NewInMemoryStore()),
	)
}
