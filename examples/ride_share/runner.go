// SPDX-License-Identifier: Apache-2.0

package rideshare

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Pipeline builds a SessionRunner for the inDrive-style
// ride-share pipeline:
//
//   Invite → Keygen → Submit → Score → Decrypt → Settle
//
// Six phases. Depth=12 circuit (price_fitness × proximity_fitness
// composite score — shallower than Fheya's depth=30 cosine chain
// but deeper than the auction's depth=10 scalar argmax).
//
// Roles are assigned by PhaseInvite: one rider, N drivers.
// The scorer computes a composite (weighted sum of price
// fitness and proximity) for each driver and selects the
// argmax. The winner package reveals (agreed_price,
// driver_id, rider_id) to both parties.
func Pipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvite(),
		NewPhaseKeygen(),
		NewPhaseSubmit(),
		NewPhaseScore(),
		NewPhaseDecrypt(),
		NewPhaseSettle(),
	)
}

// PipelineWithHelper substitutes the helper-backed phases
// for the stubs. PhaseKeygen produces real threshold CKKS keys
// (unless pre-shared keys are seeded into context by the trigger)
// and PhaseScore runs real argmax against the encrypted bids.
func PipelineWithHelper(
	helper *helperclient.Client,
	sharpening helperclient.EvalPolyParams,
) (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvite(),
		NewPhaseKeygenWithHelper(helper),
		NewPhaseSubmit(),
		NewPhaseScoreWithHelper(helper, sharpening),
		NewPhaseDecryptWithHelper(helper),
		NewPhaseSettle(),
	)
}

// PipelineWithLineage builds the ride-share pipeline with SC-10
// ciphertext lineage enabled. signer is the dispatcher's signing
// key; peerVerifiers maps signature-scheme name to a Signer that
// can verify peer signatures on inbound DAGNodes (the producer
// pubkey lives on the node itself).
func PipelineWithLineage(signer sign.Signer, peerVerifiers map[string]sign.Signer) (*phase.SessionRunner, error) {
	return phase.ComposeWith(
		[]phase.Phase{
			NewPhaseInvite(),
			NewPhaseKeygen(),
			NewPhaseSubmit(),
			NewPhaseScore(),
			NewPhaseDecrypt(),
			NewPhaseSettle(),
		},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peerVerifiers),
		phase.WithStore(lineage.NewInMemoryStore()),
	)
}

// PipelineWithLineageAndHelper is the lineage-enabled variant
// using openfhe-contract-helper for real CKKS work.
func PipelineWithLineageAndHelper(
	helper *helperclient.Client,
	sharpening helperclient.EvalPolyParams,
	signer sign.Signer,
	peerVerifiers map[string]sign.Signer,
) (*phase.SessionRunner, error) {
	return phase.ComposeWith(
		[]phase.Phase{
			NewPhaseInvite(),
			NewPhaseKeygenWithHelper(helper),
			NewPhaseSubmit(),
			NewPhaseScoreWithHelper(helper, sharpening),
			NewPhaseDecryptWithHelper(helper),
			NewPhaseSettle(),
		},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peerVerifiers),
		phase.WithStore(lineage.NewInMemoryStore()),
	)
}
