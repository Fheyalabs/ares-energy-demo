// SPDX-License-Identifier: Apache-2.0

package auction

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Pipeline builds a SessionRunner over the auction
// pipeline:
//
//	Invitation → Keygen → ScalarBid → Argmax → Decrypt → Settlement
//
// The pipeline is shorter than Fheya's (six phases vs eight) because
// the auction skips onion-shuffle and verification (no slot
// anonymity required) and replaces Phase D with a one-shot signed
// settlement.
//
// The crypto contract emitted by Invitation carries depth=10
// (vs Fheya's depth=30); Argmax requires depth_min=8, which the
// runner validates at construction time.
//
// PhaseArgmax in this variant uses the stub scoring path. For real
// CKKS scoring against the OpenFHE helper, use
// PipelineWithHelper.
func Pipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvitation(),
		NewPhaseKeygen(),
		NewPhaseScalarBid(),
		NewPhaseArgmax(),
		NewPhaseDecrypt(),
		NewPhaseSettlement(),
	)
}

// PipelineWithHelper builds the same pipeline but
// uses a helper-backed PhaseArgmax. The sharpening polynomial is
// applied to each pairwise bid difference; the [0,1]-mapped degree-3
// approximation (0.5 + 0.75x − 0.25x³) is a sensible default for
// well-separated normalized bids.
func PipelineWithHelper(
	helper *helperclient.Client,
	sharpening helperclient.EvalPolyParams,
) (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvitation(),
		NewPhaseKeygenWithHelper(helper),
		NewPhaseScalarBid(),
		NewPhaseArgmaxWithHelper(helper, sharpening),
		NewPhaseDecryptWithHelper(helper),
		NewPhaseSettlement(),
	)
}

// PipelineWithLineage builds the auction pipeline with SC-10
// ciphertext lineage enabled. signer is the auctioneer's signing
// keypair; peerVerifiers maps signature-scheme name (e.g.
// sign.Ed25519Algorithm) to a Signer that can verify peer
// signatures (typically a Signer with the matching scheme;
// pubkey is supplied per-DAGNode via node.Producer). Bidders'
// signed bid commits arrive on WSMessage.Lineage.
//
// Pipelines built via this constructor emit
// transport.WireProtocolVersionLineage ("2") frames with required
// Lineage fields. The hub rejects malformed v2 frames before they
// reach the runner.
func PipelineWithLineage(signer sign.Signer, peerVerifiers map[string]sign.Signer) (*phase.SessionRunner, error) {
	return phase.ComposeWith(
		[]phase.Phase{
			NewPhaseInvitation(),
			NewPhaseKeygen(),
			NewPhaseScalarBid(),
			NewPhaseArgmax(),
			NewPhaseDecrypt(),
			NewPhaseSettlement(),
		},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peerVerifiers),
		phase.WithStore(lineage.NewInMemoryStore()),
	)
}

// PipelineWithLineageAndHelper is the lineage-enabled variant that
// also accepts an openfhe-contract-helper for real CKKS work.
func PipelineWithLineageAndHelper(
	helper *helperclient.Client,
	sharpening helperclient.EvalPolyParams,
	signer sign.Signer,
	peerVerifiers map[string]sign.Signer,
) (*phase.SessionRunner, error) {
	return phase.ComposeWith(
		[]phase.Phase{
			NewPhaseInvitation(),
			NewPhaseKeygenWithHelper(helper),
			NewPhaseScalarBid(),
			NewPhaseArgmaxWithHelper(helper, sharpening),
			NewPhaseDecryptWithHelper(helper),
			NewPhaseSettlement(),
		},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peerVerifiers),
		phase.WithStore(lineage.NewInMemoryStore()),
	)
}
