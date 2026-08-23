// SPDX-License-Identifier: Apache-2.0

package anon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/onion"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Participant holds one non-initiator's per-session shuffle state: its
// X25519 slot delivery keypair, its deterministic slot index, and an
// ephemeral Ed25519 signer used to sign its slot submission. The
// ephemeral signer is NOT the participant's long-term identity key, so
// the signed submission proves integrity without revealing which
// identity produced which slot.
type Participant struct {
	SlotIndex int
	SlotPub   []byte // X25519 delivery public key (raw 32 bytes)

	slotPriv  []byte // X25519 delivery private key
	sigSigner *sign.Ed25519Signer
}

// NewParticipant generates a fresh slot keypair and ephemeral signing
// key, assigning the slot index for selfIndex under the shared
// permutation derived from seed.
func NewParticipant(seed []byte, n, selfIndex int) (*Participant, error) {
	priv, pub, err := onion.GenerateSlotKey()
	if err != nil {
		return nil, fmt.Errorf("anon: slot keygen: %w", err)
	}
	sig, err := sign.NewEd25519Signer()
	if err != nil {
		return nil, fmt.Errorf("anon: ephemeral signer: %w", err)
	}
	perm := onion.SlotPermutation(seed, n)
	return &Participant{
		SlotIndex: perm[selfIndex],
		SlotPub:   pub,
		slotPriv:  priv,
		sigSigner: sig,
	}, nil
}

// BuildOnion wraps this participant's (slot_index, slot_dk_pub) payload
// for the full peel order, returning the onion and the self-memo used
// to recognize its own item on peel.
func (p *Participant) BuildOnion(peelOrderPubs [][]byte, selfPeelIndex int) (onionBytes, selfMemo []byte, err error) {
	payload, err := json.Marshal(SlotEntry{SlotIndex: p.SlotIndex, SlotDKPubHex: hex.EncodeToString(p.SlotPub)})
	if err != nil {
		return nil, nil, fmt.Errorf("anon: marshal slot payload: %w", err)
	}
	return onion.BuildOnion(payload, peelOrderPubs, selfPeelIndex)
}

// Peel removes this participant's layer from each onion in the batch,
// identifying its own item via selfMemo.
func (p *Participant) Peel(selfMemo []byte, onions [][]byte) (peeled [][]byte, ownIndex int, err error) {
	return onion.PeelBatch(p.slotPriv, selfMemo, onions)
}

// SlotSubmission returns the JSON payload AND the ephemeral-key-signed
// lineage node for this participant's slot submission. The caller
// attaches the node to the outbound slot-submit frame; the receiving
// runner's HandleLineageMessage verifies it. Signing with the
// ephemeral slot signer (not the identity key) keeps the
// slot->identity mapping hidden from verifiers.
func (p *Participant) SlotSubmission(sessionID string) (payload []byte, node lineage.DAGNode, err error) {
	payload, err = json.Marshal(SlotEntry{SlotIndex: p.SlotIndex, SlotDKPubHex: hex.EncodeToString(p.SlotPub)})
	if err != nil {
		return nil, lineage.DAGNode{}, fmt.Errorf("anon: marshal submission: %w", err)
	}
	node, err = lineage.Commit(sessionID, "anon-g-verify", RoleSlotSubmission, payload, nil, p.sigSigner)
	if err != nil {
		return nil, lineage.DAGNode{}, fmt.Errorf("anon: sign submission: %w", err)
	}
	return payload, node, nil
}
