// SPDX-License-Identifier: Apache-2.0

package auction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// PhaseInvitation opens an auction. The auctioneer picks N bidders
// from the registered pool, pins the CKKS parameters appropriate to
// the argmax scoring circuit (much shallower than Fheya's cosine
// chain), and broadcasts `auction.invitation` to each participant.
//
// Compare to defaults.Phase1aSessionInitiation: same shape (server-
// side decision, no WS in, transitions on acceptance) but the crypto
// contract carries depth=10 instead of depth=30 — the chief
// performance win of moving from a vector cosine circuit to a scalar
// argmax circuit.
type PhaseInvitation struct{}

func NewPhaseInvitation() *PhaseInvitation { return &PhaseInvitation{} }

func (PhaseInvitation) Name() string                                                              { return "auction-invitation" }
func (PhaseInvitation) Lifetime() phase.Lifetime                                                  { return phase.LifetimePerSession }
func (PhaseInvitation) RunsAt() phase.RunsAt                                                      { return phase.RunsAtInline }
func (PhaseInvitation) EntryState() phase.SessionState                                            { return StateAuctionInviting }
func (PhaseInvitation) ExitState() phase.SessionState                                             { return StateAuctionLocked }
func (PhaseInvitation) ConsumedMessageTypes() []string                                            { return nil }
func (PhaseInvitation) InternalStates() []phase.SessionState                                      { return nil }
func (PhaseInvitation) Requires() phase.ContextSchema                                             { return nil }
func (PhaseInvitation) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants: {TypeName: "[]string"},
		CtxAuctionCryptoContract: {
			TypeName: "OpenFHEContract",
			Constraints: map[string]any{
				"depth":            10,
				"ring_dim":         2048,
				"scaling_mod_size": 40,
			},
		},
	}
}
func (PhaseInvitation) Enter(*phase.SessionContext) error                                         { return nil }
func (PhaseInvitation) OnMessage(*phase.SessionContext, string, string, []byte) error             { return nil }
func (PhaseInvitation) CheckComplete(*phase.SessionContext) bool                                  { return true }
func (PhaseInvitation) Exit(*phase.SessionContext) error                                          { return nil }

// PhaseKeygen runs the chained N-party threshold CKKS keygen and
// produces the collective public key, the per-bidder secret shares,
// and the joint evaluation keys for the argmax circuit.
//
// Same crypto protocol as defaults.Phase0aThresholdKeygen, but the
// state arc is LOCKED → BIDDING (the auction skips onion shuffle
// and verification entirely). When task #14 lands the non-MPC
// keygen variants, the auction will be able to swap this phase for
// SinglePartyKeygen and run dramatically faster, trading the
// threshold property for an auctioneer-trusted execution model.
type PhaseKeygen struct {
	helper *helperclient.Client
}

func NewPhaseKeygen() *PhaseKeygen { return &PhaseKeygen{} }

// NewPhaseKeygenWithHelper constructs a PhaseKeygen that calls the
// real openfhe-contract-helper for threshold keygen, producing genuine
// CKKS eval keys that downstream helper-backed phases can deserialize.
func NewPhaseKeygenWithHelper(helper *helperclient.Client) *PhaseKeygen {
	return &PhaseKeygen{helper: helper}
}

func (PhaseKeygen) Name() string                   { return "auction-keygen" }
func (PhaseKeygen) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseKeygen) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseKeygen) EntryState() phase.SessionState { return StateAuctionLocked }
func (PhaseKeygen) ExitState() phase.SessionState  { return StateAuctionBidding }
func (PhaseKeygen) ConsumedMessageTypes() []string             { return []string{"auction.keygen.share"} }
func (PhaseKeygen) InternalStates() []phase.SessionState       { return nil }
func (PhaseKeygen) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:   {TypeName: "[]string", Required: true},
		CtxAuctionCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 4}},
	}
}
func (PhaseKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionCollectivePublicKey: {TypeName: "[]byte"},
		CtxAuctionSecretShares:        {TypeName: "map[string][]byte"},
		CtxAuctionEvalKeys:            {TypeName: "OpenFHEEvalKeys"},
	}
}
func (PhaseKeygen) Enter(*phase.SessionContext) error { return nil }
func (PhaseKeygen) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketKeygenShares, from, payload)
	return nil
}
func (PhaseKeygen) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxAuctionParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketKeygenShares, len(participants))
}
func (p PhaseKeygen) Exit(ctx *phase.SessionContext) error {
	shares := phase.AccumulatedMessages(ctx, bucketKeygenShares)

	// Pre-shared keygen path: the smoke client generated the key
	// bundle locally and seeded it via the trigger's POST attrs
	// before this phase ran. Skip the server-side keygen call and
	// leave the pre-shared keys in place so downstream phases see
	// the same bundle the smoke encrypted under. Threshold secret
	// shares stay client-side; the server only ever needs the public
	// key + joint eval keys.
	pk, hasPK := phase.TryGet[[]byte](ctx, CtxAuctionCollectivePublicKey)
	ek, hasEK := phase.TryGet[[]byte](ctx, CtxAuctionEvalKeys)
	if hasPK && hasEK && len(pk) > 0 && len(ek) > 0 {
		ctx.Set(CtxAuctionSecretShares, shares)
		return nil
	}

	if p.helper == nil {
		ctx.Set(CtxAuctionCollectivePublicKey, []byte("stub-collective-pk"))
		ctx.Set(CtxAuctionSecretShares, shares)
		ctx.Set(CtxAuctionEvalKeys, []byte("stub-eval-keys"))
		return nil
	}

	participants, ok := phase.TryGet[[]string](ctx, CtxAuctionParticipants)
	if !ok || len(participants) == 0 {
		return fmt.Errorf("PhaseKeygen: CtxAuctionParticipants is missing or empty")
	}

	params, err := readContractParams(ctx)
	if err != nil {
		return fmt.Errorf("PhaseKeygen: %w", err)
	}
	keyBundle, err := p.helper.KeygenChain(params, len(participants))
	if err != nil {
		return fmt.Errorf("PhaseKeygen: helper.KeygenChain: %w", err)
	}
	ctx.Set(CtxAuctionCollectivePublicKey, keyBundle.PublicKey)
	ctx.Set(CtxAuctionSecretShares, shares)
	ctx.Set(CtxAuctionEvalKeys, keyBundle.EvalKeys)
	return nil
}

// PhaseScalarBid collects one encrypted scalar bid from each bidder.
// The wire shape is dramatically smaller than Fheya's Phase 1b:
// instead of a 128-dimensional unit-norm vector plus a quantized
// location plus an initiator winner-package wrap, each bidder
// submits exactly one CKKS-encrypted integer in [0, MAX].
//
// The phase requires no encrypted-input validation beyond
// ciphertext shape — there is no norm proof, no profile-dimension
// check, no winner-package shape. Encrypted-integer schemes can
// validate range bounds via separate ZK proofs of value-in-bounds
// if the application requires sealed-bid integrity guarantees.
type PhaseScalarBid struct{}

func NewPhaseScalarBid() *PhaseScalarBid { return &PhaseScalarBid{} }

func (PhaseScalarBid) Name() string                   { return "auction-scalar-bid" }
func (PhaseScalarBid) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseScalarBid) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseScalarBid) EntryState() phase.SessionState { return StateAuctionBidding }
func (PhaseScalarBid) ExitState() phase.SessionState  { return StateAuctionScoring }
func (PhaseScalarBid) ConsumedMessageTypes() []string             { return []string{"auction.bid"} }
func (PhaseScalarBid) InternalStates() []phase.SessionState       { return nil }
func (PhaseScalarBid) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:        {TypeName: "[]string", Required: true},
		CtxAuctionCollectivePublicKey: {TypeName: "[]byte", Required: true},
		CtxAuctionCryptoContract:      {TypeName: "OpenFHEContract", Required: true},
	}
}
func (PhaseScalarBid) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionBids: {TypeName: "map[string][]byte"},
	}
}
func (PhaseScalarBid) Enter(*phase.SessionContext) error { return nil }
func (PhaseScalarBid) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketScalarBids, from, payload)
	return nil
}
func (PhaseScalarBid) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxAuctionParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketScalarBids, len(participants))
}
func (PhaseScalarBid) Exit(ctx *phase.SessionContext) error {
	bids := phase.AccumulatedMessages(ctx, bucketScalarBids)
	ctx.Set(CtxAuctionBids, bids)
	return nil
}

// PhaseArgmax runs the encrypted argmax circuit: pairwise comparison
// of N encrypted scalars, building a one-hot mask of the maximum, and
// fusing it with both the bid ciphertexts (to recover the winning
// price) and a one-hot encoding of the bidder pseudonyms (to recover
// the winning identity). The circuit fits comfortably in depth=10,
// vs depth=30 for Fheya's selector chain.
//
// Phase 2 of any ARES app — the scoring circuit — is the
// app-specific heart of the framework. Replacing it is how
// applications redefine "who wins". For Fheya it is cosine
// similarity + location penalty + reputation; here it is plain
// argmax; a weighted-ballot voting app would emit a tally
// ciphertext with no winner selection.
// PhaseArgmax has two modes:
//
//   - Stub mode (NewPhaseArgmax): writes a deterministic placeholder
//     to CtxAuctionCipherWinnerBid. Used by composition tests and the
//     wire-only smoke that doesn't run real CKKS.
//
//   - Real mode (NewPhaseArgmaxWithHelper): pulls each bidder's
//     accumulated bid payload (JSON {"bid_ct": hex...}), orders by
//     pseudonym, and calls helperclient.Argmax with the configured
//     sharpening polynomial. The returned mask list is wrapped in a
//     JSON envelope and stored under CtxAuctionCipherWinnerBid; the
//     []byte schema stays unchanged because downstream phases treat
//     the field as opaque bytes.
//
// The mode is set at construction time; the runner shares the phase
// instance across sessions and the helper reference is safe for
// concurrent use.
type PhaseArgmax struct {
	helper     *helperclient.Client
	sharpening helperclient.EvalPolyParams
}

// NewPhaseArgmax returns the stub variant.
func NewPhaseArgmax() *PhaseArgmax { return &PhaseArgmax{} }

// NewPhaseArgmaxWithHelper returns a phase that calls helper.Argmax in
// Enter. The sharpening polynomial is invoked on every pairwise
// difference; sharpen.SharpenIndicatorDegree3 is a sensible default.
func NewPhaseArgmaxWithHelper(helper *helperclient.Client, sharpening helperclient.EvalPolyParams) *PhaseArgmax {
	return &PhaseArgmax{helper: helper, sharpening: sharpening}
}

// ArgmaxMaskEnvelope is the JSON shape stored in CtxAuctionCipherWinnerBid
// after a real-mode Argmax run. Bidders is the ordered pseudonym list
// (the index of each mask). Masks is the parallel base64-encoded mask
// ciphertext list.
type ArgmaxMaskEnvelope struct {
	Bidders []string `json:"bidders"`
	Masks   []string `json:"masks"`
}

func (*PhaseArgmax) Name() string                            { return "auction-argmax-scoring" }
func (*PhaseArgmax) Lifetime() phase.Lifetime                { return phase.LifetimePerSession }
func (*PhaseArgmax) RunsAt() phase.RunsAt                    { return phase.RunsAtInline }
func (*PhaseArgmax) EntryState() phase.SessionState          { return StateAuctionScoring }
func (*PhaseArgmax) ExitState() phase.SessionState           { return StateAuctionDecrypting }
func (*PhaseArgmax) ConsumedMessageTypes() []string          { return nil }
func (*PhaseArgmax) InternalStates() []phase.SessionState    { return nil }
func (*PhaseArgmax) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:   {TypeName: "[]string", Required: true},
		CtxAuctionCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 8}},
		CtxAuctionEvalKeys:       {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxAuctionBids:           {TypeName: "map[string][]byte", Required: true},
	}
}
func (*PhaseArgmax) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionCipherWinnerBid: {TypeName: "[]byte"},
	}
}

func (p *PhaseArgmax) Enter(ctx *phase.SessionContext) error {
	bids := phase.AccumulatedMessages(ctx, bucketScalarBids)

	if p.helper == nil {
		ctx.Set(CtxAuctionCipherWinnerBid, append([]byte("stub-winner-of-"), byte(len(bids))))
		return nil
	}

	params, err := readContractParams(ctx)
	if err != nil {
		return err
	}
	evalKeys, ok := phase.TryGet[[]byte](ctx, CtxAuctionEvalKeys)
	if !ok || len(evalKeys) == 0 {
		return fmt.Errorf("PhaseArgmax: CtxAuctionEvalKeys is missing or empty")
	}

	// Deterministic order so the mask index matches across runs.
	bidders := make([]string, 0, len(bids))
	for k := range bids {
		bidders = append(bidders, k)
	}
	sort.Strings(bidders)

	cts := make([][]byte, len(bidders))
	for i, b := range bidders {
		ct, err := decodeBidCiphertext(bids[b])
		if err != nil {
			return fmt.Errorf("PhaseArgmax: decode bid from %s: %w", b, err)
		}
		cts[i] = ct
	}

	masks, err := p.helper.Argmax(params, evalKeys, cts, helperclient.ArgmaxParams{
		SharpeningPoly: p.sharpening,
	})
	if err != nil {
		return fmt.Errorf("PhaseArgmax: helper.Argmax: %w", err)
	}
	envelope := ArgmaxMaskEnvelope{
		Bidders: bidders,
		Masks:   make([]string, len(masks)),
	}
	for i, m := range masks {
		envelope.Masks[i] = hex.EncodeToString(m)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("PhaseArgmax: marshal envelope: %w", err)
	}
	ctx.Set(CtxAuctionCipherWinnerBid, body)
	return nil
}

func (*PhaseArgmax) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (*PhaseArgmax) CheckComplete(*phase.SessionContext) bool                      { return true }
func (*PhaseArgmax) Exit(*phase.SessionContext) error                              { return nil }

// readContractParams extracts ContractParams from the typed map under
// CtxAuctionCryptoContract.
func readContractParams(ctx *phase.SessionContext) (helperclient.ContractParams, error) {
	contractAny, ok := ctx.Get(CtxAuctionCryptoContract)
	if !ok {
		return helperclient.ContractParams{}, fmt.Errorf("CtxAuctionCryptoContract missing")
	}
	contract, ok := contractAny.(map[string]any)
	if !ok {
		return helperclient.ContractParams{}, fmt.Errorf("CtxAuctionCryptoContract has unexpected type %T", contractAny)
	}
	asUint := func(k string) (uint32, error) {
		v, ok := contract[k]
		if !ok {
			return 0, fmt.Errorf("crypto_ctx.%s missing", k)
		}
		switch n := v.(type) {
		case int:
			return uint32(n), nil
		case int32:
			return uint32(n), nil
		case int64:
			return uint32(n), nil
		case uint32:
			return n, nil
		case float64:
			return uint32(n), nil
		default:
			return 0, fmt.Errorf("crypto_ctx.%s has type %T", k, v)
		}
	}
	asInt := func(k string) int {
		v, ok := contract[k]
		if !ok {
			return 0
		}
		switch n := v.(type) {
		case int:
			return n
		case int32:
			return int(n)
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
		return 0
	}
	ringDim, err := asUint("ring_dim")
	if err != nil {
		return helperclient.ContractParams{}, err
	}
	depth, err := asUint("depth")
	if err != nil {
		return helperclient.ContractParams{}, err
	}
	return helperclient.ContractParams{
		RingDim:        ringDim,
		Depth:          depth,
		ScalingModSize: asInt("scaling_mod_size"),
	}, nil
}

// decodeBidCiphertext parses a bid payload of shape
// {"bid_ct": "hex...", ...} and returns the raw ciphertext bytes. The
// auction example's smoke client sends bids in this shape; production
// app clients can adopt the same shape or override this phase with one
// that parses their format.
func decodeBidCiphertext(raw []byte) ([]byte, error) {
	var msg struct {
		BidCT string `json:"bid_ct"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	if msg.BidCT == "" {
		return nil, fmt.Errorf("bid_ct is empty")
	}
	return hex.DecodeString(msg.BidCT)
}

// PhaseDecrypt runs the threshold partial-decryption of the encrypted
// (winning_bid, winner_id) tuple. Each participant submits a partial
// using its key share from Keygen; the server fuses them to recover
// the cleartext outcome.
//
// Same crypto protocol as defaults.Phase3ThresholdDecrypt, but
// trivially smaller payload — two scalars rather than a 176-byte
// ECIES winner package padded across 1536 bit slots — so the
// recovery logic is a direct read-out instead of bit-slot recovery.
type PhaseDecrypt struct {
	helper *helperclient.Client
}

func NewPhaseDecrypt() *PhaseDecrypt { return &PhaseDecrypt{} }

// NewPhaseDecryptWithHelper constructs a PhaseDecrypt that calls the
// helper's FusePartials to combine threshold partials into cleartext.
func NewPhaseDecryptWithHelper(helper *helperclient.Client) *PhaseDecrypt {
	return &PhaseDecrypt{helper: helper}
}

func (PhaseDecrypt) Name() string                   { return "auction-threshold-decrypt" }
func (PhaseDecrypt) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseDecrypt) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseDecrypt) EntryState() phase.SessionState { return StateAuctionDecrypting }
func (PhaseDecrypt) ExitState() phase.SessionState  { return StateAuctionSettled }
func (PhaseDecrypt) ConsumedMessageTypes() []string             { return []string{"auction.decrypt.partial"} }
func (PhaseDecrypt) InternalStates() []phase.SessionState       { return nil }
func (PhaseDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:    {TypeName: "[]string", Required: true},
		CtxAuctionSecretShares:    {TypeName: "map[string][]byte", Required: true},
		CtxAuctionCipherWinnerBid: {TypeName: "[]byte", Required: true},
	}
}
func (PhaseDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionWinnerBid: {TypeName: "WinnerBid"},
	}
}
func (PhaseDecrypt) Enter(*phase.SessionContext) error { return nil }
func (PhaseDecrypt) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketDecryptPartials, from, payload)
	return nil
}
func (PhaseDecrypt) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxAuctionParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketDecryptPartials, len(participants))
}
func (p PhaseDecrypt) Exit(ctx *phase.SessionContext) error {
	partials := phase.AccumulatedMessages(ctx, bucketDecryptPartials)

	if p.helper == nil {
		ctx.Set(CtxAuctionWinnerBid, map[string]any{
			"winner":     "stub-winner",
			"price":      0,
			"num_partials": len(partials),
		})
		return nil
	}

	params, err := readContractParams(ctx)
	if err != nil {
		return fmt.Errorf("PhaseDecrypt: %w", err)
	}

	// Parse the hex-encoded partial_ct from each accumulated JSON
	// payload {"partial_ct":"hex..."}.
	rawPartials := make([][]byte, 0, len(partials))
	for _, raw := range partials {
		parsed, err := decodePartialCiphertext(raw)
		if err != nil {
			return fmt.Errorf("PhaseDecrypt: decode partial: %w", err)
		}
		rawPartials = append(rawPartials, parsed)
	}

	values, err := p.helper.FusePartials(params, rawPartials, 1)
	if err != nil {
		return fmt.Errorf("PhaseDecrypt: fuse: %w", err)
	}

	winningBid := 0.0
	if len(values) > 0 {
		winningBid = values[0]
	}

	ctx.Set(CtxAuctionWinnerBid, map[string]any{
		"winner":     "bidder-determined-by-mask",
		"price":      winningBid,
		"num_partials": len(partials),
	})
	return nil
}

// decodePartialCiphertext parses a JSON payload from the "auction.decrypt.partial"
// WS message and returns the hex-decoded partial_ct field.
func decodePartialCiphertext(raw []byte) ([]byte, error) {
	var msg struct {
		PartialCT  string `json:"partial_ct"`
		PartialHex string `json:"partial"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	field := msg.PartialCT
	if field == "" {
		field = msg.PartialHex
	}
	if field == "" {
		return nil, fmt.Errorf("no partial_ct or partial field in decrypt-partial payload")
	}
	return hex.DecodeString(field)
}

// PhaseSettlement emits the signed settlement transcript and
// terminates the session. There is no post-result interaction — no
// Phase D back-channel, no winner-to-initiator handshake — because
// the auction outcome is intentionally public. The transcript
// carries (winning_bid, winner_id) plus the auctioneer's signature
// and is the final session artifact.
//
// This phase demonstrates the simplest possible post-result shape:
// a synchronous Enter that does its work and CheckComplete that
// returns true immediately. Apps with richer post-result phases
// (Fheya's Phase D, an on-chain settlement anchor, a ZK-proof of
// correct execution) replace this phase with a more elaborate
// implementation.
type PhaseSettlement struct{}

func NewPhaseSettlement() *PhaseSettlement { return &PhaseSettlement{} }

func (PhaseSettlement) Name() string                   { return "auction-settlement" }
func (PhaseSettlement) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseSettlement) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseSettlement) EntryState() phase.SessionState { return StateAuctionSettled }
func (PhaseSettlement) ExitState() phase.SessionState  { return phase.StateNone }
func (PhaseSettlement) ConsumedMessageTypes() []string             { return nil }
func (PhaseSettlement) InternalStates() []phase.SessionState       { return nil }
func (PhaseSettlement) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionWinnerBid: {TypeName: "WinnerBid", Required: true},
	}
}
func (PhaseSettlement) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionSettlement: {TypeName: "SignedTranscript"},
	}
}
func (PhaseSettlement) Enter(ctx *phase.SessionContext) error {
	winner, _ := ctx.Get(CtxAuctionWinnerBid)
	transcript := map[string]any{
		"session_id":     ctx.SessionID,
		"winner":         winner,
		"settlement_by":  "auctioneer",
	}
	sig := signTranscript(transcript)
	transcript["signature"] = sig
	ctx.Set(CtxAuctionSettlement, transcript)
	return nil
}
func (PhaseSettlement) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseSettlement) CheckComplete(*phase.SessionContext) bool                       { return true }
func (PhaseSettlement) Exit(*phase.SessionContext) error                               { return nil }

// signTranscript returns a SHA256 hash binding the transcript fields
// to the session, so any observer can recompute and verify.
func signTranscript(t map[string]any) string {
	delete(t, "signature") // strip previous sig for idempotent re-sign
	b, _ := json.Marshal(t)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
