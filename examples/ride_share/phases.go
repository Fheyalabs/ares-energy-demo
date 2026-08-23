// SPDX-License-Identifier: Apache-2.0

package rideshare

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// ── PhaseInvite: assemble participants, assign roles, pin contract ─

type PhaseInvite struct{}

func NewPhaseInvite() *PhaseInvite { return &PhaseInvite{} }

func (PhaseInvite) Name() string                        { return "ride-invite" }
func (PhaseInvite) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseInvite) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseInvite) EntryState() phase.SessionState      { return StateInvite }
func (PhaseInvite) ExitState() phase.SessionState       { return StateKeygen }
func (PhaseInvite) InternalStates() []phase.SessionState { return nil }
func (PhaseInvite) ConsumedMessageTypes() []string      { return nil }
func (PhaseInvite) Requires() phase.ContextSchema       { return nil }
func (PhaseInvite) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string"},
		CtxRoles:        {TypeName: "map[string]string"},
		CtxCryptoContract: {TypeName: "OpenFHEContract",
			Constraints: map[string]any{
				"depth": 12, "ring_dim": 2048, "scaling_mod_size": 40,
			}},
	}
}
func (PhaseInvite) Enter(*phase.SessionContext) error    { return nil }
func (PhaseInvite) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseInvite) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseInvite) Exit(*phase.SessionContext) error     { return nil }

// ── PhaseKeygen: threshold CKKS keygen (shared with other apps) ──
//
// Three modes:
//   - Stub (NewPhaseKeygen): placeholder bytes for both PK and eval keys.
//   - Helper (NewPhaseKeygenWithHelper): full N-party threshold CKKS
//     keygen via helperclient.KeygenChain.
//   - Pre-shared: if the trigger seeded CtxCollectivePK + CtxEvalKeys
//     before this phase ran, Exit detects them and skips the keygen
//     call. The smoke client uses this when it pre-generates the key
//     bundle locally so it can encrypt under matching keys.

type PhaseKeygen struct {
	helper *helperclient.Client
}

func NewPhaseKeygen() *PhaseKeygen { return &PhaseKeygen{} }

// NewPhaseKeygenWithHelper produces real CKKS keys via the helper
// subprocess. Used by PipelineWithHelper.
func NewPhaseKeygenWithHelper(helper *helperclient.Client) *PhaseKeygen {
	return &PhaseKeygen{helper: helper}
}

func (PhaseKeygen) Name() string                        { return "ride-keygen" }
func (PhaseKeygen) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseKeygen) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseKeygen) EntryState() phase.SessionState      { return StateKeygen }
func (PhaseKeygen) ExitState() phase.SessionState       { return StateSubmit }
func (PhaseKeygen) InternalStates() []phase.SessionState { return nil }
func (PhaseKeygen) ConsumedMessageTypes() []string {
	return []string{"ride.keygen.share"}
}
func (PhaseKeygen) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:   {TypeName: "[]string", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 4}},
	}
}
func (PhaseKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCollectivePK: {TypeName: "[]byte"},
		CtxSecretShares: {TypeName: "map[string][]byte"},
		CtxEvalKeys:     {TypeName: "OpenFHEEvalKeys"},
	}
}
func (PhaseKeygen) Enter(*phase.SessionContext) error { return nil }
func (PhaseKeygen) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketKeygenShares, from, payload)
	return nil
}
func (PhaseKeygen) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketKeygenShares, len(participants))
}
func (p PhaseKeygen) Exit(ctx *phase.SessionContext) error {
	shares := phase.AccumulatedMessages(ctx, bucketKeygenShares)

	// Pre-shared keygen: smoke client pre-generated keys, trigger
	// seeded them into context. Skip the helper call so downstream
	// phases see the same bundle the smoke encrypted under.
	pk, hasPK := phase.TryGet[[]byte](ctx, CtxCollectivePK)
	ek, hasEK := phase.TryGet[[]byte](ctx, CtxEvalKeys)
	if hasPK && hasEK && len(pk) > 0 && len(ek) > 0 {
		ctx.Set(CtxSecretShares, shares)
		return nil
	}

	if p.helper == nil {
		ctx.Set(CtxCollectivePK, []byte("stub-collective-pk"))
		ctx.Set(CtxSecretShares, shares)
		ctx.Set(CtxEvalKeys, []byte("stub-eval-keys"))
		return nil
	}

	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok || len(participants) == 0 {
		return fmt.Errorf("PhaseKeygen: CtxParticipants is missing or empty")
	}
	params, err := readRideContractParams(ctx)
	if err != nil {
		return fmt.Errorf("PhaseKeygen: %w", err)
	}
	keyBundle, err := p.helper.KeygenChain(params, len(participants))
	if err != nil {
		return fmt.Errorf("PhaseKeygen: helper.KeygenChain: %w", err)
	}
	ctx.Set(CtxCollectivePK, keyBundle.PublicKey)
	ctx.Set(CtxSecretShares, shares)
	ctx.Set(CtxEvalKeys, keyBundle.EvalKeys)
	return nil
}

// ── PhaseSubmit: encrypted driver bids and rider max price + locations ─

type PhaseSubmit struct{}

func NewPhaseSubmit() *PhaseSubmit { return &PhaseSubmit{} }

func (PhaseSubmit) Name() string                        { return "ride-submit" }
func (PhaseSubmit) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseSubmit) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseSubmit) EntryState() phase.SessionState      { return StateSubmit }
func (PhaseSubmit) ExitState() phase.SessionState       { return StateScore }
func (PhaseSubmit) InternalStates() []phase.SessionState { return nil }
func (PhaseSubmit) ConsumedMessageTypes() []string {
	return []string{"ride.bid", "ride.request"}
}
func (PhaseSubmit) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
		CtxRoles:        {TypeName: "map[string]string", Required: true},
		CtxCollectivePK: {TypeName: "[]byte", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true},
	}
}
func (PhaseSubmit) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxBids: {TypeName: "RideShareBids"},
	}
}
func (PhaseSubmit) Enter(*phase.SessionContext) error { return nil }
func (PhaseSubmit) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketBids, from, payload)
	return nil
}
func (PhaseSubmit) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketBids, len(participants))
}
func (PhaseSubmit) Exit(ctx *phase.SessionContext) error {
	ctx.Set(CtxBids, phase.AccumulatedMessages(ctx, bucketBids))
	return nil
}

// ── PhaseScore: composite score = α·price_fitness + β·proximity ──

// PhaseScore has stub and helper modes (see auction PhaseArgmax for the
// shared pattern). Helper mode runs real CKKS argmax over the
// drivers' encrypted composite scores using a caller-supplied
// sharpening polynomial. The composite (α·price_fitness + β·proximity)
// is computed cleartext-side by the client and encrypted as a single
// scalar — the depth=30 budget gives plenty of headroom but the v1
// design keeps the homomorphic compute confined to the argmax/selector
// chain. Fully-homomorphic composite computation can be added later.
type PhaseScore struct {
	helper     *helperclient.Client
	sharpening helperclient.EvalPolyParams
}

func NewPhaseScore() *PhaseScore { return &PhaseScore{} }

// NewPhaseScoreWithHelper returns a phase that calls helper.Argmax
// against driver bid ciphertexts.
func NewPhaseScoreWithHelper(helper *helperclient.Client, sharpening helperclient.EvalPolyParams) *PhaseScore {
	return &PhaseScore{helper: helper, sharpening: sharpening}
}

// RideArgmaxEnvelope wraps the helper-mode mask output stored under
// CtxWinner.
type RideArgmaxEnvelope struct {
	Bidders []string `json:"bidders"`
	Masks   []string `json:"masks"`
}

func (*PhaseScore) Name() string                            { return "ride-score" }
func (*PhaseScore) Lifetime() phase.Lifetime                { return phase.LifetimePerSession }
func (*PhaseScore) RunsAt() phase.RunsAt                    { return phase.RunsAtInline }
func (*PhaseScore) EntryState() phase.SessionState          { return StateScore }
func (*PhaseScore) ExitState() phase.SessionState           { return StateDecrypt }
func (*PhaseScore) InternalStates() []phase.SessionState    { return nil }
func (*PhaseScore) ConsumedMessageTypes() []string          { return nil }
func (*PhaseScore) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:   {TypeName: "[]string", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true},
		CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxBids:           {TypeName: "RideShareBids", Required: true},
	}
}
func (*PhaseScore) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxWinner: {TypeName: "[]byte"}}
}

func (p *PhaseScore) Enter(ctx *phase.SessionContext) error {
	bids := phase.AccumulatedMessages(ctx, bucketBids)

	if p.helper == nil {
		ctx.Set(CtxWinner, append([]byte("stub-winner-of-"), byte(len(bids))))
		return nil
	}

	params, err := readRideContractParams(ctx)
	if err != nil {
		return err
	}
	evalKeys, ok := phase.TryGet[[]byte](ctx, CtxEvalKeys)
	if !ok || len(evalKeys) == 0 {
		return fmt.Errorf("PhaseScore: CtxEvalKeys is missing or empty")
	}
	bidders := make([]string, 0, len(bids))
	for k := range bids {
		bidders = append(bidders, k)
	}
	sort.Strings(bidders)
	cts := make([][]byte, len(bidders))
	for i, b := range bidders {
		ct, err := decodeRideBid(bids[b])
		if err != nil {
			return fmt.Errorf("PhaseScore: decode bid from %s: %w", b, err)
		}
		cts[i] = ct
	}

	masks, err := p.helper.Argmax(params, evalKeys, cts, helperclient.ArgmaxParams{
		SharpeningPoly: p.sharpening,
	})
	if err != nil {
		return fmt.Errorf("PhaseScore: helper.Argmax: %w", err)
	}
	envelope := RideArgmaxEnvelope{
		Bidders: bidders,
		Masks:   make([]string, len(masks)),
	}
	for i, m := range masks {
		envelope.Masks[i] = hex.EncodeToString(m)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("PhaseScore: marshal envelope: %w", err)
	}
	ctx.Set(CtxWinner, body)
	return nil
}

func (*PhaseScore) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (*PhaseScore) CheckComplete(*phase.SessionContext) bool                      { return true }
func (*PhaseScore) Exit(*phase.SessionContext) error                              { return nil }

func readRideContractParams(ctx *phase.SessionContext) (helperclient.ContractParams, error) {
	contractAny, ok := ctx.Get(CtxCryptoContract)
	if !ok {
		return helperclient.ContractParams{}, fmt.Errorf("CtxCryptoContract missing")
	}
	contract, ok := contractAny.(map[string]any)
	if !ok {
		return helperclient.ContractParams{}, fmt.Errorf("CtxCryptoContract has type %T", contractAny)
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
		}
		return 0, fmt.Errorf("crypto_ctx.%s has type %T", k, contract[k])
	}
	asInt := func(k string) int {
		v, ok := contract[k]
		if !ok {
			return 0
		}
		switch n := v.(type) {
		case int:
			return n
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

func decodeRideBid(raw []byte) ([]byte, error) {
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

// ── PhaseDecrypt: threshold decrypt → (price, driver, rider) ──

type PhaseDecrypt struct {
	helper *helperclient.Client
}

func NewPhaseDecrypt() *PhaseDecrypt { return &PhaseDecrypt{} }
func NewPhaseDecryptWithHelper(helper *helperclient.Client) *PhaseDecrypt {
	return &PhaseDecrypt{helper: helper}
}

func (PhaseDecrypt) Name() string                        { return "ride-decrypt" }
func (PhaseDecrypt) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseDecrypt) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseDecrypt) EntryState() phase.SessionState      { return StateDecrypt }
func (PhaseDecrypt) ExitState() phase.SessionState       { return StateSettle }
func (PhaseDecrypt) InternalStates() []phase.SessionState { return nil }
func (PhaseDecrypt) ConsumedMessageTypes() []string {
	return []string{"ride.decrypt.partial"}
}
func (PhaseDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
		CtxSecretShares: {TypeName: "map[string][]byte", Required: true},
		CtxWinner:       {TypeName: "[]byte", Required: true},
	}
}
func (PhaseDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxResult: {TypeName: "RideShareResult"}}
}
func (PhaseDecrypt) Enter(*phase.SessionContext) error { return nil }
func (PhaseDecrypt) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketDecryptPartials, from, payload)
	return nil
}
func (PhaseDecrypt) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketDecryptPartials, len(participants))
}
func (p PhaseDecrypt) Exit(ctx *phase.SessionContext) error {
	partials := phase.AccumulatedMessages(ctx, bucketDecryptPartials)

	if p.helper == nil {
		ctx.Set(CtxResult, map[string]any{
			"agreed_price": 0,
			"driver_id":    "stub-driver",
			"rider_id":     "stub-rider",
		})
		return nil
	}

	params, err := readContractParams(ctx)
	if err != nil {
		return fmt.Errorf("PhaseDecrypt: %w", err)
	}

	rawPartials := make([][]byte, 0, len(partials))
	for _, raw := range partials {
		parsed, err := decodePartialCiphertext(raw)
		if err != nil {
			return fmt.Errorf("PhaseDecrypt: decode partial: %w", err)
		}
		rawPartials = append(rawPartials, parsed)
	}

	// 3 slots: price, driver-score, rider-score
	values, err := p.helper.FusePartials(params, rawPartials, 3)
	if err != nil {
		return fmt.Errorf("PhaseDecrypt: fuse: %w", err)
	}

	agreedPrice := 0.0
	if len(values) > 0 {
		agreedPrice = values[0]
	}

	ctx.Set(CtxResult, map[string]any{
		"agreed_price": agreedPrice,
		"driver_id":    "winner-determined-by-mask",
		"rider_id":     "stub-rider",
	})
	return nil
}

// ── PhaseSettle: broadcast result to both parties ──

type PhaseSettle struct{}

func NewPhaseSettle() *PhaseSettle { return &PhaseSettle{} }

func (PhaseSettle) Name() string                        { return "ride-settle" }
func (PhaseSettle) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseSettle) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseSettle) EntryState() phase.SessionState      { return StateSettle }
func (PhaseSettle) ExitState() phase.SessionState       { return phase.StateNone }
func (PhaseSettle) InternalStates() []phase.SessionState { return nil }
func (PhaseSettle) ConsumedMessageTypes() []string      { return nil }
func (PhaseSettle) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxResult: {TypeName: "RideShareResult", Required: true}}
}
func (PhaseSettle) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxSettlement: {TypeName: "SignedTranscript"}}
}
func (PhaseSettle) Enter(ctx *phase.SessionContext) error {
	result, _ := ctx.Get(CtxResult)
	transcript := map[string]any{
		"session_id":    ctx.SessionID,
		"result":        result,
		"settlement_by": "rideshare",
	}
	transcript["signature"] = signTranscript(transcript)
	ctx.Set(CtxSettlement, transcript)
	return nil
}

func signTranscript(t map[string]any) string {
	delete(t, "signature")
	b, _ := json.Marshal(t)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (PhaseSettle) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseSettle) CheckComplete(*phase.SessionContext) bool                       { return true }
func (PhaseSettle) Exit(*phase.SessionContext) error                               { return nil }

// decodePartialCiphertext parses a JSON payload from the
// "ride.decrypt.partial" WS message and returns the hex-decoded
// partial_ct field.
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

func readContractParams(ctx *phase.SessionContext) (helperclient.ContractParams, error) {
	contractAny, ok := ctx.Get(CtxCryptoContract)
	if !ok {
		return helperclient.ContractParams{}, fmt.Errorf("CtxCryptoContract missing")
	}
	contract, ok := contractAny.(map[string]any)
	if !ok {
		return helperclient.ContractParams{}, fmt.Errorf("CtxCryptoContract has type %T", contractAny)
	}
	return helperclient.ContractParams{
		RingDim:        uint32(asFloat(contract, "ring_dim")),
		Depth:          uint32(asFloat(contract, "depth")),
		ScalingModSize: int(asFloat(contract, "scaling_mod_size")),
	}, nil
}

func asFloat(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
