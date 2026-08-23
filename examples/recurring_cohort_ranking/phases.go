// SPDX-License-Identifier: Apache-2.0

package cohort

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// ── Cohort-formation phases ───────────────────────────────────────

// PhaseCohortForm assembles N participants into a named cohort and
// pins the CKKS parameters. Runs once per cohort lifecycle.
// Entry: COHORT_FORMING, Exit: COHORT_KEYGEN.
type PhaseCohortForm struct{}

func NewPhaseCohortForm() *PhaseCohortForm { return &PhaseCohortForm{} }

func (PhaseCohortForm) Name() string              { return "cohort-form" }
func (PhaseCohortForm) Lifetime() phase.Lifetime   { return phase.LifetimePerCohort }
func (PhaseCohortForm) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseCohortForm) EntryState() phase.SessionState { return StateCohortForming }
func (PhaseCohortForm) ExitState() phase.SessionState  { return StateCohortKeygen }
func (PhaseCohortForm) InternalStates() []phase.SessionState { return nil }
func (PhaseCohortForm) ConsumedMessageTypes() []string { return nil }
func (PhaseCohortForm) Requires() phase.ContextSchema  { return nil }
func (PhaseCohortForm) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string"},
		CtxCohortID:     {TypeName: "string"},
	}
}
func (PhaseCohortForm) Enter(*phase.SessionContext) error { return nil }
func (PhaseCohortForm) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseCohortForm) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseCohortForm) Exit(*phase.SessionContext) error         { return nil }

// PhaseCohortKeygen runs the N-party threshold CKKS keygen once
// and persists the key bundle into context. COHORT_KEYGEN →
// COHORT_SEALED.
//
// Three modes:
//   - Stub (NewPhaseCohortKeygen): placeholder bytes.
//   - Helper (NewPhaseCohortKeygenWithHelper): real CKKS keygen via
//     helperclient.KeygenChain. Generates the joint key bundle that
//     subsequent weekly sessions reuse.
//   - Pre-shared: if CtxCollectivePK + CtxEvalKeys are already set
//     (operator pre-generated the bundle and seeded via attrs), Exit
//     skips the keygen call.
type PhaseCohortKeygen struct {
	helper *helperclient.Client
}

func NewPhaseCohortKeygen() *PhaseCohortKeygen { return &PhaseCohortKeygen{} }

// NewPhaseCohortKeygenWithHelper runs real CKKS keygen via the
// helper subprocess. The output bundle is what subsequent weekly
// runners reuse (cohort key amortization).
func NewPhaseCohortKeygenWithHelper(helper *helperclient.Client) *PhaseCohortKeygen {
	return &PhaseCohortKeygen{helper: helper}
}

func (PhaseCohortKeygen) Name() string              { return "cohort-keygen" }
func (PhaseCohortKeygen) Lifetime() phase.Lifetime   { return phase.LifetimePerCohort }
func (PhaseCohortKeygen) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseCohortKeygen) EntryState() phase.SessionState { return StateCohortKeygen }
func (PhaseCohortKeygen) ExitState() phase.SessionState  { return StateCohortSealed }
func (PhaseCohortKeygen) InternalStates() []phase.SessionState { return nil }
func (PhaseCohortKeygen) ConsumedMessageTypes() []string {
	return []string{"cohort.keygen.share"}
}
func (PhaseCohortKeygen) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
	}
}
// Cohort keygen produces a lightweight crypto contract (depth=10,
// ring_dim=2048) appropriate for the scalar-ranking circuit.
func (PhaseCohortKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCollectivePK:   {TypeName: "[]byte", Constraints: map[string]any{"topology": "preshared"}},
		CtxSecretShares:   {TypeName: "map[string][]byte", Constraints: map[string]any{"topology": "preshared"}},
		CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys"},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Constraints: map[string]any{"depth": 10, "ring_dim": 2048}},
	}
}
func (PhaseCohortKeygen) Enter(*phase.SessionContext) error { return nil }
func (PhaseCohortKeygen) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketCohortKeygenShares, from, payload)
	return nil
}
func (PhaseCohortKeygen) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketCohortKeygenShares, len(participants))
}
func (p PhaseCohortKeygen) Exit(ctx *phase.SessionContext) error {
	shares := phase.AccumulatedMessages(ctx, bucketCohortKeygenShares)

	// Pre-shared bundle: operator/smoke pre-generated keys and the
	// trigger seeded them into context.
	pk, hasPK := phase.TryGet[[]byte](ctx, CtxCollectivePK)
	ek, hasEK := phase.TryGet[[]byte](ctx, CtxEvalKeys)
	if hasPK && hasEK && len(pk) > 0 && len(ek) > 0 {
		ctx.Set(CtxSecretShares, shares)
		if !ctx.Has(CtxCryptoContract) {
			ctx.Set(CtxCryptoContract, map[string]any{"depth": 10, "ring_dim": 2048})
		}
		return nil
	}

	if p.helper == nil {
		ctx.Set(CtxCollectivePK, []byte("stub-collective-pk"))
		ctx.Set(CtxSecretShares, shares)
		ctx.Set(CtxEvalKeys, []byte("stub-eval-keys"))
		ctx.Set(CtxCryptoContract, map[string]any{"depth": 10, "ring_dim": 2048})
		return nil
	}

	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok || len(participants) == 0 {
		return fmt.Errorf("PhaseCohortKeygen: CtxParticipants is missing or empty")
	}
	params, err := readCohortContractParams(ctx)
	if err != nil {
		// Fall back to the cohort's canonical defaults if the
		// session context didn't supply a contract.
		params = helperclient.ContractParams{RingDim: 2048, Depth: 10, ScalingModSize: 50}
	}
	keyBundle, err := p.helper.KeygenChain(params, len(participants))
	if err != nil {
		return fmt.Errorf("PhaseCohortKeygen: helper.KeygenChain: %w", err)
	}
	ctx.Set(CtxCollectivePK, keyBundle.PublicKey)
	ctx.Set(CtxSecretShares, shares)
	ctx.Set(CtxEvalKeys, keyBundle.EvalKeys)
	if !ctx.Has(CtxCryptoContract) {
		ctx.Set(CtxCryptoContract, map[string]any{
			"depth": int(params.Depth), "ring_dim": int(params.RingDim),
		})
	}
	return nil
}

// ── Per-session ranking phases ────────────────────────────────────

// PhaseRankingInvitation selects N members from the cohort and
// emits ranking.invitation. RANKING_INVITING → RANKING_LOCKED.
type PhaseRankingInvitation struct{}

func NewPhaseRankingInvitation() *PhaseRankingInvitation {
	return &PhaseRankingInvitation{}
}

func (PhaseRankingInvitation) Name() string              { return "ranking-invitation" }
func (PhaseRankingInvitation) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseRankingInvitation) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseRankingInvitation) EntryState() phase.SessionState { return StateRankingInviting }
func (PhaseRankingInvitation) ExitState() phase.SessionState  { return StateRankingLocked }
func (PhaseRankingInvitation) InternalStates() []phase.SessionState { return nil }
func (PhaseRankingInvitation) ConsumedMessageTypes() []string { return nil }
func (PhaseRankingInvitation) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxParticipants: {TypeName: "[]string", Required: true}}
}
func (PhaseRankingInvitation) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string"},
	}
}
func (PhaseRankingInvitation) Enter(*phase.SessionContext) error { return nil }
func (PhaseRankingInvitation) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseRankingInvitation) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseRankingInvitation) Exit(*phase.SessionContext) error         { return nil }

// PhasePreSharedKeyLookup validates that the cohort's key bundle
// is already in the SessionContext (seeded by the caller from
// the cohort-formation runner's outputs). RANKING_LOCKED →
// RANKING_BIDDING. Per-session cost is zero — one Enter call
// with no crypto and no WS messages.
type PhasePreSharedKeyLookup struct{}

func NewPhasePreSharedKeyLookup() *PhasePreSharedKeyLookup {
	return &PhasePreSharedKeyLookup{}
}

func (PhasePreSharedKeyLookup) Name() string              { return "ranking-key-lookup" }
func (PhasePreSharedKeyLookup) Lifetime() phase.Lifetime   { return phase.LifetimePerCohort }
func (PhasePreSharedKeyLookup) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhasePreSharedKeyLookup) EntryState() phase.SessionState { return StateRankingLocked }
func (PhasePreSharedKeyLookup) ExitState() phase.SessionState  { return StateRankingBidding }
func (PhasePreSharedKeyLookup) InternalStates() []phase.SessionState { return nil }
func (PhasePreSharedKeyLookup) ConsumedMessageTypes() []string { return nil }
func (PhasePreSharedKeyLookup) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCollectivePK: {TypeName: "[]byte", Required: true},
		CtxSecretShares: {TypeName: "map[string][]byte", Required: true},
		CtxEvalKeys:     {TypeName: "OpenFHEEvalKeys", Required: true},
	}
}
func (PhasePreSharedKeyLookup) Provides() phase.ContextSchema { return nil }
func (PhasePreSharedKeyLookup) Enter(ctx *phase.SessionContext) error {
	for _, key := range []string{CtxCollectivePK, CtxSecretShares, CtxEvalKeys} {
		if !ctx.Has(key) {
			return &phase.MissingContextError{Key: key, Phase: "ranking-key-lookup"}
		}
	}
	return nil
}
func (PhasePreSharedKeyLookup) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhasePreSharedKeyLookup) CheckComplete(*phase.SessionContext) bool { return true }
func (PhasePreSharedKeyLookup) Exit(*phase.SessionContext) error         { return nil }

// PhaseSubmitRating collects one encrypted scalar rating from
// each participant. RANKING_BIDDING → RANKING_SCORING.
type PhaseSubmitRating struct{}

func NewPhaseSubmitRating() *PhaseSubmitRating { return &PhaseSubmitRating{} }

func (PhaseSubmitRating) Name() string              { return "ranking-submit-rating" }
func (PhaseSubmitRating) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseSubmitRating) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseSubmitRating) EntryState() phase.SessionState { return StateRankingBidding }
func (PhaseSubmitRating) ExitState() phase.SessionState  { return StateRankingScoring }
func (PhaseSubmitRating) InternalStates() []phase.SessionState { return nil }
func (PhaseSubmitRating) ConsumedMessageTypes() []string {
	return []string{"ranking.rating"}
}
func (PhaseSubmitRating) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
	}
}
func (PhaseSubmitRating) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxRatings: {TypeName: "map[string][]byte"}}
}
func (PhaseSubmitRating) Enter(*phase.SessionContext) error { return nil }
func (PhaseSubmitRating) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketRatings, from, payload)
	return nil
}
func (PhaseSubmitRating) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketRatings, len(participants))
}
func (PhaseSubmitRating) Exit(ctx *phase.SessionContext) error {
	ctx.Set(CtxRatings, phase.AccumulatedMessages(ctx, bucketRatings))
	return nil
}

// PhaseArgmaxScoring has stub and helper modes. Helper mode runs real
// CKKS argmax against the participants' encrypted ratings using a
// caller-supplied sharpening polynomial.
type PhaseArgmaxScoring struct {
	helper     *helperclient.Client
	sharpening helperclient.EvalPolyParams
}

func NewPhaseArgmaxScoring() *PhaseArgmaxScoring { return &PhaseArgmaxScoring{} }

// NewPhaseArgmaxScoringWithHelper returns a phase that calls
// helper.Argmax against rating ciphertexts.
func NewPhaseArgmaxScoringWithHelper(helper *helperclient.Client, sharpening helperclient.EvalPolyParams) *PhaseArgmaxScoring {
	return &PhaseArgmaxScoring{helper: helper, sharpening: sharpening}
}

// CohortArgmaxEnvelope wraps the helper-mode mask output stored under
// CtxWinnerRating.
type CohortArgmaxEnvelope struct {
	Bidders []string `json:"bidders"`
	Masks   []string `json:"masks"`
}

func (PhaseArgmaxScoring) Name() string              { return "ranking-argmax-scoring" }
func (PhaseArgmaxScoring) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseArgmaxScoring) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseArgmaxScoring) EntryState() phase.SessionState { return StateRankingScoring }
func (PhaseArgmaxScoring) ExitState() phase.SessionState  { return StateRankingDecrypt }
func (PhaseArgmaxScoring) InternalStates() []phase.SessionState { return nil }
func (PhaseArgmaxScoring) ConsumedMessageTypes() []string { return nil }
func (PhaseArgmaxScoring) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:   {TypeName: "[]string", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 8}},
		CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxRatings:        {TypeName: "map[string][]byte", Required: true},
	}
}
func (PhaseArgmaxScoring) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxWinnerRating: {TypeName: "[]byte"}}
}
func (p *PhaseArgmaxScoring) Enter(ctx *phase.SessionContext) error {
	ratings := phase.AccumulatedMessages(ctx, bucketRatings)

	if p.helper == nil {
		ctx.Set(CtxWinnerRating, append([]byte("stub-winner-of-"), byte(len(ratings))))
		return nil
	}

	params, err := readCohortContractParams(ctx)
	if err != nil {
		return err
	}
	evalKeys, ok := phase.TryGet[[]byte](ctx, CtxEvalKeys)
	if !ok || len(evalKeys) == 0 {
		return fmt.Errorf("PhaseArgmaxScoring: CtxEvalKeys is missing or empty")
	}
	bidders := make([]string, 0, len(ratings))
	for k := range ratings {
		bidders = append(bidders, k)
	}
	sort.Strings(bidders)
	cts := make([][]byte, len(bidders))
	for i, b := range bidders {
		ct, err := decodeRatingCiphertext(ratings[b])
		if err != nil {
			return fmt.Errorf("PhaseArgmaxScoring: decode rating from %s: %w", b, err)
		}
		cts[i] = ct
	}
	masks, err := p.helper.Argmax(params, evalKeys, cts, helperclient.ArgmaxParams{
		SharpeningPoly: p.sharpening,
	})
	if err != nil {
		return fmt.Errorf("PhaseArgmaxScoring: helper.Argmax: %w", err)
	}
	envelope := CohortArgmaxEnvelope{
		Bidders: bidders,
		Masks:   make([]string, len(masks)),
	}
	for i, m := range masks {
		envelope.Masks[i] = hex.EncodeToString(m)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("PhaseArgmaxScoring: marshal: %w", err)
	}
	ctx.Set(CtxWinnerRating, body)
	return nil
}
func (*PhaseArgmaxScoring) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (*PhaseArgmaxScoring) CheckComplete(*phase.SessionContext) bool { return true }
func (*PhaseArgmaxScoring) Exit(*phase.SessionContext) error         { return nil }

func readCohortContractParams(ctx *phase.SessionContext) (helperclient.ContractParams, error) {
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

func decodeRatingCiphertext(raw []byte) ([]byte, error) {
	var msg struct {
		RatingCT string `json:"rating_ct"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	if msg.RatingCT == "" {
		return nil, fmt.Errorf("rating_ct is empty")
	}
	return hex.DecodeString(msg.RatingCT)
}

// PhaseThresholdDecrypt recovers the cleartext winner rating.
// RANKING_DECRYPT → RANKING_SETTLED.
type PhaseThresholdDecrypt struct {
	helper *helperclient.Client
}

func NewPhaseThresholdDecrypt() *PhaseThresholdDecrypt {
	return &PhaseThresholdDecrypt{}
}
func NewPhaseThresholdDecryptWithHelper(helper *helperclient.Client) *PhaseThresholdDecrypt {
	return &PhaseThresholdDecrypt{helper: helper}
}

func (PhaseThresholdDecrypt) Name() string              { return "ranking-threshold-decrypt" }
func (PhaseThresholdDecrypt) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseThresholdDecrypt) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseThresholdDecrypt) EntryState() phase.SessionState { return StateRankingDecrypt }
func (PhaseThresholdDecrypt) ExitState() phase.SessionState  { return StateRankingSettled }
func (PhaseThresholdDecrypt) InternalStates() []phase.SessionState { return nil }
func (PhaseThresholdDecrypt) ConsumedMessageTypes() []string {
	return []string{"ranking.decrypt.partial"}
}
func (PhaseThresholdDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
		CtxSecretShares: {TypeName: "map[string][]byte", Required: true},
		CtxWinnerRating: {TypeName: "[]byte", Required: true},
	}
}
func (PhaseThresholdDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxWinner: {TypeName: "WinnerRating"}}
}
func (PhaseThresholdDecrypt) Enter(*phase.SessionContext) error { return nil }
func (PhaseThresholdDecrypt) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketDecryptPartials, from, payload)
	return nil
}
func (PhaseThresholdDecrypt) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketDecryptPartials, len(participants))
}
func (p PhaseThresholdDecrypt) Exit(ctx *phase.SessionContext) error {
	partials := phase.AccumulatedMessages(ctx, bucketDecryptPartials)

	if p.helper == nil {
		ctx.Set(CtxWinner, map[string]any{
			"winner_rating": 0,
			"winner_id":     "stub-cohort-winner",
		})
		return nil
	}

	params, err := readCohortContractParams(ctx)
	if err != nil {
		return fmt.Errorf("PhaseThresholdDecrypt: %w", err)
	}

	rawPartials := make([][]byte, 0, len(partials))
	for _, raw := range partials {
		parsed, err := decodePartialCiphertext(raw)
		if err != nil {
			return fmt.Errorf("PhaseThresholdDecrypt: decode partial: %w", err)
		}
		rawPartials = append(rawPartials, parsed)
	}

	values, err := p.helper.FusePartials(params, rawPartials, 1)
	if err != nil {
		return fmt.Errorf("PhaseThresholdDecrypt: fuse: %w", err)
	}

	winnerRating := 0.0
	if len(values) > 0 {
		winnerRating = values[0]
	}

	ctx.Set(CtxWinner, map[string]any{
		"winner_rating": winnerRating,
		"winner_id":     "winner-determined-by-mask",
	})
	return nil
}

// PhaseSettleRanking emits a signed transcript and terminates.
// No post-result back-channel. RANKING_SETTLED → StateNone.
type PhaseSettleRanking struct{}

func NewPhaseSettleRanking() *PhaseSettleRanking { return &PhaseSettleRanking{} }

func (PhaseSettleRanking) Name() string              { return "ranking-settle" }
func (PhaseSettleRanking) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseSettleRanking) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseSettleRanking) EntryState() phase.SessionState { return StateRankingSettled }
func (PhaseSettleRanking) ExitState() phase.SessionState  { return phase.StateNone }
func (PhaseSettleRanking) InternalStates() []phase.SessionState { return nil }
func (PhaseSettleRanking) ConsumedMessageTypes() []string { return nil }
func (PhaseSettleRanking) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxWinner: {TypeName: "WinnerRating", Required: true}}
}
func (PhaseSettleRanking) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxTranscript: {TypeName: "SignedTranscript"}}
}
func (PhaseSettleRanking) Enter(ctx *phase.SessionContext) error {
	winner, _ := ctx.Get(CtxWinner)
	transcript := map[string]any{
		"session_id":    ctx.SessionID,
		"winner":        winner,
		"settlement_by": "cohort",
	}
	transcript["signature"] = signTranscript(transcript)
	ctx.Set(CtxTranscript, transcript)
	return nil
}
func (PhaseSettleRanking) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseSettleRanking) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseSettleRanking) Exit(*phase.SessionContext) error         { return nil }

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
		return nil, fmt.Errorf("no partial_ct or partial field")
	}
	return hex.DecodeString(field)
}

func signTranscript(t map[string]any) string {
	delete(t, "signature")
	b, _ := json.Marshal(t)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
