// SPDX-License-Identifier: Apache-2.0

package bounded_admission

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// ---------------------------------------------------------------------------
// recordingHandler — persists bound-check violations to CtxAdmissionResults
// ---------------------------------------------------------------------------

// recordingHandler records each violating party so the result is observable via
// CtxAdmissionResults (the Settle phase / admin can surface it). Implements
// boundcheck.ViolationHandler.
type recordingHandler struct{}

func (recordingHandler) OnViolation(ctx *phase.SessionContext, party string, nu float64, sev boundcheck.Severity) error {
	results, _ := phase.TryGet[map[string]string](ctx, CtxAdmissionResults)
	if results == nil {
		results = map[string]string{}
	}
	results[party] = fmt.Sprintf("violation:%d", int(sev))
	ctx.Set(CtxAdmissionResults, results)
	return nil
}

// ---------------------------------------------------------------------------
// PhaseInvitation — opens the session and pins participants
// ---------------------------------------------------------------------------

// PhaseInvitation broadcasts the admission invitation and seeds the
// participant set into the session context.
type PhaseInvitation struct{}

func NewPhaseInvitation() *PhaseInvitation { return &PhaseInvitation{} }

func (PhaseInvitation) Name() string                                       { return "admission-invitation" }
func (PhaseInvitation) Lifetime() phase.Lifetime                           { return phase.LifetimePerSession }
func (PhaseInvitation) RunsAt() phase.RunsAt                               { return phase.RunsAtInline }
func (PhaseInvitation) EntryState() phase.SessionState                     { return StateInviting }
func (PhaseInvitation) ExitState() phase.SessionState                      { return StateLocked }
func (PhaseInvitation) ConsumedMessageTypes() []string                     { return nil }
func (PhaseInvitation) InternalStates() []phase.SessionState               { return nil }
func (PhaseInvitation) Requires() phase.ContextSchema                      { return nil }
func (PhaseInvitation) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		defaults.CtxParticipants: {TypeName: "[]string"},
	}
}
func (PhaseInvitation) Enter(*phase.SessionContext) error                     { return nil }
func (PhaseInvitation) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseInvitation) CheckComplete(*phase.SessionContext) bool              { return true }
func (PhaseInvitation) Exit(*phase.SessionContext) error                      { return nil }

// ---------------------------------------------------------------------------
// PhaseKeygen — pre-shared key detection (no server-side keygen)
// ---------------------------------------------------------------------------

// PhaseKeygen is a pre-shared keygen phase. It detects whether the trigger
// has already seeded boundcheck.CtxJointPublicKey and boundcheck.CtxEvalKeyBundle
// into the session context (via admin POST attrs). If present, the phase is a
// no-op. Otherwise (stub mode), it sets placeholder values so downstream
// schema validation passes.
type PhaseKeygen struct{}

func NewPhaseKeygen() *PhaseKeygen { return &PhaseKeygen{} }

func (PhaseKeygen) Name() string                                     { return "admission-keygen" }
func (PhaseKeygen) Lifetime() phase.Lifetime                         { return phase.LifetimePerSession }
func (PhaseKeygen) RunsAt() phase.RunsAt                             { return phase.RunsAtInline }
func (PhaseKeygen) EntryState() phase.SessionState                   { return StateLocked }
func (PhaseKeygen) ExitState() phase.SessionState                    { return StateSubmitting }
func (PhaseKeygen) ConsumedMessageTypes() []string                   { return nil }
func (PhaseKeygen) InternalStates() []phase.SessionState             { return nil }
func (PhaseKeygen) Requires() phase.ContextSchema                    { return nil }
func (PhaseKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		boundcheck.CtxInputDim:       {TypeName: "int"},
		boundcheck.CtxEvalKeyBundle:  {TypeName: "[]byte"},
		boundcheck.CtxJointPublicKey: {TypeName: "[]byte"},
	}
}
func (PhaseKeygen) Enter(*phase.SessionContext) error                  { return nil }
func (PhaseKeygen) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseKeygen) CheckComplete(*phase.SessionContext) bool           { return true }
func (PhaseKeygen) Exit(ctx *phase.SessionContext) error {
	// Pre-shared keygen: if the trigger already set the bundle, leave it
	// in place (clients generated keys offline).
	if _, ok := phase.TryGet[[]byte](ctx, boundcheck.CtxJointPublicKey); ok {
		return nil
	}
	// Stub mode: provide placeholder keys so boundcheck schema passes.
	ctx.Set(boundcheck.CtxInputDim, 8)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("stub-eval-key-bundle"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("stub-joint-public-key"))
	return nil
}

// ---------------------------------------------------------------------------
// PhaseSubmitInput — collects encrypted input from each participant
// ---------------------------------------------------------------------------

// PhaseSubmitInput collects each participant's encrypted vector (encoded as
// {"enc_x":"<hex>"}) and assembles them into boundcheck.CtxEncryptedInputs
// for the downstream boundcheck phase.
type PhaseSubmitInput struct{}

func NewPhaseSubmitInput() *PhaseSubmitInput { return &PhaseSubmitInput{} }

func (PhaseSubmitInput) Name() string                                       { return "admission-submit-input" }
func (PhaseSubmitInput) Lifetime() phase.Lifetime                           { return phase.LifetimePerSession }
func (PhaseSubmitInput) RunsAt() phase.RunsAt                               { return phase.RunsAtInline }
func (PhaseSubmitInput) EntryState() phase.SessionState                     { return StateSubmitting }
func (PhaseSubmitInput) ExitState() phase.SessionState                      { return StateChecking }
func (PhaseSubmitInput) ConsumedMessageTypes() []string                     { return []string{MsgInput} }
func (PhaseSubmitInput) InternalStates() []phase.SessionState               { return nil }
func (PhaseSubmitInput) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		defaults.CtxParticipants: {TypeName: "[]string", Required: true},
	}
}
func (PhaseSubmitInput) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		boundcheck.CtxEncryptedInputs: {TypeName: "map[string][]byte"},
	}
}
func (PhaseSubmitInput) Enter(*phase.SessionContext) error { return nil }
func (PhaseSubmitInput) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	var msg struct {
		EncX string `json:"enc_x"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return fmt.Errorf("decode %s admission.input: %w", from, err)
	}
	encX, err := hex.DecodeString(msg.EncX)
	if err != nil {
		return fmt.Errorf("decode enc_x hex from %s: %w", from, err)
	}
	phase.AccumulateMessage(ctx, bucketInputs, from, encX)
	return nil
}
func (PhaseSubmitInput) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, defaults.CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketInputs, len(participants))
}
func (PhaseSubmitInput) Exit(ctx *phase.SessionContext) error {
	inputs := phase.AccumulatedMessages(ctx, bucketInputs)
	ctx.Set(boundcheck.CtxEncryptedInputs, inputs)
	return nil
}

// ---------------------------------------------------------------------------
// PhaseSettle — records the admission results and terminates the session
// ---------------------------------------------------------------------------

// PhaseSettle stores the admission results (accumulated by the recordingHandler
// during boundcheck exit, or an empty map if all parties passed) and terminates
// the session.
type PhaseSettle struct{}

func NewPhaseSettle() *PhaseSettle { return &PhaseSettle{} }

func (PhaseSettle) Name() string                                       { return "admission-settle" }
func (PhaseSettle) Lifetime() phase.Lifetime                           { return phase.LifetimePerSession }
func (PhaseSettle) RunsAt() phase.RunsAt                               { return phase.RunsAtInline }
func (PhaseSettle) EntryState() phase.SessionState                     { return StateSettled }
func (PhaseSettle) ExitState() phase.SessionState                      { return phase.StateNone }
func (PhaseSettle) ConsumedMessageTypes() []string                     { return nil }
func (PhaseSettle) InternalStates() []phase.SessionState               { return nil }
func (PhaseSettle) Requires() phase.ContextSchema                      { return nil }
func (PhaseSettle) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAdmissionResults: {TypeName: "map[string]string"},
	}
}
func (PhaseSettle) Enter(ctx *phase.SessionContext) error {
	results, _ := phase.TryGet[map[string]string](ctx, CtxAdmissionResults)
	if results == nil {
		results = map[string]string{}
	}
	ctx.Set(CtxAdmissionResults, results)
	return nil
}
func (PhaseSettle) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseSettle) CheckComplete(*phase.SessionContext) bool                       { return true }
func (PhaseSettle) Exit(*phase.SessionContext) error                               { return nil }

// Accumulator bucket keys — internal to this package.
const bucketInputs = "admission.bucket.inputs"
