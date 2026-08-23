// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Phase3ThresholdDecrypt is the generic threshold-decryption phase.
// Each participant submits a partial decryption of the scorer's
// emitted result ciphertext (CtxResultCiphertext) using its secret
// share from Phase 0a; the server fuses the partials and writes the
// recovered plaintext bytes to CtxResultBytes. The phase owns
// DECRYPTING → BROADCASTING.
//
// Alternative implementations:
//   - Phase3SinglePartyDecrypt: when Phase0a is SinglePartyKeygen,
//     this phase is a no-op — the server decrypts the result with
//     its private key directly.
//   - Phase3PlaintextResolve: when Phase0a is PlaintextKeygen, this
//     phase just signs and broadcasts the cleartext result.
type Phase3ThresholdDecrypt struct{}

func NewPhase3ThresholdDecrypt() *Phase3ThresholdDecrypt { return &Phase3ThresholdDecrypt{} }

func (Phase3ThresholdDecrypt) Name() string                   { return "phase-3-threshold-decrypt" }
func (Phase3ThresholdDecrypt) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (Phase3ThresholdDecrypt) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (Phase3ThresholdDecrypt) EntryState() phase.SessionState { return StateDecrypting }
func (Phase3ThresholdDecrypt) ExitState() phase.SessionState  { return StateBroadcasting }

func (Phase3ThresholdDecrypt) ConsumedMessageTypes() []string {
	return []string{"decrypt.partial"}
}
func (Phase3ThresholdDecrypt) InternalStates() []phase.SessionState { return nil }

func (Phase3ThresholdDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
		// Demands threshold-topology secret shares so a single-party
		// keygen cannot silently substitute. The composition validator
		// in phase.Compose rejects the mismatch at construction time.
		CtxSecretShares: {
			TypeName:    "map[string][]byte",
			Required:    true,
			Constraints: map[string]any{"topology": "threshold"},
		},
		CtxResultCiphertext: {TypeName: "[]byte", Required: true},
	}
}

func (Phase3ThresholdDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxResultBytes: {TypeName: "[]byte"},
	}
}

func (Phase3ThresholdDecrypt) Enter(*phase.SessionContext) error                   { return nil }
func (Phase3ThresholdDecrypt) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (Phase3ThresholdDecrypt) CheckComplete(*phase.SessionContext) bool             { return false }
func (Phase3ThresholdDecrypt) Exit(*phase.SessionContext) error                     { return nil }
