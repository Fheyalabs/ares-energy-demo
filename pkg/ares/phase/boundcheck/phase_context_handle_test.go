// SPDX-License-Identifier: Apache-2.0

package boundcheck_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// fakeHandle satisfies fhecalib.ContextHandle with canned responses, designed
// for proving the per-session-handle context fallback path in Enter.
type fakeHandle struct{}

func (fakeHandle) Params() helperclient.ContractParams {
	return helperclient.ContractParams{RingDim: 1024, Depth: 2}
}
func (fakeHandle) EvalMult(a, b []byte) ([]byte, error)          { return []byte("chk"), nil }
func (fakeHandle) EvalSubConst(ct []byte, v []float64) ([]byte, error) { return ct, nil }
func (fakeHandle) EvalProductSum(a, b []byte, n int) ([]byte, error)   { return []byte("chk"), nil }

func TestPhase_UsesPerSessionHandleFromContext(t *testing.T) {
	// Construction WITHOUT a handle (stub-constructed using NewPhase), but
	// supply one via SessionContext. The phase must fall back to the
	// per-session handle and produce CtxBoundCheckCiphers.
	ph := boundcheck.NewPhase(boundcheck.NormCircuit{Eps: 0.01, NDim: 4},
		nil, boundcheck.DefaultParams(), defaults.StateScoring, defaults.StateDecrypting)
	ctx := phase.NewSessionContext("ctx-handle-test")
	ctx.Set(defaults.CtxParticipants, []string{"p0"})
	ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{"p0": []byte("encx")})
	ctx.Set(boundcheck.CtxInputDim, 4)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("ek"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("pk"))
	ctx.Set(boundcheck.CtxBoundCheckHandle, fhecalib.ContextHandle(fakeHandle{}))
	if err := ph.Enter(ctx); err != nil {
		t.Fatalf("Enter: %v", err)
	}
	if _, ok := phase.TryGet[map[string][]byte](ctx, boundcheck.CtxBoundCheckCiphers); !ok {
		t.Fatal("per-session handle path must populate CtxBoundCheckCiphers")
	}
}
