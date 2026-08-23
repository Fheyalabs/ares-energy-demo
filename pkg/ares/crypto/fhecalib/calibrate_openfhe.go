// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package fhecalib

import (
	"fmt"
	"strings"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// ckksFirstModSize is the hardcoded first-level modulus bit width used by the
// cgo bridge's CreateCKKSContext / make_ckks_context.
const ckksFirstModSize = 60

// maxLog2Q returns the maximum CKKS ciphertext-modulus bit budget (log2 Q) for
// a ring dimension at 128-bit classic security (HEStd_128_classic). Anchored to
// the ARES spec's authoritative N=2^16 -> 1761-bit cap (ARES v2.6 SC-3); the
// bound is linear in N, matching OpenFHE's HEStd_128_classic table within ~2
// bits across N = 2^10..2^16.
func maxLog2Q(ringDim uint32) uint64 {
	return uint64(ringDim) * 1761 / 65536
}

// exceedsModulusBudget reports whether a CKKS context at (ringDim, depth,
// scalingModSize) would need more ciphertext-modulus bits than 128-bit classic
// security permits for that ring. The cgo bridge uses HEStd_NotSet and silently
// enlarges the ring rather than erroring, so the calibrator enforces the secure
// budget itself: a circuit that exceeds it should run at a LARGER ring, not be
// silently accepted at an insecure parameter set. Total modulus bits are the
// first-level prime plus one scalingModSize prime per multiplicative level.
func exceedsModulusBudget(ringDim, depth uint32, scalingModSize int) bool {
	if ringDim == 0 || scalingModSize == 0 {
		return false
	}
	totalBits := uint64(ckksFirstModSize) + uint64(depth)*uint64(scalingModSize)
	return totalBits > maxLog2Q(ringDim)
}

// cgoHandle implements ContextHandle against the in-process OpenFHE bridge for
// one provisioned (depth-specific) context.
type cgoHandle struct {
	params    helperclient.ContractParams
	cgoParams cgo.ContractParams
	evalKeys  cgo.EvalKeyFinal
	jointPK   []byte
}

func (h *cgoHandle) Params() helperclient.ContractParams { return h.params }

func (h *cgoHandle) EvalMult(ctA, ctB []byte) ([]byte, error) {
	return cgo.EvalMultCKKSForContract(h.cgoParams, h.evalKeys.EvalMultFinal, ctA, ctB)
}

func (h *cgoHandle) EvalSubConst(ct []byte, vals []float64) ([]byte, error) {
	encCenter, err := cgo.EncryptCKKSForContract(h.cgoParams, h.jointPK, vals)
	if err != nil {
		return nil, fmt.Errorf("fhecalib: encrypt center: %w", err)
	}
	return cgo.EvalSubCKKSForContract(h.cgoParams, ct, encCenter)
}

func (h *cgoHandle) EvalProductSum(ctLeft, ctRight []byte, nSlots int) ([]byte, error) {
	return cgo.EvalProductSumForContract(h.cgoParams, h.evalKeys, ctLeft, ctRight, nSlots)
}

// NewContextHandle returns a ContextHandle backed by the in-process OpenFHE
// bridge. This is the real-mode constructor for Phase-1c (bound-check) and
// any other phase that drives homomorphic ops via a ContextHandle.
//
// params pins the CKKS scheme parameters for the session (ring_dim, depth,
// scaling_mod_size). evalKeys is the combined eval-mult + eval-sum key bundle
// produced by the threshold keygen rounds (cgo.EvalKeyFinal). jointPK is the
// final joint public key; it is used by EvalSubConst to encrypt the public
// center vector before performing the subtraction ciphertext.
//
// The returned handle is safe for concurrent use within one phase: each
// method re-enters the cgo bridge (which manages its own C context) without
// shared mutable Go state.
func NewContextHandle(params helperclient.ContractParams, evalKeys cgo.EvalKeyFinal, jointPK []byte) ContextHandle {
	cgoParams := cgo.ContractParams{
		RingDim:       params.RingDim,
		ScalingFactor: params.ScalingFactor,
		Depth:         params.Depth,
	}
	if cgoParams.ScalingFactor == 0 {
		// Mirror the bridge default (2^50) when the caller omits ScalingFactor
		// but provides ScalingModSize instead. The cgo bridge derives the
		// factor internally from ScalingModSize; pass it through unchanged.
		cgoParams.ScalingFactor = float64(uint64(1) << 50)
	}
	return &cgoHandle{
		params:    params,
		cgoParams: cgoParams,
		evalKeys:  evalKeys,
		jointPK:   jointPK,
	}
}

// buildJointEvalMultN2 mirrors buildJointEvalMult in
// helperclient/argmax_e2e_test.go: the two-round eval-mult-key chain for the
// given key shares. Returns the full EvalKeyFinal bundle (EvalMultFinal +
// EvalSumFinal) so callers can use both keys without re-running the protocol.
func buildJointEvalMultN2(params cgo.ContractParams, shares []cgo.DistributedKeyShare) (cgo.EvalKeyFinal, error) {
	finalPK := shares[len(shares)-1].PublicKey
	lead, err := cgo.EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return cgo.EvalKeyFinal{}, fmt.Errorf("evalkey round1 lead: %w", err)
	}
	pks := make([][]byte, len(shares))
	mr1 := make([][]byte, len(shares))
	sr1 := make([][]byte, len(shares))
	pks[0], mr1[0], sr1[0] = shares[0].PublicKey, lead.EvalMultBase, lead.EvalSumBase
	for i := 1; i < len(shares); i++ {
		r1, err := cgo.EvalKeyRound1Participant(params, shares[i].SecretKeyShare,
			lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return cgo.EvalKeyFinal{}, fmt.Errorf("evalkey round1 participant %d: %w", i, err)
		}
		pks[i] = shares[i].PublicKey
		mr1[i] = r1.EvalMultSwitchShare
		sr1[i] = r1.EvalSumShare
	}
	combined, err := cgo.CombineEvalKeyRound1(params, pks, mr1, sr1)
	if err != nil {
		return cgo.EvalKeyFinal{}, fmt.Errorf("combine round1: %w", err)
	}
	fs := make([][]byte, len(shares))
	for i := range shares {
		r2, err := cgo.EvalKeyRound2Participant(params, shares[i].SecretKeyShare,
			combined.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			return cgo.EvalKeyFinal{}, fmt.Errorf("evalkey round2 participant %d: %w", i, err)
		}
		fs[i] = r2.EvalMultFinalShare
	}
	final, err := cgo.CombineEvalKeyRound2(params, finalPK, fs, combined.EvalSumFinal)
	if err != nil {
		return cgo.EvalKeyFinal{}, fmt.Errorf("combine round2: %w", err)
	}
	return final, nil
}

// Calibrate finds the minimum depth for cut over a minimal n=2 threshold
// context. Depth/precision are party-count-independent, so n=2 (the keygen
// floor) yields the same answer as a single key for far less work.
//
// profileDim sets the CKKS batch slot count for the provisioned context. The
// caller must pass profileDim >= len(cut.Inputs()[i]) for every input vector i;
// values beyond profileDim are silently dropped at encryption, producing
// incorrect results without an error.
func Calibrate(cut CircuitUnderTest, p CalibrationParams, profileDim int) (CalibrationResult, error) {
	if err := cgo.SmokeCKKS(); err != nil {
		return CalibrationResult{}, fmt.Errorf("fhecalib: OpenFHE unavailable: %w", err)
	}
	if p.StartDepth == 0 {
		return CalibrationResult{}, fmt.Errorf("fhecalib: StartDepth must be >= 1 (0 is not a valid CKKS multiplicative depth)")
	}
	inputs := cut.Inputs()
	want := cut.Expected(inputs)

	// Resolve the effective ScalingModSize: prefer p.Base value; fall back to 50
	// (the bridge default inferred from ScalingFactor = 2^50).
	scalingModSize := p.Base.ScalingModSize
	if scalingModSize == 0 {
		scalingModSize = 50
	}

	var resolvedRingDim uint32
	runAtDepth := func(depth uint32) (float64, bool, error) {
		cgoParams := cgo.DefaultContractParams(profileDim, depth)
		// Honour explicit RingDim from CalibrationParams (e.g. to exercise
		// modulus-cap behaviour at small ring dimensions in tests).
		if p.Base.RingDim != 0 {
			cgoParams.RingDim = p.Base.RingDim
		}
		// Capture the resolved ring dimension so the result can report it
		// even when p.Base.RingDim was 0 (auto-sized by DefaultContractParams).
		resolvedRingDim = cgoParams.RingDim

		// Pre-flight: check the CKKS modulus budget before entering CGo.
		// The cgo bridge uses HEStd_NotSet and auto-enlarges the ring, so this
		// is the only place the constraint is enforced.
		if exceedsModulusBudget(cgoParams.RingDim, depth, scalingModSize) {
			return 0, true, nil
		}

		first, err := cgo.DistributedKeyGenFirst(cgoParams)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("keygen first: %w", err)
		}
		second, err := cgo.DistributedKeyGenNext(cgoParams, first.PublicKey)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("keygen next: %w", err)
		}
		shares := []cgo.DistributedKeyShare{first, second}
		evalKeys, err := buildJointEvalMultN2(cgoParams, shares)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, err
		}
		jointPK := second.PublicKey

		encIn := make([][]byte, len(inputs))
		for i, vec := range inputs {
			ct, err := cgo.EncryptCKKSForContract(cgoParams, jointPK, vec)
			if err != nil {
				if isModulusCap(err) {
					return 0, true, nil
				}
				return 0, false, fmt.Errorf("encrypt input %d: %w", i, err)
			}
			encIn[i] = ct
		}

		h := &cgoHandle{
			params: helperclient.ContractParams{
				RingDim:        cgoParams.RingDim,
				Depth:          depth,
				ScalingModSize: scalingModSize,
			},
			cgoParams: cgoParams,
			evalKeys:  evalKeys,
			jointPK:   jointPK,
		}
		encOut, err := cut.Eval(h, encIn)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("circuit eval: %w", err)
		}

		// Threshold-decrypt (n=2): lead = first share, follower = second.
		// Mirrors cgo.ThresholdSmokeCKKS's partial-decrypt + fuse sequence.
		p0, err := cgo.PartialDecryptCKKSForContract(cgoParams, encOut, first.SecretKeyShare, true)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("partial decrypt lead: %w", err)
		}
		p1, err := cgo.PartialDecryptCKKSForContract(cgoParams, encOut, second.SecretKeyShare, false)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("partial decrypt follower: %w", err)
		}
		got, err := cgo.FuseCKKSPartialsForContract(cgoParams, [][]byte{p0, p1}, len(want))
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("fuse partials: %w", err)
		}

		return maxSlotAbsError(got, want), false, nil
	}

	res, err := sweep(p, runAtDepth)
	res.Circuit = cut.Name()
	if resolvedRingDim != 0 {
		res.RingDim = resolvedRingDim
	}
	return res, err
}

// isModulusCap reports whether an OpenFHE provisioning error (returned by the
// cgo bridge) indicates the requested depth needs a ciphertext modulus larger
// than RingDim permits.
//
// Note: the cgo bridge uses HEStd_NotSet so OpenFHE itself does not emit
// modulus-cap errors — it silently widens the ring instead. The primary cap
// detection is the pre-flight exceedsModulusBudget check in Calibrate.
// isModulusCap is retained as a secondary guard for any bridge changes that
// restore security-level enforcement; the markers below reflect the error
// substrings emitted by OpenFHE when HEStd_128_classic (or similar) is active.
func isModulusCap(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range modulusCapMarkers {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// modulusCapMarkers are lowercased substrings of OpenFHE error messages emitted
// when a depth+scalingModSize combination exceeds the ring-dimension-bound
// ciphertext modulus. Pinned against OpenFHE 1.5.1 with HEStd_128_classic:
//
//	"the number of bits in the ciphertext modulus is too large for the ring dimension"
//
// The bridge currently uses HEStd_NotSet so these are not exercised by
// live context creation; exceedsModulusBudget() is the active enforcement path.
var modulusCapMarkers = []string{
	"ciphertext modulus is too large",
	"not enough to support",
	"hestd",
}
