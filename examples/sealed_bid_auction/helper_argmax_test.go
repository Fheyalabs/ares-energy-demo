// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package auction

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// TestPhaseArgmax_HelperMode_PicksHighestBid drives the auction
// runner end-to-end with the real OpenFHE helper plugged into
// PhaseArgmax. Setup uses the cgo bridge directly for keygen + the
// eval-mult key chain (the helper protocol exposes the per-participant
// rounds but not the orchestrator-side combine steps); the argmax call
// itself goes through helperclient → daemon → cgo → OpenFHE,
// exercising the production IPC path.
func TestPhaseArgmax_HelperMode_PicksHighestBid(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}

	// Build the helper binary once and start it in daemon mode.
	binary := buildHelperBinary(t)
	defer os.Remove(binary)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := helperclient.Start(ctx, binary)
	if err != nil {
		t.Fatalf("helper start: %v", err)
	}
	defer client.Close()

	// Keygen + eval-mult key chain via cgo (helper doesn't expose the
	// combine ops in the current protocol).
	cgoParams := cgo.DefaultContractParams(4, 10)
	first, err := cgo.DistributedKeyGenFirst(cgoParams)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := cgo.DistributedKeyGenNext(cgoParams, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	joint := second.PublicKey
	evalMultKey, err := buildJointEvalMultKeyForTest(t, cgoParams, []cgo.DistributedKeyShare{first, second})
	if err != nil {
		t.Skipf("eval-mult chain unavailable: %v", err)
	}

	// Encrypt three normalized scalar bids. Bidder-A has the
	// highest score and must come out as the argmax winner.
	scores := []float64{0.5, -0.3, 0.0}
	bidders := []string{"bidder-A", "bidder-B", "bidder-C"}
	expectedWinner := "bidder-A"
	bidPayloads := make(map[string][]byte)
	for i, s := range scores {
		ct, err := cgo.EncryptCKKSForContract(cgoParams, joint, []float64{s, 0, 0, 0})
		if err != nil {
			t.Fatalf("encrypt %s: %v", bidders[i], err)
		}
		payload, _ := json.Marshal(map[string]any{"bid_ct": hex.EncodeToString(ct)})
		bidPayloads[bidders[i]] = payload
	}

	// Build runner in helper mode.
	hcParams := helperclient.ContractParams{
		RingDim:        cgoParams.RingDim,
		Depth:          cgoParams.Depth,
		ScalingModSize: 40,
	}
	_ = hcParams // currently the phase reads params from CtxAuctionCryptoContract
	sharpening := helperclient.EvalPolyParams{
		Coefficients: []float64{0.5, 0.75, 0, -0.25}, // [0,1]-mapped sign approx
		LowerBound:   -1,
		UpperBound:   1,
	}
	runner, err := PipelineWithHelper(client, sharpening)
	if err != nil {
		t.Fatalf("runner: %v", err)
	}

	const sessionID = "argmax-real-1"
	sctx, err := runner.BeginSession(sessionID, "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	// Seed the canonical session-context entries the trigger would
	// normally inject.
	sctx.Set(CtxAuctionParticipants, bidders)
	sctx.Set(CtxAuctionCryptoContract, map[string]any{
		"ring_dim":         int(cgoParams.RingDim),
		"depth":            int(cgoParams.Depth),
		"scaling_mod_size": 50,
	})

	// Advance into BIDDING so PhaseScalarBid is current. The walk
	// fires PhaseKeygen.Exit which writes its own stub keys into ctx;
	// we override those with the real bundle below.
	if err := runner.AdvanceToState(sessionID, StateAuctionBidding); err != nil {
		t.Fatalf("advance to BIDDING: %v", err)
	}
	sctx.Set(CtxAuctionCollectivePublicKey, joint)
	sctx.Set(CtxAuctionEvalKeys, evalMultKey)

	// Submit each bid via HandleMessage. The third submission trips
	// quorum, fires Exit (writes accumulated bids to CtxAuctionBids),
	// advances to SCORING, runs PhaseArgmax.Enter — which calls the
	// real helper — and cascades to DECRYPTING.
	for _, b := range bidders {
		if _, err := runner.HandleMessage(sessionID, "auction.bid", b, bidPayloads[b]); err != nil {
			t.Fatalf("bid from %s: %v", b, err)
		}
	}

	if s, _ := runner.CurrentState(sessionID); s != StateAuctionDecrypting {
		t.Fatalf("after argmax cascade: state=%q want DECRYPTING", s)
	}

	// Inspect the mask envelope produced by helper-mode PhaseArgmax.
	rawAny, ok := sctx.Get(CtxAuctionCipherWinnerBid)
	if !ok {
		t.Fatal("CtxAuctionCipherWinnerBid not set after argmax")
	}
	raw, ok := rawAny.([]byte)
	if !ok {
		t.Fatalf("CtxAuctionCipherWinnerBid type = %T, want []byte", rawAny)
	}
	var env ArgmaxMaskEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if got := len(env.Masks); got != len(bidders) {
		t.Fatalf("len(masks) = %d, want %d", got, len(bidders))
	}
	sorted := append([]string(nil), bidders...)
	sort.Strings(sorted)
	for i, want := range sorted {
		if env.Bidders[i] != want {
			t.Errorf("Bidders[%d] = %q, want %q", i, env.Bidders[i], want)
		}
	}

	// Decrypt each mask to verify the argmax actually picked the
	// expected winner. mask[i] ≈ 1 for the winner, ≈ 0 for losers.
	maskValues := make(map[string]float64)
	for i, b := range env.Bidders {
		maskCT, err := hex.DecodeString(env.Masks[i])
		if err != nil {
			t.Fatalf("decode mask[%d]: %v", i, err)
		}
		p1, err := cgo.PartialDecryptCKKSForContract(cgoParams, maskCT, first.SecretKeyShare, first.Lead)
		if err != nil {
			t.Fatalf("partial 1 mask[%d]: %v", i, err)
		}
		p2, err := cgo.PartialDecryptCKKSForContract(cgoParams, maskCT, second.SecretKeyShare, second.Lead)
		if err != nil {
			t.Fatalf("partial 2 mask[%d]: %v", i, err)
		}
		vals, err := cgo.FuseCKKSPartialsForContract(cgoParams, [][]byte{p1, p2}, 4)
		if err != nil {
			t.Fatalf("fuse mask[%d]: %v", i, err)
		}
		maskValues[b] = vals[0]
		t.Logf("bidder=%s score=%v mask=%v", b, scoreFor(bidders, scores, b), vals[0])
	}

	winner := ""
	for b, v := range maskValues {
		if winner == "" || v > maskValues[winner] {
			winner = b
		}
	}
	if winner != expectedWinner {
		t.Errorf("argmax picked %q (mask=%v), want %q (mask=%v); all=%v",
			winner, maskValues[winner],
			expectedWinner, maskValues[expectedWinner],
			maskValues)
	}
}

// TestPhaseArgmax_HelperMode_RejectsMissingEvalKeys checks the helper-
// mode phase fails fast when CtxAuctionEvalKeys is absent.
func TestPhaseArgmax_HelperMode_RejectsMissingEvalKeys(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	binary := buildHelperBinary(t)
	defer os.Remove(binary)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := helperclient.Start(ctx, binary)
	defer client.Close()

	p := NewPhaseArgmaxWithHelper(client, helperclient.EvalPolyParams{
		Coefficients: []float64{0, 1, 0, -0.5},
		LowerBound:   -1, UpperBound: 1,
	})
	// Construct a session context directly. Set crypto contract but
	// not eval keys; Enter must error.
	sctx := newTestSessionContext(t)
	sctx.Set(CtxAuctionCryptoContract, map[string]any{"ring_dim": 8192, "depth": 10, "scaling_mod_size": 40})

	err := p.Enter(sctx)
	if err == nil {
		t.Errorf("expected Enter to fail with missing eval keys")
	}
}

// ── helpers ──────────────────────────────────────────────────────────

// buildHelperBinary builds the openfhe-contract-helper with -tags
// openfhe and returns its path. Skips the test if go or OpenFHE is
// unavailable.
func buildHelperBinary(t *testing.T) string {
	t.Helper()
	// Walk up to the repo root (this file is in ARES-core/examples/sealed_bid_auction).
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		root = filepath.Dir(root)
	}
	binary, err := os.CreateTemp("", "openfhe-contract-helper-*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	binary.Close()
	cmd := exec.Command("go", "build", "-tags", "openfhe",
		"-o", binary.Name(),
		"./cmd/openfhe-contract-helper")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(binary.Name())
		t.Skipf("helper build failed (missing OpenFHE?): %s", out)
	}
	return binary.Name()
}

// buildJointEvalMultKeyForTest mirrors the helper from the cgo
// package's eval_poly_test, but accessible here.
func buildJointEvalMultKeyForTest(t *testing.T, params cgo.ContractParams, shares []cgo.DistributedKeyShare) ([]byte, error) {
	t.Helper()
	finalPK := shares[len(shares)-1].PublicKey
	lead, err := cgo.EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return nil, err
	}
	publicKeys := make([][]byte, len(shares))
	multRound1 := make([][]byte, len(shares))
	sumRound1 := make([][]byte, len(shares))
	publicKeys[0] = shares[0].PublicKey
	multRound1[0] = lead.EvalMultBase
	sumRound1[0] = lead.EvalSumBase
	for i := 1; i < len(shares); i++ {
		publicKeys[i] = shares[i].PublicKey
		r1, err := cgo.EvalKeyRound1Participant(params, shares[i].SecretKeyShare,
			lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return nil, err
		}
		multRound1[i] = r1.EvalMultSwitchShare
		sumRound1[i] = r1.EvalSumShare
	}
	combined, err := cgo.CombineEvalKeyRound1(params, publicKeys, multRound1, sumRound1)
	if err != nil {
		return nil, err
	}
	finalShares := make([][]byte, len(shares))
	for i := range shares {
		r2, err := cgo.EvalKeyRound2Participant(params, shares[i].SecretKeyShare,
			combined.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			return nil, err
		}
		finalShares[i] = r2.EvalMultFinalShare
	}
	final, err := cgo.CombineEvalKeyRound2(params, finalPK, finalShares, combined.EvalSumFinal)
	if err != nil {
		return nil, err
	}
	return final.EvalMultFinal, nil
}

func scoreFor(bidders []string, scores []float64, name string) float64 {
	for i, b := range bidders {
		if b == name {
			return scores[i]
		}
	}
	return 0
}
