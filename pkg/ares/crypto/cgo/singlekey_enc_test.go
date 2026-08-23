// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
)

// trueArgmin returns the index of the bidder with the lowest lexicographic
// ranking key:  score_i = K*price_i/span - WStar*starNorm_i + WDist*distSq_i
// (lower score = better bid). For the EvalArgmax implementation the score
// passed into the polynomial is negated, so the argmax of the negated scores
// matches the argmin of the raw key — but from the caller's perspective the
// winner is simply the bidder that would sort first under the economic key.
func trueArgmin(prices []int, starNorms, distSqs []float64,
	floor, capVal int, w cgo.AuctionWeights) int {

	span := float64(capVal - floor)
	if span <= 0 {
		span = 1
	}
	best := -1
	bestScore := 0.0
	for i := range prices {
		s := w.K*float64(prices[i])/span - w.WStar*starNorms[i] + w.WDist*distSqs[i]
		if best < 0 || s < bestScore {
			best, bestScore = i, s
		}
	}
	return best
}

func TestSingleKeyAuctionServerLegacyEntryPointRequiresEvalKey(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("skip: %v", err)
	}

	params := cgo.ContractParams{
		RingDim:       1 << 15,
		Depth:         5,
		ScalingFactor: float64(uint64(1) << 50),
	}
	pk, _, err := cgo.SingleKeyGen(params)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, err = cgo.SingleKeyAuctionServer(
		params, pk, []int{1000, 1100}, []float64{4.5, 4.5}, []float64{0, 0},
		[][]byte{[]byte("nonce-a"), []byte("nonce-b")}, 800, 5000,
		cgo.AuctionWeights{K: 100, WStar: 1, WDist: 0.001}, 1,
	)
	if err == nil || !strings.Contains(err.Error(), "evaluation key") {
		t.Fatalf("legacy plaintext evaluator error = %v, want evaluation-key requirement", err)
	}
	encBid0, err := cgo.SingleKeyEncrypt(params, pk, 1000)
	if err != nil {
		t.Fatalf("encrypt bid 0: %v", err)
	}
	encBid1, err := cgo.SingleKeyEncrypt(params, pk, 1100)
	if err != nil {
		t.Fatalf("encrypt bid 1: %v", err)
	}
	_, err = cgo.SingleKeyAuctionServerEnc(
		params, pk, [][]byte{encBid0, encBid1}, []float64{4.5, 4.5}, []float64{0, 0},
		[][]byte{[]byte("nonce-a"), []byte("nonce-b")}, 800, 5000,
		cgo.AuctionWeights{K: 100, WStar: 1, WDist: 0.001}, 1,
	)
	if err == nil || !strings.Contains(err.Error(), "evaluation key") {
		t.Fatalf("legacy encrypted evaluator error = %v, want evaluation-key requirement", err)
	}
}

func TestSingleKeyAuctionServerEnc_MatchesPlaintext(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("skip: %v", err)
	}

	params := cgo.ContractParams{
		RingDim:       1 << 15,
		Depth:         5,
		ScalingFactor: float64(uint64(1) << 50),
	}
	w := cgo.AuctionWeights{K: 100, WStar: 1.0, WDist: 0.001}
	floor, cap := 800, 5000

	for _, n := range []int{3, 4, 5} {
		n := n
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			// The evaluator runs in a fresh context, so it must receive the
			// relinearization key produced alongside the public key.
			pk, sk, evalMultKey, err := cgo.SingleKeyGenWithEvalKey(params)
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}

			// Build inputs: prices spread so there is a clear winner at index 0
			// (lowest price = winner under K>0, all stars equal, equal dist).
			prices := make([]int, n)
			starNorms := make([]float64, n)
			distSqs := make([]float64, n)
			nonces := make([][]byte, n)
			encBids := make([][]byte, n)

			for i := 0; i < n; i++ {
				prices[i] = 1000 + i*50 // 1000, 1050, 1100, ...
				starNorms[i] = 4.5
				distSqs[i] = float64(i) * 0.5
				nonces[i] = []byte(fmt.Sprintf("nonce-%02d", i))
			}

			// --- plaintext reference path ---
			plainServerMasks, plainServerErr := cgo.SingleKeyAuctionServerWithEvalKey(
				params, pk, evalMultKey, prices, starNorms, distSqs, nonces, floor, cap, w, 1)
			masksPlain, winPlain, err := cgo.SingleKeyAuctionDecrypt(params, sk,
				mustMasks(t, plainServerMasks, plainServerErr))
			if err != nil {
				t.Fatalf("plaintext decrypt: %v", err)
			}

			// --- encrypted-bid path ---
			for i := 0; i < n; i++ {
				encBids[i], err = cgo.SingleKeyEncrypt(params, pk, float64(prices[i]))
				if err != nil {
					t.Fatalf("SingleKeyEncrypt[%d]: %v", i, err)
				}
			}
			encServerMasks, encServerErr := cgo.SingleKeyAuctionServerEncWithEvalKey(
				params, pk, evalMultKey, encBids, starNorms, distSqs, nonces, floor, cap, w, 1)
			masksEnc, winEnc, err := cgo.SingleKeyAuctionDecrypt(params, sk,
				mustMasks(t, encServerMasks, encServerErr))
			if err != nil {
				t.Fatalf("enc decrypt: %v", err)
			}

			// --- true argmin ---
			trueWin := trueArgmin(prices, starNorms, distSqs, floor, cap, w)

			// Verify enc-path winner matches plaintext-path winner.
			if winEnc != winPlain {
				t.Errorf("winner mismatch: plaintext=%d enc=%d", winPlain, winEnc)
			}
			// Verify both paths agree with the true economic argmin.
			if winPlain != trueWin {
				t.Errorf("plaintext winner %d != true argmin %d", winPlain, trueWin)
			}
			if winEnc != trueWin {
				t.Errorf("enc winner %d != true argmin %d", winEnc, trueWin)
			}

			t.Logf("n=%d trueWin=%d plainWin=%d encWin=%d plain_masks=%v enc_masks=%v",
				n, trueWin, winPlain, winEnc, roundSlice(masksPlain), roundSlice(masksEnc))
			_ = masksEnc
		})
	}
}

// mustMasks unwraps ([][]byte, error) from the server functions; fails the test
// on error and returns the slice for chaining.
func mustMasks(t *testing.T, masks [][]byte, err error) [][]byte {
	t.Helper()
	if err != nil {
		t.Fatalf("server auction: %v", err)
	}
	return masks
}

// roundSlice formats float64 values to 4 decimal places for log readability.
func roundSlice(vals []float64) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = fmt.Sprintf("%.4f", v)
	}
	return out
}
