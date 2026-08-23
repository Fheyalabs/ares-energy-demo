//go:build openfhe

package cgo

import (
	"bytes"
	"os"
	"testing"
)

// TestSingularPerIndexEvalSumSharedA verifies the SINGULAR per-index eval-sum keygen
// (GeneratePerIndexEvalSumKey/Share -- exactly what the Swift client loops over, one
// rotation index at a time) preserves the shared-CRS-a invariant the server's b-only
// reconstruction depends on: every party's a-vectors for a given index must be
// byte-identical to the lead's, since only the lead's a is uploaded and reused.
//
// If the singular path generates a fresh a per call (instead of reusing the base's a),
// the lead-a + party-b reconstruction is wrong -> noisy eval-sum -> the live union
// "approximation error too high". The plural GeneratePerIndexEvalSumKeysWithContext used
// by the in-process tests would NOT catch this.
func TestSingularPerIndexEvalSumSharedA(t *testing.T) {
	// Force the real HEStd_128_classic modulus chain (package init forces insecure).
	prev := os.Getenv("ARES_FHE_ALLOW_INSECURE")
	os.Setenv("ARES_FHE_ALLOW_INSECURE", "0")
	defer os.Setenv("ARES_FHE_ALLOW_INSECURE", prev)
	params := ContractParams{
		RingDim:                 32768,
		ScalingFactor:           float64(uint64(1) << 35),
		Depth:                   16,
		EvalSumOnlyRotationKeys: true,
		ProfileDim:              128, // live profile dim -> fold indices 1..64
	}
	ctx, err := NewCryptoContext(params)
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	defer ctx.Close()

	shares := make([]DistributedKeyShare, 3)
	shares[0], err = DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	for i := 1; i < len(shares); i++ {
		shares[i], err = DistributedKeyGenNext(params, shares[i-1].PublicKey)
		if err != nil {
			t.Fatalf("keygen next %d: %v", i, err)
		}
	}

	// Replicate the EXACT live client eval-mult round1: evalMultKeyGenLead +
	// evalMultKeySwitchShare (NOT EvalKeyRound1Lead), which is what the MacClient calls
	// before the per-index eval-sum keygen.
	evalMultBase, err := EvalMultKeyGenLeadWithContext(ctx, shares[0].SecretKeyShare)
	if err != nil {
		t.Fatalf("evalMultKeyGenLead: %v", err)
	}
	for i := 1; i < len(shares); i++ {
		if _, err := EvalMultKeySwitchShareWithContext(ctx, shares[i].SecretKeyShare, evalMultBase); err != nil {
			t.Fatalf("evalMultKeySwitchShare %d: %v", i, err)
		}
	}

	for _, idx := range []int32{1, 2, 4, 8, 16, 32, 64} {
		// Lead generates a single-index key (Swift: generatePerIndexEvalSumKey).
		leadKey, err := GeneratePerIndexEvalSumKeyWithContext(ctx, shares[0].SecretKeyShare, idx)
		if err != nil {
			t.Fatalf("lead singular key idx %d: %v", idx, err)
		}
		leadA, _, err := SplitRotShareAB(params, leadKey)
		if err != nil {
			t.Fatalf("split lead idx %d: %v", idx, err)
		}
		for p := 1; p < len(shares); p++ {
			// Party share from the lead's single-index base (Swift: generatePerIndexEvalSumShare).
			share, err := GeneratePerIndexEvalSumShareWithContext(ctx, shares[p].SecretKeyShare, leadKey, shares[p].PublicKey, idx)
			if err != nil {
				t.Fatalf("party %d singular share idx %d: %v", p, idx, err)
			}
			partyA, _, err := SplitRotShareAB(params, share)
			if err != nil {
				t.Fatalf("split party %d idx %d: %v", p, idx, err)
			}
			if !bytes.Equal(leadA, partyA) {
				t.Errorf("SHARED-A VIOLATED: party %d index %d a differs from lead (len lead=%d party=%d) -- singular keygen breaks b-only reconstruction", p, idx, len(leadA), len(partyA))
				continue
			}
		}
		t.Logf("index %d: all %d parties share the lead a-vectors (len=%d)", idx, len(shares), len(leadA))
	}
}
