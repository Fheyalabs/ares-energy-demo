// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

// Package cgo's serialization golden test. Locks OpenFHE 1.5.1's
// ciphertext serialization format in CI. SC-10 lineage hashes
// serialized ciphertext bytes; if the format changes across
// versions, deployments speaking different OpenFHE versions will
// disagree on lineage commits and SC-10 verification will silently
// break. This test catches that emergency at CI time.
//
// Two modes:
//   - Normal: load the checked-in fixture, deserialize it under the
//     current OpenFHE, re-serialize, assert byte-identity.
//   - GENERATE_GOLDEN=1: produce a fresh ciphertext, serialize it,
//     write to the fixture path. Used after an intentional OpenFHE
//     version bump (review the diff manually before committing the
//     new fixture; document any security implications for SC-10
//     lineage interop).

package cgo_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
)

const goldenFixture = "testdata/openfhe_v1_5_1_ciphertext.bin"

// goldenParams are intentionally small to keep CI fast. The
// property under test is serialization stability across OpenFHE
// version pins, not production parameter sizing.
func goldenParams() cgo.ContractParams {
	return cgo.ContractParams{
		RingDim:       8192,
		Depth:         2,
		ScalingFactor: 1 << 30, // matches the historical ScalingModSize=30 sizing
	}
}

func TestSerialization_Golden(t *testing.T) {
	if os.Getenv("GENERATE_GOLDEN") == "1" {
		regenerateGolden(t)
		return
	}

	want, err := os.ReadFile(goldenFixture)
	if err != nil {
		t.Skipf("golden fixture not found (%v); regenerate with GENERATE_GOLDEN=1 go test -tags openfhe ./pkg/ares/crypto/cgo/", err)
	}
	if len(want) == 0 {
		t.Skip("golden fixture is empty; regenerate with GENERATE_GOLDEN=1")
	}

	// Round-trip: deserialize via OpenFHE, immediately re-serialize.
	// Under a stable OpenFHE version, the bytes must round-trip
	// identically. A drift in the serialization format breaks this
	// test loudly — the operator must investigate the OpenFHE
	// version pin in CI / deploy.
	roundtripped, err := cgo.RoundTripCiphertext(goldenParams(), want)
	if err != nil {
		t.Fatalf(
			"OpenFHE ciphertext deserialization failed on golden fixture (%s).\n"+
				"This indicates an OpenFHE version drift away from the pinned\n"+
				"version that produced the fixture. SC-10 lineage hashes will\n"+
				"diverge across deployments speaking different versions.\n"+
				"Investigate the version pin before regenerating the fixture.\n"+
				"Error: %v",
			filepath.Clean(goldenFixture), err,
		)
	}
	if !bytes.Equal(want, roundtripped) {
		t.Fatalf(
			"OpenFHE ciphertext round-trip is no longer byte-identical.\n"+
				"  fixture len: %d\n"+
				"  roundtrip len: %d\n"+
				"SC-10 lineage hashes will diverge across deployments. If this\n"+
				"is an intentional OpenFHE version bump, regenerate with\n"+
				"  GENERATE_GOLDEN=1 go test -tags openfhe ./pkg/ares/crypto/cgo/\n"+
				"and review the SC-10 implications.",
			len(want), len(roundtripped),
		)
	}
}

func regenerateGolden(t *testing.T) {
	t.Helper()
	params := goldenParams()

	// Generate a fresh single-party threshold-flavor key share so we
	// have a PublicKey to encrypt under.
	share, err := cgo.DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("DistributedKeyGenFirst: %v", err)
	}

	// Encrypt a small fixed value set under the generated public key.
	ct, err := cgo.EncryptCKKSForContract(params, share.PublicKey, []float64{1.0, 2.0, 3.0, 4.0})
	if err != nil {
		t.Fatalf("EncryptCKKSForContract: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(goldenFixture), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(goldenFixture, ct, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Logf("golden fixture regenerated: %s (%d bytes)", goldenFixture, len(ct))
}
