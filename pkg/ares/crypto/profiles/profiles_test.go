// SPDX-License-Identifier: Apache-2.0

package profiles

import "testing"

func TestCKKSRing32KUnionV1(t *testing.T) {
	p := CKKSRing32KUnionV1()
	if p.Name != "ckks_ring32k_union_v1" {
		t.Fatalf("Name = %q", p.Name)
	}
	if p.Scheme != SchemeCKKS {
		t.Fatalf("Scheme = %q, want %q", p.Scheme, SchemeCKKS)
	}
	if p.RingDim != 32768 || p.Depth != 16 || p.ProfileDim != 128 || p.PayloadSlotCount != 640 {
		t.Fatalf("unexpected CKKS dimensions: %+v", p)
	}
	if p.ScalingModSize != 35 {
		t.Fatalf("ScalingModSize = %d, want 35", p.ScalingModSize)
	}
	if len(p.Comparators) != 3 {
		t.Fatalf("comparators = %d, want 3", len(p.Comparators))
	}
	wantIDs := []string{"tanh_g5_d13", "logi_g4_b5_d13", "logi_g3_b6_d13"}
	for i, want := range wantIDs {
		if p.Comparators[i].ID != want {
			t.Fatalf("comparator[%d].ID = %q, want %q", i, p.Comparators[i].ID, want)
		}
	}
	if p.Parallel.ComparatorWorkers != 3 || p.Parallel.OMPThreadsPerWorker != 3 {
		t.Fatalf("parallel defaults = %+v, want 3 workers with OMP=3", p.Parallel)
	}
}

func TestBFVRing32KBlindV1(t *testing.T) {
	p := BFVRing32KBlindV1()
	if p.Name != "bfv_ring32k_blind_v1" {
		t.Fatalf("Name = %q", p.Name)
	}
	if p.Scheme != SchemeBFV {
		t.Fatalf("Scheme = %q, want %q", p.Scheme, SchemeBFV)
	}
	if p.RingDim != 32768 || p.PlaintextModulus != 65537 || p.BatchSize != 128 {
		t.Fatalf("unexpected BFV ring/modulus/batch: %+v", p)
	}
	if p.ProfileDim != 128 || p.PackageBytes != 80 || p.QuantizationScale != 63 || p.StepPolyBits != 13 {
		t.Fatalf("unexpected BFV payload params: %+v", p)
	}
	if p.MultiplicativeDepth != 20 {
		t.Fatalf("MultiplicativeDepth = %d, want 20", p.MultiplicativeDepth)
	}
	if p.ProcessParallelism != ParallelismDisabled {
		t.Fatalf("ProcessParallelism = %q, want disabled", p.ProcessParallelism)
	}
}

func TestBFVLightBlindV1(t *testing.T) {
	p := BFVLightBlindV1()
	if p.Name != "bfv_light_blind_v1" {
		t.Fatalf("Name = %q", p.Name)
	}
	if p.Scheme != SchemeBFV {
		t.Fatalf("Scheme = %q, want %q", p.Scheme, SchemeBFV)
	}
	if p.RingDim >= BFVRing32KBlindV1().RingDim {
		t.Fatalf("light profile ring = %d, want smaller than production profile", p.RingDim)
	}
	if p.PlaintextModulus != 65537 || p.BatchSize != 32 || p.ProfileDim != 8 {
		t.Fatalf("unexpected light BFV shape: %+v", p)
	}
	if p.PackageBytes != 16 || p.QuantizationScale != 15 || p.StepPolyBits != 6 {
		t.Fatalf("unexpected light BFV payload params: %+v", p)
	}
}

func TestProfilesReturnCopies(t *testing.T) {
	p := CKKSRing32KUnionV1()
	p.Comparators[0].ID = "mutated"
	again := CKKSRing32KUnionV1()
	if again.Comparators[0].ID != "tanh_g5_d13" {
		t.Fatalf("profile comparators are mutable across calls: got %q", again.Comparators[0].ID)
	}
}
