// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import "testing"

func TestThresholdSmokeCKKS(t *testing.T) {
	if err := ThresholdSmokeCKKS(3); err != nil {
		t.Fatalf("threshold CKKS smoke failed for 3 parties: %v", err)
	}
	if err := ThresholdSmokeCKKS(6); err != nil {
		t.Fatalf("threshold CKKS smoke failed for 6 parties: %v", err)
	}
}
