// SPDX-License-Identifier: Apache-2.0

package lineage_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
)

func TestSentinelErrorsAreDistinct(t *testing.T) {
	if errors.Is(lineage.ErrNodeNotFound, lineage.ErrNodeExists) {
		t.Error("ErrNodeNotFound and ErrNodeExists must be distinct")
	}
}

func TestMismatchError_FormatsField(t *testing.T) {
	e := &lineage.MismatchError{
		Field:    "PayloadHash",
		Expected: []byte{0x01, 0x02},
		Got:      []byte{0x03, 0x04},
	}
	if got := e.Error(); got == "" {
		t.Fatal("Error() returned empty string")
	}
	// Format must include the Field for debuggability.
	if !strings.Contains(e.Error(), "PayloadHash") {
		t.Errorf("Error() = %q, want to contain %q", e.Error(), "PayloadHash")
	}
}
