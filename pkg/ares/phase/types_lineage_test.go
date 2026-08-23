// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

func TestContextKeyType_NoLineage_DefaultsFalse(t *testing.T) {
	// Zero value of ContextKeyType means lineage IS enforced —
	// secure by default. Apps must explicitly opt out via
	// NoLineage:true.
	var k phase.ContextKeyType
	if k.NoLineage {
		t.Error("NoLineage default should be false (lineage enforced)")
	}
}

func TestContextKeyType_NoLineage_RoundTrip(t *testing.T) {
	k := phase.ContextKeyType{
		TypeName:  "[]byte",
		Required:  true,
		NoLineage: true,
	}
	if !k.NoLineage {
		t.Error("NoLineage round-trip failed")
	}
	if k.TypeName != "[]byte" {
		t.Error("existing TypeName field disturbed")
	}
	if !k.Required {
		t.Error("existing Required field disturbed")
	}
}
