// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestSignerInterface_AssertableByEd25519 confirms the default
// implementation actually satisfies the interface. Compile-time check
// via type assertion in a runtime test.
func TestSignerInterface_AssertableByEd25519(t *testing.T) {
	var _ sign.Signer = (*sign.Ed25519Signer)(nil)
}
