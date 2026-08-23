// SPDX-License-Identifier: Apache-2.0

package auction

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// newTestSessionContext returns a fresh SessionContext suitable for
// hooking phases up in unit tests that don't go through a runner.
func newTestSessionContext(t *testing.T) *phase.SessionContext {
	t.Helper()
	return phase.NewSessionContext("test-session")
}
