// SPDX-License-Identifier: Apache-2.0

package transport

import "fmt"

// ValidateInboundMessage enforces the per-version invariants on
// incoming WSMessages:
//
//   - Version is one of WireProtocolVersion ("1") or
//     WireProtocolVersionLineage ("2"). Empty Version is treated as
//     "1" for backward compatibility with pre-v0.3 clients.
//   - v2 frames MUST carry a non-nil Lineage field. The runner
//     verifies the lineage content; the hub only checks presence.
//
// Returns nil on accept; descriptive error on reject. The hub
// calls this before dispatching to any session runner. Reference
// apps and tests can call it directly to assert version policy.
func ValidateInboundMessage(msg WSMessage) error {
	v := msg.Version
	if v == "" {
		v = WireProtocolVersion
	}
	switch v {
	case WireProtocolVersion:
		// v1: Lineage may be absent (the historical shape) or
		// present (lenient — Compose-built pipelines never set
		// it, but we don't reject a stray field).
		return nil
	case WireProtocolVersionLineage:
		if msg.Lineage == nil {
			return fmt.Errorf("transport: v%s frame requires non-nil Lineage field", v)
		}
		return nil
	default:
		return fmt.Errorf("transport: unknown protocol version %q (supported: %q, %q)",
			v, WireProtocolVersion, WireProtocolVersionLineage)
	}
}
