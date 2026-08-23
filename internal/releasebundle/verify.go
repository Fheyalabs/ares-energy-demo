package releasebundle

import (
	"fmt"
	"reflect"
)

// Verify is the gate: given a previously-assembled ReleaseCacheManifest and
// the bundle/repo it claims to describe, it independently re-derives the
// manifest from scratch via Assemble (which itself performs every
// fail-closed check: hashes, architecture/ABI presence, pin consistency,
// clean source revision, and the release Swift manifest scan) and then
// requires the freshly-assembled manifest to be identical to m.
//
// Verify never trusts m's own claims. A manifest that was hand-edited to
// assert different (but internally consistent) values than the bundle
// actually contains is rejected by the equality check, even if every
// individual fail-closed rule in Assemble would otherwise have nothing to
// object to about the hand-edited values in isolation.
func Verify(bundleDir, repoRoot string, m *ReleaseCacheManifest) error {
	return verify(bundleDir, repoRoot, m, inspectAppleMacOSSliceDeploymentTarget)
}

func verify(bundleDir, repoRoot string, m *ReleaseCacheManifest, inspectDeploymentTarget appleDeploymentTargetInspector) error {
	if m == nil {
		return fmt.Errorf("release-cache manifest is nil")
	}

	fresh, err := assemble(bundleDir, repoRoot, inspectDeploymentTarget)
	if err != nil {
		return fmt.Errorf("bundle no longer assembles cleanly: %w", err)
	}

	// generated_at is expected to differ between the original assembly and
	// this re-assembly; every other field must match exactly.
	freshForComparison := *fresh
	freshForComparison.GeneratedAt = m.GeneratedAt

	if !reflect.DeepEqual(&freshForComparison, m) {
		return fmt.Errorf("release-cache manifest does not match a fresh assembly of bundle %s at repo root %s (hand-edited, tampered, or stale)", bundleDir, repoRoot)
	}
	return nil
}
