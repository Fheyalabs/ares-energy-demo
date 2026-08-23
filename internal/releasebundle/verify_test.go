package releasebundle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fheyalabs/ares-core/internal/releasebundle"
	"github.com/Fheyalabs/ares-core/internal/releasebundle/releasebundletest"
)

func TestVerifyAcceptsFreshlyAssembledManifest(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})

	m, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	manifestPath := filepath.Join(t.TempDir(), "release-cache-manifest.json")
	if err := releasebundle.WriteManifest(manifestPath, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	loaded := readManifest(t, manifestPath)
	if err := releasebundle.VerifyForTest(bundleDir, repoRoot, loaded); err != nil {
		t.Fatalf("Verify rejected a freshly assembled, untampered manifest: %v", err)
	}
}

func TestVerifyRejectsHandEditedManifest(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})

	m, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	// Hand-edit the manifest to claim a different artifact hash than the
	// bundle actually contains, without touching the underlying files.
	tampered := *m
	tampered.Apple.ArtifactSHA256 = "0000000000000000000000000000000000000000000000000000000000000"

	if err := releasebundle.VerifyForTest(bundleDir, repoRoot, &tampered); err == nil {
		t.Fatal("expected Verify to reject a hand-edited manifest whose claims do not match a fresh assembly of the bundle")
	}
}

func TestVerifyRejectsWhenUnderlyingBundleNoLongerAssembles(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})

	m, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	// Corrupt the staged Android artifact after a valid manifest was
	// produced, simulating a bundle directory that was tampered with
	// post-assembly.
	releasebundletest.TamperFile(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.aar"))

	if err := releasebundle.VerifyForTest(bundleDir, repoRoot, m); err == nil {
		t.Fatal("expected Verify to reject a manifest whose bundle no longer re-assembles cleanly")
	}
}

func readManifest(t *testing.T, path string) *releasebundle.ReleaseCacheManifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m releasebundle.ReleaseCacheManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return &m
}
