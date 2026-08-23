package native_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseSwiftManifestUsesOnlyStagedBridgeBinary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "clients", "swift", "Package.release.swift"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(raw)
	for _, want := range []string{
		`.binaryTarget(name: "COpenFHEBridge", path: "Artifacts/AresPrivacyCore.xcframework")`,
		`.library(name: "AresClientFHE", targets: ["AresClientFHE"])`,
		`.linkedLibrary("c++")`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("release manifest does not contain %q", want)
		}
	}
	for _, forbidden := range []string{
		"ProcessInfo.processInfo.environment",
		"/usr/local",
		"/opt/homebrew",
		"ARES_OPENFHE",
	} {
		if strings.Contains(manifest, forbidden) {
			t.Fatalf("release manifest contains forbidden development dependency %q", forbidden)
		}
	}
}
