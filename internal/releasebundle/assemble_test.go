package releasebundle_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/internal/releasebundle"
	"github.com/Fheyalabs/ares-core/internal/releasebundle/releasebundletest"
)

func TestAssembleProducesDeterministicReleaseCacheManifest(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})

	m, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	if m.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", m.SchemaVersion)
	}
	if m.OpenFHEVersion != releasebundletest.OpenFHEVersion {
		t.Errorf("openfhe_version = %q, want %q", m.OpenFHEVersion, releasebundletest.OpenFHEVersion)
	}
	if m.OpenFHESourceCommit != releasebundletest.OpenFHECommit {
		t.Errorf("openfhe_source_commit = %q, want %q", m.OpenFHESourceCommit, releasebundletest.OpenFHECommit)
	}
	if m.AresCoreSourceRevision == "" {
		t.Error("ares_core_source_revision is empty")
	}
	if m.Apple.ArtifactKind != releasebundle.ArtifactKindAppleXCFramework {
		t.Errorf("apple.artifact_kind = %q", m.Apple.ArtifactKind)
	}
	if m.Android.ArtifactKind != releasebundle.ArtifactKindAndroidAAR {
		t.Errorf("android.artifact_kind = %q", m.Android.ArtifactKind)
	}
	if m.Apple.ArtifactFile == "" || strings.Contains(m.Apple.ArtifactFile, "/") {
		t.Errorf("apple.artifact_file should be a bundle-relative basename, got %q", m.Apple.ArtifactFile)
	}
	if m.Android.ArtifactFile == "" || strings.Contains(m.Android.ArtifactFile, "/") {
		t.Errorf("android.artifact_file should be a bundle-relative basename, got %q", m.Android.ArtifactFile)
	}
	if m.SwiftReleaseManifestSHA256 == "" {
		t.Error("swift_release_manifest_sha256 is empty")
	}
	if m.GeneratedAt == "" {
		t.Error("generated_at is empty")
	}

	// Re-assembling the same untouched bundle must be byte-for-byte
	// deterministic aside from generated_at.
	m2, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err != nil {
		t.Fatalf("second Assemble: %v", err)
	}
	m2.GeneratedAt = m.GeneratedAt
	if !reflect.DeepEqual(m, m2) {
		t.Fatalf("Assemble is not deterministic:\n%+v\n%+v", m, m2)
	}
}

func TestAssembleRejectsMismatchedSourceRevision(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AndroidAresRevOverride: "0000000000000000000000000000000000dead",
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on mismatched ares_core_source_revision between platform artifacts, got nil error")
	}
	if !strings.Contains(err.Error(), "revision") {
		t.Errorf("error does not mention revision: %v", err)
	}
}

func TestAssembleRejectsMismatchedArtifactHash(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})

	// Tamper with the staged Apple artifact after its manifest hash was
	// computed, simulating a corrupted or substituted artifact.
	releasebundletest.TamperFile(t, bundleDir+"/AresPrivacyCore-v1.5.1-apple.xcframework.zip")

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on mismatched artifact hash, got nil error")
	}
	if !strings.Contains(err.Error(), "sha256") && !strings.Contains(err.Error(), "hash") {
		t.Errorf("error does not mention hash/sha256: %v", err)
	}
}

func TestAssembleRejectsLocalSwiftPMPathDependency(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		SwiftManifestOverride: `// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AresClient",
    dependencies: [
        .package(name: "AresCore", path: "../ares-core"),
    ],
    targets: [
        .binaryTarget(name: "COpenFHEBridge", path: "Artifacts/AresPrivacyCore.xcframework"),
    ]
)
`,
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on local SwiftPM path dependency, got nil error")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("error does not mention a local path dependency: %v", err)
	}
}

func TestAssembleRejectsEnvironmentDependencySubstitution(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		SwiftManifestOverride: `// swift-tools-version: 6.0
import PackageDescription
import Foundation

let corePath = ProcessInfo.processInfo.environment["ARES_CORE_SWIFT_PATH"] ?? "Artifacts/AresPrivacyCore.xcframework"
let package = Package(
    name: "AresClient",
    targets: [
        .binaryTarget(name: "COpenFHEBridge", path: corePath),
    ]
)
`,
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on environment-driven dependency substitution, got nil error")
	}
}

func TestAssembleRejectsBridgeEvidenceOnlyInSwiftComment(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		SwiftManifestOverride: `// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AresClient",
    targets: [
        // .binaryTarget(name: "COpenFHEBridge", path: "Artifacts/AresPrivacyCore.xcframework"),
        .target(name: "AresClient"),
    ]
)
`,
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a release manifest whose required bridge target exists only in a comment")
	}
	if !strings.Contains(err.Error(), "COpenFHEBridge") {
		t.Errorf("error does not identify the missing bridge target: %v", err)
	}
}

func TestAssembleRejectsBridgeEvidenceOnlyInSwiftString(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		SwiftManifestOverride: `// swift-tools-version: 6.0
import PackageDescription

let diagnostic = #".binaryTarget(name: "COpenFHEBridge", path: "Artifacts/AresPrivacyCore.xcframework")"#
let package = Package(
    name: "AresClient",
    targets: [
        .target(name: "AresClient"),
    ]
)
`,
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a release manifest whose required bridge target exists only in a string literal")
	}
	if !strings.Contains(err.Error(), "COpenFHEBridge") {
		t.Errorf("error does not identify the missing bridge target: %v", err)
	}
}

func TestAssembleRejectsSymlinkedStagedArtifact(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	artifact := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.xcframework.zip")
	outside := filepath.Join(t.TempDir(), "outside-apple.xcframework.zip")
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, artifact); err != nil {
		t.Fatal(err)
	}

	_, err = releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a staged artifact symlink even when its target has the expected hash")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error does not identify the symlinked artifact: %v", err)
	}
}

func TestAssembleRejectsSymlinkedStagingManifest(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	manifest := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.staging-manifest.json")
	outside := filepath.Join(t.TempDir(), "outside-apple.staging-manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, manifest); err != nil {
		t.Fatal(err)
	}

	_, err = releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a staging-manifest symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error does not identify the symlinked staging manifest: %v", err)
	}
}

func TestAssembleRejectsAbsentAndroidABIJNILibrary(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AndroidLibsOverride: map[string][]string{
			"arm64-v8a": {"libOPENFHEcore.so", "libOPENFHEpke.so", "libOPENFHEbinfhe.so"}, // missing libares_fhe_jni.so
		},
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on an ABI missing the JNI bridge library, got nil error")
	}
	if !strings.Contains(err.Error(), "arm64-v8a") {
		t.Errorf("error does not name the affected ABI: %v", err)
	}
}

func TestAssembleRejectsAbsentAndroidABI(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AndroidABIs: []string{"arm64-v8a"}, // missing the required x86_64 ABI entirely
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on a bundle missing a required Android ABI, got nil error")
	}
	if !strings.Contains(err.Error(), "x86_64") {
		t.Errorf("error does not name the missing ABI: %v", err)
	}
}

func TestAssembleRejectsPinDrift(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AndroidOpenFHEVersionOverride: "v1.5.0",
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail when an artifact's OpenFHE version does not match the tracked pin, got nil error")
	}
}
