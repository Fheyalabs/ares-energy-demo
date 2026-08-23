package releasebundle_test

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/internal/releasebundle"
	"github.com/Fheyalabs/ares-core/internal/releasebundle/releasebundletest"
)

func TestAssembleRecordsAppleDeploymentTargetInReleaseCacheManifest(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})

	m, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if m.Apple.AppleMACOSDeploymentTarget != releasebundletest.AppleMACOSDeploymentTarget {
		t.Fatalf("Apple.AppleMACOSDeploymentTarget = %q, want %q", m.Apple.AppleMACOSDeploymentTarget, releasebundletest.AppleMACOSDeploymentTarget)
	}
	if m.Android.AppleMACOSDeploymentTarget != "" {
		t.Fatalf("Android.AppleMACOSDeploymentTarget = %q, want empty", m.Android.AppleMACOSDeploymentTarget)
	}
}

func TestAssembleRejectsMissingAppleDeploymentTarget(t *testing.T) {
	// Opts always writes some value into the field (an empty override
	// falls back to NewBundle's default), so overwrite the staged
	// manifest directly to exercise a genuinely absent field -- the same
	// class of staging bug this check exists to catch.
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	overwriteAppleManifestField(t, bundleDir, "apple_macos_deployment_target", "")

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on a missing apple_macos_deployment_target, got nil error")
	}
	if !strings.Contains(err.Error(), "apple_macos_deployment_target") {
		t.Errorf("error does not mention apple_macos_deployment_target: %v", err)
	}
}

func TestAssembleRejectsMalformedAppleDeploymentTarget(t *testing.T) {
	for _, malformed := range []string{"14", "abc", "14.x", "14.0.1.2", "", "014.0", "14.00"} {
		t.Run(malformed, func(t *testing.T) {
			bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
			overwriteAppleManifestField(t, bundleDir, "apple_macos_deployment_target", malformed)

			_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
			if err == nil {
				t.Fatalf("expected Assemble to fail on malformed apple_macos_deployment_target %q, got nil error", malformed)
			}
		})
	}
}

func TestAssembleRejectsAppleDeploymentTargetNewerThanDeclaredPin(t *testing.T) {
	// releasebundletest's fixture repo declares 14.0; recording 15.0 in the
	// staged manifest claims a newer minimum than what the repo currently
	// declares as supported -- exactly the "not a portable release
	// candidate" case this check exists to catch.
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleMACOSDeploymentTargetOverride: "15.0",
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail when the recorded deployment target is newer than the declared pin, got nil error")
	}
	if !strings.Contains(err.Error(), "15.0") || !strings.Contains(err.Error(), "14.0") {
		t.Errorf("error does not name both the recorded and declared targets: %v", err)
	}
}

func TestAssembleRejectsAppleDeploymentTargetOlderThanDeclaredPin(t *testing.T) {
	// The tracked pin is an exact release contract. A staging manifest that
	// records an older minimum still disagrees with that contract and must
	// not be able to represent the staged artifact as matching it.
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleMACOSDeploymentTargetOverride: "12.0",
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a recorded deployment target older than the declared pin, got nil error")
	}
	if !strings.Contains(err.Error(), "12.0") || !strings.Contains(err.Error(), "14.0") {
		t.Errorf("error does not name both the recorded and declared targets: %v", err)
	}
}

func TestAssembleProductionInspectorRejectsPATHShadowedOtool(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	releasebundletest.InstallPATHShadowOtool(t)

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected production Assemble to reject marker metadata from a PATH-shadowed otool, got nil error")
	}
	if runtime.GOOS == "darwin" && !strings.Contains(err.Error(), "/usr/bin/otool") {
		t.Errorf("Darwin failure does not identify the trusted system otool: %v", err)
	}
	if runtime.GOOS != "darwin" && !strings.Contains(err.Error(), "requires Darwin") {
		t.Errorf("non-Darwin failure does not identify the runtime requirement: %v", err)
	}
}

func TestAssembleRejectsMissingAppleDeploymentTargetPinFile(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	pinPath := filepath.Join(repoRoot, "clients", "native", "apple-deployment-target.pin.json")
	if err := os.Remove(pinPath); err != nil {
		t.Fatal(err)
	}
	// The removal itself makes the checkout dirty relative to the commit
	// staged artifacts recorded; commit the removal and re-point both
	// staged manifests at the new HEAD so this test isolates "pin file
	// absent" from the separate, already-covered "dirty checkout"/
	// "stale revision" rejections.
	commitRemoval(t, repoRoot, pinPath)
	retargetStagedRevision(t, bundleDir, repoRoot)

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail when the declared Apple deployment-target pin file is missing, got nil error")
	}
	if !strings.Contains(err.Error(), "apple-deployment-target.pin.json") {
		t.Errorf("error does not name the missing pin file: %v", err)
	}
}

func TestAssembleRejectsMalformedAppleDeploymentTargetPin(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	pinPath := filepath.Join(repoRoot, "clients", "native", "apple-deployment-target.pin.json")
	if err := os.WriteFile(pinPath, []byte(`{"macos_minimum_deployment_target":"not-a-version"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, repoRoot, "corrupt apple deployment-target pin")
	retargetStagedRevision(t, bundleDir, repoRoot)

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on a malformed declared Apple deployment-target pin, got nil error")
	}
	if !strings.Contains(err.Error(), "apple-deployment-target.pin.json") {
		t.Errorf("error does not name the malformed pin file: %v", err)
	}
}

func TestAssembleRejectsNonCanonicalAppleDeploymentTargetPin(t *testing.T) {
	for _, nonCanonical := range []string{"014.0", "14.00"} {
		t.Run(nonCanonical, func(t *testing.T) {
			bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
			pinPath := filepath.Join(repoRoot, "clients", "native", "apple-deployment-target.pin.json")
			if err := os.WriteFile(pinPath, []byte(`{"macos_minimum_deployment_target":"`+nonCanonical+`"}`), 0o644); err != nil {
				t.Fatal(err)
			}
			commitAll(t, repoRoot, "write non-canonical apple deployment-target pin")
			retargetStagedRevision(t, bundleDir, repoRoot)

			_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
			if err == nil {
				t.Fatalf("expected Assemble to reject non-canonical declared Apple deployment target %q, got nil error", nonCanonical)
			}
			if !strings.Contains(err.Error(), "apple-deployment-target.pin.json") {
				t.Errorf("error does not identify the tracked pin: %v", err)
			}
		})
	}
}

func TestAssembleRejectsNonCanonicalInspectedMachOMinOS(t *testing.T) {
	for _, nonCanonical := range []string{"014.0", "14.00"} {
		t.Run(nonCanonical, func(t *testing.T) {
			bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
				AppleMachOMinosOverride: nonCanonical,
			})

			_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
			if err == nil {
				t.Fatalf("expected Assemble to reject non-canonical inspected Mach-O minos %q, got nil error", nonCanonical)
			}
			if !strings.Contains(err.Error(), nonCanonical) {
				t.Errorf("error does not identify the inspected non-canonical minos: %v", err)
			}
		})
	}
}

func TestAssembleInspectsCanonicalMacOSMemberDespiteDecoyFirst(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleDecoyFirstMachOMinos: "14.0",
		AppleMachOMinosOverride:   "15.0",
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject the canonical macOS member's 15.0 minos despite a decoy-first 14.0 member, got nil error")
	}
	if !strings.Contains(err.Error(), "15.0") {
		t.Errorf("error does not prove the canonical 15.0 member was inspected: %v", err)
	}
}

func TestAssembleRejectsMissingCanonicalMacOSMemberDespiteDecoy(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleDecoyFirstMachOMinos:      "14.0",
		OmitCanonicalAppleMacOSLibrary: true,
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject an Apple archive with only a matching-looking decoy macOS member, got nil error")
	}
	if !strings.Contains(err.Error(), "canonical") {
		t.Errorf("error does not identify the missing canonical macOS member: %v", err)
	}
}

func TestAssembleRejectsDuplicateCanonicalMacOSMembers(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		DuplicateCanonicalAppleMacOSLibrary: true,
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject duplicate canonical macOS members, got nil error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error does not identify duplicate canonical macOS members: %v", err)
	}
}

func TestAssembleRejectsUnsafeAppleZIPMemberNames(t *testing.T) {
	for _, name := range []string{
		"../outside",
		"/absolute/member",
		"C:/absolute/member",
		"AresPrivacyCore.xcframework\\macos-arm64\\libAresPrivacyCore.a",
		"unrelated//repeated/member",
		"unrelated/./member",
	} {
		t.Run(name, func(t *testing.T) {
			bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
				AppleExtraZipMembers: []string{name},
			})

			_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
			if err == nil {
				t.Fatalf("expected Assemble to reject unsafe Apple ZIP member %q, got nil error", name)
			}
			if !strings.Contains(err.Error(), "ZIP member") {
				t.Errorf("error does not identify an unsafe ZIP member: %v", err)
			}
		})
	}
}

func TestAssembleRejectsAppleZIPAliasesOfCanonicalMacOSMember(t *testing.T) {
	const canonical = "AresPrivacyCore.xcframework/macos-arm64/libAresPrivacyCore.a"
	for _, alias := range []string{
		"./" + canonical,
		"AresPrivacyCore.xcframework/macos-arm64/../macos-arm64/libAresPrivacyCore.a",
		"AresPrivacyCore.xcframework//macos-arm64/libAresPrivacyCore.a",
		"/" + canonical,
		"AresPrivacyCore.xcframework\\macos-arm64\\libAresPrivacyCore.a",
	} {
		t.Run(alias, func(t *testing.T) {
			bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
				AppleExtraZipMembers: []string{alias},
			})

			_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
			if err == nil {
				t.Fatalf("expected Assemble to reject canonical-member alias %q, got nil error", alias)
			}
			if !strings.Contains(err.Error(), "ZIP member") {
				t.Errorf("error does not identify an unsafe or colliding ZIP member: %v", err)
			}
		})
	}
}

func TestAssembleRejectsCaseInsensitiveAppleZIPAliases(t *testing.T) {
	const caseAlias = "aresprivacycore.xcframework/macos-arm64/libaresprivacycore.a"
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleExtraZipMembers: []string{caseAlias},
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a case-insensitive alias of the canonical macOS member, got nil error")
	}
	if !strings.Contains(err.Error(), "collides") {
		t.Errorf("error does not identify the case-insensitive collision: %v", err)
	}
}

func TestAssembleRejectsNonASCIIAppleZIPMembers(t *testing.T) {
	for _, name := range []string{
		"AresPrivacyCore.xcframework/macos-arm64/Headers/caf\u00e9.h",
		"AresPrivacyCore.xcframework/macos-arm64/Headers/cafe\u0301.h",
	} {
		t.Run(name, func(t *testing.T) {
			bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
				AppleExtraZipMembers: []string{name},
			})

			_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
			if err == nil {
				t.Fatalf("expected Assemble to reject non-ASCII Apple ZIP member %q, got nil error", name)
			}
			if !strings.Contains(err.Error(), "portable ASCII") {
				t.Errorf("error does not identify the portable-ASCII restriction: %v", err)
			}
		})
	}
}

func TestAssembleRejectsAppleZIPMemberWithNonUTF8Flag(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleNonUTF8ZipMember: "AresPrivacyCore.xcframework/macos-arm64/Headers/caf\u00e9.h",
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject an Apple ZIP member with NonUTF8 set, got nil error")
	}
	if !strings.Contains(err.Error(), "NonUTF8") {
		t.Errorf("error does not identify the NonUTF8 flag: %v", err)
	}
}

func TestAssembleRejectsAppleZIPMemberSymlink(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleSymlinkZipMember: "AresPrivacyCore.xcframework/macos-arm64/Headers/alias.h",
	})

	_, err := releasebundle.AssembleForTest(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a symbolic-link Apple ZIP member, got nil error")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error does not identify the symbolic-link member: %v", err)
	}
}

// retargetStagedRevision re-points bundleDir's staged Apple and Android
// manifests' ares_core_source_revision at repoRoot's current HEAD, so a
// test that commits an additional change to repoRoot (to reach a specific
// tracked-file state) does not incidentally trip the separate, unrelated
// "stale/dirty revision" rejection while isolating a different check.
func retargetStagedRevision(t *testing.T, bundleDir, repoRoot string) {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(string(out))
	overwriteManifestField(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.staging-manifest.json"), "ares_core_source_revision", head)
	overwriteManifestField(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.staging-manifest.json"), "ares_core_source_revision", head)
}

// TestAssembleInspectsRealMachODeploymentTargetOnDarwin builds a real,
// tiny compiled static archive whose actual LC_BUILD_VERSION minos is
// newer than the declared pin, stages it as the macos-arm64 slice of a
// fixture xcframework whose *manifest* claims the correct (older, matching)
// target, and confirms Assemble still rejects it -- proving the inspected
// check catches a real discrepancy a staging-manifest claim alone would
// miss, exactly the bug class described in this task (a build that
// records/claims one target but actually links a newer one).
func TestAssembleInspectsRealMachODeploymentTargetOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real Mach-O deployment-target inspection only runs on darwin")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang is unavailable")
	}

	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	realLib := compileRealMachOStaticLib(t, "15.0") // newer than the fixture's declared/recorded 14.0
	replaceAppleXCFrameworkMacOSSlice(t, bundleDir, realLib)

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a real Mach-O whose inspected minos exceeds the declared pin, got nil error")
	}
	if !strings.Contains(err.Error(), "15.0") {
		t.Errorf("error does not name the inspected mismatch: %v", err)
	}
}

func TestAssembleRejectsRealMachOOlderThanDeclaredPinOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real Mach-O deployment-target inspection only runs on darwin")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang is unavailable")
	}

	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	realLib := compileRealMachOStaticLib(t, "12.0") // older than the fixture's declared/recorded 14.0
	replaceAppleXCFrameworkMacOSSlice(t, bundleDir, realLib)

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a real Mach-O whose inspected minos differs from the declared pin, got nil error")
	}
	if !strings.Contains(err.Error(), "12.0") || !strings.Contains(err.Error(), "14.0") {
		t.Errorf("error does not name both the inspected and declared targets: %v", err)
	}
}

// TestAssembleAcceptsRealMachOMatchingDeploymentTargetOnDarwin is the
// mirror positive case: a real compiled archive whose inspected minos
// exactly matches the declared pin must not be rejected by the inspection
// step.
func TestAssembleAcceptsRealMachOMatchingDeploymentTargetOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real Mach-O deployment-target inspection only runs on darwin")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang is unavailable")
	}

	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	realLib := compileRealMachOStaticLib(t, releasebundletest.AppleMACOSDeploymentTarget)
	replaceAppleXCFrameworkMacOSSlice(t, bundleDir, realLib)

	if _, err := releasebundle.Assemble(bundleDir, repoRoot); err != nil {
		t.Fatalf("Assemble rejected a real Mach-O whose inspected minos exactly matches the declared pin: %v", err)
	}
}

// compileRealMachOStaticLib compiles a trivial C file with an explicit
// -mmacosx-version-min and archives it into a real static library,
// returning its path. This is the "bounded real metadata probe": no
// OpenFHE build, just a few-millisecond real clang invocation to ground
// the parsing logic against genuine Mach-O bytes.
func compileRealMachOStaticLib(t *testing.T, deploymentTarget string) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "t.c")
	if err := os.WriteFile(srcPath, []byte("int ares_probe(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	objPath := filepath.Join(dir, "t.o")
	cmd := exec.CommandContext(context.Background(), "clang", "-mmacosx-version-min="+deploymentTarget, "-c", srcPath, "-o", objPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	libPath := filepath.Join(dir, "libAresPrivacyCore.a")
	cmd = exec.CommandContext(context.Background(), "ar", "rcs", libPath, objPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ar: %v\n%s", err, out)
	}
	return libPath
}

// replaceAppleXCFrameworkMacOSSlice rewrites bundleDir's staged Apple
// xcframework zip, replacing the macos-arm64 slice's libAresPrivacyCore.a
// member with the real file at realLibPath and updating the staging
// manifest's artifact_sha256 to match (mirroring what a real build would
// have recorded for its own real output).
func replaceAppleXCFrameworkMacOSSlice(t *testing.T, bundleDir, realLibPath string) {
	t.Helper()
	artifactPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.xcframework.zip")
	r, err := zip.OpenReader(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	realLibBytes, err := os.ReadFile(realLibPath)
	if err != nil {
		t.Fatal(err)
	}

	rewritten := artifactPath + ".rewritten"
	out, err := os.Create(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var content []byte
		if f.Name == "AresPrivacyCore.xcframework/macos-arm64/libAresPrivacyCore.a" {
			content = realLibBytes
		} else {
			content, err = io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
		}
		rc.Close()
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(rewritten, artifactPath); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(mustReadFile(t, artifactPath))
	overwriteAppleManifestField(t, bundleDir, "artifact_sha256", hex.EncodeToString(sum[:]))
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// overwriteAppleManifestField loads the staged Apple staging-manifest JSON,
// sets one top-level field to value, and writes it back -- used by
// mutation tests to construct a manifest shape NewBundle's Opts can't
// express directly (a missing field, an out-of-band field edit after
// artifact bytes were changed).
func overwriteAppleManifestField(t *testing.T, bundleDir, field, value string) {
	t.Helper()
	overwriteManifestField(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.staging-manifest.json"), field, value)
}

// overwriteManifestField loads the staging-manifest JSON at path, sets one
// top-level field to value (or deletes it, if value is empty), and writes
// it back.
func overwriteManifestField(t *testing.T, path, field, value string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if value == "" {
		delete(m, field)
	} else {
		m[field] = value
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, repoRoot, message string) {
	t.Helper()
	cmd := exec.Command("git", "add", "-A")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-q", "-m", message)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

func commitRemoval(t *testing.T, repoRoot, path string) {
	t.Helper()
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "rm", "-q", rel)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git rm: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-q", "-m", "remove apple deployment-target pin")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}
