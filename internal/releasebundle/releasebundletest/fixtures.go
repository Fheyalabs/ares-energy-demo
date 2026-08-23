// Package releasebundletest builds fixture release bundles (a staged
// Apple/Android artifact directory plus a matching fixture git repo root)
// shared by internal/releasebundle's own tests and
// cmd/release-artifact-gate's end-to-end subprocess test. It is a normal,
// exported package (not a _test.go file) precisely so both can import it
// without duplicating fixture-construction logic.
package releasebundletest

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Fheyalabs/ares-core/internal/releasebundle"
)

const (
	OpenFHEVersion = "v1.5.1"
	OpenFHECommit  = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"

	// AppleMACOSDeploymentTarget is the fixture repo's declared macOS
	// deployment target and the default value NewBundle's Apple staging
	// manifest records -- both must agree for the zero-value Opts to
	// build a gate-accepted bundle.
	AppleMACOSDeploymentTarget  = "14.0"
	appleMachOMinosMarker       = "ARES_RELEASEBUNDLE_TEST_MINOS="
	canonicalMacOSLibraryMember = "AresPrivacyCore.xcframework/macos-arm64/libAresPrivacyCore.a"

	ValidSwiftReleaseManifest = `// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AresClient",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "AresClient", targets: ["AresClient"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .binaryTarget(name: "COpenFHEBridge", path: "Artifacts/AresPrivacyCore.xcframework"),
    ]
)
`
)

// Opts controls what NewBundle builds, so mutation tests can request a
// deliberately broken fixture instead of hand-corrupting zip bytes after
// the fact. The zero value builds a complete, valid, gate-accepted bundle.
type Opts struct {
	AppleSlices                         []string
	AndroidABIs                         []string
	AndroidLibsOverride                 map[string][]string // abi -> lib list; overrides the default full set for that ABI only
	AresRevOverride                     string              // if set, used for BOTH platform manifests instead of the fixture repo's real HEAD
	AndroidAresRevOverride              string              // if set, used only for the android manifest (creates a cross-platform mismatch)
	AndroidOpenFHEVersionOverride       string              // if set, used only for the android manifest
	SwiftManifestOverride               string              // if set, replaces Package.release.swift content
	AppleMACOSDeploymentTargetOverride  string              // if set, used instead of AppleMACOSDeploymentTarget in the Apple manifest
	AppleMachOMinosOverride             string              // if set, encoded in the canonical macOS library for the hermetic otool fixture
	AppleDecoyFirstMachOMinos           string              // if set, adds a matching-looking decoy before the canonical macOS library
	AppleExtraZipMembers                []string            // additional member names used by ZIP-name mutation tests
	AppleNonUTF8ZipMember               string              // additional member whose ZIP NonUTF8 flag is set
	AppleSymlinkZipMember               string              // additional member encoded as a symbolic link
	OmitCanonicalAppleMacOSLibrary      bool                // if set, only headers (and any requested decoy) are staged for macos-arm64
	DuplicateCanonicalAppleMacOSLibrary bool                // if set, writes the exact canonical member twice
}

// NewRepoRoot creates a real, tiny, committed git repository shaped like
// enough of ARES-core for releasebundle to read: the two pin files and
// clients/swift/Package.release.swift. It returns the repo root and the
// exact commit it committed.
func NewRepoRoot(t testing.TB, swiftManifest string) (repoRoot, commit string) {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "releasebundle-test@example.invalid")
	runGit(t, dir, "config", "user.name", "releasebundle-test")

	writeFile(t, filepath.Join(dir, "clients", "native", "openfhe.pin.json"), mustJSON(t, map[string]string{
		"openfhe_version":       OpenFHEVersion,
		"openfhe_source_url":    "https://github.com/openfheorg/openfhe-development.git",
		"openfhe_source_commit": OpenFHECommit,
	}))
	writeFile(t, filepath.Join(dir, "clients", "native", "android-ndk.pin.json"), mustJSON(t, map[string]string{
		"android_ndk_min_major_version": "26",
	}))
	writeFile(t, filepath.Join(dir, "clients", "native", "apple-deployment-target.pin.json"), mustJSON(t, map[string]string{
		"macos_minimum_deployment_target": AppleMACOSDeploymentTarget,
	}))
	writeFile(t, filepath.Join(dir, "clients", "swift", "Package.release.swift"), []byte(swiftManifest))

	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-q", "-m", "fixture repo root")

	out := runGitOutput(t, dir, "rev-parse", "HEAD")
	return dir, trimNewline(out)
}

// NewBundle builds a complete, self-consistent staged bundle directory
// (Apple + Android artifact/sbom/provenance/staging-manifest) and a
// matching fixture repo root, per opts.
func NewBundle(t testing.TB, opts Opts) (bundleDir, repoRoot string) {
	t.Helper()

	swiftManifest := ValidSwiftReleaseManifest
	if opts.SwiftManifestOverride != "" {
		swiftManifest = opts.SwiftManifestOverride
	}
	repoRoot, commit := NewRepoRoot(t, swiftManifest)

	aresRev := commit
	if opts.AresRevOverride != "" {
		aresRev = opts.AresRevOverride
	}
	androidAresRev := aresRev
	if opts.AndroidAresRevOverride != "" {
		androidAresRev = opts.AndroidAresRevOverride
	}
	androidOpenFHEVersion := OpenFHEVersion
	if opts.AndroidOpenFHEVersionOverride != "" {
		androidOpenFHEVersion = opts.AndroidOpenFHEVersionOverride
	}

	appleSlices := opts.AppleSlices
	if appleSlices == nil {
		appleSlices = releasebundle.RequiredApplePlatforms
	}
	androidABIs := opts.AndroidABIs
	if androidABIs == nil {
		androidABIs = releasebundle.RequiredAndroidABIs
	}

	appleMACOSDeploymentTarget := AppleMACOSDeploymentTarget
	if opts.AppleMACOSDeploymentTargetOverride != "" {
		appleMACOSDeploymentTarget = opts.AppleMACOSDeploymentTargetOverride
	}

	bundleDir = t.TempDir()

	writeAppleStagingSet(t, bundleDir, appleSlices, OpenFHEVersion, OpenFHECommit, aresRev, appleMACOSDeploymentTarget, opts)
	writeAndroidStagingSet(t, bundleDir, androidABIs, opts.AndroidLibsOverride, androidOpenFHEVersion, OpenFHECommit, androidAresRev)

	return bundleDir, repoRoot
}

func writeAppleStagingSet(t testing.TB, bundleDir string, slices []string, openfheVersion, openfheCommit, aresRev, macosDeploymentTarget string, opts Opts) {
	t.Helper()

	artifactPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.xcframework.zip")
	buildAppleFixtureZip(t, artifactPath, slices, opts)

	sbomPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.sbom.json")
	writeFile(t, sbomPath, mustJSON(t, map[string]string{"bomFormat": "CycloneDX", "component": "OpenFHE"}))

	provenancePath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.provenance.json")
	writeFile(t, provenancePath, mustJSON(t, map[string]string{"predicateType": "https://slsa.dev/provenance/v1"}))

	manifest := releasebundle.ArtifactManifest{
		SchemaVersion:              1,
		ArtifactKind:               releasebundle.ArtifactKindAppleXCFramework,
		ArtifactPath:               "/original/build/machine/path/" + filepath.Base(artifactPath),
		ArtifactSHA256:             sha256OfFile(t, artifactPath),
		OpenFHEVersion:             openfheVersion,
		OpenFHESourceCommit:        openfheCommit,
		AresCoreSourceRevision:     aresRev,
		TargetArchitectures:        slices,
		SBOMPath:                   sbomPath,
		SBOMSHA256:                 sha256OfFile(t, sbomPath),
		ProvenancePath:             provenancePath,
		ProvenanceSHA256:           sha256OfFile(t, provenancePath),
		GeneratedAt:                "2026-07-19T00:00:00Z",
		AppleMACOSDeploymentTarget: macosDeploymentTarget,
	}
	writeFile(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.staging-manifest.json"), mustJSON(t, manifest))
}

func writeAndroidStagingSet(t testing.TB, bundleDir string, abis []string, libsOverride map[string][]string, openfheVersion, openfheCommit, aresRev string) {
	t.Helper()

	artifactPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.aar")
	buildAndroidFixtureAAR(t, artifactPath, abis, libsOverride)

	sbomPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.sbom.json")
	writeFile(t, sbomPath, mustJSON(t, map[string]string{"bomFormat": "CycloneDX", "component": "OpenFHE"}))

	provenancePath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.provenance.json")
	writeFile(t, provenancePath, mustJSON(t, map[string]string{"predicateType": "https://slsa.dev/provenance/v1"}))

	manifest := releasebundle.ArtifactManifest{
		SchemaVersion:          1,
		ArtifactKind:           releasebundle.ArtifactKindAndroidAAR,
		ArtifactPath:           "/original/build/machine/path/" + filepath.Base(artifactPath),
		ArtifactSHA256:         sha256OfFile(t, artifactPath),
		OpenFHEVersion:         openfheVersion,
		OpenFHESourceCommit:    openfheCommit,
		AresCoreSourceRevision: aresRev,
		TargetArchitectures:    abis,
		SBOMPath:               sbomPath,
		SBOMSHA256:             sha256OfFile(t, sbomPath),
		ProvenancePath:         provenancePath,
		ProvenanceSHA256:       sha256OfFile(t, provenancePath),
		GeneratedAt:            "2026-07-19T00:00:00Z",
	}
	writeFile(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.staging-manifest.json"), mustJSON(t, manifest))
}

// buildAppleFixtureZip writes a zip shaped like a real
// xcodebuild-created AresPrivacyCore.xcframework.zip: one directory per
// requested platform slice, each containing libAresPrivacyCore.a and the
// COpenFHEBridge module headers.
func buildAppleFixtureZip(t testing.TB, path string, slices []string, opts Opts) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	addZipFile(t, zw, "AresPrivacyCore.xcframework/Info.plist", "fake plist")
	if opts.AppleDecoyFirstMachOMinos != "" {
		addZipFile(t, zw, "decoy/macos-arm64/libAresPrivacyCore.a", appleMachOMinosMarker+opts.AppleDecoyFirstMachOMinos+"\n")
	}
	for _, name := range opts.AppleExtraZipMembers {
		addZipFile(t, zw, name, appleMachOMinosMarker+AppleMACOSDeploymentTarget+"\n")
	}
	if opts.AppleNonUTF8ZipMember != "" {
		header := &zip.FileHeader{Name: opts.AppleNonUTF8ZipMember, Method: zip.Store, NonUTF8: true}
		addZipHeader(t, zw, header, []byte("non-UTF-8 marker"))
	}
	if opts.AppleSymlinkZipMember != "" {
		header := &zip.FileHeader{Name: opts.AppleSymlinkZipMember, Method: zip.Store}
		header.SetMode(os.ModeSymlink | 0o777)
		addZipHeader(t, zw, header, []byte("../../outside"))
	}
	macOSMachOMinos := AppleMACOSDeploymentTarget
	if opts.AppleMachOMinosOverride != "" {
		macOSMachOMinos = opts.AppleMachOMinosOverride
	}
	for _, slice := range slices {
		libraryPath := "AresPrivacyCore.xcframework/" + slice + "/libAresPrivacyCore.a"
		if slice == "macos-arm64" {
			if !opts.OmitCanonicalAppleMacOSLibrary {
				addZipFile(t, zw, libraryPath, appleMachOMinosMarker+macOSMachOMinos+"\n")
				if opts.DuplicateCanonicalAppleMacOSLibrary {
					addZipFile(t, zw, libraryPath, appleMachOMinosMarker+macOSMachOMinos+"\n")
				}
			}
		} else {
			addZipFile(t, zw, libraryPath, "fake static lib for "+slice)
		}
		addZipFile(t, zw, "AresPrivacyCore.xcframework/"+slice+"/Headers/openfhe_wrapper.h", "fake header")
		addZipFile(t, zw, "AresPrivacyCore.xcframework/"+slice+"/Headers/module.modulemap", "module COpenFHEBridge { header \"openfhe_wrapper.h\" export * }")
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// InstallPATHShadowOtool puts a marker-reading fake otool first on PATH.
// Adversarial subprocess tests use it to prove the production CLI ignores
// PATH and invokes only the fixed trusted system tool.
func InstallPATHShadowOtool(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "otool")
	script := `#!/bin/sh
set -eu
if [ "$#" -ne 2 ] || [ "$1" != "-l" ]; then
  echo "hermetic otool: expected -l PATH" >&2
  exit 2
fi
IFS= read -r marker < "$2" || true
case "${marker}" in
  ARES_RELEASEBUNDLE_TEST_MINOS=*) minos="${marker#ARES_RELEASEBUNDLE_TEST_MINOS=}" ;;
  *) echo "hermetic otool: extracted member has no minos marker" >&2; exit 3 ;;
esac
printf '%s\n' \
  'Load command 1' \
  '      cmd LC_BUILD_VERSION' \
  '  cmdsize 24' \
  ' platform 1' \
  "    minos ${minos}" \
  '      sdk 26.0' \
  '   ntools 0'
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}

// ReplaceAppleMacOSLibrary rewrites the canonical macOS archive member and
// refreshes the Apple staging manifest hash. It is used only by Darwin-scoped
// production CLI tests that compile a tiny real Mach-O archive.
func ReplaceAppleMacOSLibrary(t testing.TB, bundleDir, libraryPath string) {
	t.Helper()
	artifactPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.xcframework.zip")
	r, err := zip.OpenReader(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	library, err := os.ReadFile(libraryPath)
	if err != nil {
		t.Fatal(err)
	}

	rewritten := artifactPath + ".rewritten"
	out, err := os.Create(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	replaced := 0
	for _, file := range r.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if file.Name == canonicalMacOSLibraryMember {
			content = library
			replaced++
		}
		addZipBytes(t, zw, file.Name, content)
	}
	if replaced != 1 {
		t.Fatalf("replaced %d canonical macOS members, want 1", replaced)
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

	manifestPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.staging-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest releasebundle.ArtifactManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.ArtifactSHA256 = sha256OfFile(t, artifactPath)
	writeFile(t, manifestPath, mustJSON(t, manifest))
}

// buildAndroidFixtureAAR writes a zip shaped like a real
// AresPrivacyCore-<version>-android.aar: AndroidManifest.xml, classes.jar,
// and jni/<abi>/*.so per requested ABI. libsOverride lets a mutation test
// stage an ABI with a missing library instead of the default full set.
func buildAndroidFixtureAAR(t testing.TB, path string, abis []string, libsOverride map[string][]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	addZipFile(t, zw, "AndroidManifest.xml", "<manifest/>")
	addZipFile(t, zw, "classes.jar", "fake jar")
	defaultLibs := []string{"libares_fhe_jni.so", "libOPENFHEcore.so", "libOPENFHEpke.so", "libOPENFHEbinfhe.so"}
	for _, abi := range abis {
		libs := defaultLibs
		if override, ok := libsOverride[abi]; ok {
			libs = override
		}
		for _, lib := range libs {
			addZipFile(t, zw, "jni/"+abi+"/"+lib, "fake shared object for "+abi+"/"+lib)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func addZipFile(t testing.TB, zw *zip.Writer, name, content string) {
	addZipBytes(t, zw, name, []byte(content))
}

func addZipBytes(t testing.TB, zw *zip.Writer, name string, content []byte) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
}

func addZipHeader(t testing.TB, zw *zip.Writer, header *zip.FileHeader, content []byte) {
	t.Helper()
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
}

// TamperFile appends bytes to the file at path, invalidating any
// previously-computed hash of it. Exported so mutation tests in other
// packages (e.g. cmd/release-artifact-gate's end-to-end test) can simulate
// a corrupted/substituted staged artifact without reaching into this
// package's internals.
func TamperFile(t testing.TB, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("tampered")); err != nil {
		t.Fatal(err)
	}
}

func sha256OfFile(t testing.TB, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func writeFile(t testing.TB, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runGit(t testing.TB, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func runGitOutput(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
