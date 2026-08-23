package releasebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Assemble reads the Apple and Android staging manifests already written
// into bundleDir by clients/native/build-apple-xcframework.sh and
// clients/native/build-android-aar.sh, independently re-verifies every
// claim they make against the actual staged files and the repoRoot git
// checkout, and returns one deterministic ReleaseCacheManifest.
//
// Assemble never trusts a staging manifest's self-reported hash, path, or
// architecture list: every hash is recomputed from the file on disk, every
// architecture/ABI claim is checked against the actual archive contents,
// and every source-revision/pin claim is checked against repoRoot's real
// git state and tracked pin files. Any mismatch fails closed with no
// manifest produced.
func Assemble(bundleDir, repoRoot string) (*ReleaseCacheManifest, error) {
	return assemble(bundleDir, repoRoot, inspectAppleMacOSSliceDeploymentTarget)
}

type appleDeploymentTargetInspector func(string) ([]string, error)

func assemble(bundleDir, repoRoot string, inspectDeploymentTarget appleDeploymentTargetInspector) (*ReleaseCacheManifest, error) {
	apple, err := loadStagingManifest(bundleDir, ArtifactKindAppleXCFramework)
	if err != nil {
		return nil, err
	}
	android, err := loadStagingManifest(bundleDir, ArtifactKindAndroidAAR)
	if err != nil {
		return nil, err
	}

	if err := verifyManifestHashes(bundleDir, apple); err != nil {
		return nil, err
	}
	if err := verifyManifestHashes(bundleDir, android); err != nil {
		return nil, err
	}

	if apple.AresCoreSourceRevision != android.AresCoreSourceRevision {
		return nil, fmt.Errorf("ares_core_source_revision mismatch between platform artifacts: apple=%s android=%s", apple.AresCoreSourceRevision, android.AresCoreSourceRevision)
	}
	if apple.OpenFHEVersion != android.OpenFHEVersion {
		return nil, fmt.Errorf("openfhe_version mismatch between platform artifacts: apple=%s android=%s", apple.OpenFHEVersion, android.OpenFHEVersion)
	}
	if apple.OpenFHESourceCommit != android.OpenFHESourceCommit {
		return nil, fmt.Errorf("openfhe_source_commit mismatch between platform artifacts: apple=%s android=%s", apple.OpenFHESourceCommit, android.OpenFHESourceCommit)
	}

	if err := verifyAgainstOpenFHEPin(repoRoot, apple); err != nil {
		return nil, err
	}
	if err := verifyAndroidNDKPinPresent(repoRoot); err != nil {
		return nil, err
	}
	if err := verifyCleanSourceRevision(repoRoot, apple.AresCoreSourceRevision); err != nil {
		return nil, err
	}

	if err := requireAllArchitectures("apple xcframework", RequiredApplePlatforms, apple.TargetArchitectures); err != nil {
		return nil, err
	}
	if err := requireAllArchitectures("android aar", RequiredAndroidABIs, android.TargetArchitectures); err != nil {
		return nil, err
	}

	appleArtifactPath := filepath.Join(bundleDir, filepath.Base(apple.ArtifactPath))
	if err := checkAppleXCFrameworkContents(appleArtifactPath, RequiredApplePlatforms); err != nil {
		return nil, err
	}
	if err := verifyAppleDeploymentTarget(bundleDir, repoRoot, apple, appleArtifactPath, inspectDeploymentTarget); err != nil {
		return nil, err
	}
	androidArtifactPath := filepath.Join(bundleDir, filepath.Base(android.ArtifactPath))
	if err := checkAndroidAARContents(androidArtifactPath, RequiredAndroidABIs); err != nil {
		return nil, err
	}

	swiftManifestSHA256, err := verifySwiftReleaseManifest(repoRoot)
	if err != nil {
		return nil, err
	}

	return &ReleaseCacheManifest{
		SchemaVersion:              1,
		AresCoreSourceRevision:     apple.AresCoreSourceRevision,
		OpenFHEVersion:             apple.OpenFHEVersion,
		OpenFHESourceCommit:        apple.OpenFHESourceCommit,
		Apple:                      toArtifactRef(apple),
		Android:                    toArtifactRef(android),
		SwiftReleaseManifestSHA256: swiftManifestSHA256,
		GeneratedAt:                time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// WriteManifest serializes m to path as indented, newline-terminated JSON.
func WriteManifest(path string, m *ReleaseCacheManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding release-cache manifest: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("writing release-cache manifest to %s: %w", path, err)
	}
	return nil
}

func toArtifactRef(m *ArtifactManifest) ArtifactRef {
	return ArtifactRef{
		ArtifactKind:               m.ArtifactKind,
		ArtifactFile:               filepath.Base(m.ArtifactPath),
		ArtifactSHA256:             m.ArtifactSHA256,
		TargetArchitectures:        m.TargetArchitectures,
		SBOMFile:                   filepath.Base(m.SBOMPath),
		SBOMSHA256:                 m.SBOMSHA256,
		ProvenanceFile:             filepath.Base(m.ProvenancePath),
		ProvenanceSHA256:           m.ProvenanceSHA256,
		AppleMACOSDeploymentTarget: m.AppleMACOSDeploymentTarget,
	}
}

// loadStagingManifest scans bundleDir for exactly one *.staging-manifest.json
// whose artifact_kind equals kind. It fails closed on zero or more than one
// match: an absent or ambiguous platform artifact is never silently
// skipped.
func loadStagingManifest(bundleDir, kind string) (*ArtifactManifest, error) {
	entries, err := os.ReadDir(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("reading bundle directory %s: %w", bundleDir, err)
	}

	var matches []*ArtifactManifest
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".staging-manifest.json") {
			continue
		}
		path := filepath.Join(bundleDir, entry.Name())
		raw, err := readRegularFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading staging manifest %s: %w", path, err)
		}
		var m ArtifactManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("parsing staging manifest %s: %w", path, err)
		}
		if m.ArtifactKind == kind {
			matches = append(matches, &m)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("bundle directory %s has no staging manifest with artifact_kind %q", bundleDir, kind)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("bundle directory %s has %d staging manifests with artifact_kind %q, expected exactly 1", bundleDir, len(matches), kind)
	}
	return matches[0], nil
}

// verifyManifestHashes recomputes the SHA-256 of the artifact, SBOM, and
// provenance files a staging manifest references (resolved by basename
// inside bundleDir, never by the manifest's own recorded absolute path)
// and fails closed on any mismatch against the manifest's claimed hash.
func verifyManifestHashes(bundleDir string, m *ArtifactManifest) error {
	checks := []struct {
		label    string
		filename string
		want     string
	}{
		{"artifact", filepath.Base(m.ArtifactPath), m.ArtifactSHA256},
		{"sbom", filepath.Base(m.SBOMPath), m.SBOMSHA256},
		{"provenance", filepath.Base(m.ProvenancePath), m.ProvenanceSHA256},
	}
	for _, c := range checks {
		path := filepath.Join(bundleDir, c.filename)
		got, err := sha256OfPath(path)
		if err != nil {
			return fmt.Errorf("hashing %s file %s: %w", c.label, path, err)
		}
		if got != c.want {
			return fmt.Errorf("%s file %s sha256 mismatch: manifest claims %s, actual %s", c.label, path, c.want, got)
		}
	}
	return nil
}

func sha256OfPath(path string) (string, error) {
	raw, err := readRegularFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// requireAllArchitectures fails closed if any entry in required is absent
// from actual.
func requireAllArchitectures(label string, required, actual []string) error {
	present := make(map[string]bool, len(actual))
	for _, a := range actual {
		present[a] = true
	}
	var missing []string
	for _, r := range required {
		if !present[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s: missing required architecture(s)/ABI(s) %v (staged: %v)", label, missing, actual)
	}
	return nil
}

type pinFile struct {
	OpenFHEVersion            string `json:"openfhe_version"`
	OpenFHESourceCommit       string `json:"openfhe_source_commit"`
	AndroidNDKMinMajorVersion string `json:"android_ndk_min_major_version"`
}

// verifyAgainstOpenFHEPin fails closed unless the artifact's openfhe_version
// and openfhe_source_commit exactly match repoRoot's currently-tracked
// clients/native/openfhe.pin.json. This catches assembling a bundle from
// artifacts that were staged against a since-rotated pin.
func verifyAgainstOpenFHEPin(repoRoot string, m *ArtifactManifest) error {
	pinPath := filepath.Join(repoRoot, "clients", "native", "openfhe.pin.json")
	raw, err := readRegularFile(pinPath)
	if err != nil {
		return fmt.Errorf("reading tracked OpenFHE pin %s: %w", pinPath, err)
	}
	var pin pinFile
	if err := json.Unmarshal(raw, &pin); err != nil {
		return fmt.Errorf("parsing tracked OpenFHE pin %s: %w", pinPath, err)
	}
	if pin.OpenFHEVersion == "" || pin.OpenFHESourceCommit == "" {
		return fmt.Errorf("tracked OpenFHE pin %s is missing openfhe_version or openfhe_source_commit", pinPath)
	}
	if m.OpenFHEVersion != pin.OpenFHEVersion || m.OpenFHESourceCommit != pin.OpenFHESourceCommit {
		return fmt.Errorf("artifact OpenFHE pin (%s @ %s) does not match tracked pin %s (%s @ %s); artifact was staged against a different pin than the one currently checked in", m.OpenFHEVersion, m.OpenFHESourceCommit, pinPath, pin.OpenFHEVersion, pin.OpenFHESourceCommit)
	}
	return nil
}

// verifyAndroidNDKPinPresent fails closed unless repoRoot's tracked
// clients/native/android-ndk.pin.json exists and declares a nonempty
// minimum NDK major version. The native build scripts do not currently
// record which exact NDK build produced a given artifact anywhere in the
// staging manifest, so this is the strongest NDK-provenance assertion
// available without modifying those scripts: the release this bundle
// belongs to is governed by a present, well-formed NDK pin, not an absent
// or unpinned one.
func verifyAndroidNDKPinPresent(repoRoot string) error {
	pinPath := filepath.Join(repoRoot, "clients", "native", "android-ndk.pin.json")
	raw, err := readRegularFile(pinPath)
	if err != nil {
		return fmt.Errorf("reading tracked Android NDK pin %s: %w", pinPath, err)
	}
	var pin pinFile
	if err := json.Unmarshal(raw, &pin); err != nil {
		return fmt.Errorf("parsing tracked Android NDK pin %s: %w", pinPath, err)
	}
	if pin.AndroidNDKMinMajorVersion == "" {
		return fmt.Errorf("tracked Android NDK pin %s is missing android_ndk_min_major_version", pinPath)
	}
	return nil
}

// verifyCleanSourceRevision fails closed unless repoRoot is a git checkout
// with no uncommitted changes whose current HEAD exactly equals
// wantRevision. This is the "clean-cache" guarantee: a release bundle can
// only be assembled from artifacts whose recorded source revision matches
// exactly what is currently checked out, not a stale or locally-modified
// tree.
func verifyCleanSourceRevision(repoRoot, wantRevision string) error {
	head, err := runGitCapture(repoRoot, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return fmt.Errorf("%s is not a git checkout with a HEAD commit: %w", repoRoot, err)
	}
	head = strings.TrimSpace(head)
	if head != wantRevision {
		return fmt.Errorf("repo root %s is at revision %s, but staged artifacts record ares_core_source_revision %s", repoRoot, head, wantRevision)
	}

	status, err := runGitCapture(repoRoot, "status", "--porcelain")
	if err != nil {
		return fmt.Errorf("checking git status of %s: %w", repoRoot, err)
	}
	if strings.TrimSpace(status) != "" {
		return fmt.Errorf("repo root %s has uncommitted changes; a release bundle cannot be assembled from a dirty checkout", repoRoot)
	}
	return nil
}

// verifySwiftReleaseManifest reads and checks
// clients/swift/Package.release.swift and returns its SHA-256.
func verifySwiftReleaseManifest(repoRoot string) (string, error) {
	path := filepath.Join(repoRoot, "clients", "swift", "Package.release.swift")
	raw, err := readRegularFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	if err := checkSwiftReleaseManifest(string(raw)); err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// readRegularFile rejects symlinks and every non-regular file before reading
// release evidence. A release bundle must be self-contained: following a
// filesystem reference outside the reviewed staging or source tree would make
// the checked path and the actually consumed bytes diverge.
func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink is not permitted")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected a regular file, got mode %s", info.Mode())
	}
	return os.ReadFile(path)
}

func runGitCapture(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
