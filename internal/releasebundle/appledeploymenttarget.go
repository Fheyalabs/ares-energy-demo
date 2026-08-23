package releasebundle

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	canonicalAppleMacOSLibraryMember = "AresPrivacyCore.xcframework/macos-arm64/libAresPrivacyCore.a"
	trustedSystemOtoolPath           = "/usr/bin/otool"
)

// appleDeploymentTargetPinFile mirrors clients/native/apple-deployment-target.pin.json's
// single tracked field: the declared minimum macOS deployment target every
// staged Apple XCFramework's macos-arm64 slice must exactly match.
type appleDeploymentTargetPinFile struct {
	MACOSMinimumDeploymentTarget string `json:"macos_minimum_deployment_target"`
}

// readDeclaredAppleDeploymentTarget reads and validates repoRoot's tracked
// clients/native/apple-deployment-target.pin.json, the sole source of
// truth for what macOS deployment target this repository currently
// declares as supported.
func readDeclaredAppleDeploymentTarget(repoRoot string) (string, error) {
	path := filepath.Join(repoRoot, "clients", "native", "apple-deployment-target.pin.json")
	raw, err := readRegularFile(path)
	if err != nil {
		return "", fmt.Errorf("reading tracked Apple deployment-target pin %s: %w", path, err)
	}
	var pin appleDeploymentTargetPinFile
	if err := json.Unmarshal(raw, &pin); err != nil {
		return "", fmt.Errorf("parsing tracked Apple deployment-target pin %s: %w", path, err)
	}
	if err := validateAppleVersionFormat(pin.MACOSMinimumDeploymentTarget); err != nil {
		return "", fmt.Errorf("tracked Apple deployment-target pin %s has an invalid macos_minimum_deployment_target: %w", path, err)
	}
	return pin.MACOSMinimumDeploymentTarget, nil
}

var appleVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// validateAppleVersionFormat fails closed unless value is a well-formed
// canonical MAJOR.MINOR version string. Empty values, missing components,
// non-numeric values, and leading zeroes are rejected rather than normalized.
func validateAppleVersionFormat(value string) error {
	if value == "" {
		return fmt.Errorf("value is empty (want MAJOR.MINOR)")
	}
	if !appleVersionPattern.MatchString(value) {
		return fmt.Errorf("value %q is not a canonical MAJOR.MINOR version", value)
	}
	return nil
}

// verifyAppleDeploymentTarget fails closed unless the Apple artifact's
// recorded macos_minimum_deployment_target is present, well-formed, and an
// exact match for repoRoot's currently tracked declared target. It extracts
// the macos-arm64 slice's combined static library from the real staged archive and
// inspects its actual Mach-O LC_BUILD_VERSION/LC_VERSION_MIN_MACOSX minos
// values, rejecting the bundle if any differ from the declared target --
// producer metadata alone is never sufficient.
func verifyAppleDeploymentTarget(bundleDir, repoRoot string, apple *ArtifactManifest, artifactPath string, inspectDeploymentTarget appleDeploymentTargetInspector) error {
	if err := validateAppleVersionFormat(apple.AppleMACOSDeploymentTarget); err != nil {
		return fmt.Errorf("apple artifact staging manifest has an invalid apple_macos_deployment_target: %w", err)
	}
	declared, err := readDeclaredAppleDeploymentTarget(repoRoot)
	if err != nil {
		return err
	}
	if apple.AppleMACOSDeploymentTarget != declared {
		return fmt.Errorf("apple artifact's recorded macOS deployment target %s does not exactly match the declared supported target %s",
			apple.AppleMACOSDeploymentTarget, declared)
	}

	inspectedMinOS, err := inspectDeploymentTarget(artifactPath)
	if err != nil {
		return fmt.Errorf("inspecting real Mach-O deployment target metadata in %s: %w", artifactPath, err)
	}
	for _, value := range inspectedMinOS {
		if err := validateAppleVersionFormat(value); err != nil {
			return fmt.Errorf("apple artifact %s: inspected Mach-O minos value is malformed: %w", artifactPath, err)
		}
		if value != declared {
			return fmt.Errorf("apple artifact %s: inspected Mach-O minimum macOS %s does not exactly match the declared supported target %s",
				artifactPath, value, declared)
		}
	}
	return nil
}

// inspectAppleMacOSSliceDeploymentTarget extracts the canonical macos-arm64
// library member from the staged xcframework zip and runs the real `otool -l`
// against it, returning every LC_BUILD_VERSION/
// LC_VERSION_MIN_MACOSX "minos" value found. It fails closed when otool is
// unavailable or the archive member is not a real Mach-O object.
func inspectAppleMacOSSliceDeploymentTarget(artifactPath string) ([]string, error) {
	otoolPath, err := verifiedSystemOtoolPath()
	if err != nil {
		return nil, err
	}
	return inspectAppleMacOSSliceDeploymentTargetWithRunner(artifactPath, func(extractedPath string) ([]byte, error) {
		out, err := exec.Command(otoolPath, "-l", extractedPath).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s -l failed: %w (%s)", otoolPath, err, string(out))
		}
		if strings.Contains(string(out), "is not an object file") {
			return nil, fmt.Errorf("trusted %s rejected the extracted member as non-Mach-O", otoolPath)
		}
		return out, nil
	})
}

func verifiedSystemOtoolPath() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("Mach-O deployment-target inspection requires Darwin and trusted %s (runtime is %s)", trustedSystemOtoolPath, runtime.GOOS)
	}
	if !filepath.IsAbs(trustedSystemOtoolPath) || filepath.Clean(trustedSystemOtoolPath) != trustedSystemOtoolPath {
		return "", fmt.Errorf("trusted otool path is not canonical and absolute: %s", trustedSystemOtoolPath)
	}
	info, err := os.Lstat(trustedSystemOtoolPath)
	if err != nil {
		return "", fmt.Errorf("trusted system otool is unavailable at %s: %w", trustedSystemOtoolPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("trusted system otool path %s is not a regular executable", trustedSystemOtoolPath)
	}
	return trustedSystemOtoolPath, nil
}

type otoolRunner func(string) ([]byte, error)

func inspectAppleMacOSSliceDeploymentTargetWithRunner(artifactPath string, runOtool otoolRunner) ([]string, error) {

	r, err := zip.OpenReader(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("opening apple artifact as zip: %w", err)
	}
	defer r.Close()
	if err := validateZIPMemberNames(r.File); err != nil {
		return nil, fmt.Errorf("apple artifact %s: %w", artifactPath, err)
	}

	var matches []*zip.File
	for _, f := range r.File {
		if f.Name == canonicalAppleMacOSLibraryMember {
			matches = append(matches, f)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("canonical macOS library member %s is missing from %s", canonicalAppleMacOSLibraryMember, artifactPath)
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("duplicate canonical macOS library member %s appears %d times in %s", canonicalAppleMacOSLibraryMember, len(matches), artifactPath)
	}
	member := matches[0]

	rc, err := member.Open()
	if err != nil {
		return nil, fmt.Errorf("opening archive member %s: %w", member.Name, err)
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "ares-macos-slice-*.a")
	if err != nil {
		return nil, fmt.Errorf("creating temp file for Mach-O inspection: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("extracting %s for Mach-O inspection: %w", member.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing extracted Mach-O temp file: %w", err)
	}

	out, err := runOtool(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("otool -l failed on extracted %s: %w", member.Name, err)
	}
	var values []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "minos" {
			values = append(values, fields[1])
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no LC_BUILD_VERSION/LC_VERSION_MIN_MACOSX minos load command found in %s", member.Name)
	}
	return values, nil
}
