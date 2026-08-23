package native_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const applePinnedVersion = "v1.5.1"

func appleScriptPath(t *testing.T) string {
	t.Helper()
	productionScript := appleProductionScriptPath(t)
	harness := filepath.Join(t.TempDir(), "build-apple-xcframework-test-harness.sh")
	body := `#!/usr/bin/env bash
set -euo pipefail
source "` + productionScript + `"
sw_vers_path="$(command -v sw_vers || true)"
otool_path="$(command -v otool || true)"
run_apple_xcframework_build "${sw_vers_path}" "${otool_path}" "$@"
`
	if err := os.WriteFile(harness, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return harness
}

func appleProductionScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "clients", "native", "build-apple-xcframework.sh")
}

func currentRepoRevision(t *testing.T) string {
	t.Helper()
	out := runGitOutput(t, repoRoot(t), "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

type runResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func runScript(t *testing.T, script string, args []string, path string, extraEnv map[string]string) runResult {
	t.Helper()
	cmd := exec.Command(script, args...)
	env := []string{"PATH=" + path, "HOME=" + os.Getenv("HOME")}
	for k, v := range extraEnv {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("running %s: %v", script, err)
		}
	}
	return runResult{exitCode: code, stdout: stdout.String(), stderr: stderr.String()}
}

// fullApplePath returns a mock PATH with every required toolchain present
// and succeeding (cmake, xcodebuild, libtool, otool, sw_vers all mocked to
// succeed, with mockOtoolScript/mockSwVersScript defaulting to values that
// satisfy the real, tracked apple-deployment-target.pin.json of 14.0).
func fullApplePath(t *testing.T) string {
	t.Helper()
	return newMockPath(t, map[string]string{
		"cmake":      mockCMakeScript,
		"xcodebuild": mockXcodebuildScript,
		"libtool":    mockLibtoolScript,
		"otool":      mockOtoolScript,
		"sw_vers":    mockSwVersScript,
	})
}

func TestAppleXCFrameworkRejectsMissingOutputDirArgument(t *testing.T) {
	res := runScript(t, appleScriptPath(t), nil, fullApplePath(t), nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0; stderr=%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "output directory argument is required") {
		t.Fatalf("expected missing-output-dir message, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkRejectsOutputDirInsideRepo(t *testing.T) {
	inside := filepath.Join(repoRoot(t), "tmp-native-test-output")
	defer os.RemoveAll(inside)
	res := runScript(t, appleScriptPath(t), []string{inside}, fullApplePath(t), nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0; stderr=%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "inside the repository") {
		t.Fatalf("expected inside-repository rejection, got stderr=%s", res.stderr)
	}
	if _, err := os.Stat(inside); err == nil {
		t.Fatal("rejected output directory must not be left behind inside the repository")
	}
}

func TestAppleXCFrameworkFailsClosedWithoutCMake(t *testing.T) {
	path := newMockPath(t, map[string]string{
		"xcodebuild": mockXcodebuildScript,
		"libtool":    mockLibtoolScript,
		"otool":      mockOtoolScript,
		"sw_vers":    mockSwVersScript,
	})
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, path, nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "cmake") {
		t.Fatalf("expected a cmake-related failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedWithoutXcodebuild(t *testing.T) {
	path := newMockPath(t, map[string]string{
		"cmake":   mockCMakeScript,
		"libtool": mockLibtoolScript,
		"otool":   mockOtoolScript,
		"sw_vers": mockSwVersScript,
	})
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, path, nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "xcodebuild") {
		t.Fatalf("expected an xcodebuild-related failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnSourceCommitMismatch(t *testing.T) {
	// The fake repo's tag resolves to some locally-generated commit, but we
	// deliberately do NOT override the pin file, so the real, committed
	// pin's expected commit (the actual upstream OpenFHE v1.5.1 revision)
	// is what gets checked -- a real, not synthetic, mismatch.
	url, fakeCommit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "revision mismatch") {
		t.Fatalf("expected a revision mismatch failure, got stderr=%s", res.stderr)
	}
	if strings.Contains(res.stderr, fakeCommit) == false {
		t.Fatalf("expected the mismatch message to name the actual cloned commit %s, got: %s", fakeCommit, res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnMissingRequiredPlatform(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		"MOCK_CMAKE_FAIL_PREFIX_SUBSTRING":    "ios-arm64-simulator",
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit when one required platform's build fails, got 0")
	}
	manifest := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-apple.staging-manifest.json")
	if _, err := os.Stat(manifest); err == nil {
		t.Fatal("no staging manifest must be produced when a required platform's build fails")
	}
}

func TestAppleXCFrameworkProducesDeterministicStagingManifest(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	beforeStatus := runGitOutput(t, repoRoot(t), "status", "--porcelain")
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
	})
	if res.exitCode != 0 {
		t.Fatalf("expected success, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}

	manifestPath := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-apple.staging-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, raw)
	}

	if got := m["artifact_kind"]; got != "apple_xcframework" {
		t.Fatalf("artifact_kind = %v, want apple_xcframework", got)
	}
	if got := m["openfhe_version"]; got != applePinnedVersion {
		t.Fatalf("openfhe_version = %v, want %s", got, applePinnedVersion)
	}
	if got := m["openfhe_source_commit"]; got != commit {
		t.Fatalf("openfhe_source_commit = %v, want %s", got, commit)
	}
	wantRev := currentRepoRevision(t)
	if got := m["ares_core_source_revision"]; got != wantRev {
		t.Fatalf("ares_core_source_revision = %v, want %s", got, wantRev)
	}

	targets, ok := m["target_architectures"].([]any)
	if !ok {
		t.Fatalf("target_architectures missing or wrong type: %v", m["target_architectures"])
	}
	wantTargets := []string{"ios-arm64", "ios-arm64-simulator", "macos-arm64"}
	if len(targets) != len(wantTargets) {
		t.Fatalf("target_architectures = %v, want %v", targets, wantTargets)
	}
	for i, want := range wantTargets {
		if targets[i] != want {
			t.Fatalf("target_architectures[%d] = %v, want %s", i, targets[i], want)
		}
	}

	assertPathHashMatches(t, m, "artifact_path", "artifact_sha256")
	assertPathHashMatches(t, m, "sbom_path", "sbom_sha256")
	assertPathHashMatches(t, m, "provenance_path", "provenance_sha256")

	afterStatus := runGitOutput(t, repoRoot(t), "status", "--porcelain")
	if afterStatus != beforeStatus {
		t.Fatalf("script left new/changed files inside the repository worktree:\nbefore:\n%s\nafter:\n%s", beforeStatus, afterStatus)
	}
}

func TestAppleXCFrameworkStagesCanonicalBridgeModule(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
	})
	if res.exitCode != 0 {
		t.Fatalf("expected success, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}

	artifact := filepath.Join(out, "AresPrivacyCore-"+applePinnedVersion+"-apple.xcframework.zip")
	assertZipContainsEntries(t, artifact, []string{
		"AresPrivacyCore.xcframework/ios-arm64/libAresPrivacyCore.a",
		"AresPrivacyCore.xcframework/ios-arm64/Headers/openfhe_wrapper.h",
		"AresPrivacyCore.xcframework/ios-arm64/Headers/module.modulemap",
		"AresPrivacyCore.xcframework/ios-arm64-simulator/libAresPrivacyCore.a",
		"AresPrivacyCore.xcframework/ios-arm64-simulator/Headers/openfhe_wrapper.h",
		"AresPrivacyCore.xcframework/ios-arm64-simulator/Headers/module.modulemap",
		"AresPrivacyCore.xcframework/macos-arm64/libAresPrivacyCore.a",
		"AresPrivacyCore.xcframework/macos-arm64/Headers/openfhe_wrapper.h",
		"AresPrivacyCore.xcframework/macos-arm64/Headers/module.modulemap",
	})
}

func assertPathHashMatches(t *testing.T, m map[string]any, pathKey, hashKey string) {
	t.Helper()
	path, _ := m[pathKey].(string)
	if path == "" {
		t.Fatalf("%s missing from manifest", pathKey)
	}
	wantHash, _ := m[hashKey].(string)
	if wantHash == "" {
		t.Fatalf("%s missing from manifest", hashKey)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (%s): %v", pathKey, path, err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != wantHash {
		t.Fatalf("%s sha256 = %s, manifest %s = %s", pathKey, got, hashKey, wantHash)
	}
}
