package native_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAppleXCFrameworkFailsClosedWithoutSwVers(t *testing.T) {
	path := newMockPath(t, map[string]string{
		"cmake":      mockCMakeScript,
		"xcodebuild": mockXcodebuildScript,
		"libtool":    mockLibtoolScript,
		"otool":      mockOtoolScript,
	})
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, path, nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "sw_vers") {
		t.Fatalf("expected an sw_vers-related failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedWithoutOtool(t *testing.T) {
	path := newMockPath(t, map[string]string{
		"cmake":      mockCMakeScript,
		"xcodebuild": mockXcodebuildScript,
		"libtool":    mockLibtoolScript,
		"sw_vers":    mockSwVersScript,
	})
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, path, nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "otool") {
		t.Fatalf("expected an otool-related failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkNormalModeIgnoresPATHShadowedAppleTools(t *testing.T) {
	productionScript := appleProductionScriptPath(t)
	raw, err := os.ReadFile(productionScript)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`readonly TRUSTED_SW_VERS_PATH="/usr/bin/sw_vers"`,
		`readonly TRUSTED_OTOOL_PATH="/usr/bin/otool"`,
		`run_apple_xcframework_build "${TRUSTED_SW_VERS_PATH}" "${TRUSTED_OTOOL_PATH}" "$@"`,
	} {
		if !strings.Contains(string(raw), required) {
			t.Errorf("normal producer omits fixed trusted-tool boundary %q", required)
		}
	}

	markerDir := t.TempDir()
	swVersMarker := filepath.Join(markerDir, "sw-vers-invoked")
	otoolMarker := filepath.Join(markerDir, "otool-invoked")
	path := newMockPath(t, map[string]string{
		"cmake":      mockCMakeScript,
		"xcodebuild": mockXcodebuildScript,
		"libtool":    mockLibtoolScript,
		"sw_vers": `#!/bin/sh
set -eu
: > "${SHADOW_SW_VERS_MARKER}"
printf '%s\n' '99.0'
`,
		"otool": `#!/bin/sh
set -eu
: > "${SHADOW_OTOOL_MARKER}"
printf '%s\n' '    minos 14.0'
`,
	})

	res := runScript(t, productionScript, nil, path, map[string]string{
		"SHADOW_SW_VERS_MARKER": swVersMarker,
		"SHADOW_OTOOL_MARKER":   otoolMarker,
	})
	if res.exitCode == 0 {
		t.Fatalf("PATH-shadowed Apple tools made the normal producer succeed: stdout=%s stderr=%s", res.stdout, res.stderr)
	}
	for tool, marker := range map[string]string{"sw_vers": swVersMarker, "otool": otoolMarker} {
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("normal producer invoked PATH-shadowed %s", tool)
		} else if !os.IsNotExist(err) {
			t.Fatalf("checking %s marker: %v", tool, err)
		}
	}
	wantFailure := "output directory argument is required"
	if runtime.GOOS != "darwin" {
		wantFailure = "requires Darwin"
	}
	if !strings.Contains(res.stderr, wantFailure) {
		t.Fatalf("normal producer did not reach the expected pre-build failure through trusted tools: stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnMissingDeploymentTargetPin(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":                             "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL":               url,
		"ARES_NATIVE_TEST_PIN_FILE":                         pin,
		"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "deployment-target pin file not found") {
		t.Fatalf("expected a missing-pin-file failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnMalformedDeploymentTargetPin(t *testing.T) {
	for _, malformed := range []string{
		"", "14", "abc", "14.x", "014.0", "14.00", "14.0.1",
		"+14.0", "-14.0", " 14.0", "14.0 ", ".0", "14.", "14..0",
	} {
		t.Run(malformed, func(t *testing.T) {
			url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
			pin := writeTestPin(t, applePinnedVersion, url, commit)
			deploymentPin := writeTestAppleDeploymentTargetPin(t, malformed)
			out := t.TempDir()
			res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
				"ARES_NATIVE_TEST_MODE":                             "1",
				"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL":               url,
				"ARES_NATIVE_TEST_PIN_FILE":                         pin,
				"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": deploymentPin,
			})
			if res.exitCode == 0 {
				t.Fatalf("expected nonzero exit for malformed target %q, got 0", malformed)
			}
			if !strings.Contains(res.stderr, "macos_minimum_deployment_target") {
				t.Fatalf("expected a macos_minimum_deployment_target-related failure, got stderr=%s", res.stderr)
			}
			if strings.Contains(res.stderr, "cloning pinned OpenFHE") {
				t.Fatalf("malformed deployment target %q reached source cloning instead of failing at the producer boundary", malformed)
			}
		})
	}
}

func TestAppleXCFrameworkFailsClosedOnHostNewerDeploymentTarget(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	// Pin a deployment target newer than the (mocked) host's reported
	// macOS version: the host cannot meaningfully build or validate
	// against a target newer than itself.
	deploymentPin := writeTestAppleDeploymentTargetPin(t, "20.0")
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":                             "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL":               url,
		"ARES_NATIVE_TEST_PIN_FILE":                         pin,
		"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": deploymentPin,
		"MOCK_SW_VERS_PRODUCT_VERSION":                      "15.0",
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "newer than the host macOS version") {
		t.Fatalf("expected a host-newer rejection, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnRealMachOMismatch(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		// Pin (and mocked host) accept 14.0, but the mocked otool reports
		// that the built library actually links against 15.0 -- exactly
		// the class of real-world drift (a flag that did not propagate to
		// every translation unit) this inspection step exists to catch.
		"MOCK_OTOOL_MINOS": "15.0",
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "Mach-O deployment target mismatch") {
		t.Fatalf("expected a Mach-O deployment-target mismatch failure, got stderr=%s", res.stderr)
	}
	manifest := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-apple.staging-manifest.json")
	if _, err := os.Stat(manifest); err == nil {
		t.Fatal("no staging manifest must be produced when real Mach-O inspection finds a mismatch")
	}
}

func TestAppleXCFrameworkPropagatesDeploymentTargetIntoManifest(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	deploymentPin := writeTestAppleDeploymentTargetPin(t, "13.5")
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":                             "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL":               url,
		"ARES_NATIVE_TEST_PIN_FILE":                         pin,
		"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": deploymentPin,
		"MOCK_OTOOL_MINOS":                                  "13.5",
		"MOCK_CMAKE_EXPECT_MACOS_DEPLOYMENT_TARGET":         "13.5",
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
	if got := m["apple_macos_deployment_target"]; got != "13.5" {
		t.Fatalf("apple_macos_deployment_target = %v, want 13.5", got)
	}
}
