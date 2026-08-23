package native_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func androidScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "clients", "native", "build-android-aar.sh")
}

// fullAndroidPath returns a mock PATH with cmake mocked to succeed; the
// Android NDK itself is supplied separately via ANDROID_NDK_HOME, since
// (unlike cmake/xcodebuild/libtool) it is a directory tree, not a single
// command on PATH.
func fullAndroidPath(t *testing.T) string {
	t.Helper()
	return newMockPath(t, map[string]string{
		"cmake": mockCMakeScript,
	})
}

func androidTestEnv(t *testing.T, extra map[string]string) map[string]string {
	t.Helper()
	env := map[string]string{
		"ANDROID_NDK_HOME": newFakeAndroidNDK(t, "27.1.12345678"),
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func TestAndroidAARRejectsMissingOutputDirArgument(t *testing.T) {
	res := runScript(t, androidScriptPath(t), nil, fullAndroidPath(t), androidTestEnv(t, nil))
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0; stderr=%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "output directory argument is required") {
		t.Fatalf("expected missing-output-dir message, got stderr=%s", res.stderr)
	}
}

func TestAndroidAARRejectsOutputDirInsideRepo(t *testing.T) {
	inside := filepath.Join(repoRoot(t), "tmp-native-android-test-output")
	defer os.RemoveAll(inside)
	res := runScript(t, androidScriptPath(t), []string{inside}, fullAndroidPath(t), androidTestEnv(t, nil))
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

func TestAndroidAARFailsClosedWithoutCMake(t *testing.T) {
	path := newMockPath(t, nil)
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, path, androidTestEnv(t, nil))
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "cmake") {
		t.Fatalf("expected a cmake-related failure, got stderr=%s", res.stderr)
	}
}

func TestAndroidAARFailsClosedWithoutNDK(t *testing.T) {
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), map[string]string{})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "ANDROID_NDK_HOME") {
		t.Fatalf("expected an ANDROID_NDK_HOME-related failure, got stderr=%s", res.stderr)
	}
}

func TestAndroidAARFailsClosedOnNDKBelowPinnedMinimumVersion(t *testing.T) {
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), map[string]string{
		"ANDROID_NDK_HOME": newFakeAndroidNDK(t, "21.4.7075529"),
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "older than the pinned minimum") {
		t.Fatalf("expected a below-minimum-NDK-version failure, got stderr=%s", res.stderr)
	}
}

func TestAndroidAARFailsClosedOnMissingToolchainFile(t *testing.T) {
	ndkRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(ndkRoot, "source.properties"), []byte("Pkg.Revision = 27.1.12345678\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), map[string]string{
		"ANDROID_NDK_HOME": ndkRoot,
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "android.toolchain.cmake") {
		t.Fatalf("expected a missing-toolchain-file failure, got stderr=%s", res.stderr)
	}
}

func TestAndroidAARUsesTargetJNIHeadersWithoutHostJava(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	ndkRoot := newFakeAndroidNDK(t, "27.1.12345678")
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), map[string]string{
		"ANDROID_NDK_HOME":                    ndkRoot,
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
	})
	if res.exitCode != 0 {
		t.Fatalf("expected an NDK-only JNI build to succeed, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}
}

func TestAndroidAARFailsClosedOnSourceCommitMismatch(t *testing.T) {
	url, fakeCommit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), androidTestEnv(t, map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
	}))
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "revision mismatch") {
		t.Fatalf("expected a revision mismatch failure, got stderr=%s", res.stderr)
	}
	if !strings.Contains(res.stderr, fakeCommit) {
		t.Fatalf("expected the mismatch message to name the actual cloned commit %s, got: %s", fakeCommit, res.stderr)
	}
}

func TestAndroidAARFailsClosedOnMissingRequiredABI(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), androidTestEnv(t, map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		"MOCK_CMAKE_FAIL_PREFIX_SUBSTRING":    "x86_64",
	}))
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit when a required ABI's build fails, got 0")
	}
	manifest := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-android.staging-manifest.json")
	if _, err := os.Stat(manifest); err == nil {
		t.Fatal("no staging manifest must be produced when a required ABI's build fails")
	}
}

func TestAndroidAARProducesDeterministicStagingManifest(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	beforeStatus := runGitOutput(t, repoRoot(t), "status", "--porcelain")
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), androidTestEnv(t, map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
	}))
	if res.exitCode != 0 {
		t.Fatalf("expected success, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}

	manifestPath := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-android.staging-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, raw)
	}

	if got := m["artifact_kind"]; got != "android_aar" {
		t.Fatalf("artifact_kind = %v, want android_aar", got)
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
	wantTargets := []string{"arm64-v8a", "x86_64"}
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

	// The .aar must actually contain per-ABI jni libraries -- assert the
	// zip contains the expected entries, not merely that some file exists.
	assertZipContainsEntries(t, m["artifact_path"].(string), []string{
		"AndroidManifest.xml",
		"classes.jar",
		"jni/arm64-v8a/libOPENFHEcore.so",
		"jni/arm64-v8a/libOPENFHEpke.so",
		"jni/arm64-v8a/libOPENFHEbinfhe.so",
		"jni/x86_64/libOPENFHEcore.so",
		"jni/x86_64/libOPENFHEpke.so",
		"jni/x86_64/libOPENFHEbinfhe.so",
	})

	afterStatus := runGitOutput(t, repoRoot(t), "status", "--porcelain")
	if afterStatus != beforeStatus {
		t.Fatalf("script left new/changed files inside the repository worktree:\nbefore:\n%s\nafter:\n%s", beforeStatus, afterStatus)
	}
}

func TestAndroidAARStagesJNIAlongsideOpenFHE(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), androidTestEnv(t, map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
	}))
	if res.exitCode != 0 {
		t.Fatalf("expected success, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}

	artifact := filepath.Join(out, "AresPrivacyCore-"+applePinnedVersion+"-android.aar")
	assertZipContainsEntries(t, artifact, []string{
		"jni/arm64-v8a/libares_fhe_jni.so",
		"jni/arm64-v8a/libOPENFHEcore.so",
		"jni/arm64-v8a/libOPENFHEpke.so",
		"jni/arm64-v8a/libOPENFHEbinfhe.so",
		"jni/x86_64/libares_fhe_jni.so",
		"jni/x86_64/libOPENFHEcore.so",
		"jni/x86_64/libOPENFHEpke.so",
		"jni/x86_64/libOPENFHEbinfhe.so",
	})
}

func TestAndroidAARRecordsPinnedNoBacktraceCompatibilityPatch(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), androidTestEnv(t, map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
	}))
	if res.exitCode != 0 {
		t.Fatalf("expected success, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}

	manifestPath := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-android.staging-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	const patchPath = "clients/native/patches/openfhe-v1.5.1-android-no-backtrace.patch"
	if got := manifest["openfhe_compatibility_patch_path"]; got != patchPath {
		t.Fatalf("openfhe_compatibility_patch_path = %v, want %s", got, patchPath)
	}
	patch, err := os.ReadFile(filepath.Join(repoRoot(t), patchPath))
	if err != nil {
		t.Fatalf("read compatibility patch: %v", err)
	}
	sum := sha256.Sum256(patch)
	wantHash := hex.EncodeToString(sum[:])
	if got := manifest["openfhe_compatibility_patch_sha256"]; got != wantHash {
		t.Fatalf("openfhe_compatibility_patch_sha256 = %v, want %s", got, wantHash)
	}
}

func TestAndroidAARBuildsOptionalExtraABIsWhenRequested(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, androidScriptPath(t), []string{out}, fullAndroidPath(t), androidTestEnv(t, map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		"ARES_NATIVE_ANDROID_EXTRA_ABIS":      "armeabi-v7a",
	}))
	if res.exitCode != 0 {
		t.Fatalf("expected success, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}
	manifestPath := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-android.staging-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	targets, _ := m["target_architectures"].([]any)
	found := false
	for _, target := range targets {
		if target == "armeabi-v7a" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected optional armeabi-v7a in target_architectures, got %v", targets)
	}
}
