package native_test

import (
	"archive/zip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// assertZipContainsEntries requires every named entry to be present in the
// zip (or zip-shaped, e.g. .aar/.xcframework.zip) archive at path.
func assertZipContainsEntries(t *testing.T, path string, want []string) {
	t.Helper()
	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("opening %s as zip: %v", path, err)
	}
	defer r.Close()

	present := make(map[string]bool, len(r.File))
	for _, f := range r.File {
		present[f.Name] = true
	}
	for _, name := range want {
		if !present[name] {
			t.Fatalf("expected entry %q in %s, not found (entries: %v)", name, path, keysOf(present))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// realTools are external commands the scripts (via lib/common.sh) need
// that are never mocked: standard POSIX/coreutils-shaped tools plus git,
// jq, and zip. Each test's PATH is built from scratch out of symlinks to
// these, so a test can precisely control which of cmake/xcodebuild/libtool
// (mocked, and individually omittable) are visible, without accidentally
// falling back to whatever real toolchain happens to be installed on the
// host running the test.
var realTools = []string{
	"bash", "sh", "env", "git", "jq", "zip", "unzip",
	"awk", "date", "mkdir", "rmdir", "rm", "cp", "ls", "cat", "grep", "sed",
	"basename", "dirname", "shasum", "sha256sum", "tar", "chmod", "touch",
}

// newMockPath builds a directory containing symlinks to the real tools
// above, plus whichever fake scripts are named in extra (a map from
// command name to script body). It returns the directory to prepend as
// PATH. Real tools missing on the host (e.g. sha256sum on some macOS
// versions) are skipped rather than failing the test, since scripts probe
// for either shasum or sha256sum.
func newMockPath(t *testing.T, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range realTools {
		real, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := os.Symlink(real, filepath.Join(dir, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	for name, body := range extra {
		writeExecutable(t, filepath.Join(dir, name), body)
	}
	return dir
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// mockCMake is a fake cmake that understands exactly the two invocation
// shapes the build scripts use: a configure call (-S/-B/-DCMAKE_INSTALL_PREFIX=)
// and `cmake --build <dir> ... --target install`. Configure records the
// resolved install prefix inside the build directory so the later build+
// install call (a separate process) can find it again. If
// MOCK_CMAKE_FAIL_PREFIX_SUBSTRING is set in the environment and the
// resolved install prefix contains that substring, configure fails --
// used to simulate exactly one platform/ABI's build failing.
//
// The static-library filenames (lib*_static.a) match OpenFHE's own
// src/{core,pke,binfhe}/CMakeLists.txt install rules exactly -- confirmed
// against a real clone during a real (non-mocked) build of this commit,
// not assumed. The shared-library filenames (lib*.so, no suffix) match the
// same source for the SHARED target name.
const mockCMakeScript = `#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  echo "cmake version 3.99.0 (mock)"
  exit 0
fi
if [ "${1:-}" = "--build" ]; then
  build_dir="$2"

  if [ -f "${build_dir}/.mock-required-macos-deployment-target" ]; then
    expected="$(cat "${build_dir}/.mock-required-macos-deployment-target")"
    if [ "${MACOSX_DEPLOYMENT_TARGET:-}" != "${expected}" ]; then
      echo "mock cmake: build MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-<unset>}, want ${expected}" >&2
      exit 1
    fi
  fi

  target=""
  prev=""
  for arg in "$@"; do
    if [ "${prev}" = "--target" ]; then
      target="${arg}"
    fi
    prev="${arg}"
  done
  if [ "${target}" = "ares_privacy_core" ]; then
    mkdir -p "${build_dir}/lib"
    : > "${build_dir}/lib/libares_privacy_core.a"
    exit 0
  fi
  if [ "${target}" = "ares_fhe_jni" ]; then
    mkdir -p "${build_dir}/lib"
    : > "${build_dir}/lib/libares_fhe_jni.so"
    exit 0
  fi
  prefix_file="${build_dir}/.mock-install-prefix"
  if [ ! -f "${prefix_file}" ]; then
    echo "mock cmake: no configure state found for ${build_dir}" >&2
    exit 1
  fi
  prefix="$(cat "${prefix_file}")"
  mkdir -p "${prefix}/lib" "${prefix}/include/openfhe"
  : > "${prefix}/lib/libOPENFHEcore_static.a"
  : > "${prefix}/lib/libOPENFHEpke_static.a"
  : > "${prefix}/lib/libOPENFHEbinfhe_static.a"
  : > "${prefix}/lib/libOPENFHEcore.so"
  : > "${prefix}/lib/libOPENFHEpke.so"
  : > "${prefix}/lib/libOPENFHEbinfhe.so"
  : > "${prefix}/include/openfhe/openfhe.h"
  exit 0
fi

build_dir=""
prefix=""
source_dir=""
prev=""
for arg in "$@"; do
  if [ "${prev}" = "-B" ]; then
    build_dir="${arg}"
  fi
  if [ "${prev}" = "-S" ]; then
    source_dir="${arg}"
  fi
  case "${arg}" in
    -DCMAKE_INSTALL_PREFIX=*) prefix="${arg#-DCMAKE_INSTALL_PREFIX=}" ;;
  esac
  prev="${arg}"
done
if [ -z "${build_dir}" ]; then
  echo "mock cmake: configure call missing -B: $*" >&2
  exit 1
fi
if [ -n "${MOCK_CMAKE_EXPECT_MACOS_DEPLOYMENT_TARGET:-}" ]; then
  expected_flag="-DCMAKE_OSX_DEPLOYMENT_TARGET=${MOCK_CMAKE_EXPECT_MACOS_DEPLOYMENT_TARGET}"
  saw_expected_flag=0
  saw_apple_architecture=0
  saw_ios_system=0
  for arg in "$@"; do
    if [ "${arg}" = "${expected_flag}" ]; then
      saw_expected_flag=1
    fi
    if [ "${arg}" = "-DCMAKE_OSX_ARCHITECTURES=arm64" ]; then
      saw_apple_architecture=1
    fi
    if [ "${arg}" = "-DCMAKE_SYSTEM_NAME=iOS" ]; then
      saw_ios_system=1
    fi
  done
  if [ "${saw_apple_architecture}" = "1" ] && [ "${saw_ios_system}" = "0" ]; then
    if [ "${saw_expected_flag}" != "1" ]; then
      echo "mock cmake: macOS configure is missing ${expected_flag}" >&2
      exit 1
    fi
    if [ "${MACOSX_DEPLOYMENT_TARGET:-}" != "${MOCK_CMAKE_EXPECT_MACOS_DEPLOYMENT_TARGET}" ]; then
      echo "mock cmake: configure MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-<unset>}, want ${MOCK_CMAKE_EXPECT_MACOS_DEPLOYMENT_TARGET}" >&2
      exit 1
    fi
    mkdir -p "${build_dir}"
    printf '%s' "${MOCK_CMAKE_EXPECT_MACOS_DEPLOYMENT_TARGET}" > "${build_dir}/.mock-required-macos-deployment-target"
  fi
fi
case "${source_dir}" in
  */clients/native/bridge/apple)
    mkdir -p "${build_dir}"
    : > "${build_dir}/.mock-apple-bridge"
    exit 0
    ;;
  */clients/native/bridge/android)
    mkdir -p "${build_dir}"
    : > "${build_dir}/.mock-android-bridge"
    exit 0
    ;;
esac
if [ -z "${prefix}" ]; then
  echo "mock cmake: configure call missing -B or -DCMAKE_INSTALL_PREFIX=: $*" >&2
  exit 1
fi
if [ -n "${MOCK_CMAKE_FAIL_PREFIX_SUBSTRING:-}" ]; then
  case "${prefix}" in
    *"${MOCK_CMAKE_FAIL_PREFIX_SUBSTRING}"*)
      echo "mock cmake: simulated configure failure for ${prefix}" >&2
      exit 1
      ;;
  esac
fi
mkdir -p "${build_dir}"
echo "${prefix}" > "${build_dir}/.mock-install-prefix"
exit 0
`

const mockXcodebuildScript = `#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-version" ]; then
  echo "Xcode 16.0 (mock)"
  echo "Build version 16A000"
  exit 0
fi
if [ "${1:-}" = "-create-xcframework" ]; then
  shift
  output=""
  headers=""
  libraries=()
  prev=""
  for arg in "$@"; do
    if [ "${prev}" = "-output" ]; then
      output="${arg}"
    fi
    if [ "${prev}" = "-headers" ]; then
      headers="${arg}"
    fi
    if [ "${prev}" = "-library" ]; then
      libraries+=("${arg}")
    fi
    prev="${arg}"
  done
  if [ -z "${output}" ]; then
    echo "mock xcodebuild: no -output" >&2
    exit 1
  fi
  mkdir -p "${output}"
  : > "${output}/Info.plist"
  for library in "${libraries[@]}"; do
    slice="$(basename "$(dirname "${library}")")"
    slice_dir="${output}/${slice}"
    mkdir -p "${slice_dir}/Headers"
    cp "${library}" "${slice_dir}/$(basename "${library}")"
    cp -R "${headers}/." "${slice_dir}/Headers/"
  done
  exit 0
fi
echo "mock xcodebuild: unhandled invocation: $*" >&2
exit 1
`

// mockOtoolScript understands exactly `otool -l PATH`, ignoring PATH's
// actual contents (the mocked cmake/libtool above produce empty
// placeholder files, not real Mach-O objects) and reporting a single
// LC_BUILD_VERSION load command whose minos value is
// MOCK_OTOOL_MINOS (default: matches the repo's real tracked
// clients/native/apple-deployment-target.pin.json, "14.0") -- so a test
// can simulate a build whose real linked output disagrees with what was
// pinned, independent of what the mocked cmake/libtool actually wrote to
// disk.
const mockOtoolScript = `#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-l" ]; then
  minos="${MOCK_OTOOL_MINOS:-14.0}"
  cat <<EOF
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 24
 platform 1
    minos ${minos}
      sdk 26.0
   ntools 0
EOF
  exit 0
fi
echo "mock otool: unhandled invocation: $*" >&2
exit 1
`

// mockSwVersScript understands exactly `sw_vers -productVersion`,
// reporting MOCK_SW_VERS_PRODUCT_VERSION (default: a recent real macOS
// version, newer than any deployment target these tests pin) so a test
// can simulate running on an older host without needing one.
const mockSwVersScript = `#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-productVersion" ]; then
  echo "${MOCK_SW_VERS_PRODUCT_VERSION:-26.2}"
  exit 0
fi
echo "mock sw_vers: unhandled invocation: $*" >&2
exit 1
`

const mockLibtoolScript = `#!/usr/bin/env bash
set -euo pipefail
output=""
prev=""
for arg in "$@"; do
  if [ "${prev}" = "-o" ]; then
    output="${arg}"
  fi
  prev="${arg}"
done
if [ -z "${output}" ]; then
  echo "mock libtool: no -o argument" >&2
  exit 1
fi
mkdir -p "$(dirname "${output}")"
: > "${output}"
exit 0
`

// newFakeOpenFHETagRepo creates a real, local, tiny git repository with a
// tag matching the given version, and returns its file:// clone URL and
// the exact commit that tag resolves to. Used with
// ARES_NATIVE_TEST_OPENFHE_SOURCE_URL so clone_pinned_openfhe exercises a
// real `git clone` + commit-verification without touching the network.
func newFakeOpenFHETagRepo(t *testing.T, version string) (url, commit string) {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "native-test@fheya.de")
	runGit(t, dir, "config", "user.name", "native-test")
	if err := os.WriteFile(filepath.Join(dir, "CMakeLists.txt"), []byte("# fake openfhe source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	callStackDir := filepath.Join(dir, "src", "core", "lib", "utils")
	if err := os.MkdirAll(callStackDir, 0o755); err != nil {
		t.Fatal(err)
	}
	callStack := strings.Repeat("\n", 29) + "//==================================================================================\n#include \"utils/get-call-stack.h\"\n\n#if defined(__linux__) && defined(__GNUC__)\n// clang-format off\n#include \"utils/demangle.h\"\n"
	if err := os.WriteFile(filepath.Join(callStackDir, "get-call-stack.cpp"), []byte(callStack), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-q", "-m", "fake openfhe source")
	runGit(t, dir, "tag", version)

	out := runGitOutput(t, dir, "rev-parse", "HEAD")
	return "file://" + dir, strings.TrimSpace(out)
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

// writeTestPin writes a pin file for use with ARES_NATIVE_TEST_PIN_FILE.
func writeTestPin(t *testing.T, version, sourceURL, sourceCommit string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openfhe.pin.json")
	raw, err := json.Marshal(map[string]string{
		"openfhe_version":       version,
		"openfhe_source_url":    sourceURL,
		"openfhe_source_commit": sourceCommit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeTestNDKPin writes an Android NDK minimum-version pin file for use
// with ARES_NATIVE_TEST_NDK_PIN_FILE.
func writeTestNDKPin(t *testing.T, minMajor string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "android-ndk.pin.json")
	raw, err := json.Marshal(map[string]string{"android_ndk_min_major_version": minMajor})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeTestAppleDeploymentTargetPin writes a pin file for use with
// ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE. target is written
// as-is (including deliberately malformed/empty values, so mutation tests
// can exercise the malformed-pin rejection path).
func writeTestAppleDeploymentTargetPin(t *testing.T, target string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "apple-deployment-target.pin.json")
	raw, err := json.Marshal(map[string]string{"macos_minimum_deployment_target": target})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// newFakeAndroidNDK creates the Android-specific build and target-JNI
// structure the staging script requires, with the given Pkg.Revision.
func newFakeAndroidNDK(t *testing.T, revision string) string {
	t.Helper()
	dir := t.TempDir()
	toolchainDir := filepath.Join(dir, "build", "cmake")
	if err := os.MkdirAll(toolchainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolchainDir, "android.toolchain.cmake"), []byte("# fake ndk toolchain file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	props := "Pkg.Desc = Android NDK\nPkg.Revision = " + revision + "\n"
	if err := os.WriteFile(filepath.Join(dir, "source.properties"), []byte(props), 0o644); err != nil {
		t.Fatal(err)
	}
	jniDir := filepath.Join(dir, "toolchains", "llvm", "prebuilt", "darwin-arm64", "sysroot", "usr", "include")
	if err := os.MkdirAll(jniDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jniDir, "jni.h"), []byte("/* fake Android target JNI header */\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// clients/native -> repo root
	return filepath.Join(dir, "..", "..")
}
