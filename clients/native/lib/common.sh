#!/usr/bin/env bash
# Shared helpers for clients/native/build-*.sh. Sourced, not executed
# directly. Every function fails closed: on any ambiguity about a
# toolchain, pin, or path, it exits nonzero with a clear message rather
# than proceeding with a best-effort guess.

set -euo pipefail

NATIVE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="$(cd "${NATIVE_LIB_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${NATIVE_DIR}/../.." && pwd)"

# PIN_FILE is the tracked, committed source of truth. It is only ever
# redirected in ARES_NATIVE_TEST_MODE=1, so a test can exercise the clone
# + commit-verification logic against a small local repository instead of
# the real network -- a real release invocation always reads the tracked
# file at its fixed repo-relative location.
if [ "${ARES_NATIVE_TEST_MODE:-}" = "1" ] && [ -n "${ARES_NATIVE_TEST_PIN_FILE:-}" ]; then
  PIN_FILE="${ARES_NATIVE_TEST_PIN_FILE}"
else
  PIN_FILE="${NATIVE_DIR}/openfhe.pin.json"
fi

# APPLE_DEPLOYMENT_TARGET_PIN_FILE is the tracked source of truth for the
# minimum macOS version the Apple XCFramework's macos-arm64 slice must
# support. Same test-only override gate as every other pin: it can never
# activate against a real release invocation by accident.
if [ "${ARES_NATIVE_TEST_MODE:-}" = "1" ] && [ -n "${ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE:-}" ]; then
  APPLE_DEPLOYMENT_TARGET_PIN_FILE="${ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE}"
else
  APPLE_DEPLOYMENT_TARGET_PIN_FILE="${NATIVE_DIR}/apple-deployment-target.pin.json"
fi

log_info()  { printf '[native] %s\n' "$*" >&2; }
log_error() { printf '[native] ERROR: %s\n' "$*" >&2; }

die() {
  log_error "$*"
  exit 1
}

# require_cmd NAME [MIN_VERSION_HINT] fails closed if NAME is not on PATH.
# It only checks presence; callers that care about an exact version run
# their own check afterward (see require_version_output).
require_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    die "required toolchain command not found on PATH: ${name}"
  fi
}

# require_version_output CMD_DESCRIPTION VERSION_COMMAND PATTERN runs
# VERSION_COMMAND, requires it to succeed, and requires its output to match
# PATTERN (an extended regex). Fails closed on a missing command, a nonzero
# exit, or output that does not match -- an unrecognized or unparsable
# version string is treated the same as an absent toolchain, never silently
# accepted.
require_version_output() {
  local description="$1"
  local pattern="$2"
  shift 2
  local output
  if ! output="$("$@" 2>&1)"; then
    die "${description}: version command failed: $*"
  fi
  if ! printf '%s' "${output}" | grep -Eq "${pattern}"; then
    die "${description}: version output did not match expected pattern (${pattern}): ${output}"
  fi
  printf '%s' "${output}"
}

# read_pin KEY reads one field from the checked-in, tracked pin file. The
# pin file is the sole source of truth for what OpenFHE source/version is
# releasable; it is never overridable by an ordinary environment variable,
# so a release build cannot silently point at an unpinned source. A
# test-only, explicitly-named escape hatch
# (ARES_NATIVE_TEST_OPENFHE_SOURCE_URL) exists solely so this script can be
# tested without a real network clone; see resolve_openfhe_source_url.
read_pin() {
  local key="$1"
  [ -f "${PIN_FILE}" ] || die "pin file not found: ${PIN_FILE}"
  local value
  value="$(jq -r --arg k "${key}" '.[$k] // empty' "${PIN_FILE}" 2>/dev/null || true)"
  [ -n "${value}" ] || die "pin file ${PIN_FILE} is missing required key: ${key}"
  printf '%s' "${value}"
}

# resolve_openfhe_source_url prints the OpenFHE clone URL. It honors
# ARES_NATIVE_TEST_OPENFHE_SOURCE_URL only when ARES_NATIVE_TEST_MODE=1 is
# also set, so the override can never activate by accident against a real
# release invocation that merely inherited a stray environment variable.
resolve_openfhe_source_url() {
  if [ "${ARES_NATIVE_TEST_MODE:-}" = "1" ] && [ -n "${ARES_NATIVE_TEST_OPENFHE_SOURCE_URL:-}" ]; then
    printf '%s' "${ARES_NATIVE_TEST_OPENFHE_SOURCE_URL}"
    return 0
  fi
  read_pin openfhe_source_url
}

# sha256_of FILE prints a lowercase hex SHA-256, using whichever of shasum
# / sha256sum is available (macOS ships shasum by default; Linux runners
# ship sha256sum).
sha256_of() {
  local file="$1"
  [ -f "${file}" ] || die "cannot hash missing file: ${file}"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  else
    die "no sha256 tool found (need shasum or sha256sum)"
  fi
}

# ares_core_source_revision prints the git commit this checkout is at. It
# refuses to guess: an unclean detection (not a git repo, or a dirty
# worktree) is a hard failure, because a staged artifact whose provenance
# cannot be tied to an exact source commit is not releasable evidence.
ares_core_source_revision() {
  require_cmd git
  ( cd "${REPO_ROOT}" && git rev-parse --verify HEAD 2>/dev/null ) \
    || die "cannot determine ares-core source revision: ${REPO_ROOT} is not a git checkout with a HEAD commit"
}

# Canonical bridge sources are intentionally shared by Go, Swift, and JNI
# builds. Packaging scripts must compile these exact tracked files instead of
# copying or reimplementing cryptographic operations per client platform.
bridge_source_path() {
  local path="${REPO_ROOT}/pkg/ares/crypto/cgo/openfhe_wrapper.cpp"
  [ -f "${path}" ] || die "canonical OpenFHE bridge source is missing: ${path}"
  printf '%s' "${path}"
}

bridge_header_path() {
  local path="${REPO_ROOT}/pkg/ares/crypto/cgo/openfhe_wrapper.h"
  [ -f "${path}" ] || die "canonical OpenFHE bridge header is missing: ${path}"
  printf '%s' "${path}"
}

jni_bridge_source_path() {
  local path="${REPO_ROOT}/clients/kotlin/native/jni_openfhe.cpp"
  [ -f "${path}" ] || die "canonical JNI bridge source is missing: ${path}"
  printf '%s' "${path}"
}

# Android's target JNI declarations are shipped by the configured NDK. Using
# a host JDK's jni.h (and, on macOS, its Darwin-specific jni_md.h) in an
# Android cross-compile can silently build against the wrong ABI. Require one
# unambiguous target header from the NDK instead of accepting JAVA_HOME.
require_android_jni_include_dir() {
  local ndk_root="$1"
  [ -n "${ndk_root}" ] || die "Android NDK root is required to locate target JNI headers"
  local prebuilt_dir="${ndk_root}/toolchains/llvm/prebuilt"
  [ -d "${prebuilt_dir}" ] || die "Android NDK at ${ndk_root} has no LLVM prebuilt toolchain directory"

  local -a headers=()
  local header
  for header in "${prebuilt_dir}"/*/sysroot/usr/include/jni.h; do
    [ -f "${header}" ] || continue
    headers+=("${header}")
  done

  if [ "${#headers[@]}" -eq 0 ]; then
    die "Android NDK at ${ndk_root} has no target sysroot JNI header"
  fi
  if [ "${#headers[@]}" -ne 1 ]; then
    die "Android NDK at ${ndk_root} has ambiguous target sysroot JNI headers (${#headers[@]} found)"
  fi
  printf '%s' "$(dirname "${headers[0]}")"
}

# stage_copenfhe_headers emits the public C module interface consumed by the
# release-only Swift binary target. The caller owns DEST and must keep it out
# of the repository worktree.
stage_copenfhe_headers() {
  local dest="$1"
  [ -n "${dest}" ] || die "COpenFHEBridge header destination is required"
  mkdir -p "${dest}"
  cp "$(bridge_header_path)" "${dest}/openfhe_wrapper.h"
  cat > "${dest}/module.modulemap" <<'EOF'
module COpenFHEBridge {
    header "openfhe_wrapper.h"
    export *
}
EOF
}

# require_android_ndk fails closed unless an Android NDK is configured and
# meets the pinned minimum major version, printing its root path on
# success. It checks ANDROID_NDK_HOME first, then ANDROID_NDK_ROOT; an
# unset/missing/malformed/too-old NDK is a hard failure, never a silent
# fallback to "whatever NDK happens to be findable."
require_android_ndk() {
  local ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  [ -n "${ndk_root}" ] || die "ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) is not set"
  [ -d "${ndk_root}" ] || die "Android NDK root does not exist: ${ndk_root}"

  local toolchain_file="${ndk_root}/build/cmake/android.toolchain.cmake"
  [ -f "${toolchain_file}" ] || die "Android NDK at ${ndk_root} has no build/cmake/android.toolchain.cmake"

  local props="${ndk_root}/source.properties"
  [ -f "${props}" ] || die "Android NDK at ${ndk_root} has no source.properties"
  local revision
  revision="$(awk -F '= *' '/^Pkg\.Revision/{print $2}' "${props}")"
  [ -n "${revision}" ] || die "could not read Pkg.Revision from ${props}"
  local major="${revision%%.*}"
  case "${major}" in
    ''|*[!0-9]*) die "unparsable Android NDK major version in ${props}: ${revision}" ;;
  esac

  local ndk_pin="${NATIVE_DIR}/android-ndk.pin.json"
  if [ "${ARES_NATIVE_TEST_MODE:-}" = "1" ] && [ -n "${ARES_NATIVE_TEST_NDK_PIN_FILE:-}" ]; then
    ndk_pin="${ARES_NATIVE_TEST_NDK_PIN_FILE}"
  fi
  [ -f "${ndk_pin}" ] || die "NDK pin file not found: ${ndk_pin}"
  local min_major
  min_major="$(jq -r '.android_ndk_min_major_version // empty' "${ndk_pin}")"
  [ -n "${min_major}" ] || die "NDK pin file ${ndk_pin} is missing android_ndk_min_major_version"

  if [ "${major}" -lt "${min_major}" ]; then
    die "Android NDK ${revision} at ${ndk_root} is older than the pinned minimum major version ${min_major}"
  fi

  log_info "using Android NDK ${revision} at ${ndk_root}"
  printf '%s' "${ndk_root}"
}

# require_untracked_output_dir OUTPUT_DIR fails closed unless OUTPUT_DIR is
# an explicit argument that resolves outside this repository's working
# tree. Native build output is never something a release process should
# risk committing, so there is no default: a missing argument is also a
# failure, not a fallback into the repo.
require_untracked_output_dir() {
  local raw="${1:-}"
  [ -n "${raw}" ] || die "an output directory argument is required (no default is provided inside the repository)"

  local created=0
  if [ ! -d "${raw}" ]; then
    mkdir -p "${raw}"
    created=1
  fi
  local resolved
  resolved="$(cd "${raw}" && pwd)"
  case "${resolved}" in
    "${REPO_ROOT}"|"${REPO_ROOT}"/*)
      # Reject before leaving a stray directory behind inside the repo: only
      # remove it if this call is what created it (never delete a
      # pre-existing directory the caller happened to point at).
      if [ "${created}" -eq 1 ]; then
        rmdir "${resolved}" 2>/dev/null || true
      fi
      die "output directory ${resolved} is inside the repository (${REPO_ROOT}); pass an untracked directory outside the repo"
      ;;
  esac
  printf '%s' "${resolved}"
}

# clone_pinned_openfhe DEST clones the pinned OpenFHE tag into DEST and
# fails closed unless the checked-out HEAD exactly matches the pinned
# commit -- a moved or re-pointed tag is caught here rather than trusted.
clone_pinned_openfhe() {
  local dest="$1"
  require_cmd git
  local version url expected_commit
  version="$(read_pin openfhe_version)"
  url="$(resolve_openfhe_source_url)"
  expected_commit="$(read_pin openfhe_source_commit)"

  log_info "cloning pinned OpenFHE ${version} from ${url}"
  rm -rf "${dest}"
  git clone --branch "${version}" --depth 1 "${url}" "${dest}" >&2

  local actual_commit
  actual_commit="$(git -C "${dest}" rev-parse HEAD)"
  if [ "${actual_commit}" != "${expected_commit}" ]; then
    die "OpenFHE source revision mismatch: tag ${version} at ${url} resolved to ${actual_commit}, pin file requires ${expected_commit}"
  fi
  log_info "OpenFHE source revision verified: ${actual_commit}"
}

# Android's libc does not provide the execinfo backtrace APIs used by the
# generic GNU/Linux branch in OpenFHE 1.5.1. The tracked compatibility patch
# selects OpenFHE's existing empty-call-stack fallback for Android. It is
# applied only through git's exact-context check, so an upstream source change
# fails closed instead of receiving a fuzzy source edit.
android_openfhe_compatibility_patch_path() {
  printf '%s' 'clients/native/patches/openfhe-v1.5.1-android-no-backtrace.patch'
}

apply_android_openfhe_compatibility_patch() {
  local source_dir="$1"
  local patch_rel patch_path
  patch_rel="$(android_openfhe_compatibility_patch_path)"
  patch_path="${REPO_ROOT}/${patch_rel}"
  [ -f "${patch_path}" ] || die "Android OpenFHE compatibility patch is missing: ${patch_path}"

  git -C "${source_dir}" apply --check "${patch_path}" \
    || die "Android OpenFHE compatibility patch does not apply cleanly to the pinned source"
  git -C "${source_dir}" apply "${patch_path}" \
    || die "failed to apply Android OpenFHE compatibility patch"

  local changed
  changed="$(git -C "${source_dir}" diff --name-only)"
  [ "${changed}" = "src/core/lib/utils/get-call-stack.cpp" ] \
    || die "Android OpenFHE compatibility patch changed unexpected files: ${changed:-none}"
  sha256_of "${patch_path}"
}

# apple_version_gt A B returns success (0) if MAJOR.MINOR version A is
# strictly greater than B, comparing the major and minor components
# numerically -- never lexicographically, so "9.0" is correctly not
# greater than "10.0". Callers must have already validated both A and B
# are well-formed MAJOR.MINOR strings.
apple_version_gt() {
  local a_major="${1%%.*}" a_minor="${1#*.}"
  local b_major="${2%%.*}" b_minor="${2#*.}"
  a_minor="${a_minor%%.*}"
  b_minor="${b_minor%%.*}"
  if [ "${a_major}" -gt "${b_major}" ]; then
    return 0
  fi
  if [ "${a_major}" -eq "${b_major}" ] && [ "${a_minor}" -gt "${b_minor}" ]; then
    return 0
  fi
  return 1
}

# is_canonical_apple_version_component VALUE accepts decimal zero or a
# nonzero decimal without leading zeroes.
is_canonical_apple_version_component() {
  local value="$1"
  case "${value}" in
    0) return 0 ;;
    [1-9]*)
      case "${value}" in
        *[!0-9]*) return 1 ;;
        *) return 0 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

# require_apple_version_format LABEL VALUE fails closed unless VALUE is the
# unique canonical MAJOR.MINOR representation: exactly one dot, decimal
# components, and no signs, whitespace, empty components, or leading zeroes.
require_apple_version_format() {
  local label="$1" value="$2"
  case "${value}" in
    ''|*[!0-9.]*|*.*.*) die "${label} is not a canonical MAJOR.MINOR version: ${value}" ;;
  esac
  local major="${value%%.*}"
  local minor="${value#*.}"
  if [ "${minor}" = "${value}" ]; then
    die "${label} is missing a minor version component (want MAJOR.MINOR): ${value}"
  fi
  is_canonical_apple_version_component "${major}" \
    || die "${label} has a non-canonical major version component: ${value}"
  is_canonical_apple_version_component "${minor}" \
    || die "${label} has a non-canonical minor version component: ${value}"
}

# require_macos_deployment_target SW_VERS_PATH reads, validates, and prints the pinned
# minimum macOS deployment target for the macos-arm64 slice. It fails
# closed if the pin file is missing, the value is absent, the value is not
# a well-formed MAJOR.MINOR version string, or the pinned value is newer
# than the host's own macOS version -- a target this machine cannot build
# or validate against, and never a sane "minimum supported" value for a
# macOS build in any case.
require_macos_deployment_target() {
  local sw_vers_path="$1"
  require_trusted_apple_tool_path "${sw_vers_path}" "sw_vers"
  [ -f "${APPLE_DEPLOYMENT_TARGET_PIN_FILE}" ] || die "Apple deployment-target pin file not found: ${APPLE_DEPLOYMENT_TARGET_PIN_FILE}"
  local target
  target="$(jq -r '.macos_minimum_deployment_target // empty' "${APPLE_DEPLOYMENT_TARGET_PIN_FILE}" 2>/dev/null || true)"
  [ -n "${target}" ] || die "Apple deployment-target pin ${APPLE_DEPLOYMENT_TARGET_PIN_FILE} is missing macos_minimum_deployment_target"
  require_apple_version_format "Apple deployment-target pin ${APPLE_DEPLOYMENT_TARGET_PIN_FILE}'s macos_minimum_deployment_target" "${target}"

  local host_version
  host_version="$("${sw_vers_path}" -productVersion)" \
    || die "trusted ${sw_vers_path} failed to report the host macOS version"
  case "${host_version}" in
    *.*.*.*) die "host macOS version has too many components: ${host_version}" ;;
    *.*.*)
      local host_patch="${host_version##*.}"
      is_canonical_apple_version_component "${host_patch}" \
        || die "host macOS version has a non-canonical patch component: ${host_version}"
      host_version="${host_version%.*}"
      ;;
  esac
  if [ "${host_version#*.}" = "${host_version}" ]; then
    host_version="${host_version}.0"
  fi
  require_apple_version_format "host macOS version (sw_vers -productVersion)" "${host_version}"

  if apple_version_gt "${target}" "${host_version}"; then
    die "pinned macOS deployment target ${target} is newer than the host macOS version ${host_version}; refusing to build against an unvalidatable target"
  fi

  printf '%s' "${target}"
}

# require_trusted_apple_tool_path PATH NAME accepts only a canonical absolute,
# regular executable. Production passes fixed /usr/bin paths; native Go tests
# source the producer through a test-only harness and inject regular mock files.
require_trusted_apple_tool_path() {
  local tool_path="$1" tool_name="$2"
  [ -n "${tool_path}" ] || die "trusted ${tool_name} path is empty"
  case "${tool_path}" in
    /*) ;;
    *) die "trusted ${tool_name} path is not absolute: ${tool_path}" ;;
  esac
  case "${tool_path}" in
    *//*|*/./*|*/../*) die "trusted ${tool_name} path is not canonical: ${tool_path}" ;;
  esac
  [ ! -L "${tool_path}" ] || die "trusted ${tool_name} path is a symbolic link: ${tool_path}"
  [ -f "${tool_path}" ] && [ -x "${tool_path}" ] \
    || die "trusted ${tool_name} is not a regular executable: ${tool_path}"
}

# verify_apple_macho_deployment_target LIB_PATH EXPECTED OTOOL_PATH fails closed
# unless every LC_BUILD_VERSION/LC_VERSION_MIN_MACOSX "minos" value `otool
# -l` finds inside LIB_PATH (a static archive or object file) exactly
# equals EXPECTED. otool is used rather than vtool because vtool refuses
# to open a static archive ("file is not mach-o"), confirmed directly,
# while otool -l reports each archive member's load commands. This
# inspects the real Mach-O metadata rather than trusting that passing
# -DCMAKE_OSX_DEPLOYMENT_TARGET was actually honored by every translation
# unit -- the exact class of gap that can let a macOS-14-pinned build
# silently link against a newer host-default minimum in practice.
verify_apple_macho_deployment_target() {
  local lib_path="$1" expected="$2" otool_path="$3"
  require_trusted_apple_tool_path "${otool_path}" "otool"
  [ -f "${lib_path}" ] || die "cannot inspect missing Mach-O file: ${lib_path}"
  local output
  output="$("${otool_path}" -l "${lib_path}" 2>&1)" || die "${otool_path} failed to inspect Mach-O deployment target metadata: ${lib_path}"
  local minos_values
  minos_values="$(printf '%s\n' "${output}" | awk '/^ *minos /{print $2}')"
  [ -n "${minos_values}" ] || die "no LC_BUILD_VERSION/LC_VERSION_MIN_MACOSX minos load command found in ${lib_path}; cannot verify its deployment target"
  local value
  while IFS= read -r value; do
    [ -n "${value}" ] || continue
    if [ "${value}" != "${expected}" ]; then
      die "Mach-O deployment target mismatch in ${lib_path}: inspected minos=${value}, pinned target=${expected}"
    fi
  done <<EOF2
${minos_values}
EOF2
}

# require_all_present LABEL REQUIRED_LIST... ACTUAL_LIST... fails closed if
# any entry named in the (space-separated) required list is absent from
# the (space-separated) actual list -- used to enforce that every required
# target architecture actually produced a build output, not merely that
# the build command exited zero.
require_all_present() {
  local label="$1"; shift
  local -a required=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    required+=("$1"); shift
  done
  shift # drop the --
  local -a actual=("$@")
  local req
  for req in "${required[@]}"; do
    local found=0
    local act
    for act in "${actual[@]}"; do
      if [ "${act}" = "${req}" ]; then
        found=1
        break
      fi
    done
    if [ "${found}" -ne 1 ]; then
      die "${label}: required architecture/ABI '${req}' is absent from the build output (produced: ${actual[*]:-none})"
    fi
  done
}

# write_sbom PATH COMPONENT_NAME COMPONENT_VERSION SOURCE_COMMIT emits a
# minimal, valid CycloneDX-shaped SBOM naming the single vendored
# component (OpenFHE) this artifact embeds.
write_sbom() {
  local path="$1" name="$2" version="$3" commit="$4"
  jq -n \
    --arg bomFormat "CycloneDX" \
    --arg specVersion "1.5" \
    --arg name "${name}" \
    --arg version "${version}" \
    --arg commit "${commit}" \
    --arg purl "pkg:github/openfheorg/openfhe-development@${version}" \
    '{
      bomFormat: $bomFormat,
      specVersion: $specVersion,
      components: [
        {
          type: "library",
          name: $name,
          version: $version,
          purl: $purl,
          externalReferences: [
            { type: "vcs", url: ("https://github.com/openfheorg/openfhe-development/commit/" + $commit) }
          ]
        }
      ]
    }' > "${path}"
}

# write_provenance PATH ARTIFACT_NAME ARTIFACT_SHA256 ARES_CORE_REVISION
# OPENFHE_COMMIT BUILDER_ID [PATCH_PATH PATCH_SHA256] emits a minimal,
# SLSA-provenance-shaped statement tying the artifact hash to its exact source
# materials. PATCH_PATH/PATCH_SHA256 are optional for normal builds and
# required for a compatibility-patched native artifact.
write_provenance() {
  local path="$1" artifact_name="$2" artifact_sha256="$3" ares_core_revision="$4" openfhe_commit="$5" builder_id="$6"
  local patch_path="${7:-}" patch_sha256="${8:-}"
  jq -n \
    --arg predicateType "https://slsa.dev/provenance/v1" \
    --arg artifact_name "${artifact_name}" \
    --arg artifact_sha256 "${artifact_sha256}" \
    --arg ares_core_revision "${ares_core_revision}" \
    --arg openfhe_commit "${openfhe_commit}" \
    --arg builder_id "${builder_id}" \
    --arg patch_path "${patch_path}" \
    --arg patch_sha256 "${patch_sha256}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      predicateType: $predicateType,
      subject: [ { name: $artifact_name, digest: { sha256: $artifact_sha256 } } ],
      predicate: {
        buildDefinition: {
          builder: { id: $builder_id },
          resolvedDependencies: [
            { uri: "git+https://github.com/openfheorg/openfhe-development.git", digest: { sha1: $openfhe_commit } }
          ]
        },
        materials: (
          [{ uri: ("git+https://github.com/Fheyalabs/ARES-core.git@" + $ares_core_revision) }]
          + if $patch_path == "" then [] else
              [{ uri: ("git+https://github.com/Fheyalabs/ARES-core.git/" + $patch_path), digest: { sha256: $patch_sha256 } }]
            end
        ),
        generatedAt: $generated_at
      }
    }' > "${path}"
}

# emit_native_manifest PATH ARTIFACT_KIND ARTIFACT_PATH ARTIFACT_SHA256
# OPENFHE_VERSION OPENFHE_COMMIT ARES_CORE_REVISION SBOM_PATH PROVENANCE_PATH
# TARGET1 [TARGET2 ...] writes the deterministic staging-manifest JSON a
# downstream release-audit gate (see the sibling internal/releaseaudit
# NativeArtifact/HashedFile schema) can consume: artifact path, hash,
# source revision, OpenFHE version, target ABI/platform list, and
# SBOM/provenance paths and hashes. Field order and key names are fixed on
# purpose so byte-identical inputs produce byte-identical manifests (modulo
# the generated_at timestamp).
emit_native_manifest() {
  local path="$1" kind="$2" artifact_path="$3" artifact_sha256="$4"
  local openfhe_version="$5" openfhe_commit="$6" ares_core_revision="$7"
  local sbom_path="$8" provenance_path="$9"
  shift 9
  local -a targets=("$@")
  local compatibility_patch_path="${NATIVE_ARTIFACT_COMPATIBILITY_PATCH_PATH:-}"
  local compatibility_patch_sha256="${NATIVE_ARTIFACT_COMPATIBILITY_PATCH_SHA256:-}"
  local apple_macos_deployment_target="${NATIVE_ARTIFACT_APPLE_MACOS_DEPLOYMENT_TARGET:-}"

  local sbom_sha256 provenance_sha256
  sbom_sha256="$(sha256_of "${sbom_path}")"
  provenance_sha256="$(sha256_of "${provenance_path}")"

  local targets_json
  targets_json="$(printf '%s\n' "${targets[@]}" | jq -R . | jq -s .)"

  jq -n \
    --arg schema_version "1" \
    --arg artifact_kind "${kind}" \
    --arg artifact_path "${artifact_path}" \
    --arg artifact_sha256 "${artifact_sha256}" \
    --arg openfhe_version "${openfhe_version}" \
    --arg openfhe_source_commit "${openfhe_commit}" \
    --arg ares_core_source_revision "${ares_core_revision}" \
    --arg sbom_path "${sbom_path}" \
    --arg sbom_sha256 "${sbom_sha256}" \
    --arg provenance_path "${provenance_path}" \
    --arg provenance_sha256 "${provenance_sha256}" \
    --arg compatibility_patch_path "${compatibility_patch_path}" \
    --arg compatibility_patch_sha256 "${compatibility_patch_sha256}" \
    --arg apple_macos_deployment_target "${apple_macos_deployment_target}" \
    --argjson target_architectures "${targets_json}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema_version: ($schema_version | tonumber),
      artifact_kind: $artifact_kind,
      artifact_path: $artifact_path,
      artifact_sha256: $artifact_sha256,
      openfhe_version: $openfhe_version,
      openfhe_source_commit: $openfhe_source_commit,
      ares_core_source_revision: $ares_core_source_revision,
      target_architectures: $target_architectures,
      sbom_path: $sbom_path,
      sbom_sha256: $sbom_sha256,
      provenance_path: $provenance_path,
      provenance_sha256: $provenance_sha256,
      generated_at: $generated_at
    }
    + if $compatibility_patch_path == "" then {} else {
        openfhe_compatibility_patch_path: $compatibility_patch_path,
        openfhe_compatibility_patch_sha256: $compatibility_patch_sha256
      } end
    + if $apple_macos_deployment_target == "" then {} else {
        apple_macos_deployment_target: $apple_macos_deployment_target
      } end' > "${path}"
}
