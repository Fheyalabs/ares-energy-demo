#!/usr/bin/env bash
# Builds and stages the pinned OpenFHE Apple XCFramework plus ARES-core's
# canonical C bridge from clean, pinned source. See
# clients/native/openfhe.pin.json for the exact version and source commit,
# and clients/native/README.md for expected RSS/disk usage and the staging
# manifest schema.
#
# This script cross-compiles OpenFHE and the canonical wrapper for each
# required Apple platform slice, then packages them as a standalone
# AresPrivacyCore.xcframework. It does not alter Package.swift or publish a
# Swift package; assembling a complete Fheya release is separate work.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Required platform slices. macos-arm64 is the "host test architecture"
# used for local Swift Package tests; ios-arm64 is the device slice;
# ios-arm64-simulator is the Apple Silicon simulator slice. All three are
# required -- a build that produces only some of them fails closed rather
# than shipping an incomplete xcframework.
REQUIRED_PLATFORMS=(ios-arm64 ios-arm64-simulator macos-arm64)
BRIDGE_APPLE_CMAKE_DIR="${SCRIPT_DIR}/bridge/apple"

# MACOS_DEPLOYMENT_TARGET is resolved once in run_apple_xcframework_build (see
# require_macos_deployment_target in lib/common.sh: fails closed on an
# unset, malformed, or host-newer pin) and referenced by both
# build_openfhe_slice and build_bridge_slice for the macos-arm64 case,
# matching how BUILD_JOBS below is a script-global read by function body
# rather than threaded through every call site.
MACOS_DEPLOYMENT_TARGET=""
APPLE_OTOOL_PATH=""

readonly TRUSTED_UNAME_PATH="/usr/bin/uname"
readonly TRUSTED_SW_VERS_PATH="/usr/bin/sw_vers"
readonly TRUSTED_OTOOL_PATH="/usr/bin/otool"

# Native builds are serialized deliberately: this script never launches
# more than one platform slice's cmake configure/build/install at a time,
# and the release workflow never runs this script concurrently with
# build-android-aar.sh. Intra-build compiler parallelism (ARES_NATIVE_BUILD_JOBS)
# is a separate, bounded knob -- see README.md for RSS guidance.
BUILD_JOBS="${ARES_NATIVE_BUILD_JOBS:-2}"

usage() {
  cat >&2 <<'EOF'
Usage: build-apple-xcframework.sh OUTPUT_DIR

Builds the pinned OpenFHE Apple XCFramework (ios-arm64, ios-arm64-simulator,
macos-arm64) from clean, pinned source and stages it, its SBOM, its
provenance statement, and a staging manifest into OUTPUT_DIR.

OUTPUT_DIR is required and must resolve outside this repository's working
tree; there is no default and no path inside the repo is accepted.

The macos-arm64 slice's minimum deployment target is read from the tracked
clients/native/apple-deployment-target.pin.json (macos_minimum_deployment_target)
and fails closed if unset, malformed, or newer than the host's own macOS
version. The real Mach-O metadata of every macos-arm64 static library this
script produces is inspected with otool -l and must exactly match that
pinned target.

Environment:
  ARES_NATIVE_BUILD_JOBS               compiler parallelism per slice (default: 2)
  ARES_NATIVE_APPLE_CODESIGN_IDENTITY  optional codesign identity; unset skips signing
EOF
}

build_openfhe_slice() {
  local src="$1" install_dir="$2" platform="$3"
  local build_dir="${src}-build-${platform}"
  rm -rf "${build_dir}" "${install_dir}"

  local -a cmake_args=(
    -S "${src}" -B "${build_dir}"
    -DCMAKE_INSTALL_PREFIX="${install_dir}"
    -DBUILD_BENCHMARKS=OFF -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_EXTRAS=OFF
    -DWITH_OPENMP=OFF -DBUILD_SHARED=OFF -DBUILD_STATIC=ON
  )
  case "${platform}" in
    ios-arm64)
      cmake_args+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0)
      ;;
    ios-arm64-simulator)
      cmake_args+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0)
      ;;
    macos-arm64)
      cmake_args+=(-DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}")
      ;;
    *)
      die "unknown apple platform slice: ${platform}"
      ;;
  esac

  log_info "configuring OpenFHE for ${platform}"
  if [ "${platform}" = "macos-arm64" ]; then
    # CMAKE_OSX_DEPLOYMENT_TARGET alone is not reliably honored by every
    # translation unit in a project this size (this is the exact gap that
    # let a macOS-14-pinned build previously link against the host's
    # macOS-26 default). Also exporting MACOSX_DEPLOYMENT_TARGET pins
    # clang's own default for any sub-invocation that reads the
    # environment instead of (or in addition to) the CMake cache variable.
    MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" cmake "${cmake_args[@]}" >&2
  else
    cmake "${cmake_args[@]}" >&2
  fi
  log_info "building OpenFHE for ${platform} (jobs=${BUILD_JOBS})"
  if [ "${platform}" = "macos-arm64" ]; then
    MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" cmake --build "${build_dir}" -j"${BUILD_JOBS}" --target install >&2
  else
    cmake --build "${build_dir}" -j"${BUILD_JOBS}" --target install >&2
  fi

  [ -d "${install_dir}/lib" ] || die "OpenFHE build for ${platform} produced no install/lib directory: ${install_dir}/lib"

  if [ "${platform}" = "macos-arm64" ]; then
    # Verify the real Mach-O metadata of every OpenFHE static library this
    # slice just produced, rather than trusting that the CMake/environment
    # deployment-target flags above were actually honored -- see
    # verify_apple_macho_deployment_target in lib/common.sh.
    local component
    for component in OPENFHEcore OPENFHEpke OPENFHEbinfhe; do
      verify_apple_macho_deployment_target "${install_dir}/lib/lib${component}_static.a" "${MACOS_DEPLOYMENT_TARGET}" "${APPLE_OTOOL_PATH}"
    done
  fi

  # Reclaim the build directory (object files; far larger than the
  # installed libs/headers) immediately once install succeeds, so peak
  # disk usage across the whole run stays close to one slice's build
  # directory rather than growing with every additional platform.
  rm -rf "${build_dir}"
}

build_bridge_slice() {
  local install_dir="$1" bridge_build_dir="$2" platform="$3"
  rm -rf "${bridge_build_dir}"

  local -a cmake_args=(
    -S "${BRIDGE_APPLE_CMAKE_DIR}" -B "${bridge_build_dir}"
    -DOPENFHE_PREFIX="${install_dir}"
    -DARES_WRAPPER_SOURCE="$(bridge_source_path)"
  )
  case "${platform}" in
    ios-arm64)
      cmake_args+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0)
      ;;
    ios-arm64-simulator)
      cmake_args+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0)
      ;;
    macos-arm64)
      cmake_args+=(-DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}")
      ;;
    *)
      die "unknown Apple bridge platform slice: ${platform}"
      ;;
  esac

  log_info "configuring canonical bridge for ${platform}"
  if [ "${platform}" = "macos-arm64" ]; then
    MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" cmake "${cmake_args[@]}" >&2
  else
    cmake "${cmake_args[@]}" >&2
  fi
  log_info "building canonical bridge for ${platform} (jobs=${BUILD_JOBS})"
  if [ "${platform}" = "macos-arm64" ]; then
    MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" cmake --build "${bridge_build_dir}" -j"${BUILD_JOBS}" --target ares_privacy_core >&2
  else
    cmake --build "${bridge_build_dir}" -j"${BUILD_JOBS}" --target ares_privacy_core >&2
  fi

  local bridge_archive="${bridge_build_dir}/lib/libares_privacy_core.a"
  [ -f "${bridge_archive}" ] || die "Apple bridge build for ${platform} produced no static archive: ${bridge_archive}"
  if [ "${platform}" = "macos-arm64" ]; then
    verify_apple_macho_deployment_target "${bridge_archive}" "${MACOS_DEPLOYMENT_TARGET}" "${APPLE_OTOOL_PATH}"
  fi
  printf '%s' "${bridge_archive}"
}

combine_bridge_and_openfhe_static_libs() {
  local install_dir="$1" bridge_archive="$2" combined="$3" platform="$4"
  local -a libs=("${bridge_archive}")
  local component
  # OpenFHE's CMake install rules name the static-library targets with an
  # explicit "_static" suffix (e.g. OPENFHEcore_static -> libOPENFHEcore_static.a)
  # to coexist with the shared-library target of the same base name
  # (libOPENFHEcore.so, what Android links against) -- confirmed against
  # src/{core,pke,binfhe}/CMakeLists.txt, not assumed.
  for component in OPENFHEcore OPENFHEpke OPENFHEbinfhe; do
    local lib_path="${install_dir}/lib/lib${component}_static.a"
    [ -f "${lib_path}" ] || die "expected static library missing after build: ${lib_path}"
    libs+=("${lib_path}")
  done
  mkdir -p "$(dirname "${combined}")"
  libtool -static -o "${combined}" "${libs[@]}"
  [ -f "${combined}" ] || die "libtool did not produce combined static library: ${combined}"

  if [ "${platform}" = "macos-arm64" ]; then
    # Final safety net: verify the exact artifact that gets zipped into the
    # shipped xcframework, not just its individual pre-combination inputs.
    verify_apple_macho_deployment_target "${combined}" "${MACOS_DEPLOYMENT_TARGET}" "${APPLE_OTOOL_PATH}"
  fi
}

run_apple_xcframework_build() {
  local sw_vers_path="$1" otool_path="$2"
  shift 2
  require_trusted_apple_tool_path "${sw_vers_path}" "sw_vers"
  require_trusted_apple_tool_path "${otool_path}" "otool"
  APPLE_OTOOL_PATH="${otool_path}"

  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  require_cmd git
  require_cmd jq
  require_cmd cmake
  require_cmd xcodebuild
  require_cmd libtool
  require_cmd zip

  require_version_output "Xcode" '^Xcode [0-9]+\.' xcodebuild -version >/dev/null

  MACOS_DEPLOYMENT_TARGET="$(require_macos_deployment_target "${sw_vers_path}")"
  log_info "pinned macOS deployment target: ${MACOS_DEPLOYMENT_TARGET}"

  local output_dir
  output_dir="$(require_untracked_output_dir "${1:-}")"

  local version commit ares_rev
  version="$(read_pin openfhe_version)"
  commit="$(read_pin openfhe_source_commit)"
  ares_rev="$(ares_core_source_revision)"

  local work_dir="${output_dir}/.work/apple-xcframework"
  rm -rf "${work_dir}"
  mkdir -p "${work_dir}"

  local openfhe_src="${work_dir}/openfhe-src"
  clone_pinned_openfhe "${openfhe_src}"

  local -a built_platforms=()
  local -a slice_libs=()
  local headers_dir="${work_dir}/COpenFHEBridgeHeaders"
  stage_copenfhe_headers "${headers_dir}"

  local platform
  for platform in "${REQUIRED_PLATFORMS[@]}"; do
    local install_dir="${work_dir}/install/${platform}"
    build_openfhe_slice "${openfhe_src}" "${install_dir}" "${platform}"
    local bridge_build_dir="${work_dir}/bridge-build/${platform}"
    local bridge_archive
    bridge_archive="$(build_bridge_slice "${install_dir}" "${bridge_build_dir}" "${platform}")"
    local combined="${work_dir}/combined/${platform}/libAresPrivacyCore.a"
    combine_bridge_and_openfhe_static_libs "${install_dir}" "${bridge_archive}" "${combined}" "${platform}"
    slice_libs+=("${combined}")
    built_platforms+=("${platform}")
  done

  require_all_present "apple xcframework platform slices" "${REQUIRED_PLATFORMS[@]}" -- "${built_platforms[@]}"
  [ -f "${headers_dir}/openfhe_wrapper.h" ] || die "canonical bridge header was not staged: ${headers_dir}/openfhe_wrapper.h"
  [ -f "${headers_dir}/module.modulemap" ] || die "canonical bridge module map was not staged: ${headers_dir}/module.modulemap"

  local xcframework_dir="${work_dir}/AresPrivacyCore.xcframework"
  rm -rf "${xcframework_dir}"
  local -a xcodebuild_args=(-create-xcframework)
  local lib
  for lib in "${slice_libs[@]}"; do
    xcodebuild_args+=(-library "${lib}" -headers "${headers_dir}")
  done
  xcodebuild_args+=(-output "${xcframework_dir}")

  log_info "creating xcframework from ${#slice_libs[@]} slice(s)"
  xcodebuild "${xcodebuild_args[@]}" >&2
  [ -d "${xcframework_dir}" ] || die "xcodebuild did not produce ${xcframework_dir}"

  if [ -n "${ARES_NATIVE_APPLE_CODESIGN_IDENTITY:-}" ]; then
    require_cmd codesign
    log_info "codesigning xcframework"
    codesign --force --deep --sign "${ARES_NATIVE_APPLE_CODESIGN_IDENTITY}" "${xcframework_dir}" >&2
  else
    log_info "ARES_NATIVE_APPLE_CODESIGN_IDENTITY not set; staging unsigned (SHA-256 is the primary integrity check; record this as provenance-pinned but not code-signed)"
  fi

  local artifact_zip="${output_dir}/AresPrivacyCore-${version}-apple.xcframework.zip"
  rm -f "${artifact_zip}"
  ( cd "${work_dir}" && zip -r -q "${artifact_zip}" "$(basename "${xcframework_dir}")" )

  local artifact_sha256
  artifact_sha256="$(sha256_of "${artifact_zip}")"

  local sbom_path="${output_dir}/OpenFHE-${version}-apple.sbom.json"
  local provenance_path="${output_dir}/OpenFHE-${version}-apple.provenance.json"
  write_sbom "${sbom_path}" "AresPrivacyCore (OpenFHE)" "${version}" "${commit}"
  write_provenance "${provenance_path}" "$(basename "${artifact_zip}")" "${artifact_sha256}" \
    "${ares_rev}" "${commit}" "ares-core/clients/native/build-apple-xcframework.sh"

  local manifest_path="${output_dir}/OpenFHE-${version}-apple.staging-manifest.json"
  NATIVE_ARTIFACT_APPLE_MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" \
  emit_native_manifest "${manifest_path}" "apple_xcframework" "${artifact_zip}" "${artifact_sha256}" \
    "${version}" "${commit}" "${ares_rev}" \
    "${sbom_path}" "${provenance_path}" \
    "${REQUIRED_PLATFORMS[@]}"

  log_info "staged artifact:  ${artifact_zip}"
  log_info "staged sbom:      ${sbom_path}"
  log_info "staged provenance: ${provenance_path}"
  log_info "staged manifest:  ${manifest_path}"
}

# Direct execution is the production/release entrypoint. Tests source this
# file and call run_apple_xcframework_build through their own generated harness;
# no environment variable or command-line option can redirect these paths.
main() {
  require_trusted_apple_tool_path "${TRUSTED_UNAME_PATH}" "uname"
  local host_os
  host_os="$("${TRUSTED_UNAME_PATH}" -s)" \
    || die "trusted ${TRUSTED_UNAME_PATH} failed to report the host operating system"
  [ "${host_os}" = "Darwin" ] || die "Apple XCFramework production requires Darwin (host is ${host_os})"
  run_apple_xcframework_build "${TRUSTED_SW_VERS_PATH}" "${TRUSTED_OTOOL_PATH}" "$@"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
