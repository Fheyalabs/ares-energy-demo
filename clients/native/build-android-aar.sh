#!/usr/bin/env bash
# Builds and stages the pinned OpenFHE Android AAR plus ARES-core's canonical
# JNI bridge from clean, pinned source, cross-compiled per ABI with the
# Android NDK. See clients/native/openfhe.pin.json and
# clients/native/android-ndk.pin.json for the exact pins, and
# clients/native/README.md for expected RSS/disk usage and the staging
# manifest schema.
#
# This script packages the bridge and all required OpenFHE shared libraries
# as a standalone AAR (jni/<abi>/*.so plus a minimal manifest). It does not
# alter a Kotlin/Gradle dependency declaration; wiring a consuming Gradle
# module to this artifact is separate release-packaging work.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Required ABIs: arm64-v8a covers real devices, x86_64 covers the emulator/
# host-test architecture. armeabi-v7a and x86 are optional and only built
# when explicitly requested via ARES_NATIVE_ANDROID_EXTRA_ABIS, since older
# 32-bit targets are increasingly out of scope for new releases.
REQUIRED_ABIS=(arm64-v8a x86_64)
ANDROID_PLATFORM="${ARES_NATIVE_ANDROID_PLATFORM:-android-24}"
BUILD_JOBS="${ARES_NATIVE_BUILD_JOBS:-2}"
BRIDGE_ANDROID_CMAKE_DIR="${SCRIPT_DIR}/bridge/android"

usage() {
  cat >&2 <<'EOF'
Usage: build-android-aar.sh OUTPUT_DIR

Builds the pinned OpenFHE Android AAR (arm64-v8a, x86_64 required; extra
ABIs opt-in) from clean, pinned source and stages it, its SBOM, its
provenance statement, and a staging manifest into OUTPUT_DIR.

OUTPUT_DIR is required and must resolve outside this repository's working
tree; there is no default and no path inside the repo is accepted.

Environment:
  ANDROID_NDK_HOME / ANDROID_NDK_ROOT   Android NDK root (required)
  ARES_NATIVE_ANDROID_PLATFORM          Android platform level (default: android-24)
  ARES_NATIVE_ANDROID_EXTRA_ABIS        comma-separated optional extra ABIs
                                         (e.g. "armeabi-v7a,x86")
  ARES_NATIVE_BUILD_JOBS                compiler parallelism per ABI (default: 2)
EOF
}

build_openfhe_abi() {
  local src="$1" install_dir="$2" abi="$3" ndk_root="$4"
  local build_dir="${src}-build-${abi}"
  rm -rf "${build_dir}" "${install_dir}"

  log_info "configuring OpenFHE for ${abi} (platform=${ANDROID_PLATFORM})"
  cmake -S "${src}" -B "${build_dir}" \
    -DCMAKE_TOOLCHAIN_FILE="${ndk_root}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="${abi}" \
    -DANDROID_PLATFORM="${ANDROID_PLATFORM}" \
    -DCMAKE_INSTALL_PREFIX="${install_dir}" \
    -DBUILD_BENCHMARKS=OFF -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_EXTRAS=OFF \
    -DWITH_OPENMP=OFF -DBUILD_SHARED=ON -DBUILD_STATIC=OFF \
    >&2

  log_info "building OpenFHE for ${abi} (jobs=${BUILD_JOBS})"
  cmake --build "${build_dir}" -j"${BUILD_JOBS}" --target install >&2

  [ -d "${install_dir}/lib" ] || die "OpenFHE build for ${abi} produced no install/lib directory: ${install_dir}/lib"

  # Reclaim the build directory (object files; far larger than the
  # installed libs) immediately once install succeeds, so peak disk usage
  # across the whole run stays close to one ABI's build directory rather
  # than growing with every additional ABI.
  rm -rf "${build_dir}"
}

stage_abi_shared_libs() {
  local install_dir="$1" bridge_library="$2" jni_abi_dir="$3"
  [ -f "${bridge_library}" ] || die "Android bridge library is missing: ${bridge_library}"
  mkdir -p "${jni_abi_dir}"
  cp "${bridge_library}" "${jni_abi_dir}/libares_fhe_jni.so"
  local component found=0
  for component in OPENFHEcore OPENFHEpke OPENFHEbinfhe; do
    local so_path="${install_dir}/lib/lib${component}.so"
    [ -f "${so_path}" ] || die "expected shared library missing after build: ${so_path}"
    cp "${so_path}" "${jni_abi_dir}/"
    found=$((found + 1))
  done
  [ "${found}" -eq 3 ] || die "expected 3 OpenFHE shared libraries staged for ${jni_abi_dir}, got ${found}"
}

build_android_bridge() {
  local install_dir="$1" bridge_build_dir="$2" abi="$3" ndk_root="$4" jni_include_dir="$5"
  rm -rf "${bridge_build_dir}"

  log_info "configuring canonical JNI bridge for ${abi} (platform=${ANDROID_PLATFORM})"
  cmake -S "${BRIDGE_ANDROID_CMAKE_DIR}" -B "${bridge_build_dir}" \
    -DCMAKE_TOOLCHAIN_FILE="${ndk_root}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="${abi}" \
    -DANDROID_PLATFORM="${ANDROID_PLATFORM}" \
    -DOPENFHE_PREFIX="${install_dir}" \
    -DARES_JNI_SOURCE="$(jni_bridge_source_path)" \
    -DARES_WRAPPER_SOURCE="$(bridge_source_path)" \
    -DARES_JNI_INCLUDE_DIR="${jni_include_dir}" \
    >&2
  log_info "building canonical JNI bridge for ${abi} (jobs=${BUILD_JOBS})"
  cmake --build "${bridge_build_dir}" -j"${BUILD_JOBS}" --target ares_fhe_jni >&2

  local bridge_library="${bridge_build_dir}/lib/libares_fhe_jni.so"
  [ -f "${bridge_library}" ] || die "Android bridge build for ${abi} produced no JNI library: ${bridge_library}"
  printf '%s' "${bridge_library}"
}

write_android_manifest() {
  local path="$1"
  cat > "${path}" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.openfheorg.openfhe">
</manifest>
EOF
}

write_empty_classes_jar() {
  local path="$1" work="$2"
  local jar_root="${work}/classes-jar-root/META-INF"
  mkdir -p "${jar_root}"
  printf 'Manifest-Version: 1.0\n' > "${jar_root}/MANIFEST.MF"
  rm -f "${path}"
  ( cd "${work}/classes-jar-root" && zip -q -r "${path}" META-INF )
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  require_cmd git
  require_cmd jq
  require_cmd cmake
  require_cmd zip

  local ndk_root
  ndk_root="$(require_android_ndk)"
  local jni_include_dir
  jni_include_dir="$(require_android_jni_include_dir "${ndk_root}")"

  local output_dir
  output_dir="$(require_untracked_output_dir "${1:-}")"

  local version commit ares_rev
  version="$(read_pin openfhe_version)"
  commit="$(read_pin openfhe_source_commit)"
  ares_rev="$(ares_core_source_revision)"

  local -a abis=("${REQUIRED_ABIS[@]}")
  if [ -n "${ARES_NATIVE_ANDROID_EXTRA_ABIS:-}" ]; then
    IFS=',' read -r -a extra_abis <<< "${ARES_NATIVE_ANDROID_EXTRA_ABIS}"
    abis+=("${extra_abis[@]}")
  fi

  local work_dir="${output_dir}/.work/android-aar"
  rm -rf "${work_dir}"
  mkdir -p "${work_dir}"

  local openfhe_src="${work_dir}/openfhe-src"
  clone_pinned_openfhe "${openfhe_src}"
  local compatibility_patch_path compatibility_patch_sha256
  compatibility_patch_path="$(android_openfhe_compatibility_patch_path)"
  compatibility_patch_sha256="$(apply_android_openfhe_compatibility_patch "${openfhe_src}")"

  local aar_root="${work_dir}/aar-root"
  rm -rf "${aar_root}"
  mkdir -p "${aar_root}/jni"

  local -a built_abis=()
  local abi
  for abi in "${abis[@]}"; do
    local install_dir="${work_dir}/install/${abi}"
    build_openfhe_abi "${openfhe_src}" "${install_dir}" "${abi}" "${ndk_root}"
    local bridge_library
    bridge_library="$(build_android_bridge "${install_dir}" "${work_dir}/bridge-build/${abi}" "${abi}" "${ndk_root}" "${jni_include_dir}")"
    stage_abi_shared_libs "${install_dir}" "${bridge_library}" "${aar_root}/jni/${abi}"
    built_abis+=("${abi}")
  done

  require_all_present "android aar ABIs" "${REQUIRED_ABIS[@]}" -- "${built_abis[@]}"

  write_android_manifest "${aar_root}/AndroidManifest.xml"
  write_empty_classes_jar "${aar_root}/classes.jar" "${work_dir}"

  local artifact_aar="${output_dir}/AresPrivacyCore-${version}-android.aar"
  rm -f "${artifact_aar}"
  ( cd "${aar_root}" && zip -q -r "${artifact_aar}" AndroidManifest.xml classes.jar jni )

  local artifact_sha256
  artifact_sha256="$(sha256_of "${artifact_aar}")"

  local sbom_path="${output_dir}/OpenFHE-${version}-android.sbom.json"
  local provenance_path="${output_dir}/OpenFHE-${version}-android.provenance.json"
  write_sbom "${sbom_path}" "AresPrivacyCore (OpenFHE)" "${version}" "${commit}"
  write_provenance "${provenance_path}" "$(basename "${artifact_aar}")" "${artifact_sha256}" \
    "${ares_rev}" "${commit}" "ares-core/clients/native/build-android-aar.sh" \
    "${compatibility_patch_path}" "${compatibility_patch_sha256}"

  local manifest_path="${output_dir}/OpenFHE-${version}-android.staging-manifest.json"
  NATIVE_ARTIFACT_COMPATIBILITY_PATCH_PATH="${compatibility_patch_path}" \
  NATIVE_ARTIFACT_COMPATIBILITY_PATCH_SHA256="${compatibility_patch_sha256}" \
    emit_native_manifest "${manifest_path}" "android_aar" "${artifact_aar}" "${artifact_sha256}" \
      "${version}" "${commit}" "${ares_rev}" \
      "${sbom_path}" "${provenance_path}" \
      "${built_abis[@]}"

  log_info "staged artifact:  ${artifact_aar}"
  log_info "staged sbom:      ${sbom_path}"
  log_info "staged provenance: ${provenance_path}"
  log_info "staged manifest:  ${manifest_path}"
}

main "$@"
