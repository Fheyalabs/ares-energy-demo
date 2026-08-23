# Native Client Bridge Artifact Evidence

Date: 2026-07-19

## Scope

This report records release-staging evidence for immutable ARES-core native
bridge artifacts. It does not certify the separately-owned Fheya Rust privacy
core, a combined Fheya release manifest, artifact signing or publication, or
physical-device execution.

The artifacts compile the canonical tracked sources directly:

- `pkg/ares/crypto/cgo/openfhe_wrapper.{h,cpp}`
- `clients/kotlin/native/jni_openfhe.cpp` for Android

They are built against pinned OpenFHE source, not a Homebrew install or an
environment-selected source path.

## Source Validation

Executed from this worktree at ARES-core revision
`e72e874c3ac445aeeec76e0a7a8b9c3cf9896fa0`:

```sh
go test ./clients/native/... -count=1 -v
go vet ./...
go build ./...
git diff --check
```

All commands exited zero. The 24-test native suite covers Apple slices and
Android ABIs using mocked toolchains, pin validation, fail-closed paths,
canonical source ownership, encrypted-input JNI entry points, and the
immutable Swift release manifest.

The candidate restores the canonical CKKS and BFV encrypted-input C wrapper
functions that the current Kotlin JNI source calls. The focused
`TestCanonicalWrapperSuppliesEveryEncryptedInputJNIEntryPoint` test was red
until those declarations and implementations were present, then passed.

## Real Apple Build

A serialized build with bounded compiler parallelism completed:

```sh
PATH=/opt/homebrew/bin:$PATH \
  ARES_NATIVE_BUILD_JOBS=2 \
  ./clients/native/build-apple-xcframework.sh \
  /Volumes/Hardik_external_T7/ares-release-artifacts/apple-20260719-e72e874
```

Required slices completed: `ios-arm64`, `ios-arm64-simulator`, and
`macos-arm64`.

```text
/Volumes/Hardik_external_T7/ares-release-artifacts/apple-20260719-e72e874/AresPrivacyCore-v1.5.1-apple.xcframework.zip
SHA-256: 99ecfc0e414fe5ac29d9b90c69ae94ad80a95f890da06cd6fb25adfc32248737
```

`unzip -t` validates the archive. Every slice exports
`libAresPrivacyCore.a`, `openfhe_wrapper.h`, and `module.modulemap`. The
staging manifest records the pinned OpenFHE tag `v1.5.1`, source commit
`1306d14f8c26bb6150d3e6ad54f28dfe1007689e`, the ARES-core revision, and
hashes for its SBOM and provenance.

## Real Android Build

A serialized build used pinned Android NDK `27.2.12479018`. It takes the
target NDK JNI header and does not consume a host `JAVA_HOME` header:

```sh
env -u JAVA_HOME \
  ANDROID_NDK_HOME=/Volumes/Hardik_external_T7/android-toolchains/ndk-r27c-20260719/android-ndk-r27c \
  ARES_NATIVE_BUILD_JOBS=2 \
  ./clients/native/build-android-aar.sh \
  /Volumes/Hardik_external_T7/ares-release-artifacts/android-20260719-bridge
```

Required `arm64-v8a` and `x86_64` ABIs completed.

```text
/Volumes/Hardik_external_T7/ares-release-artifacts/android-20260719-bridge/AresPrivacyCore-v1.5.1-android.aar
SHA-256: 1ff7bc613f4f69da08927eaccd184d3cc617b9cf42ab7a45985f1130c1261528
```

`unzip -t` validates the AAR. Each ABI includes `libares_fhe_jni.so`,
`libOPENFHEcore.so`, `libOPENFHEpke.so`, and `libOPENFHEbinfhe.so`. The JNI
bridge has `RUNPATH=$ORIGIN` and `NEEDED` entries for those exact three
OpenFHE libraries. Provenance records the tracked Android compatibility patch:

```text
clients/native/patches/openfhe-v1.5.1-android-no-backtrace.patch
SHA-256: da5003b632d939afb35391b9161359ad2485e359f3faca33971c21b09b28ad70
```

## Clean Consumer Checks

A disposable external SwiftPM consumer used `Package.release.swift` as its
manifest and unzipped the Apple artifact to
`Artifacts/AresPrivacyCore.xcframework`:

```sh
swift package dump-package
swift build -c release --target AresClientFHE
```

`AresClientFHE` built successfully against the staged macOS binary target.
The only diagnostic is the existing `String(cString:)` deprecation in
`FHEEnvironment.swift`; it does not alter the artifact ABI.

Kotlin `:ares-client-fhe:test` also compiles and passes. Its native OpenFHE
tests correctly skip in this source-only Gradle invocation because the staged
AAR is not yet wired into Gradle's test runtime. The real Android build above
validates JNI/C++ compilation, not device or emulator loading.

## Remaining Release Boundaries

- Apple artifacts are unsigned because `ARES_NATIVE_APPLE_CODESIGN_IDENTITY`
  was intentionally unset. Release signing is still required.
- The Android AAR has not been installed or loaded on a device or emulator.
  Android signing, Maven publication, and consumer dependency wiring remain.
- Fheya's release assembler must stage these artifacts with Rust privacy-core
  bindings and run the combined clean-cache `release-artifact-gate`.
- Native N=6 CKKS/BFV restart, wire, and RSS acceptance remains required.
  The Fheya BFV execution path must prove the specified blind end-to-end
  contract; this ARES-core primitive alone is not that evidence.
