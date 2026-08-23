# clients/native

Native client artifact staging layer for the v0.9.15 release line: builds
and stages the pinned OpenFHE 1.5.1 **and ARES-core's canonical C/JNI bridge**
from clean, pinned source, cross-compiled per platform/ABI.

The Apple artifact is `AresPrivacyCore.xcframework`: a static library that
combines the canonical `openfhe_wrapper.cpp` with OpenFHE and exports the
`COpenFHEBridge` C module. The Android artifact is an AAR containing
`libares_fhe_jni.so` beside the three OpenFHE shared libraries for every
required ABI. Both use the same tracked bridge source already exercised by
the Go, Swift, and Kotlin development clients; neither duplicates FHE logic.

`clients/swift/Package.release.swift` is the immutable consumer manifest for
a release staging directory. It declares a `COpenFHEBridge` binary target at
`Artifacts/AresPrivacyCore.xcframework`; it contains no local Homebrew path,
environment switch, or workstation dependency. The tracked `Package.swift`
remains the development manifest and is intentionally not a release input.

**Scope boundary:** the scripts stage only the native artifacts owned by this
repository. They do not publish package coordinates, alter downstream
dependencies, or assemble a consumer product release. Downstream consumers
remain responsible for their own bindings, provenance, and release gates.

## Pins

- `openfhe.pin.json` — `openfhe_version` (git tag), `openfhe_source_url`,
  and `openfhe_source_commit` (the exact commit that tag must resolve to).
  Verified live against `https://api.github.com/repos/openfheorg/openfhe-development/git/refs/tags/v1.5.1`
  when this pin was written.
- `android-ndk.pin.json` — `android_ndk_min_major_version`, the minimum
  Android NDK major version `build-android-aar.sh` accepts.
- `apple-deployment-target.pin.json` —
  `macos_minimum_deployment_target`, currently `14.0`, the canonical
  `MAJOR.MINOR` minimum for the shipped macOS slice. Leading zero forms such
  as `014.0` or `14.00` are not canonical release values.

These files are the sole tracked source of truth for what is releasable.
Neither script accepts an ordinary environment variable to redirect them;
release builds cannot substitute workstation or downstream-consumer inputs.
The only override is `ARES_NATIVE_TEST_MODE=1` plus an
explicitly-named `ARES_NATIVE_TEST_*` variable, gated so it can never
activate by accident; see "Testing" below.

Android additionally applies the tracked
`clients/native/patches/openfhe-v1.5.1-android-no-backtrace.patch` after the
OpenFHE commit check. OpenFHE 1.5.1 mistakes Android Clang for generic
GNU/Linux and calls `execinfo` APIs that the Android NDK does not provide. The
one-line patch selects OpenFHE's existing empty-call-stack fallback for
Android. It is applied with `git apply --check`, must change exactly
`src/core/lib/utils/get-call-stack.cpp`, and its path and SHA-256 are recorded
in the Android manifest and provenance.

## Usage

```
clients/native/build-apple-xcframework.sh OUTPUT_DIR
clients/native/build-android-aar.sh OUTPUT_DIR
```

`OUTPUT_DIR` is a required, explicit argument. There is no default, and a
path that resolves inside this repository's working tree is rejected —
native build output (source clones, object files, the staged artifacts
themselves) must never be committed, and giving it nowhere accidental to
land is the enforcement mechanism, not a policy note. Point it at somewhere
like `/Volumes/<external-disk>/native-staging` locally, or `${RUNNER_TEMP}`
in CI (see `.github/workflows/release-clients.yml`).

Each script writes, into `OUTPUT_DIR`:

- the artifact itself (`AresPrivacyCore-<version>-apple.xcframework.zip` or
  `AresPrivacyCore-<version>-android.aar`);
- `*.sbom.json` — a minimal CycloneDX-shaped SBOM naming the embedded
  OpenFHE version/commit and ARES bridge artifact;
- `*.provenance.json` — a minimal SLSA-provenance-shaped statement binding
  the artifact's SHA-256 to its exact source commit and the ares-core
  revision that triggered the build;
- `*.staging-manifest.json` — see schema below.

A `.work/` subdirectory under `OUTPUT_DIR` holds the OpenFHE source clone
and per-platform/per-ABI build directories; each build directory is removed
immediately after that slice installs successfully (see "Disk usage"
below), so it does not need to be cleaned up separately, but nothing
prevents deleting `OUTPUT_DIR/.work` once staging succeeds.

## Fail-closed guarantees

Both scripts exit nonzero and produce **no** artifact/manifest, rather than
a partial or best-effort one, when:

- any required toolchain command is missing (`git`, `jq`, `cmake`, plus
  `xcodebuild`/`libtool`/`zip` for Apple; `cmake` plus the NDK for Android);
- the installed Xcode version does not report a parsable `Xcode N.M` string;
- the tracked Apple deployment target is missing, non-canonical, newer than
  the build host, or does not exactly equal every `minos` value inspected
  from each produced macOS Mach-O archive;
- `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) is unset, does not exist, has
  no `build/cmake/android.toolchain.cmake`, has no `source.properties`, or
  reports a major version below `android-ndk.pin.json`'s pinned minimum;
- the cloned OpenFHE tag's actual `HEAD` commit does not exactly equal the
  pinned `openfhe_source_commit` — a moved or re-pointed upstream tag is
  caught, not trusted;
- the exact-context Android compatibility patch cannot apply cleanly, or it
  would modify any file other than OpenFHE's call-stack implementation;
- any required platform slice (Apple: `ios-arm64`, `ios-arm64-simulator`,
  `macos-arm64`) or ABI (Android: `arm64-v8a`, `x86_64`) fails to build or
  produce its bridge and OpenFHE libraries;
- the configured Android NDK does not provide exactly one target
  `sysroot/usr/include/jni.h` header for the Android JNI build;
- the output directory argument is missing, or resolves inside this
  repository.

Optional/extra Android ABIs (`armeabi-v7a`, `x86` via
`ARES_NATIVE_ANDROID_EXTRA_ABIS`) are attempted but are not part of the
fail-closed required set.

Apple XCFramework signing (`ARES_NATIVE_APPLE_CODESIGN_IDENTITY`) is
best-effort: an unset identity stages an unsigned, hash-verified artifact
and logs that explicitly, rather than failing the whole build, since a
local/CI staging run will not usually have a release signing identity
available. The SHA-256 in the staging manifest is the primary integrity
check regardless of signing state.

## Staging manifest schema

```json
{
  "schema_version": 1,
  "artifact_kind": "apple_xcframework | android_aar",
  "artifact_path": "...",
  "artifact_sha256": "...",
  "openfhe_version": "v1.5.1",
  "openfhe_source_commit": "...",
  "ares_core_source_revision": "...",
  "target_architectures": ["..."],
  "sbom_path": "...",
  "sbom_sha256": "...",
  "provenance_path": "...",
  "provenance_sha256": "...",
  "apple_macos_deployment_target": "14.0",
  "generated_at": "..."
}
```

`apple_macos_deployment_target` is required for `apple_xcframework` and
omitted for `android_aar`. The Apple build records the tracked value only
after inspecting the produced macOS libraries with `otool`.

The schema is intended for product-neutral downstream integration.
`ares_core_source_revision` binds the staged artifacts to this repository's
exact source revision; consumers can include that value and the accompanying
artifact, SBOM, and provenance hashes in their own release evidence without
this repository depending on a consumer-specific assembler.

## Disk usage and RSS

These are from-scratch native builds of a template-heavy C++ lattice-crypto
library, not lightweight scripting. Budget accordingly before running a
real (non-mocked) build:

- **Per-slice/per-ABI build**: OpenFHE's own build system reports comparable
  full from-source builds taking on the order of several minutes to tens of
  minutes per target on a modern multi-core machine, with compiler RSS in
  the low single-digit GB range per parallel job (some translation units in
  `PALISADE`/`OpenFHE`'s core and `pke` libraries are large template
  instantiations). `ARES_NATIVE_BUILD_JOBS` (default `2`) bounds
  parallelism, and therefore peak RSS, deliberately rather than defaulting
  to "all cores" — raise it only on a machine with enough free RAM per job
  (roughly 2-3 GiB free per job is a reasonable starting budget; measure on
  your own machine before raising it for a real release build).
- **Disk**: a single platform/ABI's build directory (object files) has been
  observed in the low-single-digit-GB range for OpenFHE; both scripts
  delete each build directory immediately after that slice's `cmake
  --install` succeeds, so peak disk usage stays close to one build
  directory's worth plus the (much smaller, header+library only) install
  directories already completed, rather than growing linearly with the
  full platform/ABI list. The final staged artifacts themselves (combined
  static libs in an xcframework, or per-ABI shared libs in an aar) are
  small by comparison (tens of MB).
- **Serialization**: both scripts build platforms/ABIs strictly one at a
  time (a plain sequential loop, never backgrounded) — this is the "native
  builds are serialized" requirement, distinct from
  `ARES_NATIVE_BUILD_JOBS` (which only bounds *compiler* parallelism
  *within* one slice's build). The release workflow additionally serializes
  the Apple and Android jobs against each other (see
  `.github/workflows/release-clients.yml`) even though they run on
  independent macOS/Ubuntu runners and could technically overlap.
- Always point `OUTPUT_DIR` at a volume with enough free space for at least
  one platform/ABI's peak build directory plus the source clone (OpenFHE's
  source tree itself is on the order of a few hundred MB) — never the
  system/boot volume if that volume is otherwise low on space.

## Testing

`clients/native/*_test.go` (package `native_test`, run via `go test
./clients/native/...`) drive both scripts as real subprocesses against a
fully controlled `PATH` (real `git`/`jq`/`zip`/coreutils, plus mocked
`cmake`/`xcodebuild`/`libtool` that fake a successful or selectively-failing
build without ever compiling anything) and a real, tiny local git
repository standing in for the OpenFHE source (so `clone_pinned_openfhe`'s
`git clone` + commit-verification logic is exercised for real, just against
a fast local repo instead of the network). This is what
`ARES_NATIVE_TEST_MODE=1` plus `ARES_NATIVE_TEST_OPENFHE_SOURCE_URL` /
`ARES_NATIVE_TEST_PIN_FILE` / `ARES_NATIVE_TEST_NDK_PIN_FILE` exist for —
they are read only when `ARES_NATIVE_TEST_MODE=1` is also set, so they can
never activate against a real release invocation by accident.

Run the tests:

```
go test ./clients/native/... -v -count=1
```

These tests never invoke a real toolchain build (no real OpenFHE compile
happens), so they run in seconds. Run a real, non-mocked build only when
the real toolchains (Xcode, Android NDK, cmake) are already installed and
the target volume has enough free space per the disk guidance above.

## Release-cache bundle assembly and verification

`internal/releasebundle` (Go package) and `cmd/release-artifact-gate` (its
CLI) are ARES-core's own assembly and verification step for its own two
staged platform artifacts. They consume the Apple and Android staging
output described above and produce one deterministic release-cache
manifest; they do not build, sign, publish, tag, or claim device/emulator
runtime validation of anything.

This is deliberately scoped to what this repository owns: it does not
combine these artifacts with a downstream consumer's own bindings and
provenance evidence, and it is not a substitute for that consumer's own,
separately-owned release-artifact gate (see the "Scope boundary" note
above). Treat it as the release-time counterpart to the fail-closed staging
guarantees already documented above: an internal consistency and integrity
check over exactly the two artifacts this repository stages, nothing more.

### What it checks

Given a bundle directory containing both platforms' staged output and this
repository's checkout root, `release-artifact-gate assemble` fails closed
unless:

- both `*.staging-manifest.json` files are present, exactly one of each
  `artifact_kind`, and every hash they claim (artifact, SBOM, provenance)
  matches a hash recomputed from the actual file on disk;
- `ares_core_source_revision`, `openfhe_version`, and
  `openfhe_source_commit` agree exactly between the two platform artifacts;
- that shared `openfhe_version`/`openfhe_source_commit` matches the
  currently tracked `clients/native/openfhe.pin.json` (an artifact staged
  against a since-rotated pin is rejected, not silently bundled);
- `clients/native/android-ndk.pin.json` is present and well-formed;
- the tracked `clients/native/apple-deployment-target.pin.json` value, the
  Apple staging manifest's `apple_macos_deployment_target`, and every
  inspected Mach-O `minos` value are the same canonical string (`14.0` for
  this release line); numeric aliases such as `014.0` and `14.00` are
  rejected rather than normalized;
- the repo root's checkout is clean (`git status --porcelain` empty) and
  its `HEAD` exactly equals the artifacts' recorded
  `ares_core_source_revision` — the "clean-cache" guarantee: a bundle
  cannot be assembled from a stale or locally-modified tree;
- every required Apple slice / Android ABI (the same sets documented above)
  is present, and the artifact archives actually contain what they claim:
  the Android AAR has `libares_fhe_jni.so` plus all three OpenFHE shared
  libraries under `jni/<abi>/` for every required ABI, and the Apple
  XCFramework has `libAresPrivacyCore.a` plus the `COpenFHEBridge` module
  headers for every required slice;
- `clients/swift/Package.release.swift` contains no local
  (`.package(path: ...)`) dependency, no `ProcessInfo`-driven or
  workstation-toolchain-path (`/usr/local`, `/opt/homebrew`) substitution,
  and does bind the staged `COpenFHEBridge` binary target.

None of the above is re-derived from the native build scripts or their
`emit_native_manifest` output at gate time — the gate opens the actual
staged files and recomputes everything itself, the same fail-closed
posture as the scripts that produced them.

The production release gate requires Darwin and the verified system tool at
`/usr/bin/otool`; it does not resolve the inspector through `PATH`. A missing
or invalid system tool is a hard failure, not permission to trust producer
metadata. `.github/workflows/release-clients.yml` therefore pins the gate job
to `macos-14`, and the production CLI fails closed on every non-Darwin runtime.

`release-artifact-gate verify -manifest=... -bundle-dir=... -repo-root=...`
re-assembles the bundle from scratch and requires the result to be
identical (aside from `generated_at`) to the given manifest, so a
hand-edited or stale `release-cache-manifest.json` is rejected even if it
happens to look internally plausible on its own.

### Known limitation: NDK provenance

The Android staging manifest (see schema above) does not record which
exact NDK build produced a given artifact — that would require changing
`build-android-aar.sh`, which is out of scope here. The gate's NDK check is
therefore limited to confirming `android-ndk.pin.json` is present and
well-formed, not to independently re-deriving the exact NDK version that
built a specific staged AAR.

### Release-cache manifest schema

```json
{
  "schema_version": 1,
  "ares_core_source_revision": "...",
  "openfhe_version": "v1.5.1",
  "openfhe_source_commit": "...",
  "apple": {
    "artifact_kind": "apple_xcframework",
    "artifact_file": "AresPrivacyCore-v1.5.1-apple.xcframework.zip",
    "artifact_sha256": "...",
    "target_architectures": ["ios-arm64", "ios-arm64-simulator", "macos-arm64"],
    "apple_macos_deployment_target": "14.0",
    "sbom_file": "...", "sbom_sha256": "...",
    "provenance_file": "...", "provenance_sha256": "..."
  },
  "android": {
    "artifact_kind": "android_aar",
    "artifact_file": "AresPrivacyCore-v1.5.1-android.aar",
    "artifact_sha256": "...",
    "target_architectures": ["arm64-v8a", "x86_64"],
    "sbom_file": "...", "sbom_sha256": "...",
    "provenance_file": "...", "provenance_sha256": "..."
  },
  "swift_release_manifest_sha256": "...",
  "generated_at": "..."
}
```

Artifact/SBOM/provenance files are recorded as bundle-relative basenames,
never the absolute local path the native build scripts happened to use for
`OUTPUT_DIR` — a release-cache manifest is meant to be reproducible from a
copy of the bundle directory on any machine.

### Testing

`internal/releasebundle/*_test.go` cover `Assemble` and `Verify` directly
against fixture bundles (a real, tiny, committed local git repository plus
hand-built fixture zip archives shaped like the real artifacts), including
mutation coverage for a mismatched source revision, a mismatched artifact
hash, a local SwiftPM path dependency, an environment-driven dependency
substitution, an absent required Android ABI/JNI library, non-canonical
deployment-target forms, and decoy/duplicate macOS archive members.
`cmd/release-artifact-gate/main_test.go` drives the built CLI binary as a
real subprocess through `assemble` then `verify` against a fixture bundle,
including a tampered-artifact rejection case, so the exit-code and
stdout/stderr contract is exercised end to end, not just the underlying Go
functions.

In-process bundle tests use a `_test.go`-only metadata runner and deterministic
`minos` markers while retaining the production ZIP validation and member
selection code. This keeps `.github/workflows/go.yml`'s ordinary
`ubuntu-latest` `go test ./...` run hermetic without exposing an inspector
override to the production CLI. Darwin-only subprocess tests compile tiny
real Mach-O archives and inspect them with the verified `/usr/bin/otool`;
adversarial tests prove a PATH-shadowed fake cannot satisfy the gate. Neither
test path runs an OpenFHE build.

```
go test ./internal/releasebundle/... ./cmd/release-artifact-gate/... -v -count=1
```
