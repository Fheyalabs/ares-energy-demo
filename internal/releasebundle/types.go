// Package releasebundle assembles and verifies ARES-core's own combined
// release-cache manifest from the per-platform artifacts that
// clients/native/build-apple-xcframework.sh and
// clients/native/build-android-aar.sh already stage.
//
// This package is deliberately self-contained: it reads only tracked
// ARES-core files (the OpenFHE/NDK pin files, clients/swift/Package.release.swift)
// and the staged artifact bundle, and it never imports or depends on
// anything outside this repository. It does not attempt to reproduce or
// substitute for a downstream consumer's own combined release-artifact
// gate that folds in artifacts this repository does not own.
package releasebundle

// Artifact kinds, matching the artifact_kind values
// clients/native/lib/common.sh's emit_native_manifest writes.
const (
	ArtifactKindAppleXCFramework = "apple_xcframework"
	ArtifactKindAndroidAAR       = "android_aar"
)

// RequiredApplePlatforms and RequiredAndroidABIs are this package's own,
// independently-declared minimum acceptance set. They intentionally
// duplicate (rather than parse out of) the REQUIRED_PLATFORMS/REQUIRED_ABIS
// arrays in build-apple-xcframework.sh / build-android-aar.sh: the gate
// must not trust the producing script's own claim of what it built, only
// what is actually present in the staged artifact bytes.
var (
	RequiredApplePlatforms = []string{"ios-arm64", "ios-arm64-simulator", "macos-arm64"}
	RequiredAndroidABIs    = []string{"arm64-v8a", "x86_64"}
)

// requiredAndroidLibraries are the shared objects every required ABI
// directory in the AAR must contain: the canonical ARES JNI bridge plus
// the three OpenFHE component libraries it links against.
var requiredAndroidLibraries = []string{
	"libares_fhe_jni.so",
	"libOPENFHEcore.so",
	"libOPENFHEpke.so",
	"libOPENFHEbinfhe.so",
}

// ArtifactManifest mirrors the JSON object clients/native/lib/common.sh's
// emit_native_manifest function writes as *.staging-manifest.json. Field
// names and JSON tags match exactly; this package only ever reads that
// output, never the scripts that produce it.
type ArtifactManifest struct {
	SchemaVersion            int      `json:"schema_version"`
	ArtifactKind             string   `json:"artifact_kind"`
	ArtifactPath             string   `json:"artifact_path"`
	ArtifactSHA256           string   `json:"artifact_sha256"`
	OpenFHEVersion           string   `json:"openfhe_version"`
	OpenFHESourceCommit      string   `json:"openfhe_source_commit"`
	AresCoreSourceRevision   string   `json:"ares_core_source_revision"`
	TargetArchitectures      []string `json:"target_architectures"`
	SBOMPath                 string   `json:"sbom_path"`
	SBOMSHA256               string   `json:"sbom_sha256"`
	ProvenancePath           string   `json:"provenance_path"`
	ProvenanceSHA256         string   `json:"provenance_sha256"`
	GeneratedAt              string   `json:"generated_at"`
	CompatibilityPatchPath   string   `json:"openfhe_compatibility_patch_path,omitempty"`
	CompatibilityPatchSHA256 string   `json:"openfhe_compatibility_patch_sha256,omitempty"`
	// AppleMACOSDeploymentTarget is set only on the apple_xcframework
	// artifact: the macos-arm64 slice's minimum deployment target, as
	// recorded by build-apple-xcframework.sh's own real Mach-O inspection
	// (see clients/native/lib/common.sh's verify_apple_macho_deployment_target).
	AppleMACOSDeploymentTarget string `json:"apple_macos_deployment_target,omitempty"`
}

// ArtifactRef is the bundle-relative record of one platform artifact inside
// a ReleaseCacheManifest. Unlike ArtifactManifest.ArtifactPath (an absolute
// path on the machine that ran the native build script), file references
// here are bundle-relative basenames: a release-cache manifest must be
// reproducible from a bundle directory copied to any machine, not tied to
// wherever OUTPUT_DIR happened to be when it was staged.
type ArtifactRef struct {
	ArtifactKind        string   `json:"artifact_kind"`
	ArtifactFile        string   `json:"artifact_file"`
	ArtifactSHA256      string   `json:"artifact_sha256"`
	TargetArchitectures []string `json:"target_architectures"`
	SBOMFile            string   `json:"sbom_file"`
	SBOMSHA256          string   `json:"sbom_sha256"`
	ProvenanceFile      string   `json:"provenance_file"`
	ProvenanceSHA256    string   `json:"provenance_sha256"`
	// AppleMACOSDeploymentTarget is populated only on the Apple ref; empty
	// (and omitted) on the Android ref.
	AppleMACOSDeploymentTarget string `json:"apple_macos_deployment_target,omitempty"`
}

// ReleaseCacheManifest is the single deterministic manifest Assemble
// produces from one Apple staging manifest and one Android staging
// manifest. Field order is fixed so that byte-identical bundle inputs
// produce byte-identical output modulo GeneratedAt.
type ReleaseCacheManifest struct {
	SchemaVersion              int         `json:"schema_version"`
	AresCoreSourceRevision     string      `json:"ares_core_source_revision"`
	OpenFHEVersion             string      `json:"openfhe_version"`
	OpenFHESourceCommit        string      `json:"openfhe_source_commit"`
	Apple                      ArtifactRef `json:"apple"`
	Android                    ArtifactRef `json:"android"`
	SwiftReleaseManifestSHA256 string      `json:"swift_release_manifest_sha256"`
	GeneratedAt                string      `json:"generated_at"`
}
