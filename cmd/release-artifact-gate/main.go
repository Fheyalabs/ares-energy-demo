// Command release-artifact-gate assembles and verifies ARES-core's own
// combined release-cache manifest from the Apple XCFramework and Android
// AAR artifacts staged by clients/native/build-apple-xcframework.sh and
// clients/native/build-android-aar.sh.
//
// It only ever assembles or verifies; it never tags, publishes, signs, or
// claims device/emulator runtime validation. See
// clients/native/README.md for the release-cache manifest schema and the
// scope of what "verified" means here.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Fheyalabs/ares-core/internal/releasebundle"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "assemble":
		runAssemble(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "-h", "--help":
		usage()
	default:
		fail("unknown subcommand %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  release-artifact-gate assemble -bundle-dir=DIR -repo-root=DIR -out=PATH
  release-artifact-gate verify   -manifest=PATH -bundle-dir=DIR -repo-root=DIR

assemble reads the Apple and Android *.staging-manifest.json files already
present in -bundle-dir, independently re-verifies every hash/pin/revision/
architecture claim they make, and writes one deterministic release-cache
manifest to -out.

verify re-reads -manifest and independently re-assembles -bundle-dir from
scratch, failing unless the two are identical (aside from generated_at).

Neither subcommand tags, publishes, signs, or claims device/emulator
runtime validation.
`)
}

func runAssemble(args []string) {
	fs := flag.NewFlagSet("assemble", flag.ExitOnError)
	bundleDir := fs.String("bundle-dir", "", "directory containing staged Apple/Android artifacts and their staging manifests (required)")
	repoRoot := fs.String("repo-root", "", "ARES-core git checkout root (required)")
	out := fs.String("out", "", "path to write the release-cache manifest to (required)")
	fs.Parse(args)

	if *bundleDir == "" || *repoRoot == "" || *out == "" {
		fs.Usage()
		fail("assemble: -bundle-dir, -repo-root, and -out are all required")
	}

	m, err := releasebundle.Assemble(*bundleDir, *repoRoot)
	if err != nil {
		fail("assemble: %v", err)
	}
	if err := releasebundle.WriteManifest(*out, m); err != nil {
		fail("assemble: %v", err)
	}
	fmt.Printf("wrote release-cache manifest: %s\n", *out)
}

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "path to a release-cache manifest produced by 'assemble' (required)")
	bundleDir := fs.String("bundle-dir", "", "directory containing staged Apple/Android artifacts and their staging manifests (required)")
	repoRoot := fs.String("repo-root", "", "ARES-core git checkout root (required)")
	fs.Parse(args)

	if *manifestPath == "" || *bundleDir == "" || *repoRoot == "" {
		fs.Usage()
		fail("verify: -manifest, -bundle-dir, and -repo-root are all required")
	}

	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		fail("verify: reading %s: %v", *manifestPath, err)
	}
	var m releasebundle.ReleaseCacheManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		fail("verify: parsing %s: %v", *manifestPath, err)
	}

	if err := releasebundle.Verify(*bundleDir, *repoRoot, &m); err != nil {
		fail("verify: %v", err)
	}
	fmt.Println("release-cache manifest verified OK")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "release-artifact-gate: "+format+"\n", args...)
	os.Exit(1)
}
