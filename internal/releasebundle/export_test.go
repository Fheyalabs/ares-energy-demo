package releasebundle

import (
	"fmt"
	"os"
	"strings"
)

const testMachOMinosMarker = "ARES_RELEASEBUNDLE_TEST_MINOS="

// AssembleForTest substitutes only the extracted Mach-O metadata command.
// The symbol exists only in the test build; ZIP validation, member selection,
// and every other gate check execute through the production implementation.
func AssembleForTest(bundleDir, repoRoot string) (*ReleaseCacheManifest, error) {
	return assemble(bundleDir, repoRoot, inspectAppleDeploymentTargetFixture)
}

func VerifyForTest(bundleDir, repoRoot string, m *ReleaseCacheManifest) error {
	return verify(bundleDir, repoRoot, m, inspectAppleDeploymentTargetFixture)
}

func inspectAppleDeploymentTargetFixture(artifactPath string) ([]string, error) {
	return inspectAppleMacOSSliceDeploymentTargetWithRunner(artifactPath, func(extractedPath string) ([]byte, error) {
		raw, err := os.ReadFile(extractedPath)
		if err != nil {
			return nil, err
		}
		marker := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(marker, testMachOMinosMarker) {
			return nil, fmt.Errorf("test Mach-O member has no deployment-target marker")
		}
		minos := strings.TrimPrefix(marker, testMachOMinosMarker)
		return []byte("Load command 1\n      cmd LC_BUILD_VERSION\n    minos " + minos + "\n"), nil
	})
}
