package releasebundle

import (
	"archive/zip"
	"fmt"
)

// checkAppleXCFrameworkContents fails closed unless every platform slice in
// requiredPlatforms has its own directory entry (a path segment matching
// the slice name exactly) containing libAresPrivacyCore.a and the
// COpenFHEBridge module headers. It never trusts the staging manifest's own
// target_architectures claim: it opens the actual archive and looks.
func checkAppleXCFrameworkContents(path string, requiredPlatforms []string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("opening apple artifact %s as zip: %w", path, err)
	}
	defer r.Close()
	if err := validateZIPMemberNames(r.File); err != nil {
		return fmt.Errorf("apple artifact %s: %w", path, err)
	}

	present := make(map[string]bool, len(r.File))
	for _, f := range r.File {
		present[f.Name] = true
	}

	for _, slice := range requiredPlatforms {
		prefix := "AresPrivacyCore.xcframework/" + slice + "/"
		hasLib := present[prefix+"libAresPrivacyCore.a"]
		hasHeader := present[prefix+"Headers/openfhe_wrapper.h"]
		hasModulemap := present[prefix+"Headers/module.modulemap"]
		if slice == "macos-arm64" && !hasLib {
			return fmt.Errorf("apple artifact %s is missing canonical macOS library member %s", path, canonicalAppleMacOSLibraryMember)
		}
		if !hasLib || !hasHeader || !hasModulemap {
			return fmt.Errorf("apple artifact %s is missing required bridge module contents for slice %s (lib=%v header=%v modulemap=%v)", path, slice, hasLib, hasHeader, hasModulemap)
		}
	}
	return nil
}
