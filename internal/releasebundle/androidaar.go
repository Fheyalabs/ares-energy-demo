package releasebundle

import (
	"archive/zip"
	"fmt"
)

// checkAndroidAARContents fails closed unless every ABI in requiredABIs has
// every entry in requiredAndroidLibraries present under jni/<abi>/ in the
// AAR at path. It never trusts the staging manifest's own
// target_architectures claim: it opens the actual archive and looks.
func checkAndroidAARContents(path string, requiredABIs []string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("opening android artifact %s as zip: %w", path, err)
	}
	defer r.Close()

	present := make(map[string]bool, len(r.File))
	for _, f := range r.File {
		present[f.Name] = true
	}

	for _, abi := range requiredABIs {
		var missing []string
		for _, lib := range requiredAndroidLibraries {
			entry := "jni/" + abi + "/" + lib
			if !present[entry] {
				missing = append(missing, lib)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("android artifact %s is missing required libraries for ABI %s: %v", path, abi, missing)
		}
	}
	return nil
}
