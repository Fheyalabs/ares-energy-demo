package releasebundle

import (
	"archive/zip"
	"fmt"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

// validateZIPMemberNames rejects names whose interpretation can differ
// between ZIP readers or Apple filesystems. Accepted paths use a portable
// ASCII subset and are collision-keyed case-insensitively after canonical
// slash/path cleanup before callers select any member.
func validateZIPMemberNames(files []*zip.File) error {
	seen := make(map[string]string, len(files))
	for _, file := range files {
		name := file.Name
		if file.NonUTF8 {
			return fmt.Errorf("ZIP member %q has the ambiguous NonUTF8 flag set", name)
		}
		if err := validateZIPMemberName(name); err != nil {
			return err
		}
		if file.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ZIP member %q is a symbolic link", name)
		}
		collisionKey := strings.ToLower(normalizedZIPMemberName(name))
		if previous, ok := seen[collisionKey]; ok {
			return fmt.Errorf("duplicate or case-insensitive ZIP member %q collides with %q", name, previous)
		}
		seen[collisionKey] = name
	}
	return nil
}

func normalizedZIPMemberName(name string) string {
	normalized := strings.ReplaceAll(name, `\`, "/")
	normalized = strings.TrimLeft(normalized, "/")
	return path.Clean(strings.TrimSuffix(normalized, "/"))
}

func validateZIPMemberName(name string) error {
	if name == "" || !utf8.ValidString(name) {
		return fmt.Errorf("ZIP member name %q is empty or invalid UTF-8", name)
	}
	for i := 0; i < len(name); i++ {
		if !isPortableAppleZIPNameByte(name[i]) {
			return fmt.Errorf("ZIP member %q contains byte 0x%02x outside the portable ASCII name set", name, name[i])
		}
	}
	if strings.Contains(name, `\`) {
		return fmt.Errorf("ZIP member %q uses a non-canonical backslash separator", name)
	}
	if strings.HasPrefix(name, "/") || hasWindowsDrivePrefix(name) {
		return fmt.Errorf("ZIP member %q uses an absolute path", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return fmt.Errorf("ZIP member %q is not a canonical relative path", name)
	}
	for _, component := range strings.Split(trimmed, "/") {
		if component == "." || component == ".." {
			return fmt.Errorf("ZIP member %q contains an unsafe path component", name)
		}
	}
	return nil
}

func isPortableAppleZIPNameByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '/' || value == '.' || value == '_' || value == '-'
}

func hasWindowsDrivePrefix(name string) bool {
	return len(name) >= 3 && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) && name[1] == ':' && name[2] == '/'
}
