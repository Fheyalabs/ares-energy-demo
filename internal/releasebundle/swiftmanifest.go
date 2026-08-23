package releasebundle

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	requiredBridgeTargetName = "COpenFHEBridge"
	requiredBridgeTargetPath = "Artifacts/AresPrivacyCore.xcframework"
)

var (
	literalNamedArgument = regexp.MustCompile(`(?s)(?:^|,)\s*([[:alpha:]_][[:alnum:]_]*)\s*:\s*"([^"\\]*)"`)
	localPathArgument    = regexp.MustCompile(`(?:^|,)\s*path\s*:`)
)

// forbiddenSwiftManifestSubstrings are development-only resolution hooks.
// They are checked only after comments are removed, so a disabled example
// cannot either trip the gate or count as active evidence.
var forbiddenSwiftManifestSubstrings = []string{
	"ProcessInfo.processInfo.environment",
	"getenv(",
	"file://",
	"/usr/local",
	"/opt/homebrew",
	"ARES_OPENFHE",
	"ARES_CORE_SWIFT_PATH",
}

// checkSwiftReleaseManifest requires active, structural evidence that the
// release manifest binds the exact staged C bridge. It never treats comments
// or a mere substring as proof of an immutable binary target.
func checkSwiftReleaseManifest(raw string) error {
	active, err := stripSwiftComments(raw)
	if err != nil {
		return fmt.Errorf("clients/swift/Package.release.swift cannot be inspected safely: %w", err)
	}
	for _, forbidden := range forbiddenSwiftManifestSubstrings {
		if strings.Contains(active, forbidden) {
			return fmt.Errorf("clients/swift/Package.release.swift contains a forbidden local-path/environment dependency substitution pattern: %q", forbidden)
		}
	}
	if err := rejectLocalPackagePathDependencies(active); err != nil {
		return err
	}
	return requireStagedBridgeTarget(active)
}

// rejectLocalPackagePathDependencies walks active .package(...) calls and
// rejects local filesystem and file-URL dependencies. Call argument parsing
// is parenthesis-balanced and string-aware, so nested calls and URL strings do
// not cause a later package declaration to be skipped.
func rejectLocalPackagePathDependencies(raw string) error {
	calls, err := swiftCalls(raw, ".package")
	if err != nil {
		return err
	}
	for _, call := range calls {
		if localPathArgument.MatchString(call) {
			return fmt.Errorf("clients/swift/Package.release.swift declares a local path package dependency: .package(%s)", call)
		}
		if strings.Contains(call, "file://") {
			return fmt.Errorf("clients/swift/Package.release.swift declares a file URL package dependency: .package(%s)", call)
		}
	}
	return nil
}

func requireStagedBridgeTarget(raw string) error {
	calls, err := swiftCalls(raw, ".binaryTarget")
	if err != nil {
		return err
	}

	var bridgeCalls []string
	for _, call := range calls {
		if swiftLiteralArgument(call, "name") == requiredBridgeTargetName {
			bridgeCalls = append(bridgeCalls, call)
		}
	}
	if len(bridgeCalls) == 0 {
		return fmt.Errorf("clients/swift/Package.release.swift is missing the active %q staged bridge binary target", requiredBridgeTargetName)
	}
	if len(bridgeCalls) != 1 {
		return fmt.Errorf("clients/swift/Package.release.swift declares %d active %q binary targets, expected exactly 1", len(bridgeCalls), requiredBridgeTargetName)
	}
	if got := swiftLiteralArgument(bridgeCalls[0], "path"); got != requiredBridgeTargetPath {
		return fmt.Errorf("clients/swift/Package.release.swift must bind %q to literal path %q, got %q", requiredBridgeTargetName, requiredBridgeTargetPath, got)
	}
	return nil
}

func swiftLiteralArgument(call, want string) string {
	for _, match := range literalNamedArgument.FindAllStringSubmatch(call, -1) {
		if match[1] == want {
			return match[2]
		}
	}
	return ""
}

func swiftCalls(raw, token string) ([]string, error) {
	var calls []string
	for i := 0; i < len(raw); {
		stringEnd, isString, err := swiftStringEnd(raw, i)
		if err != nil {
			return nil, err
		}
		if isString {
			i = stringEnd
			continue
		}
		if !strings.HasPrefix(raw[i:], token) {
			i++
			continue
		}
		openParen := i + len(token)
		for openParen < len(raw) && (raw[openParen] == ' ' || raw[openParen] == '\t' || raw[openParen] == '\n' || raw[openParen] == '\r') {
			openParen++
		}
		if openParen == len(raw) || raw[openParen] != '(' {
			i++
			continue
		}
		argumentStart := openParen + 1
		argumentEnd, err := swiftBalancedCallEnd(raw, argumentStart)
		if err != nil {
			return nil, fmt.Errorf("clients/swift/Package.release.swift has an unterminated %s call: %w", token, err)
		}
		calls = append(calls, raw[argumentStart:argumentEnd-1])
		i = argumentEnd
	}
	return calls, nil
}

func swiftBalancedCallEnd(raw string, start int) (int, error) {
	depth := 1
	for i := start; i < len(raw); i++ {
		stringEnd, isString, err := swiftStringEnd(raw, i)
		if err != nil {
			return 0, err
		}
		if isString {
			i = stringEnd - 1
			continue
		}
		switch raw[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}
	return 0, fmt.Errorf("unbalanced parentheses")
}

// stripSwiftComments removes line and nested block comments while preserving
// string literals, including URL strings with "//". The release manifest is
// deliberately restricted to ordinary quoted strings; multiline strings are
// rejected because their comment semantics would otherwise expand the parser
// surface without helping dependency declarations.
func stripSwiftComments(raw string) (string, error) {
	var out strings.Builder
	out.Grow(len(raw))
	blockDepth := 0
	for i := 0; i < len(raw); {
		if blockDepth > 0 {
			if i+1 < len(raw) && raw[i:i+2] == "/*" {
				blockDepth++
				out.WriteString("  ")
				i += 2
				continue
			}
			if i+1 < len(raw) && raw[i:i+2] == "*/" {
				blockDepth--
				out.WriteString("  ")
				i += 2
				continue
			}
			if raw[i] == '\n' {
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
			i++
			continue
		}
		stringEnd, isString, err := swiftStringEnd(raw, i)
		if err != nil {
			return "", err
		}
		if isString {
			out.WriteString(raw[i:stringEnd])
			i = stringEnd
			continue
		}
		if i+1 < len(raw) && raw[i:i+2] == "//" {
			for i < len(raw) && raw[i] != '\n' {
				out.WriteByte(' ')
				i++
			}
			continue
		}
		if i+1 < len(raw) && raw[i:i+2] == "/*" {
			blockDepth = 1
			out.WriteString("  ")
			i += 2
			continue
		}
		out.WriteByte(raw[i])
		i++
	}
	if blockDepth != 0 {
		return "", fmt.Errorf("unterminated block comment")
	}
	return out.String(), nil
}

// swiftStringEnd returns the first byte after an ordinary or raw Swift string
// that begins at start. Multiline strings are intentionally unsupported in a
// release dependency manifest and fail closed rather than widening this small
// parser into a Swift interpreter.
func swiftStringEnd(raw string, start int) (end int, isString bool, err error) {
	if start >= len(raw) {
		return start, false, nil
	}
	if raw[start] == '"' {
		if start+2 < len(raw) && raw[start:start+3] == `"""` {
			return 0, true, fmt.Errorf("multiline string literal is not permitted")
		}
		for i := start + 1; i < len(raw); i++ {
			if raw[i] == '\\' {
				i++
				continue
			}
			if raw[i] == '"' {
				return i + 1, true, nil
			}
		}
		return 0, true, fmt.Errorf("unterminated string literal")
	}
	if raw[start] != '#' {
		return start, false, nil
	}
	hashes := 0
	for start+hashes < len(raw) && raw[start+hashes] == '#' {
		hashes++
	}
	if start+hashes >= len(raw) || raw[start+hashes] != '"' {
		return start, false, nil
	}
	if start+hashes+2 < len(raw) && raw[start+hashes:start+hashes+3] == `"""` {
		return 0, true, fmt.Errorf("multiline string literal is not permitted")
	}
	for i := start + hashes + 1; i < len(raw); i++ {
		if raw[i] != '"' || i+hashes >= len(raw) {
			continue
		}
		allHashes := true
		for j := 0; j < hashes; j++ {
			if raw[i+1+j] != '#' {
				allHashes = false
				break
			}
		}
		if allHashes {
			return i + 1 + hashes, true, nil
		}
	}
	return 0, true, fmt.Errorf("unterminated raw string literal")
}
