package native_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeBridgeProjectsUseCanonicalSources(t *testing.T) {
	for _, path := range []string{
		"clients/native/bridge/apple/CMakeLists.txt",
		"clients/native/bridge/android/CMakeLists.txt",
	} {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(raw), "pkg/ares/crypto/cgo/openfhe_wrapper.cpp") {
			t.Fatalf("%s does not reference the canonical OpenFHE bridge source", path)
		}
	}
}

func TestCanonicalWrapperSuppliesEveryEncryptedInputJNIEntryPoint(t *testing.T) {
	root := repoRoot(t)
	header, err := os.ReadFile(filepath.Join(root, "pkg/ares/crypto/cgo/openfhe_wrapper.h"))
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := os.ReadFile(filepath.Join(root, "pkg/ares/crypto/cgo/openfhe_wrapper.cpp"))
	if err != nil {
		t.Fatal(err)
	}

	for _, symbol := range []string{
		"EncryptSerializedPayloadChunk",
		"EncryptSerializedRepeatedScalarCKKS",
		"ComputeSerializedSquaredDistanceCKKS",
		"EncryptSerializedRepeatedScalarBFV",
		"ComputeSerializedSquaredDistanceBFV",
	} {
		if !strings.Contains(string(header), symbol) {
			t.Fatalf("canonical wrapper header does not declare JNI encrypted-input entry point %s", symbol)
		}
		if !strings.Contains(string(implementation), symbol) {
			t.Fatalf("canonical wrapper implementation does not define JNI encrypted-input entry point %s", symbol)
		}
	}
}
