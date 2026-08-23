package native_test

import (
	"os"
	"strings"
	"testing"
)

func TestNativeREADMEIsProductNeutral(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "fheya") {
		t.Fatal("clients/native/README.md contains a product-specific consumer or assembler reference")
	}
}
