// SPDX-License-Identifier: Apache-2.0

//go:build !openfhe

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "openfhe-contract-helper requires rebuilding with -tags openfhe")
	os.Exit(1)
}
