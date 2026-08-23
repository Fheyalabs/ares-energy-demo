// SPDX-License-Identifier: Apache-2.0

//go:build openfhe && darwin

package cgo

// Darwin OpenFHE paths. Apple Silicon Homebrew installs under
// /opt/homebrew; Intel Homebrew and `make install` defaults use
// /usr/local. Both prefixes are searched.

/*
#cgo CXXFLAGS: -DOPENFHE_VERSION=v1.5.1 -I/usr/local/include/openfhe -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/core -I/usr/local/include/openfhe/cereal -I/usr/local/include/openfhe/binfhe -I/opt/homebrew/include/openfhe -I/opt/homebrew/include/openfhe/pke -I/opt/homebrew/include/openfhe/core -I/opt/homebrew/include/openfhe/cereal -I/opt/homebrew/include/openfhe/binfhe
#cgo LDFLAGS: -L/usr/local/lib -Wl,-rpath,/usr/local/lib -L/opt/homebrew/lib -Wl,-rpath,/opt/homebrew/lib -lOPENFHEpke -lOPENFHEbinfhe -lOPENFHEcore
*/
import "C"
