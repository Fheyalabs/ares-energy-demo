// SPDX-License-Identifier: Apache-2.0

//go:build openfhe && linux

package cgo

// Linux OpenFHE paths. Debian/Ubuntu install to /usr/local/lib;
// RHEL/Fedora/openSUSE install to /usr/local/lib64. Both are
// searched.

/*
#cgo CXXFLAGS: -DOPENFHE_VERSION=v1.5.1 -I/usr/local/include/openfhe -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/core -I/usr/local/include/openfhe/cereal -I/usr/local/include/openfhe/binfhe
#cgo LDFLAGS: -L/usr/local/lib -Wl,-rpath,/usr/local/lib -L/usr/local/lib64 -Wl,-rpath,/usr/local/lib64 -lOPENFHEpke -lOPENFHEbinfhe -lOPENFHEcore
*/
import "C"
