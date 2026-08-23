// SPDX-License-Identifier: Apache-2.0

package lineage

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrNodeNotFound is returned by Store.Get when the requested hash
// is not present.
var ErrNodeNotFound = errors.New("lineage: node not found")

// ErrNodeExists is returned by Store.Append when the hash is
// already present. The store is content-addressed and idempotent
// on identical content; this error is informational for callers
// that care about novelty.
var ErrNodeExists = errors.New("lineage: node exists")

// MismatchError describes why Verify failed. Field names the
// specific check that failed ("PayloadHash" | "Signature" |
// "ParentRef" | "Algorithm"); Expected and Got carry the relevant
// byte material for forensic logging.
type MismatchError struct {
	Field    string
	Expected []byte
	Got      []byte
	NodeHash NodeRef
}

// Error implements error.
func (e *MismatchError) Error() string {
	return fmt.Sprintf(
		"lineage: mismatch on field %q: expected=%s got=%s node=%s",
		e.Field,
		hex.EncodeToString(e.Expected),
		hex.EncodeToString(e.Got),
		hex.EncodeToString(e.NodeHash[:]),
	)
}
