// SPDX-License-Identifier: Apache-2.0

package helperclient

import (
	"encoding/base64"
	"fmt"
)

func encodeB64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func decodeB64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return out, nil
}
