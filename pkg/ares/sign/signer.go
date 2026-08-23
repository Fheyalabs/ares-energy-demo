// SPDX-License-Identifier: Apache-2.0

package sign

// Signer signs and verifies arbitrary byte payloads. The lineage
// package uses it to attest authorship of DAG nodes; applications can
// reuse it for any signed-message pattern.
//
// Implementations must be safe for concurrent use.
type Signer interface {
	// Sign produces a signature over msg using this signer's private
	// key.
	Sign(msg []byte) ([]byte, error)

	// Verify checks that sig is a valid signature over msg under
	// pubkey. Returns nil on success, error on any failure (malformed
	// key, malformed signature, signature/message mismatch).
	Verify(pubkey, msg, sig []byte) error

	// PublicKey returns the public-key bytes corresponding to this
	// signer. Verifiers use it to check signatures this Signer
	// produced.
	PublicKey() []byte

	// Algorithm returns a stable identifier for the signature scheme.
	// Used by the lineage package's Verify to select the right
	// verifier when multiple algorithms coexist in a deployment.
	Algorithm() string
}
