// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// Ed25519Algorithm is the value returned by Ed25519Signer.Algorithm().
// Exported so applications can reference it in algorithm-keyed
// verifier maps without depending on the string literal.
const Ed25519Algorithm = "ed25519"

// Ed25519Signer is the default Signer implementation, backed by
// crypto/ed25519 from the standard library.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewEd25519Signer generates a fresh keypair. Use
// NewEd25519SignerFromKey when loading an existing private key (e.g.,
// from secure storage).
func NewEd25519Signer() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sign: ed25519 keygen: %w", err)
	}
	return &Ed25519Signer{privateKey: priv, publicKey: pub}, nil
}

// NewEd25519SignerFromKey constructs a signer wrapping an existing
// private key. The public key is derived from the private key.
func NewEd25519SignerFromKey(priv ed25519.PrivateKey) *Ed25519Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Signer{privateKey: priv, publicKey: pub}
}

// Sign implements Signer.
func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, msg), nil
}

// Verify implements Signer.
func (s *Ed25519Signer) Verify(pubkey, msg, sig []byte) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return errors.New("sign: invalid ed25519 pubkey size")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("sign: invalid ed25519 signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubkey), msg, sig) {
		return errors.New("sign: ed25519 signature verification failed")
	}
	return nil
}

// PublicKey implements Signer. Returns a defensive copy so callers
// cannot mutate the signer's internal state.
func (s *Ed25519Signer) PublicKey() []byte {
	out := make([]byte, len(s.publicKey))
	copy(out, s.publicKey)
	return out
}

// Algorithm implements Signer.
func (s *Ed25519Signer) Algorithm() string {
	return Ed25519Algorithm
}
