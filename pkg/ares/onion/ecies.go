// SPDX-License-Identifier: Apache-2.0

package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	x25519KeyLen = 32
	gcmNonceLen  = 12
	hkdfInfo     = "ares_onion_v1"
)

// GenerateSlotKey returns a fresh X25519 keypair as raw 32-byte
// (privateKey, publicKey). Used for the per-slot ECIES delivery key.
func GenerateSlotKey() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("onion: x25519 keygen: %w", err)
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// ECIESEncrypt seals plaintext to recipientPub (raw 32-byte X25519
// public key). Envelope layout: ephemeral_pub(32) || nonce(12) ||
// ciphertext+tag.
func ECIESEncrypt(recipientPub, plaintext []byte) ([]byte, error) {
	curve := ecdh.X25519()
	rpub, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("onion: bad recipient pubkey: %w", err)
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("onion: ephemeral keygen: %w", err)
	}
	shared, err := eph.ECDH(rpub)
	if err != nil {
		return nil, fmt.Errorf("onion: ecdh: %w", err)
	}
	key, err := deriveKey(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("onion: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, x25519KeyLen+gcmNonceLen+len(ct))
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// ECIESDecrypt opens an envelope with recipientPriv (raw 32-byte
// X25519 private key).
func ECIESDecrypt(recipientPriv, envelope []byte) ([]byte, error) {
	if len(envelope) < x25519KeyLen+gcmNonceLen {
		return nil, errors.New("onion: envelope too short")
	}
	curve := ecdh.X25519()
	rpriv, err := curve.NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("onion: bad recipient privkey: %w", err)
	}
	ephPub, err := curve.NewPublicKey(envelope[:x25519KeyLen])
	if err != nil {
		return nil, fmt.Errorf("onion: bad ephemeral pubkey: %w", err)
	}
	nonce := envelope[x25519KeyLen : x25519KeyLen+gcmNonceLen]
	ct := envelope[x25519KeyLen+gcmNonceLen:]

	shared, err := rpriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("onion: ecdh: %w", err)
	}
	key, err := deriveKey(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("onion: aead open: %w", err)
	}
	return pt, nil
}

func deriveKey(shared []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("onion: hkdf: %w", err)
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("onion: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("onion: gcm: %w", err)
	}
	return gcm, nil
}
