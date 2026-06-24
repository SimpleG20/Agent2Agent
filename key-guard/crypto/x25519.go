package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
)

// Ed25519PrivateKeyToX25519 derives an X25519 private key from an Ed25519
// private key deterministically. Uses the ed2curve algorithm:
//  1. Take the Ed25519 seed (first 32 bytes of 64-byte private key)
//  2. SHA-512(seed) → take first 32 bytes → clamp
//  3. Create ecdh.PrivateKey from clamped bytes
//
// See: https://github.com/golang/crypto/blob/master/curve25519/doc.go
func Ed25519PrivateKeyToX25519(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	seed := priv.Seed()
	h := sha512.Sum512(seed)
	xPriv := h[:32]

	// Clamp the scalar (RFC 7748 §5)
	xPriv[0] &= 248
	xPriv[31] &= 127
	xPriv[31] |= 64

	return ecdh.X25519().NewPrivateKey(xPriv)
}

// Ed25519PrivateKeyToX25519Bytes returns the raw 32-byte X25519 public key
// derived from an Ed25519 private key. Useful for serialization in peer info.
func Ed25519PrivateKeyToX25519Bytes(priv ed25519.PrivateKey) ([]byte, error) {
	xPriv, err := Ed25519PrivateKeyToX25519(priv)
	if err != nil {
		return nil, err
	}
	return xPriv.PublicKey().Bytes(), nil
}
