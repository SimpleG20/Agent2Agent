// Package crypto provides Ed25519 key management, signing, and verification
// for the A2A Key Guard service.
//
// All operations use Go's standard library crypto/ed25519 — zero CGO, no external deps.
// Keys are never written to disk by the service; they are loaded from environment.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	// SeedSize is the Ed25519 seed length (32 bytes).
	SeedSize = ed25519.SeedSize
)

// GenerateKey creates a new Ed25519 key pair from a random seed.
// Returns the seed (32 bytes), public key, and private key.
func GenerateKey() (seed []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	seed = priv.Seed()
	return seed, pub, priv, nil
}

// KeyFromSeed reconstructs a private key from its 32-byte seed.
// This is the deterministic counterpart to GenerateKey.
func KeyFromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("invalid seed length: got %d, want %d", len(seed), SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs the payload with the given private key and returns the raw
// 64-byte Ed25519 signature.
func Sign(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

// Verify checks whether the signature is a valid Ed25519 signature of the
// payload by the given public key.
func Verify(pub ed25519.PublicKey, payload []byte, sig []byte) bool {
	return ed25519.Verify(pub, payload, sig)
}

// SeedFromHex decodes a hex-encoded seed string into raw bytes.
// The input should be 64 hex characters (32 bytes).
func SeedFromHex(s string) ([]byte, error) {
	seed, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid seed hex: %w", err)
	}
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("invalid seed length: got %d bytes from hex, want %d", len(seed), SeedSize)
	}
	return seed, nil
}

// SeedHex returns the hex encoding of the seed.
func SeedHex(seed []byte) string {
	return hex.EncodeToString(seed)
}

// PubKeyBytes returns the raw 32-byte public key.
func PubKeyBytes(pub ed25519.PublicKey) []byte {
	return []byte(pub)
}
