package tests

import (
	"crypto/ed25519"
	"testing"

	"github.com/stumgart/a2a/key-guard/internal/crypto"
)

func TestGenerateKey(t *testing.T) {
	seed, pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	if len(seed) != crypto.SeedSize {
		t.Errorf("seed length = %d, want %d", len(seed), crypto.SeedSize)
	}

	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("pub key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("priv key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestSignVerify(t *testing.T) {
	_, pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	payload := []byte("hello, a2a world")
	sig := crypto.Sign(priv, payload)

	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if !crypto.Verify(pub, payload, sig) {
		t.Error("Verify() returned false for valid signature")
	}

	// Verify with wrong payload should fail
	if crypto.Verify(pub, []byte("tampered"), sig) {
		t.Error("Verify() returned true for tampered payload")
	}
}

func TestKeyFromSeed(t *testing.T) {
	seed, _, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	priv, err := crypto.KeyFromSeed(seed)
	if err != nil {
		t.Fatalf("KeyFromSeed() failed: %v", err)
	}

	// Verify the derived key produces the same signatures
	payload := []byte("deterministic test")
	sig1 := crypto.Sign(priv, payload)

	priv2, _ := crypto.KeyFromSeed(seed)
	sig2 := crypto.Sign(priv2, payload)

	if !crypto.Verify(priv.Public().(ed25519.PublicKey), payload, sig1) {
		t.Error("First signature verification failed")
	}

	if !crypto.Verify(priv2.Public().(ed25519.PublicKey), payload, sig2) {
		t.Error("Second signature verification failed")
	}
}

func TestKeyFromSeedInvalidLength(t *testing.T) {
	_, err := crypto.KeyFromSeed([]byte("too-short"))
	if err == nil {
		t.Error("KeyFromSeed() should error on invalid seed length")
	}
}

func TestSeedFromHex(t *testing.T) {
	seed, _, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	hexStr := crypto.SeedHex(seed)
	restored, err := crypto.SeedFromHex(hexStr)
	if err != nil {
		t.Fatalf("SeedFromHex() failed: %v", err)
	}

	if string(seed) != string(restored) {
		t.Error("SeedFromHex() did not restore the original seed")
	}
}

func TestSeedFromHexInvalid(t *testing.T) {
	tests := []struct {
		name string
		hex  string
	}{
		{"empty", ""},
		{"too short", "abcd"},
		{"invalid hex", "zzzz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.SeedFromHex(tt.hex)
			if err == nil {
				t.Errorf("SeedFromHex(%q) should have failed", tt.hex)
			}
		})
	}
}
