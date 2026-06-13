package tests

import (
	"strings"
	"testing"

	"github.com/stumgart/a2a/key-guard/internal/crypto"
)

func TestDIDFromPublicKey(t *testing.T) {
	_, pub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	did, err := crypto.DIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("DIDFromPublicKey() failed: %v", err)
	}

	if !strings.HasPrefix(did, crypto.DIDPeerPrefix) {
		t.Errorf("DID = %q, want prefix %q", did, crypto.DIDPeerPrefix)
	}

	// Should contain the multibase marker
	if !strings.Contains(did, ".z") {
		t.Errorf("DID = %q, should contain '.z' for base58btc", did)
	}
}

func TestDIDRoundtrip(t *testing.T) {
	_, pub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	did, err := crypto.DIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("DIDFromPublicKey() failed: %v", err)
	}

	restored, err := crypto.PublicKeyFromDID(did)
	if err != nil {
		t.Fatalf("PublicKeyFromDID() failed: %v", err)
	}

	if string(pub) != string(restored) {
		t.Error("PublicKeyFromDID() did not restore the original public key")
	}
}

func TestDIDFromPublicKeyInvalidLength(t *testing.T) {
	_, err := crypto.DIDFromPublicKey([]byte("too-short"))
	if err == nil {
		t.Error("DIDFromPublicKey() should error on invalid key size")
	}
}

func TestPublicKeyFromDIDInvalid(t *testing.T) {
	tests := []struct {
		name string
		did  string
	}{
		{"wrong method", "did:key:z..."},
		{"missing encoding", "did:peer:2"},
		{"no multibase", "did:peer:2.abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.PublicKeyFromDID(tt.did)
			if err == nil {
				t.Errorf("PublicKeyFromDID(%q) should have failed", tt.did)
			}
		})
	}
}

func TestBuildEnvelope(t *testing.T) {
	_, pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	fromDID, err := crypto.DIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("DIDFromPublicKey() failed: %v", err)
	}

	payload := []byte("Hello, Agent Beta!")
	toDID := "did:peer:2.zRecipientExample"

	env, err := crypto.BuildEnvelope(payload, priv, fromDID, toDID)
	if err != nil {
		t.Fatalf("BuildEnvelope() failed: %v", err)
	}

	if env.Protected == "" {
		t.Error("envelope missing protected header")
	}
	if env.Payload == "" {
		t.Error("envelope missing payload")
	}
	if env.Signature == "" {
		t.Error("envelope missing signature")
	}
	if env.SigningDID != fromDID {
		t.Errorf("envelope SigningDID = %q, want %q", env.SigningDID, fromDID)
	}
}

func TestBuildEnvelopeEmptyFromDID(t *testing.T) {
	_, _, priv, _ := crypto.GenerateKey()
	_, err := crypto.BuildEnvelope([]byte("test"), priv, "", "did:peer:2.zto")
	if err == nil {
		t.Error("BuildEnvelope() should fail with empty fromDID")
	}
}

func TestVerifyEnvelope(t *testing.T) {
	_, pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	fromDID, err := crypto.DIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("DIDFromPublicKey() failed: %v", err)
	}

	payload := []byte("verify me")
	env, err := crypto.BuildEnvelope(payload, priv, fromDID, "did:peer:2.zrecipient")
	if err != nil {
		t.Fatalf("BuildEnvelope() failed: %v", err)
	}

	// Verify valid envelope
	decoded, valid, err := crypto.VerifyEnvelope(env, fromDID)
	if err != nil {
		t.Fatalf("VerifyEnvelope() failed: %v", err)
	}
	if !valid {
		t.Fatal("VerifyEnvelope() returned false for valid envelope")
	}
	if string(decoded) != string(payload) {
		t.Errorf("decoded payload = %q, want %q", string(decoded), string(payload))
	}
}

func TestVerifyEnvelopeTampered(t *testing.T) {
	_, pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	fromDID, err := crypto.DIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("DIDFromPublicKey() failed: %v", err)
	}

	env, err := crypto.BuildEnvelope([]byte("original"), priv, fromDID, "did:peer:2.zrecipient")
	if err != nil {
		t.Fatalf("BuildEnvelope() failed: %v", err)
	}

	// Tamper with payload
	tampered := *env
	tampered.Payload = "dGFtcGVyZWQ" // base64url("tampered")

	_, valid, err := crypto.VerifyEnvelope(&tampered, fromDID)
	if err != nil {
		// Accept error OR invalid — both are fine for tampered data
		t.Logf("VerifyEnvelope returned error (acceptable): %v", err)
		return
	}
	if valid {
		t.Error("VerifyEnvelope() returned true for tampered envelope")
	}
}

func TestVerifyEnvelopeWrongSender(t *testing.T) {
	_, _, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	// Create second key pair for the "claimed" sender DID
	_, wrongPub, _, _ := crypto.GenerateKey()
	wrongDID, _ := crypto.DIDFromPublicKey(wrongPub)

	// Build envelope with the actual key
	_, actualPub, _, _ := crypto.GenerateKey()
	actualDID, _ := crypto.DIDFromPublicKey(actualPub)

	env, err := crypto.BuildEnvelope([]byte("who am i?"), priv, actualDID, "did:peer:2.zrecipient")
	if err != nil {
		t.Fatalf("BuildEnvelope() failed: %v", err)
	}

	// Verify with wrong DID
	_, valid, err := crypto.VerifyEnvelope(env, wrongDID)
	// Should fail — either error from kid mismatch or invalid signature
	if valid {
		t.Error("VerifyEnvelope() returned true with wrong sender DID")
	}
}

func TestMultipleSignVerifyCycles(t *testing.T) {
	for range 100 {
		_, pub, priv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() failed: %v", err)
		}

		did1, _ := crypto.DIDFromPublicKey(pub)
		did2, _ := crypto.PublicKeyFromDID(did1)

		if string(pub) != string(did2) {
			t.Fatal("DID roundtrip failed after multiple cycles")
		}

		payload := []byte("stress test")
		env, _ := crypto.BuildEnvelope(payload, priv, did1, "did:peer:2.zrecipient")
		decoded, valid, _ := crypto.VerifyEnvelope(env, did1)
		if !valid || string(decoded) != string(payload) {
			t.Fatal("Sign/verify cycle failed")
		}
	}
}
