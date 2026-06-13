package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

// did:peer:2 encoding constants.
const (
	DIDPeerPrefix = "did:peer:2"
	// Multicodec prefix for Ed25519 public key (0xed).
	// See https://github.com/multiformats/multicodec
	Ed25519PubMulticodec = byte(0xed)
)

// Envelope represents a JWS Compact Serialization message.
// Format: base64url(protected).base64url(payload).base64url(signature)
type Envelope struct {
	Protected  string `json:"protected"`
	Payload    string `json:"payload"`
	Signature  string `json:"signature"`
	SigningDID string `json:"signing_did,omitempty"`
}

// DIDFromPublicKey encodes an Ed25519 public key into a did:peer:2 identifier.
//
// Format: did:peer:2.z{base58btc(0xed || pubKey)}
// The 'z' prefix indicates base58btc multibase encoding.
func DIDFromPublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// Prepend multicodec prefix for Ed25519 public key
	encoded := make([]byte, 0, 1+ed25519.PublicKeySize)
	encoded = append(encoded, Ed25519PubMulticodec)
	encoded = append(encoded, pub...)

	// Base58btc encode with multibase prefix 'z'
	b58 := base58.Encode(encoded)
	return DIDPeerPrefix + ".z" + b58, nil
}

// PublicKeyFromDID decodes a did:peer:2 identifier back to an Ed25519 public key.
func PublicKeyFromDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, DIDPeerPrefix) {
		return nil, fmt.Errorf("unsupported DID method: %s", did)
	}

	// Extract the encoded part after "did:peer:2."
	parts := strings.SplitN(did, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid did:peer:2 format: %s", did)
	}

	encoded := parts[1]

	// Expect multibase prefix 'z' (base58btc)
	if len(encoded) < 1 || encoded[0] != 'z' {
		return nil, fmt.Errorf("unsupported multibase encoding in DID: expected 'z' (base58btc), got '%c'", encoded[0])
	}

	decoded, err := base58.Decode(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base58 DID: %w", err)
	}

	if len(decoded) < 1 || decoded[0] != Ed25519PubMulticodec {
		return nil, fmt.Errorf("unsupported key type in DID: expected multicodec 0xed (Ed25519), got 0x%02x", decoded[0])
	}

	pub := ed25519.PublicKey(decoded[1:])
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key in DID: got %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}

	return pub, nil
}

// BuildEnvelope creates a JWS Compact Serialization envelope.
//
// The envelope is signed with the sender's Ed25519 private key and includes
// the sender's DID in the JWS header for key identification.
//
// Format: base64url(protected).base64url(payload).base64url(signature)
func BuildEnvelope(payload []byte, priv ed25519.PrivateKey, fromDID string, toDID string) (*Envelope, error) {
	if fromDID == "" {
		return nil, fmt.Errorf("fromDID is required")
	}

	// JWS Protected Header
	protected := fmt.Sprintf(
		`{"alg":"EdDSA","kid":"%s"}`,
		fromDID,
	)

	protectedB64 := base64.RawURLEncoding.EncodeToString([]byte(protected))
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	// Signing input: protected.payload
	signingInput := protectedB64 + "." + payloadB64
	signature := Sign(priv, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return &Envelope{
		Protected:  protectedB64,
		Payload:    payloadB64,
		Signature:  sigB64,
		SigningDID: fromDID,
	}, nil
}

// VerifyEnvelope verifies a JWS Compact Serialization envelope against a
// public key identified by the sender's DID.
func VerifyEnvelope(env *Envelope, senderDID string) ([]byte, bool, error) {
	// Decode protected header to verify kid
	headerJSON, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode protected header: %w", err)
	}

	// We expect the kid to match senderDID
	if !strings.Contains(string(headerJSON), senderDID) {
		return nil, false, fmt.Errorf("kid in header does not match sender DID")
	}

	// Resolve public key from DID
	pub, err := PublicKeyFromDID(senderDID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to resolve sender DID: %w", err)
	}

	// Verify signature
	signingInput := env.Protected + "." + env.Payload
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode signature: %w", err)
	}

	if !Verify(pub, []byte(signingInput), sig) {
		return nil, false, nil
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode payload: %w", err)
	}

	return payload, true, nil
}
