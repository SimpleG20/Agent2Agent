package didcomm

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// DIDCommMessage represents the plaintext DIDComm v2 message.
type DIDCommMessage struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Body        map[string]interface{} `json:"body"`
	From        string                 `json:"from,omitempty"`
	To          []string               `json:"to,omitempty"`
	CreatedTime int64                  `json:"created_time,omitempty"`
	ExpiresTime int64                  `json:"expires_time,omitempty"`
}

// Signature represents the JWS signature.
type Signature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// SignedMessage represents the JWS Flat Serialization of a DIDComm message.
type SignedMessage struct {
	Payload    string      `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

// SignMessage wraps and signs a DIDComm message using Ed25519 key.
func SignMessage(msg *DIDCommMessage, privKey ed25519.PrivateKey) (*SignedMessage, error) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	payloadEncoded := base64.RawURLEncoding.EncodeToString(msgBytes)

	// Create protected header
	header := map[string]string{
		"alg": "EdDSA",
		"kid": msg.From + "#key-1",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	protectedEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Signature input: protected.payload
	sigInput := protectedEncoded + "." + payloadEncoded
	sigBytes := ed25519.Sign(privKey, []byte(sigInput))
	sigEncoded := base64.RawURLEncoding.EncodeToString(sigBytes)

	return &SignedMessage{
		Payload: payloadEncoded,
		Signatures: []Signature{
			{
				Protected: protectedEncoded,
				Signature: sigEncoded,
			},
		},
	}, nil
}

// VerifyMessage verifies a signed JWS message against a resolver Ed25519 public key.
func VerifyMessage(signed *SignedMessage, pubKey ed25519.PublicKey) (*DIDCommMessage, error) {
	if len(signed.Signatures) == 0 {
		return nil, errors.New("no signatures found in signed message")
	}

	sigObj := signed.Signatures[0]
	sigInput := sigObj.Protected + "." + signed.Payload

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigObj.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	if !ed25519.Verify(pubKey, []byte(sigInput), sigBytes) {
		return nil, errors.New("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(signed.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var msg DIDCommMessage
	if err := json.Unmarshal(payloadBytes, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plaintext message: %w", err)
	}

	return &msg, nil
}
