package didcomm

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// JWE structures for ECDH-ES + XC20P (XChaCha20-Poly1305) encryption.
// Uses Flattened JSON Serialization per RFC 7516.

// JWEDirectEncryption represents a JWE with direct key agreement (ECDH-ES).
type JWEDirectEncryption struct {
	Protected  string         `json:"protected"`  // base64url(protected header)
	Recipients []JWERecipient `json:"recipients"` // single recipient for ECDH-ES
	IV         string         `json:"iv"`         // base64url(nonce)
	Ciphertext string         `json:"ciphertext"` // base64url(encrypted data)
	Tag        string         `json:"tag"`        // base64url(authentication tag)
}

// JWERecipient represents a JWE recipient.
type JWERecipient struct {
	EncryptedKey string             `json:"encrypted_key"` // empty for ECDH-ES (CEK is derived)
	Header       JWERecipientHeader `json:"header,omitempty"`
}

// JWERecipientHeader contains per-recipient header parameters.
type JWERecipientHeader struct {
	Alg string `json:"alg"` // "ECDH-ES"
	Kid string `json:"kid"` // recipient DID key identifier
}

// EncryptMessage encrypts plaintext bytes using ECDH-ES with X25519 + XC20P.
//
// Algorithm:
//  1. Generate ephemeral X25519 key pair
//  2. ECDH with recipient's X25519 public key → shared secret
//  3. Derive CEK = SHA-256(shared secret)
//  4. Encrypt plaintext with XC20P (XChaCha20-Poly1305) using CEK + random 24-byte nonce
//  5. Return JWE JSON bytes
func EncryptMessage(plaintext []byte, recipientPubKey *ecdh.PublicKey, kid string) ([]byte, error) {
	// 1. Generate ephemeral X25519 key pair
	curve := ecdh.X25519()
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// 2. ECDH key agreement
	sharedSecret, err := ephPriv.ECDH(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement failed: %w", err)
	}

	// 3. Derive Content Encryption Key (CEK)
	cek := sha256.Sum256(sharedSecret)

	// 4. Build protected header
	ephPubBytes := ephPriv.PublicKey().Bytes()
	header := map[string]interface{}{
		"alg": "ECDH-ES",
		"enc": "XC20P",
		"epk": map[string]string{
			"kty": "OKP",
			"crv": "X25519",
			"x":   base64.RawURLEncoding.EncodeToString(ephPubBytes),
		},
		"kid": kid,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWE header: %w", err)
	}
	protectedEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	// 5. Generate random 24-byte nonce (IV for XC20P)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 6. Create XC20P cipher
	aead, err := chacha20poly1305.NewX(cek[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create XC20P cipher: %w", err)
	}

	// 7. Encrypt with AAD = protected header (base64url encoded)
	aad := []byte(protectedEncoded)
	ciphertextWithTag := aead.Seal(nil, nonce, plaintext, aad)

	// XC20P output: ciphertext + 16-byte authentication tag
	if len(ciphertextWithTag) < 16 {
		return nil, errors.New("XC20P output too short")
	}
	tagStart := len(ciphertextWithTag) - 16
	ct := ciphertextWithTag[:tagStart]
	tag := ciphertextWithTag[tagStart:]

	// 8. Build JWE structure
	jwe := JWEDirectEncryption{
		Protected: protectedEncoded,
		Recipients: []JWERecipient{
			{
				EncryptedKey: "", // ECDH-ES: CEK is derived, not wrapped
				Header: JWERecipientHeader{
					Alg: "ECDH-ES",
					Kid: kid,
				},
			},
		},
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ct),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}

	return json.Marshal(jwe)
}

// DecryptMessage decrypts a JWE JSON message using the recipient's X25519 private key.
//
// Algorithm:
//  1. Parse JWE JSON
//  2. Extract ephemeral public key from protected header
//  3. ECDH with own X25519 private key + ephemeral public key → shared secret
//  4. Derive CEK = SHA-256(shared secret)
//  5. Decrypt with XC20P
func DecryptMessage(jweData []byte, ownPrivKey *ecdh.PrivateKey) ([]byte, error) {
	// 1. Parse JWE
	var jwe JWEDirectEncryption
	if err := json.Unmarshal(jweData, &jwe); err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %w", err)
	}

	// 2. Decode protected header
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwe.Protected)
	if err != nil {
		return nil, fmt.Errorf("failed to decode protected header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse protected header: %w", err)
	}

	// 3. Extract ephemeral public key (epk) from header
	epkObj, ok := header["epk"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing epk in JWE protected header")
	}

	xStr, ok := epkObj["x"].(string)
	if !ok {
		return nil, errors.New("missing 'x' field in epk")
	}

	epkBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode epk x: %w", err)
	}

	ephPubKey, err := ecdh.X25519().NewPublicKey(epkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// 4. ECDH key agreement
	sharedSecret, err := ownPrivKey.ECDH(ephPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement failed: %w", err)
	}

	// 5. Derive CEK
	cek := sha256.Sum256(sharedSecret)

	// 6. Decode ciphertext components
	nonce, err := base64.RawURLEncoding.DecodeString(jwe.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(jwe.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(jwe.Tag)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	// Reconstruct full ciphertext (ciphertext + 16-byte tag)
	fullCt := append(ciphertext, tag...)

	// 7. Create XC20P cipher and decrypt
	aead, err := chacha20poly1305.NewX(cek[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create XC20P cipher: %w", err)
	}

	aad := []byte(jwe.Protected)
	plaintext, err := aead.Open(nil, nonce, fullCt, aad)
	if err != nil {
		return nil, fmt.Errorf("XC20P decryption failed: %w", err)
	}

	return plaintext, nil
}
