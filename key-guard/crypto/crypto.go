package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
)

// GenerateKeyPair generates a new Ed25519 public/private keypair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// Sign signs a message using the Ed25519 private key.
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Verify verifies a signature against a message and public key.
func Verify(publicKey ed25519.PublicKey, message []byte, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// SaveKeyToFile saves the base64-encoded key representation to a file.
func SaveKeyToFile(filePath string, key []byte) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	return os.WriteFile(filePath, []byte(encoded), 0600)
}

// LoadKeyFromFile loads a base64-encoded key from a file.
func LoadKeyFromFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
