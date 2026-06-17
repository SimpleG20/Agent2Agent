package crypto

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
)

// base58 alphabet (Bitcoin-style)
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58btcEncode encodes a byte slice to base58btc.
func base58btcEncode(input []byte) string {
	n := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var chars []byte

	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		chars = append(chars, base58Alphabet[mod.Int64()])
	}

	// Add leading '1's for leading zero bytes
	for _, b := range input {
		if b != 0 {
			break
		}
		chars = append(chars, '1')
	}

	// Reverse
	for i, j := 0, len(chars)-1; i < j; i, j = i+1, j-1 {
		chars[i], chars[j] = chars[j], chars[i]
	}

	return string(chars)
}

// base58btcDecode decodes a base58btc string back to bytes.
func base58btcDecode(input string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)

	for _, c := range input {
		idx := -1
		for i := 0; i < len(base58Alphabet); i++ {
			if byte(c) == base58Alphabet[i] {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}

	result := n.Bytes()

	// Add leading zero bytes for leading '1's
	leadingZeros := 0
	for _, c := range input {
		if c != '1' {
			break
		}
		leadingZeros++
	}
	if leadingZeros > 0 {
		result = append(make([]byte, leadingZeros), result...)
	}

	return result, nil
}

// GenerateDIDKey generates a did:key: string from an Ed25519 public key.
// Format: did:key:z<base58btc(multicodec_prefix + pub_key)>
// Multicodec prefix for Ed25519: 0xed01
func GenerateDIDKey(pub ed25519.PublicKey) string {
	// Ed25519 multicodec prefix: varint(0xed) = [0xed, 0x01]
	prefix := []byte{0xed, 0x01}
	codecKey := append(prefix, pub...)
	return "did:key:z" + base58btcEncode(codecKey)
}

// ParseDIDKey extracts the raw public key bytes from a did:key: string.
func ParseDIDKey(didKey string) ([]byte, error) {
	if len(didKey) < 9 || didKey[:8] != "did:key:" {
		return nil, fmt.Errorf("invalid did:key prefix: %s", didKey[:8])
	}

	encoded := didKey[8:]
	if len(encoded) < 2 || encoded[0] != 'z' {
		return nil, fmt.Errorf("invalid multibase prefix, expected 'z': %s", string(encoded[0]))
	}

	decoded, err := base58btcDecode(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base58: %w", err)
	}

	if len(decoded) < 3 {
		return nil, fmt.Errorf("decoded key too short: %d bytes", len(decoded))
	}

	// Verify multicodec prefix for Ed25519 (0xed01)
	if decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("unknown multicodec prefix: %x %x", decoded[0], decoded[1])
	}

	return decoded[2:], nil
}

// DIDKeyToBytes is an alias for ParseDIDKey.
func DIDKeyToBytes(didKey string) ([]byte, error) {
	return ParseDIDKey(didKey)
}

// DIDKeyFromBytes is an alias for GenerateDIDKey.
func DIDKeyFromBytes(pub ed25519.PublicKey) string {
	return GenerateDIDKey(pub)
}
