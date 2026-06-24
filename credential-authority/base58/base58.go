package base58

import (
	"fmt"
	"math/big"
)

// Bitcoin-style base58 alphabet
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Encode encodes a byte slice to base58 (Bitcoin alphabet).
func Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	n := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var chars []byte

	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		chars = append(chars, alphabet[mod.Int64()])
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

// Decode decodes a base58 string to bytes.
func Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	n := new(big.Int)
	base := big.NewInt(58)

	for _, c := range input {
		idx := -1
		for i := 0; i < len(alphabet); i++ {
			if byte(c) == alphabet[i] {
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
func GenerateDIDKey(pub []byte) string {
	prefix := []byte{0xed, 0x01}
	codecKey := append(prefix, pub...)
	return "did:key:z" + Encode(codecKey)
}
