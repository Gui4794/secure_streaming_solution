package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// DeriveMediaKey returns the key selected by the XML configuration.
// AES-256 retains the existing 256-bit session-key derivation.
func DeriveMediaKey(sharedSecret []byte, bits int) ([]byte, error) {
	if bits == 256 {
		return DeriveAESKey(sharedSecret)
	}
	if bits != 128 && bits != 192 {
		return nil, fmt.Errorf("unsupported AES key size: %d", bits)
	}
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("invalid shared secret size")
	}
	extract := hmac.New(sha256.New, make([]byte, 32))
	extract.Write(sharedSecret)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte(fmt.Sprintf("3s media AES-%d-GCM v1", bits)))
	expand.Write([]byte{1})
	return expand.Sum(nil)[:bits/8], nil
}
