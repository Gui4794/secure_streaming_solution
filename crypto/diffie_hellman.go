package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
)

// generates a x25519 private key (pk)
func GeneratePrivateKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// generates one's public key from their own private key
func GetPublicKey(generatedPrivateKey *ecdh.PrivateKey) []byte {
	return generatedPrivateKey.PublicKey().Bytes()
}

// computes shared secret, pk + received public key
func SharedSecret(privateKey *ecdh.PrivateKey, receivedPublicKey []byte) ([]byte, error) {
	publicKey, err := ecdh.X25519().NewPublicKey(receivedPublicKey)
	if err != nil {
		return nil, err
	}
	return privateKey.ECDH(publicKey)
}
