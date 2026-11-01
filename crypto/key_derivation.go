package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func DeriveAESKey(sharedSecret []byte) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("invalid shared secret tamanho")
	}

	hkdfReader := hkdf.New(
		sha256.New,
		sharedSecret,
		nil,
		[]byte("3s session key v1"),
	)

	aesKey := make([]byte, 32)

	_, err := io.ReadFull(hkdfReader, aesKey)
	if err != nil {
		return nil, err
	}

	return aesKey, nil
}

/*
generateKeyPair()
       ↓
establishSharedSecret()
       ↓
   sharedSecret
       ↓
DeriveAESKey()
       ↓
    aesKey
       ↓
    AES-GCM

Encrypt   Decrypt
(Server)  (Proxy)


*/
