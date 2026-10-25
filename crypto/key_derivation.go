// estes comentarios estão aqui porque eu (beatriz) esqueço me do que estou a fazer a meio
// mas o meu plano é :
// Diffie-Hellman → sharedSecret → HKDF → AES-256 Key (o dh estabelece o segredo comum, o HKDF transforma numa chave para AES-GCM )

package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

//recebe o segredo shared que vem do hellman , dps usamos o hkdk-sha256 para derivar uma chave ,devolve uma chave aes

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
