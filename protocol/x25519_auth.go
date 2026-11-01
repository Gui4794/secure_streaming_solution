/*
 * what is happenig?
 Troca das chaves públicas X25519

 Server assina ambas as chaves com Ed25519

 Proxy verifica e envia a sua assinatura

 Server verifica a assinatura do Proxy

 Só depois continua o handshake seguro
*/

package protocol

import (
	"crypto/ed25519"
	"fmt"
)

const (
	X25519SignerServer byte = 1
	X25519SignerProxy  byte = 2
)

// Bind both ephemeral keys and the signer's identity.
func x25519AuthTranscript(
	signer byte,
	serverX25519, proxyX25519 []byte,
) ([]byte, error) {
	if signer != X25519SignerServer && signer != X25519SignerProxy {
		return nil, fmt.Errorf("invalid X25519 signer")
	}

	if len(serverX25519) != 32 || len(proxyX25519) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key size")
	}

	transcript := []byte("3S/X25519/Ed25519/v1")
	transcript = append(transcript, signer)
	transcript = append(transcript, serverX25519...)
	transcript = append(transcript, proxyX25519...)

	return transcript, nil
}

// sign the X25519 exchange using an Ed25519 identity key.
func SignX25519Exchange(
	privateKey ed25519.PrivateKey,
	signer byte,
	serverX25519, proxyX25519 []byte,
) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}

	transcript, err := x25519AuthTranscript(
		signer, serverX25519, proxyX25519,
	)
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(privateKey, transcript), nil
}

// verify the signature against a trusted Ed25519 public key.
func VerifyX25519Exchange(
	publicKey ed25519.PublicKey,
	signer byte,
	serverX25519, proxyX25519, signature []byte,
) error {
	if len(publicKey) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid Ed25519 key or signature size")
	}

	transcript, err := x25519AuthTranscript(
		signer, serverX25519, proxyX25519,
	)
	if err != nil {
		return err
	}

	if !ed25519.Verify(publicKey, transcript, signature) {
		return fmt.Errorf("X25519 exchange authentication failed")
	}

	return nil
}
