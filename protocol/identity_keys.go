package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// reads an Ed25519 identity private key
func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Ed25519 private key: %w", err)
	}

	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid Ed25519 private key PEM")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 private key: %w", err)
	}

	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	return key, nil
}

// reads a trusted Ed25519 public key from a PKIX PEM file.
func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Ed25519 public key: %w", err)
	}

	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid Ed25519 public key PEM")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 public key: %w", err)
	}

	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}

	return key, nil
}

/* whats hapennig?? */

/*
	LoadEd25519PrivateKey() — lê a chave privada usada para assinar.

LoadEd25519PublicKey() — lê a chave pública previamente confiável usada para verificar assinaturas.

Rejeita ficheiros com formato inválido ou chaves de outro algoritmo.
*/
