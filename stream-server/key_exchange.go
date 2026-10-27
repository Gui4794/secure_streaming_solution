package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"secure_streaming_solution/crypto"
)

/**
 * Generates one's own public and private keys.
 * It uses X25519, other possible options are P384, P521 or P256
 */
func generateKeyPair() (*ecdh.PublicKey, *ecdh.PrivateKey) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if(err != nil) {
		fmt.Println("something went wrong while generating a private key")
	}
	publicKey := privateKey.PublicKey()
	return publicKey, privateKey
}

/*
* added by gui: computes the secret key from
* diffie-hellman
 */
func establishSharedSecret(ownPrivateKey *ecdh.PrivateKey, receivedPublicKey *ecdh.PublicKey) ([]byte, error) {
	return ownPrivateKey.ECDH(receivedPublicKey)
}

//Given an array of bytes, turns it into a public key
func byteArrayToPublicKey(byteArray []byte) (*ecdh.PublicKey, error) {
	receivedPublicKey, err := ecdh.X25519().NewPublicKey(byteArray)
	if (err != nil) {
		fmt.Println("something went wrong when parsing the byte array")
	}
	return receivedPublicKey, nil
}

/*
 * Takes a received byte array (the proxy server's public key in a byte array form)
 * from a socket and turns it into a public key. It takes as the reader as input, from which
 * it will receive the byte array, and returns the public key, computed from the byte array
 */

//NOTE: this used to output a byte array, and now outputs a *PublicKey instead
func receivePublicKey(reader io.Reader) (*ecdh.PublicKey, error) {
	receivedByteArray := make([]byte, 32)

	//read 32 bytes
	_, err := io.ReadFull(reader, receivedByteArray)
	if err != nil {
		return nil, fmt.Errorf("failed to receive public key: %w", err)
	}

	//Validate the received public key
	receivedPublicKey, err := byteArrayToPublicKey(receivedByteArray)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	return receivedPublicKey, nil
}

func sendPublicKey(publicKey *ecdh.PublicKey, writer io.Writer) {
	_, err := writer.Write(publicKey.Bytes())
	if err != nil {
		panic(err)
	}
}
