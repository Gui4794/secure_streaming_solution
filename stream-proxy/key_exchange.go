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


//Given an array of bytes, turns it into a public key
func byteArrayToPublicKey(byteArray []byte) (*ecdh.PublicKey, error) {
	receivedPublicKey, err := ecdh.X25519().NewPublicKey(byteArray)
	if (err != nil) {
		fmt.Println("something went wrong when parsing the byte array")
	}
	return receivedPublicKey, nil
}

/*
* based on what was received from the stream server
* and on what the proxy server has, computes a shared
* secret
 */
func establishSharedSecret(ownPrivateKey *ecdh.PrivateKey, receivedPublicKey *ecdh.PublicKey) ([]byte, error) {
	return ownPrivateKey.ECDH(receivedPublicKey)
}

/*
* receives the public key that the stream server sent
* TODO: i now assume that it receives a byte array
 */
func receivePublicKey(reader io.Reader) (*ecdh.PublicKey, error) {
	receivedByteArray := make([]byte, 32)

	_, err := io.ReadFull(reader, receivedByteArray)
	if err != nil {
		fmt.Println(err.Error())
		return nil, nil
	}

	receivedPublicKey, err := byteArrayToPublicKey(receivedByteArray)
	if err != nil {
		fmt.Println(err.Error())
	}

	return receivedPublicKey, nil
}

func sendPublicKey(publicKey *ecdh.PublicKey, writer io.Writer) {
	_, err := writer.Write(publicKey.Bytes())
	if err != nil {
		panic(err)
	}
}

/*
	the proxy server should generate and send its parameters
	after establishing a connection with the streaming server
*/
/*
	now, the proxy server must send their public key to the stream server
	and receive the stream server's public key in order to generate the secret
*/
