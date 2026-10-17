package main

import (
	"crypto/ecdh"
	"fmt"
	"io"
)

func receivePublicKey(reader io.Reader) ([]byte, error) {
	receivedPublicKey := make([]byte, 32)

	//read 32 bytes
	_, err := io.ReadFull(reader, receivedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to receive public key: %w", err)
	}

	//Validate the received public key
	_, err = ecdh.X25519().NewPublicKey(receivedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	return receivedPublicKey, nil

}
