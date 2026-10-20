package main

import (
	"crypto/ecdh"
	"fmt"
	"io"
)


/*
* added by gui: computes the secret key from
* diffie-hellman
*/
func establishSharedSecret(ownPrivateKey *PrivateKey, receivedPublicKey *PublicKey) {
	return ownPrivateKey.ECDH(receivedPublicKey), nil
}

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

	/*
  * added by gui: sends the public key
	*/
	func sendPublicKey(privateKey *ecdh.PrivateKey, writer io.Writer) {
		/*
		my issue with this implementation VVVVVVVVV is that it'd generate the private key inside the function and there would
		be no way to return it other than to actually return the private key into the function
		privateKey, err := crypto.GeneratePrivateKey()
		if err != nil {
			//there is likely a better way to do this
			fmt.Println(err.Error())
		}
	*/
		publicKey := crypto.GetPublicKey(privateKey)
		_, err = writer.Write(publicKey)
		if err != nil {
			//there is likely a better way to do this
			fmt.Println(err.Error())
		}
	}


}
