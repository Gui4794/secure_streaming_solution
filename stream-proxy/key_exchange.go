package main

import (
	"fmt"
	"io"
	"secure_streaming_solution/crypto"
)

/*
* based on what was received from the stream server
* and on what the proxy server has, computes a shared
* secret
*/
func establishSharedSecret(ownPrivateKey *PrivateKey, receivedPublicKey *PublicKey) ([]byte, error){
	return ownPrivateKey.ECDH(receivedPublicKey), nil
}

/*
* receives the public key that the stream server sent
* TODO: i now assume that it receives a byte array
*/
func receivePublicKey(reader.io Reader) ([]byte, error) {
	receivedByteArray := make([]byte, 32)

	_, err := io.ReadFull(reader, receivedByteArray)
	if(err != nil) {
		fmt.Println(err.Error())
		return nil
	}

	receivedPublicKey, err = ecdh.X25519().NewPublicKey(receivedPublicKey)
	if err != nil {
		fmt.Println(err.Error());
	}
	
	//pretty sure that NewPublicKey() returns a *PublicKey
	return receivedPublicKey, nil
}

func sendPublicKey(privateKey *PrivateKey, writer io.Writer) {
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

/*
	the proxy server should generate and send its parameters
	after establishing a connection with the streaming server
*/
/*
	now, the proxy server must send their public key to the stream server
	and receive the stream server's public key in order to generate the secret
*/
