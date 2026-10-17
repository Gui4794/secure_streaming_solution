package main

import (
	"fmt"
	"io"
	"secure_streaming_solution/crypto"
)

func establishSharedSecret() {
	//it should receive what the stream server sent
}

func sendPublicKey(writer io.Writer) {
	privateKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		//there is likely a better way to do this
		fmt.Println(err.Error())
	}
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
