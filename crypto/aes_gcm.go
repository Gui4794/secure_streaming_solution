/*
 * A file meant to be a wrapper for using the AES-GCM protocol
 * (just like we have diffie_hellman.go and key_exchange.go)
 * inspired by this link https://gist.github.com/kkirsche/e28da6754c39d5e7ea10
 */
package crypto

import (
	"io"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/cipher"
	"crypto/rand"
)

/*
Creates a new ACM cipher based on a key. Since NewCipher takes a []byte as input,
it first converts the key to a []byte
*/
func createAcmCipher(key *ecdh.PublicKey) (cipher.Block, error){
	block, err := aes.NewCipher(key.Bytes())
	if (err != nil) {
		panic(err)
	}
	return block, nil
}


//Generates a nonce
func generateNonce() ([]byte) {
	nonce := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, nonce)
	if (err != nil) {
		panic(err)
	}
	return nonce
}

/*
 * Given plaintext, a block and a nonce,
 * ciphers them into a block
 * TODO: possibly send in this function, too? achievable by adding a destination []byte
 * Returns the ciphered content (i think?)
 */
func cipherBlock(plaintext []byte, block cipher.Block, nonce []byte) ([]byte) {
	aesgcm, err := cipher.NewGCM(block)
	if(err != nil) {
		panic(err)
	}
	return aesgcm.Seal(nil, nonce, plaintext, nil)
}

/*
Given a nonce and a block, packages both
into a block, ready to be sent
*/
func packageContents(block cipher.Block, nonce []byte) {
	return
}
