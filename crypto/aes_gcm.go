/*
 * A file meant to be a wrapper for using the AES-GCM protocol
 * (just like we have diffie_hellman.go and key_exchange.go)
 * inspired by this link https://gist.github.com/kkirsche/e28da6754c39d5e7ea10
 */
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

/*
Creates a new ACM cipher based on a key. Since NewCipher takes a []byte as input,
it first converts the key to a []byte
*/
func createAcmCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key) //a função aceita a chave aes derivada pelo hkdf

}

// Generates a nonce
func generateNonce() []byte {
	nonce := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}
	return nonce
}

func EncryptBlock(plaintext []byte, block cipher.Block, nonce []byte, seq uint64) ([]byte, error) {
	//create teh aes-gcm cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//Check if nonce has tamanho certo
	if len(nonce) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}

	//converte seq number into 8 bytes for authentication
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, seq)

	//encrypt the plaintext and sequence number
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)

	return ciphertext, nil
}

/*
Given a nonce and a block, packages both
into a block, ready to be sent
*/
func PackageContents(seq uint64, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce size")
	}

	packet := make([]byte, 8+len(nonce)+len(ciphertext))

	binary.BigEndian.PutUint64(packet[:8], seq)

	copy(packet[8:20], nonce)
	copy(packet[20:], ciphertext)

	return packet, nil
}

/*
 * decrypts a block encrypted with AES-GCM.
 * verifies the authentication tag and the sequence number
 * returns the original plaintext if authentication succeeds.
 */
func DecryptBlock(ciphertext []byte, block cipher.Block, nonce []byte, seq uint64) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}

	// reconstruct the same verification tag and sequence number used during encryption
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, seq)

	// verify authenticity and decrypt the ciphertext
	return aesgcm.Open(nil, nonce, ciphertext, aad)
}

/*
Formato do payload de um bloco

Número de sequência do bloco 8 bytes

Nonce — 12 bytes
Valor usado na cifragem AES-GCM

Ciphertext + Tag (16) — tamanho variável

*/
