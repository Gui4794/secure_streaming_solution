/*
	STREAM SERVER
     |
Último Type 4: SEQB = 105
     |
SEQF = 106
     ↓
Cria ENDBLOCK:
SEQF + "END" + RandomString
     ↓
Cifra com AES-GCM
     ↓
Envia mensagem Type 5
     ↓
SECURE PROXY
     |
Verifica SEQF = expectedSeq
     ↓
Autentica e decifra
     ↓
Verifica "END"
     ↓
Termina o streaming
*/

package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"secure_streaming_solution/crypto"
)

const endRandomSize = 32

/*
 * creates a type 5 message to signal the end of the stream
 * the message contains SEQF, "END" , and a random string
 * encrypted and authenticated using aes-gcm
 */

func CreateType5Message(seqF uint64, aesKey []byte) (Message, error) {
	if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
		return Message{}, fmt.Errorf("invalid AES key")
	}

	// generate a random string
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return Message{}, err
	}

	randomString := hex.EncodeToString(randomBytes)

	//endblock = SEQF || "END" || RandomString
	plaintext := make([]byte, 8+3+len(randomString))

	binary.BigEndian.PutUint64(plaintext[:8], seqF)
	copy(plaintext[8:11], "END")
	copy(plaintext[11:], randomString)

	// creates AES cipher and generate nonce
	block, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		return Message{}, err
	}

	nonce := crypto.GenerateNonce()

	// encrypt and authenticate the END block
	ciphertext, err := crypto.EncryptBlock(
		plaintext, block, nonce, seqF,
	)
	if err != nil {
		return Message{}, err
	}

	// package seqf + nonce + ciphertext + tag
	payload, err := crypto.PackageContents(seqF, nonce, ciphertext)
	if err != nil {
		return Message{}, err
	}

	return Message{
		Type:    TypeEndBlock,
		Payload: payload,
	}, nil
}

func ParseType5Message(msg Message, expectedSeq uint64, aesKey []byte) error {
	if msg.Type != TypeEndBlock {
		return fmt.Errorf("expected Type 5 message")
	}

	if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
		return fmt.Errorf("invalid AES key")
	}

	seqF, nonce, ciphertext, err := crypto.UnpackContents(msg.Payload)
	if err != nil {
		return err
	}

	// verify sequence number
	if seqF != expectedSeq {
		return fmt.Errorf("unexpected SEQF")
	}

	block, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		return err
	}
	// autheticate and decrypt
	plaintext, err := crypto.DecryptBlock(
		ciphertext, block, nonce, expectedSeq,
	)
	if err != nil {
		return fmt.Errorf("type 5 auuthentication failed: %w", err)
	}

	// verify endblock structure
	if len(plaintext) != 8+3+endRandomSize {
		return fmt.Errorf("invalid END block size")
	}

	innerSeq := binary.BigEndian.Uint64(plaintext[:8])
	if innerSeq != expectedSeq {
		return fmt.Errorf("invalid END block sequence")
	}

	// Verify END marker
	if string(plaintext[8:11]) != "END" {
		return fmt.Errorf("invalid END marker")
	}

	return nil
}

//sites usados
// https://cs.opensource.google/go/go/+/refs/tags/go1.27.3:src/crypto/cipher/gcm.go;l=26
//
// https://pkg.go.dev/github.com/hazyhaar/go-secretstream
//https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream
