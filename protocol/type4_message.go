package protocol

import (
	"secure_streaming_solution/crypto"
)

/* i don't think we need this anymore
// Represents the payload of a Type 4 Message
type Type4Message struct {
	SequenceNumber uint64
 	EncryptedBlock []byte
}
*/

/*
 * Receives a Type 3 Handshake and defines the parameters
 * (the sequence number and media, at least for now)
 */
func ParametersFromType3(msg Message, seqY uint64, challenge [32]byte, aesKey []byte) (uint64, string, error) {
	type3Handshake, err := ParseHandshakeType3(msg, seqY, challenge, aesKey)
	if err != nil {
		return 0, "", err
	}
	firstSeqB := type3Handshake.SequenceNumber + 1
	media := type3Handshake.Media
	return firstSeqB, media, nil
}

/*
 * Based on the received parameters from the initial handshake,
 * creates a Type 4 Message, ready to be sent.
 * sequenceNumber is the current sequence number that the
 * proxy expects
 * readContents is what is in the buffer that the os read in serveFile()
 * (from ../stream-server/stream_server.go)
 */
func CreateType4Message(seqNumber uint64, readContents []byte, aesKey []byte) ([]byte, error) {
	blockToEncrypt, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		return []byte{}, err
	}
	nonce := crypto.GenerateNonce()
	ciphertext, err := crypto.EncryptBlock(readContents, blockToEncrypt, nonce, seqNumber)
	if err != nil {
		return []byte{}, err
	}
	encryptedBlock, err := crypto.PackageContents(seqNumber, nonce, ciphertext)
	if err != nil {
		return []byte{}, err
	}
	return encryptedBlock, nil
}

/*
* Meant for the proxy:
* parses a Type4 Message
 */
func parseType4Message() {}

/*
 * YPE 3: Proxy → Server
     SEQZ = 102
          ↓
 TYPE 4: Server → Proxy
     SEQB = SEQZ + 1 = 103
          ↓
     Lê bloco de vídeo (1024 bytes)
          ↓
     Cifra com AES-GCM + nonce
          ↓
     Envia SEQB + bloco cifrado
          ↓
 TYPE 4: Proxy recebe
          ↓
     Verifica SEQB == expectedSeq
          ↓
     Decifra com AES-GCM
          ↓
     Envia bloco ao Browser
          ↓
     expectedSeq++
          ↓
     Repete para os próximos blocos
          ↓
 TYPE 5: Fim do vídeo
*/
