package protocol

import (
	"errors"
	"fmt"
	"log"
	"secure_streaming_solution/crypto"
	//"golang.org/x/text/message"
)

/*
 * Meant for the Stream Server:
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
 * Meant for the Stream Server:
 * Based on the received parameters from the initial handshake,
 * creates a Type 4 Message, ready to be sent.
 * sequenceNumber is the current sequence number that the
 * proxy expects
 * readContents is what is in the buffer that the os read in serveFile()
 * (from ../stream-server/stream_server.go)
 */

func CreateType4Message(seqNumber uint64, readContents []byte, aesKey []byte) (Message, error) {
	if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
		return Message{}, fmt.Errorf("invalid AES key")
	}

	block, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		return Message{}, err
	}

	nonce := crypto.GenerateNonce()

	ciphertextPlusMac, err := crypto.EncryptBlock(
		readContents, block, nonce, seqNumber,
	)
	if err != nil {
		return Message{}, err
	}

	payload, err := crypto.PackageContents(seqNumber, nonce, ciphertextPlusMac)
	if err != nil {
		return Message{}, err
	}

	return Message{
		Type:    TypeMediaBlock,
		Payload: payload,
	}, nil
}

// Meant for the Proxy Server: parses a Type4 Message
func ParseType4Message(type4Message []byte, expectedSeqNumber uint64, aesKey []byte) ([]byte, error) {
	seqNumber, nonce, ciphertextPlusMac, err := crypto.UnpackContents(type4Message)

	if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
		return nil, errors.New("invalid AES key")
	}

	if err != nil {
		log.Println("error unpacking a type4 message")
		return []byte{}, err
	}
	if seqNumber != expectedSeqNumber {
		log.Println("sequence number in the type4 message is not the expected sequence number")
		return []byte{}, errors.New("sequence number in the type4 message is not the expected sequence number")
	}
	block, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		log.Println("error in creating the acm cipher")
		return []byte{}, errors.New("error in creating the acm cipher")
	}
	decryptedBlock, err := crypto.DecryptBlock(ciphertextPlusMac, block, nonce, seqNumber)
	if err != nil {
		log.Println("error decrypting a block corresponding to a type4 message")
		return []byte{}, err
	}
	return decryptedBlock, nil
}

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
