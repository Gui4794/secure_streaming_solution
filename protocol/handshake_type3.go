package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"secure_streaming_solution/crypto"
	"strings"
	"unicode/utf8"
)

type HandshakeType3 struct {
	SequenceNumber uint64
	Response       [32]byte
	Media          string
}

// check the request media name valid
func validMediaName(media string) bool {
	return len(media) > 0 &&
		len(media) <= 255 &&
		utf8.ValidString(media) &&
		!strings.ContainsAny(media, "/\\\x00\r\n") &&
		media != "." && media != ".."
}

// proxy responds to server challange and requests the media file to start streaming
func CreateHandshakeType3(HandshakeType2, media string, aesKey []byte) (Message, error) {
	if len(aesKey) != 32 {
		return Message{}, fmt.Errorf("key AES invalida")
	}

	if type2.SequenceNumber == ^uint64(0) {
		return Message{}, fmt.Errorf("sequence number overflow")
	}

	// SEQZ = SEQY +1
	seqZ := type2.SequenceNumber + 1

	// R = SHA256(SRV)
	response := sha256.Sum256(type2.Challenge[:])

	// Plaintext = SEQZ || R || MEDIA
	plaintext := make([]byte, 8+32+len(media))

	// generate a new AES-GCM nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return Message{}, err
	}

	block, err := crypto.CreateAcmCipher(aeskey)
	if err != nil {
		return Message{}, err
	}

	//encifrar and authenticate Type3
	ciphertext, err := crypto.EncryptBlock(
		plaintext, block, nonce, seqZ,
	)
	if err != nil {
		return Message{}, err
	}

	//pauload = nonce || ciphertext || tag
	payload := append(nonce, ciphertext...)

	return Message{
		Type:    TypeResquest,
		Payload: payload,
	}, nil
}

//Dedcrypts anad validates the 3 handshake message
// the server verifies SEQZ and the challange responde

func ParseHandshakeType3(msg Message, seqY uint64, challenge [32]byte, aesKey []byte) (HandshakeType3, error) {
	if msg.Type != TypeRequest || len(msg.Payload) < 69 { // nonce + seqz + r + media + tag = 12 + 8 + 32 + 1 + 16 = 69
		return HandshakeType3{}, fmt.Errorf("invalida Type3 message")
	}
	if len(aesKey) != 32 || seqY == ^uint64(0) {
		return HandshakeType3{}, fmt.Errorf("invalid key or sequence number")
	}

	//expected seq number
	seqZ = seqY + 1

	//extract nonce and ciphertext
	nonce := msg.Payloa[:12]
	ciphertext := msg.Payload[12:]

	block, err := crypto.CreateAcmCipher(aesKey)
	if err !nil {
		return HandshakeType3{},err
	}

	//decrypts and uuthenticate the massage
	plaintext, err := crypto.DecryptBlock(
		ciphertext, block, nonce, seqz,
	)
	if err != nil {
		return HandshakeType3{}, fmt.Errorf("Type 3 uuthentication failed: %w", err)
	}

	if len(plaintext) < 41 {
		return HandshakeType3{}, fmt.Errorf("invalid Type 3 plaintext")
	}

	//verify SEQZ
	receivedSeq := binary.BigEndian.Uint64(playtext[:8])
	if receivedSeq != seqZ {
		return HandshakeType3, fmt.Errorf("unexpected SEQZ")
	}

	//verify R = sha256
	var responde [32]byte
	copy(responde[:], plaintext[8:40])

	expectedResponse := sha256.Sum256(challange[:])

	if subtle.ConstantTimeCompare(response[:], expectedResponse[:]) != 1{
		return HandshakeType3{}, fmt.Errorf("invalid challange response")
	}

	//Extract request media name
	media := strings(plaintext[40:])
	if !validMediaName(media){
		return HandshakeType3{}, fmt.Errorf("invalid media name")
	}

	return HandshakeType3{
		SequenceNumber: seqZ,
		Response:       response,
		Media:          media,
	}, nil
}
