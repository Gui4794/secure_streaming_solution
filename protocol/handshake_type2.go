package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"secure_streaming_solution/config"
	"secure_streaming_solution/crypto"
)

type HandshakeType2 struct {
	SequenceNumber         uint64
	Challenge              [32]byte
	ConfirmedConfiguration string
}

// server confirms the proposed configuration and
// sends an encrypted challenge to the Proxy.
func CreateHandshakeType2(type1 HandshakeType1, cfg config.ConfigOutput, aesKey []byte) (Message, [32]byte, error) {
	var challenge [32]byte

	//ola gui ainda tenho de confirmar este codigo melhor mas estou a morrer de sono !!!!!!!!!!!!!!!!
	//
	//
	// https://pkg.go.dev/crypto/cipher
	// https://www.rfc-editor.org/info/rfc5869/
	// and also stuff about handshakes : https://noiseprotocol.org/noise.html
	//
	// also temos de autenticar a troca de chaves
	//
	//proposed and supported configurations
	cccFields := []string{cfg.CipherAlgorithm, cfg.CipherMode, cfg.IV, cfg.Padding}
	if cfg.SymKeySize != 256 {
		cccFields = append(cccFields, strconv.Itoa(cfg.SymKeySize))
	}
	ccc := strings.Join(cccFields, "/")

	pccFields := []string{type1.Algorithm, type1.Mode, type1.IV, type1.Padding}
	if type1.KeySize != 256 {
		pccFields = append(pccFields, strconv.Itoa(type1.KeySize))
	}
	pcc := strings.Join(pccFields, "/")

	if ccc != pcc || cfg.SymKeySize != type1.KeySize || cfg.CipherAlgorithm != "AES" || cfg.CipherMode != "GCM" {
		return Message{}, challenge, fmt.Errorf("proposed configuration not supported")
	}

	if len(aesKey) != 32 || type1.SequenceNumber > ^uint64(0)-3 {
		return Message{}, challenge, fmt.Errorf("invalid session key or sequence number")
	}

	// SEQY = SEQX + 1
	seqY := type1.SequenceNumber + 1

	// Generate a random 256-bit challenge (SRV)
	if _, err := rand.Read(challenge[:]); err != nil {
		return Message{}, challenge, err
	}

	// generate a 12-byte AES-GCM nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return Message{}, challenge, err
	}

	// plaintext = SEQY || SRV || CCC
	plaintext := make([]byte, 8+32+len(ccc))

	binary.BigEndian.PutUint64(plaintext[:8], seqY)
	copy(plaintext[8:40], challenge[:])
	copy(plaintext[40:], ccc)

	// encifrar the Type 2 contents using AES-GCM
	block, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		return Message{}, challenge, err
	}

	ciphertext, err := crypto.EncryptBlock(
		plaintext, block, nonce, seqY,
	)
	if err != nil {
		return Message{}, challenge, err
	}

	// payload = nonce || ciphertext || authentication tag
	payload := append(nonce, ciphertext...)

	return Message{
		Type:    TypeConfirmation,
		Payload: payload,
	}, challenge, nil
}

// decrypts and interprets the second handshake message.
// the Proxy verifies SEQY and the confirmed configuration.
func ParseHandshakeType2(msg Message, seqX uint64, cfg config.ConfigOutput, aesKey []byte) (HandshakeType2, error) {
	if msg.Type != TypeConfirmation || len(msg.Payload) < 69 {
		return HandshakeType2{}, fmt.Errorf("invalid Type 2 message")
	}

	if len(aesKey) != 32 || seqX > ^uint64(0)-3 {
		return HandshakeType2{}, fmt.Errorf("invalid session key or sequence number")
	}

	// expected sequence number
	seqY := seqX + 1

	// extract nonce and encrypted contents
	nonce := msg.Payload[:12]
	ciphertext := msg.Payload[12:]

	block, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		return HandshakeType2{}, err
	}

	// decrypt and authenticate the message
	plaintext, err := crypto.DecryptBlock(
		ciphertext, block, nonce, seqY,
	)
	if err != nil {
		return HandshakeType2{}, fmt.Errorf("Type 2 authentication failed: %w", err)
	}

	// verify SEQY
	receivedSeq := binary.BigEndian.Uint64(plaintext[:8])
	if receivedSeq != seqY {
		return HandshakeType2{}, fmt.Errorf("unexpected SEQY")
	}

	// verify the confirmed cryptographic configuration
	ccc := string(plaintext[40:])

	expectedFields := []string{cfg.CipherAlgorithm, cfg.CipherMode, cfg.IV, cfg.Padding}
	if cfg.SymKeySize != 256 {
		expectedFields = append(expectedFields, strconv.Itoa(cfg.SymKeySize))
	}
	expected := strings.Join(expectedFields, "/")

	if ccc != expected {
		return HandshakeType2{}, fmt.Errorf("server confirmed a different configuration")
	}

	// extract the 256-bit challenge
	var challenge [32]byte
	copy(challenge[:], plaintext[8:40])

	return HandshakeType2{
		SequenceNumber:         seqY,
		Challenge:              challenge,
		ConfirmedConfiguration: ccc,
	}, nil
}

//diagramaaa que poder ficar bem em relatorio e helps beatriz
//
/* SECURE PROXY                     STREAM SERVER
   |                                 |
   |<------ X25519 Key Exchange ---->|
   |         HKDF → AES Key          |
   |                                 |
   |---- Type 1: SEQX + PCC -------->|
   |                                 |
   |<--- Type 2: SEQY + SRV + CCC ---|
   |         (Encrypted)             |
   |                                 |
   |---- Type 3: SEQZ + R + MEDIA -->|
   |         (Encrypted)             |
   |                                 |
   |====== HANDSHAKE COMPLETE =======|
   |                                 |
   |<--- Type 4: Encrypted Block ----|
   |<--- Type 4: Encrypted Block ----|
   |<--- Type 4: Encrypted Block ----|
   |             ...                 |
   |<--- Type 5: END BLOCK ---------|
   |                                 |
   v                                 |
BROWSER                              |
(Decrypted Video)                    |

*/
