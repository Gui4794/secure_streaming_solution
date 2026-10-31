package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"

	"secure_streaming_solution/config"
)

type HandshakeType1 struct {
	SequenceNumber uint64
	Algorithm      string
	Mode           string
	IV             string
	Padding        string
}

// The Proxy sends SEQX and its proposed cryptographic
// configuration (PCC) to the Stream Server.
func CreateHandshakeType1(cfg config.ConfigOutput) (Message, uint64, error) {
	fields := []string{
		cfg.CipherAlgorithm,
		cfg.CipherMode,
		cfg.IV,
		cfg.Padding,
	}

	for _, field := range fields {
		if field == "" || strings.Contains(field, "/") {
			return Message{}, 0, fmt.Errorf("invalid cryptographic configuration")
		}
	}

	// generar a random initial sequence number (SEQX).
	var randomBytes [8]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return Message{}, 0, err
	}

	seqX := binary.BigEndian.Uint64(randomBytes[:])

	if seqX > ^uint64(0)-3 {
		return Message{}, 0, fmt.Errorf("sequence number overflow")
	}

	// PCC format: ALG/MODE/IV/Padding
	pcc := strings.Join(fields, "/")

	// Payload = SEQX (8 bytes) + PCC
	payload := make([]byte, 8+len(pcc))
	binary.BigEndian.PutUint64(payload[:8], seqX)
	copy(payload[8:], pcc)

	return Message{
		Type:    TypeProposal,
		Payload: payload,
	}, seqX, nil
}

// Reads and interprets the first handshake message.
// Extracts SEQX and the proposed cryptographic configuration.
func ParseHandshakeType1(msg Message) (HandshakeType1, error) {
	if msg.Type != TypeProposal {
		return HandshakeType1{}, fmt.Errorf("expected Type 1 message")
	}

	if len(msg.Payload) < 9 {
		return HandshakeType1{}, fmt.Errorf("invalid Type 1 payload")
	}

	seqX := binary.BigEndian.Uint64(msg.Payload[:8])

	if seqX > ^uint64(0)-3 {
		return HandshakeType1{}, fmt.Errorf("sequence number overflow")
	}

	fields := strings.Split(string(msg.Payload[8:]), "/")
	if len(fields) != 4 {
		return HandshakeType1{}, fmt.Errorf("invalid PCC format")
	}

	for _, field := range fields {
		if field == "" {
			return HandshakeType1{}, fmt.Errorf("empty PCC field")
		}
	}

	return HandshakeType1{
		SequenceNumber: seqX,
		Algorithm:      fields[0],
		Mode:           fields[1],
		IV:             fields[2],
		Padding:        fields[3],
	}, nil
}

//exemplo de conteudooo: Type 1
/*
	SEQX = 123456789
	PCC  = AES/GCM/NULL/NULL
*/
