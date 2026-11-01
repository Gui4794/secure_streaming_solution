package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Version uint16 = 1
	Release uint16 = 1

	headerSize     = 9
	maxPayloadSize = 1 << 20

	TypeProposal     uint8 = 1
	TypeConfirmation uint8 = 2
	TypeRequest      uint8 = 3
	TypeMediaBlock   uint8 = 4
	TypeEndBlock     uint8 = 5
	TypeError        uint8 = 255
)

type Message struct {
	Type    uint8
	Payload []byte
}

// what does this do :
// WriteMessage() — constrói e envia uma mensagem.
// ReadMessage() — recebe uma mensagem e verifica o header.
//Message — representa o tipo e conteúdo de uma mensagem.

func validType(t uint8) bool {
	return (t >= TypeProposal && t <= TypeEndBlock) || t == TypeError
}

// Sends a protocol message with a header and payload.
func WriteMessage(w io.Writer, messageType uint8, payload []byte) error {
	if !validType(messageType) {
		return fmt.Errorf("invalid message type: %d", messageType)
	}

	if len(payload) > maxPayloadSize {
		return fmt.Errorf("payload too large")
	}

	var header [headerSize]byte

	binary.BigEndian.PutUint16(header[0:2], Version)
	binary.BigEndian.PutUint16(header[2:4], Release)
	header[4] = messageType
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))

	if _, err := io.Copy(w, bytes.NewReader(header[:])); err != nil {
		return err
	}

	_, err := io.Copy(w, bytes.NewReader(payload))
	return err
}

// Reads a protocol message and validates its header.
func ReadMessage(r io.Reader) (Message, error) {
	var header [headerSize]byte

	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Message{}, err
	}

	if binary.BigEndian.Uint16(header[0:2]) != Version ||
		binary.BigEndian.Uint16(header[2:4]) != Release {
		return Message{}, fmt.Errorf("unsupported protocol version")
	}

	messageType := header[4]
	if !validType(messageType) {
		return Message{}, fmt.Errorf("invalid message type")
	}

	payloadSize := binary.BigEndian.Uint32(header[5:9])
	if payloadSize > maxPayloadSize {
		return Message{}, fmt.Errorf("payload too large")
	}

	payload := make([]byte, payloadSize)

	if _, err := io.ReadFull(r, payload); err != nil {
		return Message{}, err
	}

	return Message{
		Type:    messageType,
		Payload: payload,
	}, nil
}
