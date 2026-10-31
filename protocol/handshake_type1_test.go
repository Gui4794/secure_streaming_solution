package protocol

import (
	"bytes"
	"testing"

	"secure_streaming_solution/config"
)

// Tests the creation and parsing of a Type 1 handshake message.
func TestHandshakeType1(t *testing.T) {

	cfg := config.ConfigOutput{
		CipherAlgorithm: "AES",
		CipherMode:      "GCM",
		IV:              "NULL",
		Padding:         "NULL",
	}

	// Create Type 1 message
	msg, seqX, err := CreateHandshakeType1(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Parse Type 1 message
	parsed, err := ParseHandshakeType1(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify sequence number
	if parsed.SequenceNumber != seqX {
		t.Fatal("Sequence number does not match")
	}

	// Verify cryptographic configuration
	if parsed.Algorithm != "AES" ||
		parsed.Mode != "GCM" ||
		parsed.IV != "NULL" ||
		parsed.Padding != "NULL" {
		t.Fatal("Cryptographic configuration does not match")
	}

	t.Log("Handshake Type 1 created and parsed successfully")
}

// Tests sending and receiving a Type 1 message.
func TestHandshakeType1Transmission(t *testing.T) {

	cfg := config.ConfigOutput{
		CipherAlgorithm: "AES",
		CipherMode:      "GCM",
		IV:              "NULL",
		Padding:         "NULL",
	}

	msg, _, err := CreateHandshakeType1(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var buffer bytes.Buffer

	// Write message to buffer
	err = WriteMessage(&buffer, msg.Type, msg.Payload)
	if err != nil {
		t.Fatal(err)
	}

	// Read message from buffer
	received, err := ReadMessage(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	if received.Type != TypeProposal {
		t.Fatal("Incorrect message type")
	}

	if !bytes.Equal(msg.Payload, received.Payload) {
		t.Fatal("Received payload does not match")
	}

	t.Log("Handshake Type 1 transmission successful")
}
