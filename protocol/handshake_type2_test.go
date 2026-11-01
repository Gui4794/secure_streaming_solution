package protocol

import (
	"bytes"
	"testing"

	"secure_streaming_solution/config"
)

// Tests the creation, encryption and decryption
// of the second handshake message.
func TestHandshakeType2(t *testing.T) {

	cfg := config.ConfigOutput{
		CipherAlgorithm: "AES",
		CipherMode:      "GCM",
		IV:              "NULL",
		Padding:         "NULL",
	}

	type1 := HandshakeType1{
		SequenceNumber: 100,
		Algorithm:      "AES",
		Mode:           "GCM",
		IV:             "NULL",
		Padding:        "NULL",
	}

	// AES-256 test key
	aesKey := bytes.Repeat([]byte{1}, 32)

	// Server creates Type 2
	msg, challenge, err := CreateHandshakeType2(
		type1, cfg, aesKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Proxy decrypts and parses Type 2
	parsed, err := ParseHandshakeType2(
		msg, type1.SequenceNumber, cfg, aesKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Verify SEQY = SEQX + 1
	if parsed.SequenceNumber != 101 {
		t.Fatal("Incorrect sequence number")
	}

	// Verify the 256-bit challenge
	if parsed.Challenge != challenge {
		t.Fatal("Challenge does not match")
	}

	// Verify confirmed configuration
	if parsed.ConfirmedConfiguration != "AES/GCM/NULL/NULL" {
		t.Fatal("Incorrect confirmed configuration")
	}

	t.Log("Handshake Type 2 encryption and decryption successful")
}

// Tests that modified encrypted data is rejected.
func TestHandshakeType2Tampering(t *testing.T) {

	cfg := config.ConfigOutput{
		CipherAlgorithm: "AES",
		CipherMode:      "GCM",
		IV:              "NULL",
		Padding:         "NULL",
	}

	type1 := HandshakeType1{
		SequenceNumber: 100,
		Algorithm:      "AES",
		Mode:           "GCM",
		IV:             "NULL",
		Padding:        "NULL",
	}

	aesKey := bytes.Repeat([]byte{1}, 32)

	msg, _, err := CreateHandshakeType2(type1, cfg, aesKey)
	if err != nil {
		t.Fatal(err)
	}

	// Modify one byte of the encrypted payload
	msg.Payload[15] ^= 0xFF

	_, err = ParseHandshakeType2(
		msg, type1.SequenceNumber, cfg, aesKey,
	)

	if err == nil {
		t.Fatal("Tampered Type 2 message was accepted")
	}

	t.Log("Tampered Type 2 message correctly rejected")
}

// Tests that an incorrect sequence number is rejected.
func TestHandshakeType2WrongSequence(t *testing.T) {

	cfg := config.ConfigOutput{
		CipherAlgorithm: "AES",
		CipherMode:      "GCM",
		IV:              "NULL",
		Padding:         "NULL",
	}

	type1 := HandshakeType1{
		SequenceNumber: 100,
		Algorithm:      "AES",
		Mode:           "GCM",
		IV:             "NULL",
		Padding:        "NULL",
	}

	aesKey := bytes.Repeat([]byte{1}, 32)

	msg, _, err := CreateHandshakeType2(type1, cfg, aesKey)
	if err != nil {
		t.Fatal(err)
	}

	// Proxy uses the wrong SEQX
	_, err = ParseHandshakeType2(msg, 200, cfg, aesKey)

	if err == nil {
		t.Fatal("Wrong sequence number was accepted")
	}

	t.Log("Incorrect sequence number correctly rejected")
}
