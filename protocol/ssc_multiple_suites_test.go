package protocol

import (
	"bytes"
	"fmt"
	"testing"

	"secure_streaming_solution/config"
	"secure_streaming_solution/crypto"
)

func TestMultipleAESGCMKeySizes(t *testing.T) {
	secret := bytes.Repeat([]byte{42}, 32)
	for _, bits := range []int{128, 192, 256} {
		t.Run(fmt.Sprintf("AES-%d-GCM", bits), func(t *testing.T) {
			cfg := config.ConfigOutput{CipherAlgorithm: "AES", CipherMode: "GCM", IV: "NULL", IVSize: 96, Padding: "NULL", MacAlgorithm: "NULL", SymKeySize: bits}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			control, err := crypto.DeriveAESKey(secret)
			if err != nil {
				t.Fatal(err)
			}
			media, err := crypto.DeriveMediaKey(secret, bits)
			if err != nil {
				t.Fatal(err)
			}
			if len(media) != bits/8 {
				t.Fatalf("expected %d bytes, got %d", bits/8, len(media))
			}
			type1msg, _, err := CreateHandshakeType1(cfg)
			if err != nil {
				t.Fatal(err)
			}
			type1, err := ParseHandshakeType1(type1msg)
			if err != nil {
				t.Fatal(err)
			}
			if type1.KeySize != bits {
				t.Fatalf("expected key size %d, got %d", bits, type1.KeySize)
			}
			type2msg, challenge, err := CreateHandshakeType2(type1, cfg, control)
			if err != nil {
				t.Fatal(err)
			}
			type2, err := ParseHandshakeType2(type2msg, type1.SequenceNumber, cfg, control)
			if err != nil {
				t.Fatal(err)
			}
			type3msg, err := CreateHandshakeType3(type2, "dante.mp4", control)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseHandshakeType3(type3msg, type2.SequenceNumber, challenge, control); err != nil {
				t.Fatal(err)
			}
			msg4, err := CreateType4Message(type2.SequenceNumber+2, []byte("a media block"), media)
			if err != nil {
				t.Fatal(err)
			}
			seq, nonce, ciphertext, err := crypto.UnpackContents(msg4.Payload)
			if err != nil {
				t.Fatal(err)
			}
			block, err := crypto.CreateAcmCipher(media)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := crypto.DecryptBlock(ciphertext, block, nonce, seq)
			if err != nil {
				t.Fatal(err)
			}
			if string(plain) != "a media block" {
				t.Fatal("wrong plaintext")
			}
			msg5, err := CreateType5Message(seq+1, media)
			if err != nil {
				t.Fatal(err)
			}
			if err := ParseType5Message(msg5, seq+1, media); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDifferentConfiguredKeySizesRejected(t *testing.T) {
	cfg := config.ConfigOutput{CipherAlgorithm: "AES", CipherMode: "GCM", IV: "NULL", IVSize: 96, Padding: "NULL", MacAlgorithm: "NULL", SymKeySize: 128}
	msg, _, err := CreateHandshakeType1(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseHandshakeType1(msg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SymKeySize = 256
	key, err := crypto.DeriveAESKey(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreateHandshakeType2(parsed, cfg, key); err == nil {
		t.Fatal("mismatch accepted")
	}
}
