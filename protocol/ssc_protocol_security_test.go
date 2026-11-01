package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"secure_streaming_solution/config"
	streamcrypto "secure_streaming_solution/crypto"
	"secure_streaming_solution/protocol"
)

func sscConfig() config.ConfigOutput {
	return config.ConfigOutput{CipherAlgorithm: "AES", CipherMode: "GCM", IV: "NULL", IVSize: 96, Padding: "NULL", MacAlgorithm: "NULL", SymKeySize: 256}
}
func sscAESKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}
func sscSendAlert(t *testing.T, key []byte, direction byte) protocol.Message {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.SendAuthenticatedErrorAlert(&buf, "security test", key, direction); err != nil {
		t.Fatal(err)
	}
	msg, err := protocol.ReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
func sscMustReject(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("insecure acceptance: expected an error")
	}
}

func TestSSCMessageFraming(t *testing.T) {
	for _, kind := range []uint8{protocol.TypeProposal, protocol.TypeConfirmation, protocol.TypeRequest, protocol.TypeMediaBlock, protocol.TypeEndBlock, protocol.TypeError} {
		t.Run(fmt.Sprintf("roundtrip_type_%d", kind), func(t *testing.T) {
			var wire bytes.Buffer
			payload := []byte{0, 1, 2, 0, 255}
			if err := protocol.WriteMessage(&wire, kind, payload); err != nil {
				t.Fatal(err)
			}
			if wire.Len() != 9+len(payload) {
				t.Fatal("incorrect header size")
			}
			b := wire.Bytes()
			if binary.BigEndian.Uint16(b[:2]) != protocol.Version || binary.BigEndian.Uint16(b[2:4]) != protocol.Release || b[4] != kind {
				t.Fatal("invalid header")
			}
			msg, err := protocol.ReadMessage(&wire)
			if err != nil {
				t.Fatal(err)
			}
			if msg.Type != kind || !bytes.Equal(msg.Payload, payload) {
				t.Fatal("corrupt message roundtrip")
			}
		})
	}
	for _, kind := range []uint8{0, 6, 254} {
		var b bytes.Buffer
		sscMustReject(t, protocol.WriteMessage(&b, kind, nil))
	}
	t.Run("oversized_outgoing_payload", func(t *testing.T) {
		var b bytes.Buffer
		sscMustReject(t, protocol.WriteMessage(&b, protocol.TypeError, make([]byte, (1<<20)+1)))
	})
	var good bytes.Buffer
	if err := protocol.WriteMessage(&good, protocol.TypeProposal, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"wrong_version", func(b []byte) []byte { b[1] = 0xff; return b }},
		{"wrong_release", func(b []byte) []byte { b[3] = 0xff; return b }},
		{"wrong_type", func(b []byte) []byte { b[4] = 254; return b }},
		{"oversized_size", func(b []byte) []byte { binary.BigEndian.PutUint32(b[5:9], 1<<20+1); return b }},
		{"truncated_payload", func(b []byte) []byte { return b[:len(b)-1] }},
		{"truncated_header", func(b []byte) []byte { return b[:5] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.change(bytes.Clone(good.Bytes()))
			_, err := protocol.ReadMessage(bytes.NewReader(b))
			sscMustReject(t, err)
		})
	}
}

func TestSSCHandshakeAndStreaming(t *testing.T) {
	cfg := sscConfig()
	key := sscAESKey(t)
	first, seqX, err := protocol.CreateHandshakeType1(cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstParsed, err := protocol.ParseHandshakeType1(first)
	if err != nil {
		t.Fatal(err)
	}
	if firstParsed.SequenceNumber != seqX || firstParsed.Algorithm != "AES" {
		t.Fatal("Type 1 differs")
	}
	second, challenge, err := protocol.CreateHandshakeType2(firstParsed, cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	secondParsed, err := protocol.ParseHandshakeType2(second, seqX, cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	if secondParsed.Challenge != challenge || secondParsed.SequenceNumber != seqX+1 {
		t.Fatal("Type 2 differs")
	}
	third, err := protocol.CreateHandshakeType3(secondParsed, "dante.mp4", key)
	if err != nil {
		t.Fatal(err)
	}
	thirdParsed, err := protocol.ParseHandshakeType3(third, seqX+1, challenge, key)
	if err != nil {
		t.Fatal(err)
	}
	if thirdParsed.Media != "dante.mp4" || thirdParsed.SequenceNumber != seqX+2 {
		t.Fatal("Type 3 differs")
	}
	plaintext := []byte("encrypted stream block 1")
	fourth, err := protocol.CreateType4Message(seqX+3, plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseType4Message(fourth.Payload, seqX+3, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("Type 4 decrypted contents differ")
	}
	end, err := protocol.CreateType5Message(seqX+4, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.ParseType5Message(end, seqX+4, key); err != nil {
		t.Fatal(err)
	}

	t.Run("Type1_bad_format", func(t *testing.T) {
		sscMustReject(t, func() error {
			_, err := protocol.ParseHandshakeType1(protocol.Message{Type: protocol.TypeProposal, Payload: []byte{1}})
			return err
		}())
	})
	t.Run("Type2_changed_ciphertext", func(t *testing.T) {
		bad := second
		bad.Payload = bytes.Clone(second.Payload)
		bad.Payload[len(bad.Payload)-1] ^= 1
		_, err := protocol.ParseHandshakeType2(bad, seqX, cfg, key)
		sscMustReject(t, err)
	})
	t.Run("Type2_wrong_session_key", func(t *testing.T) {
		_, err := protocol.ParseHandshakeType2(second, seqX, cfg, sscAESKey(t))
		sscMustReject(t, err)
	})
	t.Run("Type2_wrong_sequence", func(t *testing.T) {
		_, err := protocol.ParseHandshakeType2(second, seqX+1, cfg, key)
		sscMustReject(t, err)
	})
	t.Run("Type2_configuration_mismatch", func(t *testing.T) {
		other := cfg
		other.IV = "DIFFERENT"
		_, _, err := protocol.CreateHandshakeType2(firstParsed, other, key)
		sscMustReject(t, err)
	})
	t.Run("Type3_changed_ciphertext", func(t *testing.T) {
		bad := third
		bad.Payload = bytes.Clone(third.Payload)
		bad.Payload[len(bad.Payload)-1] ^= 1
		_, err := protocol.ParseHandshakeType3(bad, seqX+1, challenge, key)
		sscMustReject(t, err)
	})
	t.Run("Type3_wrong_challenge", func(t *testing.T) {
		wrong := challenge
		wrong[0] ^= 1
		_, err := protocol.ParseHandshakeType3(third, seqX+1, wrong, key)
		sscMustReject(t, err)
	})
	t.Run("Type3_media_path_traversal", func(t *testing.T) {
		bad, err := protocol.CreateHandshakeType3(secondParsed, "../secret.mp4", key)
		if err != nil {
			return
		}
		_, err = protocol.ParseHandshakeType3(bad, seqX+1, challenge, key)
		sscMustReject(t, err)
	})
	t.Run("Type4_changed_ciphertext", func(t *testing.T) {
		bad := bytes.Clone(fourth.Payload)
		bad[len(bad)-1] ^= 1
		_, err := protocol.ParseType4Message(bad, seqX+3, key)
		sscMustReject(t, err)
	})
	t.Run("Type4_replay", func(t *testing.T) {
		_, err := protocol.ParseType4Message(fourth.Payload, seqX+4, key)
		sscMustReject(t, err)
	})
	t.Run("Type4_reordering", func(t *testing.T) {
		later, err := protocol.CreateType4Message(seqX+4, []byte("later"), key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = protocol.ParseType4Message(later.Payload, seqX+3, key)
		sscMustReject(t, err)
	})
	t.Run("Type4_wrong_key", func(t *testing.T) {
		_, err := protocol.ParseType4Message(fourth.Payload, seqX+3, sscAESKey(t))
		sscMustReject(t, err)
	})
	t.Run("Type5_changed_ciphertext", func(t *testing.T) {
		bad := end
		bad.Payload = bytes.Clone(end.Payload)
		bad.Payload[len(bad.Payload)-1] ^= 1
		sscMustReject(t, protocol.ParseType5Message(bad, seqX+4, key))
	})
	t.Run("Type5_wrong_sequence", func(t *testing.T) { sscMustReject(t, protocol.ParseType5Message(end, seqX+3, key)) })
	t.Run("Type5_invalid_END_marker_with_valid_tag", func(t *testing.T) {
		seq, nonce, ciphertext, err := streamcrypto.UnpackContents(end.Payload)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := streamcrypto.CreateAcmCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := streamcrypto.DecryptBlock(ciphertext, aead, nonce, seq)
		if err != nil {
			t.Fatal(err)
		}
		plaintext[8] = 'B'
		freshNonce := streamcrypto.GenerateNonce()
		encrypted, err := streamcrypto.EncryptBlock(plaintext, aead, freshNonce, seq)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := streamcrypto.PackageContents(seq, freshNonce, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		sscMustReject(t, protocol.ParseType5Message(protocol.Message{Type: protocol.TypeEndBlock, Payload: payload}, seq, key))
	})
	t.Run("Type5_wrong_key", func(t *testing.T) { sscMustReject(t, protocol.ParseType5Message(end, seqX+4, sscAESKey(t))) })
}

func TestSSCAuthenticatedAlertAndReplay(t *testing.T) {
	key := sscAESKey(t)
	msg := sscSendAlert(t, key, protocol.AlertFromServer)
	reason, err := protocol.ParseAuthenticatedErrorAlert(msg, key, protocol.AlertFromServer)
	if err != nil || reason != "security test" {
		t.Fatalf("valid Type255 rejected: %q %v", reason, err)
	}
	t.Run("tampered_tag", func(t *testing.T) {
		bad := msg
		bad.Payload = bytes.Clone(msg.Payload)
		bad.Payload[len(bad.Payload)-1] ^= 1
		_, err := protocol.ParseAuthenticatedErrorAlert(bad, key, protocol.AlertFromServer)
		sscMustReject(t, err)
	})
	t.Run("tampered_nonce", func(t *testing.T) {
		bad := msg
		bad.Payload = bytes.Clone(msg.Payload)
		bad.Payload[0] ^= 1
		_, err := protocol.ParseAuthenticatedErrorAlert(bad, key, protocol.AlertFromServer)
		sscMustReject(t, err)
	})
	t.Run("wrong_sender", func(t *testing.T) {
		_, err := protocol.ParseAuthenticatedErrorAlert(msg, key, protocol.AlertFromProxy)
		sscMustReject(t, err)
	})
	t.Run("wrong_key", func(t *testing.T) {
		_, err := protocol.ParseAuthenticatedErrorAlert(msg, sscAESKey(t), protocol.AlertFromServer)
		sscMustReject(t, err)
	})
	t.Run("plaintext_alert", func(t *testing.T) {
		_, err := protocol.ParseAuthenticatedErrorAlert(protocol.Message{Type: protocol.TypeError, Payload: []byte("plain")}, key, protocol.AlertFromServer)
		sscMustReject(t, err)
	})
	t.Run("wrong_message_type", func(t *testing.T) {
		bad := msg
		bad.Type = protocol.TypeEndBlock
		_, err := protocol.ParseAuthenticatedErrorAlert(bad, key, protocol.AlertFromServer)
		sscMustReject(t, err)
	})
	t.Run("empty_reason", func(t *testing.T) {
		var b bytes.Buffer
		sscMustReject(t, protocol.SendAuthenticatedErrorAlert(&b, "", key, protocol.AlertFromServer))
	})
	t.Run("oversized_reason", func(t *testing.T) {
		var b bytes.Buffer
		sscMustReject(t, protocol.SendAuthenticatedErrorAlert(&b, strings.Repeat("x", 257), key, protocol.AlertFromServer))
	})
	t.Run("invalid_sender", func(t *testing.T) {
		var b bytes.Buffer
		sscMustReject(t, protocol.SendAuthenticatedErrorAlert(&b, "test", key, 66))
	})
	t.Run("replay", func(t *testing.T) {
		var guard protocol.AlertReplayGuard
		if _, err := guard.ParseAuthenticatedErrorAlertOnce(msg, key, protocol.AlertFromServer); err != nil {
			t.Fatal(err)
		}
		_, err := guard.ParseAuthenticatedErrorAlertOnce(msg, key, protocol.AlertFromServer)
		sscMustReject(t, err)
		fresh := sscSendAlert(t, key, protocol.AlertFromServer)
		if _, err := guard.ParseAuthenticatedErrorAlertOnce(fresh, key, protocol.AlertFromServer); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tampering_does_not_consume_nonce", func(t *testing.T) {
		var guard protocol.AlertReplayGuard
		bad := msg
		bad.Payload = bytes.Clone(msg.Payload)
		bad.Payload[len(bad.Payload)-1] ^= 1
		_, err := guard.ParseAuthenticatedErrorAlertOnce(bad, key, protocol.AlertFromServer)
		sscMustReject(t, err)
		if _, err := guard.ParseAuthenticatedErrorAlertOnce(msg, key, protocol.AlertFromServer); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSSCEd25519BindingAndConfig(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proxyPub, proxyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverX := make([]byte, 32)
	proxyX := make([]byte, 32)
	if _, err := rand.Read(serverX); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(proxyX); err != nil {
		t.Fatal(err)
	}
	serverSig, err := protocol.SignX25519Exchange(serverPriv, protocol.X25519SignerServer, serverX, proxyX)
	if err != nil {
		t.Fatal(err)
	}
	proxySig, err := protocol.SignX25519Exchange(proxyPriv, protocol.X25519SignerProxy, serverX, proxyX)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyX25519Exchange(serverPub, protocol.X25519SignerServer, serverX, proxyX, serverSig); err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyX25519Exchange(proxyPub, protocol.X25519SignerProxy, serverX, proxyX, proxySig); err != nil {
		t.Fatal(err)
	}
	t.Run("MITM_modifies_X25519_key", func(t *testing.T) {
		bad := bytes.Clone(proxyX)
		bad[0] ^= 1
		sscMustReject(t, protocol.VerifyX25519Exchange(serverPub, protocol.X25519SignerServer, serverX, bad, serverSig))
	})
	t.Run("MITM_modifies_signature", func(t *testing.T) {
		bad := bytes.Clone(serverSig)
		bad[0] ^= 1
		sscMustReject(t, protocol.VerifyX25519Exchange(serverPub, protocol.X25519SignerServer, serverX, proxyX, bad))
	})
	t.Run("untrusted_signer", func(t *testing.T) {
		sscMustReject(t, protocol.VerifyX25519Exchange(proxyPub, protocol.X25519SignerServer, serverX, proxyX, serverSig))
	})
	t.Run("signature_direction", func(t *testing.T) {
		sscMustReject(t, protocol.VerifyX25519Exchange(serverPub, protocol.X25519SignerProxy, serverX, proxyX, serverSig))
	})
	cfg := sscConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		modify func(*config.ConfigOutput)
	}{
		{"unsupported_algorithm", func(c *config.ConfigOutput) { c.CipherAlgorithm = "DES" }},
		{"unsupported_mode", func(c *config.ConfigOutput) { c.CipherMode = "CBC" }},
		{"wrong_IV_size", func(c *config.ConfigOutput) { c.IVSize = 64 }},
		{"wrong_AES_key_size", func(c *config.ConfigOutput) { c.SymKeySize = 64 }},
		{"wrong_padding", func(c *config.ConfigOutput) { c.Padding = "PKCS7" }},
		{"wrong_MAC", func(c *config.ConfigOutput) { c.MacAlgorithm = "HMAC-SHA256" }},
	} {
		t.Run("config_"+tc.name, func(t *testing.T) { bad := cfg; tc.modify(&bad); sscMustReject(t, bad.Validate()) })
	}
}
