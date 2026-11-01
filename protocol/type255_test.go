package protocol

import (
	"bytes"
	"testing"
)

func TestSendErrorAlert(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)

	for _, tc := range []struct {
		name   string
		sender byte
	}{
		{"Proxy", AlertFromProxy},
		{"Server", AlertFromServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer

			// Send authenticated Type 255
			err := SendAuthenticatedErrorAlert(&buffer, "expected Type 3", key, tc.sender)
			if err != nil {
				t.Fatalf("failed to send alert: %v", err)
			}

			// Receive Type 255
			msg, err := ReadMessage(&buffer)
			if err != nil {
				t.Fatalf("failed to read alert: %v", err)
			}

			// Verify message type
			if msg.Type != TypeError {
				t.Fatalf("expected Type 255, got Type %d", msg.Type)
			}

			// Authenticate and decrypt the alert
			reason, err := ParseAuthenticatedErrorAlert(msg, key, tc.sender)
			if err != nil {
				t.Fatalf("failed to authenticate alert: %v", err)
			}
			if reason != "expected Type 3" {
				t.Fatalf("unexpected alert reason: %q", reason)
			}
		})
	}
}

func TestType255RejectsModifiedPayload(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var buffer bytes.Buffer

	if err := SendAuthenticatedErrorAlert(&buffer, "invalid Type 4 block", key, AlertFromProxy); err != nil {
		t.Fatal(err)
	}
	msg, err := ReadMessage(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	// Change one bit of the authentication tag.
	msg.Payload[len(msg.Payload)-1] ^= 0x01
	if _, err := ParseAuthenticatedErrorAlert(msg, key, AlertFromProxy); err == nil {
		t.Fatal("modified Type 255 alert was accepted")
	}
}

func TestType255RejectsWrongSenderAndKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	wrongKey := bytes.Repeat([]byte{0x43}, 32)
	var buffer bytes.Buffer

	if err := SendAuthenticatedErrorAlert(&buffer, "expected Type 2", key, AlertFromServer); err != nil {
		t.Fatal(err)
	}
	msg, err := ReadMessage(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseAuthenticatedErrorAlert(msg, key, AlertFromProxy); err == nil {
		t.Fatal("Type 255 alert was accepted with the wrong sender")
	}
	if _, err := ParseAuthenticatedErrorAlert(msg, wrongKey, AlertFromServer); err == nil {
		t.Fatal("Type 255 alert was accepted with the wrong key")
	}
}

func TestType255RejectsInvalidAndPlaintextAlerts(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)

	// An old plaintext Type 255 alert must not be accepted.
	plaintext := Message{Type: TypeError, Payload: []byte("expected Type 1")}
	if _, err := ParseAuthenticatedErrorAlert(plaintext, key, AlertFromServer); err == nil {
		t.Fatal("plaintext Type 255 alert was accepted")
	}

	var buffer bytes.Buffer
	if err := SendAuthenticatedErrorAlert(&buffer, "", key, AlertFromProxy); err == nil {
		t.Fatal("empty alert reason was accepted")
	}
	if err := SendAuthenticatedErrorAlert(&buffer, "reason", []byte("short"), AlertFromProxy); err == nil {
		t.Fatal("invalid AES key size was accepted")
	}
	if err := SendAuthenticatedErrorAlert(&buffer, "reason", key, 99); err == nil {
		t.Fatal("unknown sender was accepted")
	}
}
