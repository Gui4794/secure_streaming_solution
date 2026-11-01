package protocol

import (
	"bytes"
	"testing"
)

func TestSendErrorAlert(t *testing.T) {
	var buffer bytes.Buffer

	// Send Type 255
	err := SendErrorAlert(&buffer, "expected Type 3")
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
		t.Errorf("expected Type 255, got Type %d", msg.Type)
	}

	// Verify error message
	if string(msg.Payload) != "expected Type 3" {
		t.Errorf("unexpected alert payload: %s", msg.Payload)
	}
}
