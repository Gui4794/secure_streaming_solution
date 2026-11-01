package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestType255ReplayGuardRejectsDuplicate(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var guard AlertReplayGuard

	var first bytes.Buffer
	if err := SendAuthenticatedErrorAlert(&first, "invalid Type 4 block", key, AlertFromProxy); err != nil {
		t.Fatal(err)
	}
	alert1, err := ReadMessage(&first)
	if err != nil {
		t.Fatal(err)
	}
	reason, err := guard.ParseAuthenticatedErrorAlertOnce(alert1, key, AlertFromProxy)
	if err != nil || reason != "invalid Type 4 block" {
		t.Fatalf("first alert must be accepted: reason=%q err=%v", reason, err)
	}
	if _, err := guard.ParseAuthenticatedErrorAlertOnce(alert1, key, AlertFromProxy); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replayed alert was not rejected: %v", err)
	}

	// A different, authenticated alert in the same session still works.
	var second bytes.Buffer
	if err := SendAuthenticatedErrorAlert(&second, "expected Type 3", key, AlertFromProxy); err != nil {
		t.Fatal(err)
	}
	alert2, err := ReadMessage(&second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.ParseAuthenticatedErrorAlertOnce(alert2, key, AlertFromProxy); err != nil {
		t.Fatalf("new authenticated alert was rejected: %v", err)
	}
}

func TestType255InvalidAlertDoesNotPoisonReplayGuard(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var guard AlertReplayGuard
	var wire bytes.Buffer
	if err := SendAuthenticatedErrorAlert(&wire, "expected Type 2", key, AlertFromServer); err != nil {
		t.Fatal(err)
	}
	msg, err := ReadMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}

	tampered := Message{Type: msg.Type, Payload: append([]byte(nil), msg.Payload...)}
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if _, err := guard.ParseAuthenticatedErrorAlertOnce(tampered, key, AlertFromServer); err == nil {
		t.Fatal("tampered alert accepted")
	}
	if _, err := guard.ParseAuthenticatedErrorAlertOnce(msg, key, AlertFromServer); err != nil {
		t.Fatalf("valid alert was blocked by earlier failed authentication: %v", err)
	}
}

func TestType255ReplayGuardRequiresState(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var wire bytes.Buffer
	if err := SendAuthenticatedErrorAlert(&wire, "expected Type 2", key, AlertFromServer); err != nil {
		t.Fatal(err)
	}
	msg, err := ReadMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}
	var missing *AlertReplayGuard
	if _, err := missing.ParseAuthenticatedErrorAlertOnce(msg, key, AlertFromServer); err == nil {
		t.Fatal("missing replay state accepted")
	}
}
