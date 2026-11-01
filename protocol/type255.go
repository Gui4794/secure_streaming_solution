package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

const (
	AlertFromProxy  byte = 1
	AlertFromServer byte = 2

	maxAlertReasonSize = 256
)

// Bind the alert to the protocol and sender.
func alertAAD(sender byte) ([]byte, error) {
	switch sender {
	case AlertFromProxy:
		return []byte("3S/1.1/Type255/Proxy"), nil
	case AlertFromServer:
		return []byte("3S/1.1/Type255/Server"), nil
	default:
		return nil, fmt.Errorf("invalid alert sender")
	}
}

// Encrypt and authenticate a Type 255 alert.
func SendAuthenticatedErrorAlert(
	w io.Writer,
	reason string,
	aesKey []byte,
	sender byte,
) error {
	if len(aesKey) != 32 || len(reason) == 0 || len(reason) > maxAlertReasonSize {
		return fmt.Errorf("invalid alert key or reason")
	}

	aad, err := alertAAD(sender)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(reason), aad)
	payload := append(nonce, ciphertext...)

	return WriteMessage(w, TypeError, payload)
}

// Authenticate and decrypt a received Type 255 alert.
func ParseAuthenticatedErrorAlert(
	msg Message,
	aesKey []byte,
	expectedSender byte,
) (string, error) {
	if msg.Type != TypeError || len(aesKey) != 32 {
		return "", fmt.Errorf("invalid Type 255 message or key")
	}

	aad, err := alertAAD(expectedSender)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(msg.Payload) < gcm.NonceSize()+gcm.Overhead()+1 ||
		len(msg.Payload) > gcm.NonceSize()+gcm.Overhead()+maxAlertReasonSize {
		return "", fmt.Errorf("invalid Type 255 payload length")
	}

	nonce := msg.Payload[:gcm.NonceSize()]
	ciphertext := msg.Payload[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", fmt.Errorf("Type 255 authentication failed: %w", err)
	}

	return string(plaintext), nil
}

// AlertReplayGuard tracks authenticated Type 255 nonces for one connection.
// Create a new guard for every new key exchange / session.
type AlertReplayGuard struct {
	mu   sync.Mutex
	seen map[[12]byte]struct{}
}

// ParseAuthenticatedErrorAlertOnce rejects any alert already accepted in this session.
func (guard *AlertReplayGuard) ParseAuthenticatedErrorAlertOnce(
	msg Message,
	aesKey []byte,
	expectedSender byte,
) (string, error) {
	if guard == nil {
		return "", fmt.Errorf("missing Type 255 replay guard")
	}

	// Authenticate first: unauthenticated data must not populate replay state.
	reason, err := ParseAuthenticatedErrorAlert(msg, aesKey, expectedSender)
	if err != nil {
		return "", err
	}

	var nonce [12]byte
	copy(nonce[:], msg.Payload[:12])

	guard.mu.Lock()
	defer guard.mu.Unlock()
	if _, exists := guard.seen[nonce]; exists {
		return "", fmt.Errorf("replayed Type 255 alert")
	}
	if guard.seen == nil {
		guard.seen = make(map[[12]byte]struct{})
	}
	guard.seen[nonce] = struct{}{}
	return reason, nil
}
