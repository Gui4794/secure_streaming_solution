package crypto

//ficheirooooo de testeeeeeeeeee typeshit

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

// Test 1: Verify that encryption and decryption recover
// the original plaintext.
func TestEncryptDecryptBlock(t *testing.T) {
	key := make([]byte, 32) // AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Hello Secure Streaming!")
	seq := uint64(1)

	ciphertext, err := EncryptBlock(plaintext, block, nonce, seq)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptBlock(ciphertext, block, nonce, seq)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("Decrypted text does not match original")
	}

	t.Log("Encryption and decryption successful")
}

// Test 2: Verify that modifying encrypted data
// causes authentication to fail.
func TestTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	ciphertext, err := EncryptBlock(
		[]byte("Secret video block"), block, nonce, 1,
	)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext[0] ^= 0xFF // Modify one byte

	_, err = DecryptBlock(ciphertext, block, nonce, 1)

	if err == nil {
		t.Fatal("Tampered ciphertext was accepted")
	}

	t.Log("Tampering correctly detected")
}

// Test 3: Verify that a different sequence number
// causes authentication to fail.
func TestWrongSequenceNumber(t *testing.T) {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	ciphertext, err := EncryptBlock(
		[]byte("Video block"), block, nonce, 1,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptBlock(ciphertext, block, nonce, 2)

	if err == nil {
		t.Fatal("Wrong sequence number was accepted")
	}

	t.Log("Wrong sequence number correctly rejected")
}

// Test 4: Verify that decryption with a wrong key fails.
func TestWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := bytes.Repeat([]byte{1}, 32)

	block1, _ := aes.NewCipher(key1)
	block2, _ := aes.NewCipher(key2)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	ciphertext, err := EncryptBlock(
		[]byte("Secret data"), block1, nonce, 1,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptBlock(ciphertext, block2, nonce, 1)

	if err == nil {
		t.Fatal("Decryption succeeded with wrong key")
	}

	t.Log("Wrong key correctly rejected")
}

// Test 5: Verify that an invalid nonce is rejected.
func TestInvalidNonce(t *testing.T) {
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)

	invalidNonce := make([]byte, 8)

	_, err := EncryptBlock(
		[]byte("Video block"), block, invalidNonce, 1,
	)

	if err == nil {
		t.Fatal("Invalid nonce was accepted")
	}

	t.Log("Invalid nonce correctly rejected")
}
