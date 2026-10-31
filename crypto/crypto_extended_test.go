package crypto

import (
	"bytes"
	"testing"
)

// Tests the full DH -> HKDF pipeline
func TestDiffieHellmanEndToEnd(t *testing.T) {
	proxyPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Proxy private key failed: %v", err)
	}
	proxyPub := GetPublicKey(proxyPriv)

	serverPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Server private key failed: %v", err)
	}
	serverPub := GetPublicKey(serverPriv)

	proxyShared, err := SharedSecret(proxyPriv, serverPub)
	if err != nil {
		t.Fatalf("Proxy shared secret failed: %v", err)
	}

	serverShared, err := SharedSecret(serverPriv, proxyPub)
	if err != nil {
		t.Fatalf("Server shared secret failed: %v", err)
	}

	if !bytes.Equal(proxyShared, serverShared) {
		t.Fatal("Shared secrets do not match")
	}

	proxyAES, err := DeriveAESKey(proxyShared)
	if err != nil {
		t.Fatalf("Proxy AES derivation failed: %v", err)
	}

	serverAES, err := DeriveAESKey(serverShared)
	if err != nil {
		t.Fatalf("Server AES derivation failed: %v", err)
	}

	if !bytes.Equal(proxyAES, serverAES) {
		t.Fatal("Derived AES keys do not match")
	}
}

// Tests Pack -> Unpack -> Decrypt
func TestAESGCMPackagingAndTamper(t *testing.T) {
	key := make([]byte, 32)
	block, _ := CreateAcmCipher(key)
	nonce := GenerateNonce()
	plaintext := []byte("Valid media block")
	seq := uint64(1)

	// Encrypt and Pack
	encrypted, err := EncryptBlock(plaintext, block, nonce, seq)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	packet, err := PackageContents(seq, nonce, encrypted)
	if err != nil {
		t.Fatalf("Packaging failed: %v", err)
	}

	// Simulate transit tampering
	tamperedPacket := make([]byte, len(packet))
	copy(tamperedPacket, packet)
	tamperedPacket[30] ^= 0xFF 

	// Unpack and attempt decrypt on tampered
	unpackedSeq, unpackedNonce, unpackedCipher, err := UnpackContents(tamperedPacket)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	_, err = DecryptBlock(unpackedCipher, block, unpackedNonce, unpackedSeq)
	if err == nil {
		t.Fatal("Tampered packet successfully decrypted; authentication failed to catch it")
	}
}

// Simulates rejecting a replayed packet (stateful check)
func TestReplayAttack(t *testing.T) {
	key := make([]byte, 32)
	block, _ := CreateAcmCipher(key)
	nonce := GenerateNonce()
	plaintext := []byte("Sensitive data")
	
	encrypted, _ := EncryptBlock(plaintext, block, nonce, 5)
	packet, _ := PackageContents(5, nonce, encrypted)

	// Simulated Proxy State
	var expectedSeq uint64 = 5

	// Intercept and replay the exact same valid packet
	for i := 0; i < 2; i++ {
		seq, extNonce, cipher, _ := UnpackContents(packet)
		
		if seq < expectedSeq {
			if i == 1 {
				return // Replay successfully caught
			}
			t.Fatalf("Legitimate packet rejected on first pass")
		}
		
		_, err := DecryptBlock(cipher, block, extNonce, seq)
		if err != nil {
			t.Fatalf("Failed to decrypt valid packet: %v", err)
		}
		expectedSeq++ // Proxy increments expected sequence after success
	}
	t.Fatal("Replayed packet was accepted")
}

func TestEdgeCases(t *testing.T) {
	key := make([]byte, 32)
	block, _ := CreateAcmCipher(key)
	nonce := GenerateNonce()
	
	// Test 0-byte payload (End of stream signaling)
	emptyPlaintext := []byte{}
	encrypted, err := EncryptBlock(emptyPlaintext, block, nonce, 1)
	if err != nil {
		t.Fatalf("Failed to encrypt empty payload: %v", err)
	}
	
	decrypted, err := DecryptBlock(encrypted, block, nonce, 1)
	if err != nil || len(decrypted) != 0 {
		t.Fatalf("Failed to decrypt empty payload: %v", err)
	}

	// Test oversized payload (e.g., 5MB block)
	largePlaintext := make([]byte, 5*1024*1024)
	encryptedLarge, _ := EncryptBlock(largePlaintext, block, nonce, 2)
	decryptedLarge, err := DecryptBlock(encryptedLarge, block, nonce, 2)
	if err != nil || !bytes.Equal(largePlaintext, decryptedLarge) {
		t.Fatal("Failed to handle large payload")
	}
}

// Tests throughput to ensure AES operations don't bottleneck the stream
func BenchmarkAESGCM(b *testing.B) {
	key := make([]byte, 32)
	block, _ := CreateAcmCipher(key)
	nonce := GenerateNonce()
	plaintext := make([]byte, 1024) // 1KB standard block

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i)
		encrypted, _ := EncryptBlock(plaintext, block, nonce, seq)
		_, _ = DecryptBlock(encrypted, block, nonce, seq)
	}
}
