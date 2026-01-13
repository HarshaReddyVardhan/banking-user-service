package crypto

import (
	"strings"
	"sync"
	"testing"
)

// Test keys for testing (32 bytes = 256 bits, base64 encoded = 44 chars)
// Generated using: base64.StdEncoding.EncodeToString(make([]byte, 32))
const (
	testKey1Base64 = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=" // "01234567890123456789012345678901"
	testKey2Base64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=" // "abcdefghijklmnopqrstuvwxyz012345"
	testHMACSecret = "hmac-secret-for-testing-purposes-32chars"
)

func TestNewFieldEncryptor_Success(t *testing.T) {
	keys := []string{testKey1Base64, testKey2Base64}

	encryptor, err := NewFieldEncryptor(keys, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if encryptor.CurrentKeyVersion() != 1 {
		t.Errorf("expected current version 1, got %d", encryptor.CurrentKeyVersion())
	}
}

func TestNewFieldEncryptor_InvalidVersion(t *testing.T) {
	keys := []string{testKey1Base64}

	_, err := NewFieldEncryptor(keys, 5, testHMACSecret)
	if err == nil {
		t.Error("expected error for invalid version")
	}
}

func TestNewFieldEncryptor_InvalidKeyLength(t *testing.T) {
	// Key that decodes to wrong length
	shortKey := "c2hvcnQ=" // "short" in base64

	_, err := NewFieldEncryptor([]string{shortKey}, 1, testHMACSecret)
	if err == nil {
		t.Error("expected error for invalid key length")
	}
}

func TestNewFieldEncryptor_EmptyKeys(t *testing.T) {
	_, err := NewFieldEncryptor([]string{}, 1, testHMACSecret)
	if err == nil {
		t.Error("expected error for empty keys")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	encryptor, err := NewFieldEncryptor([]string{testKey1Base64}, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"simple string", "hello world"},
		{"email", "user@example.com"},
		{"phone", "+1-555-123-4567"},
		{"empty string", ""},
		{"unicode", "日本語テスト"},
		{"special chars", "!@#$%^&*()"},
		{"long string", strings.Repeat("a", 10000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := encryptor.EncryptString(tc.plaintext)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			decrypted, version, err := encryptor.DecryptString(encrypted)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			if decrypted != tc.plaintext {
				t.Errorf("expected %q, got %q", tc.plaintext, decrypted)
			}

			if version != 1 {
				t.Errorf("expected version 1, got %d", version)
			}
		})
	}
}

func TestEncrypt_UniqueCiphertext(t *testing.T) {
	encryptor, err := NewFieldEncryptor([]string{testKey1Base64}, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	plaintext := "same plaintext"

	// Encrypt the same plaintext multiple times
	encrypted1, _ := encryptor.EncryptString(plaintext)
	encrypted2, _ := encryptor.EncryptString(plaintext)

	// Should produce different ciphertexts due to random nonce
	if encrypted1 == encrypted2 {
		t.Error("expected different ciphertexts for same plaintext")
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	encryptor, err := NewFieldEncryptor([]string{testKey1Base64}, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name       string
		ciphertext string
	}{
		{"empty string", ""},
		{"no colons", "invalid"},
		{"one colon", "v1:invalid"},
		{"no version prefix", "1:abc:def"},
		{"invalid version", "vX:abc:def"},
		{"invalid nonce encoding", "v1:!!!:def"},
		{"invalid ciphertext encoding", "v1:YWJj:!!!"},
		{"unknown version", "v999:YWJj:YWJj"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := encryptor.DecryptString(tc.ciphertext)
			if err == nil {
				t.Error("expected error for invalid ciphertext")
			}
		})
	}
}

func TestKeyRotation(t *testing.T) {
	keys := []string{testKey1Base64, testKey2Base64}
	encryptor, err := NewFieldEncryptor(keys, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Encrypt with version 1
	plaintext := "test data"
	encryptedV1, _ := encryptor.EncryptString(plaintext)

	// Verify encrypted with version 1
	if !strings.HasPrefix(encryptedV1, "v1:") {
		t.Error("expected ciphertext to start with v1:")
	}

	// Change to version 2
	err = encryptor.SetCurrentVersion(2)
	if err != nil {
		t.Fatalf("failed to set version: %v", err)
	}

	// Encrypt with version 2
	encryptedV2, _ := encryptor.EncryptString(plaintext)
	if !strings.HasPrefix(encryptedV2, "v2:") {
		t.Error("expected ciphertext to start with v2:")
	}

	// Both should decrypt correctly
	decryptedV1, ver1, _ := encryptor.DecryptString(encryptedV1)
	decryptedV2, ver2, _ := encryptor.DecryptString(encryptedV2)

	if decryptedV1 != plaintext || decryptedV2 != plaintext {
		t.Error("decryption failed after key rotation")
	}

	if ver1 != 1 || ver2 != 2 {
		t.Errorf("expected versions 1 and 2, got %d and %d", ver1, ver2)
	}
}

func TestNeedsReEncryption(t *testing.T) {
	keys := []string{testKey1Base64, testKey2Base64}
	encryptor, err := NewFieldEncryptor(keys, 2, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Set to version 1, encrypt, then set to version 2
	encryptor.SetCurrentVersion(1)
	oldEncrypted, _ := encryptor.EncryptString("test")
	encryptor.SetCurrentVersion(2)
	newEncrypted, _ := encryptor.EncryptString("test")

	if !encryptor.NeedsReEncryption(oldEncrypted) {
		t.Error("old ciphertext should need re-encryption")
	}

	if encryptor.NeedsReEncryption(newEncrypted) {
		t.Error("new ciphertext should not need re-encryption")
	}
}

func TestReEncrypt(t *testing.T) {
	keys := []string{testKey1Base64, testKey2Base64}
	encryptor, err := NewFieldEncryptor(keys, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	plaintext := "sensitive data"
	oldEncrypted, _ := encryptor.EncryptString(plaintext)

	// Switch to version 2
	encryptor.SetCurrentVersion(2)

	// Re-encrypt
	newEncrypted, err := encryptor.ReEncrypt(oldEncrypted)
	if err != nil {
		t.Fatalf("re-encryption failed: %v", err)
	}

	// Should be encrypted with version 2
	if !strings.HasPrefix(newEncrypted, "v2:") {
		t.Error("re-encrypted data should use new version")
	}

	// Should decrypt to same plaintext
	decrypted, _, _ := encryptor.DecryptString(newEncrypted)
	if decrypted != plaintext {
		t.Error("re-encrypted data did not decrypt correctly")
	}
}

func TestHash_Deterministic(t *testing.T) {
	encryptor, err := NewFieldEncryptor([]string{testKey1Base64}, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	data := "user@example.com"
	hash1 := encryptor.Hash(data)
	hash2 := encryptor.Hash(data)

	if hash1 != hash2 {
		t.Error("hash should be deterministic")
	}
}

func TestHash_DifferentInputs(t *testing.T) {
	encryptor, err := NewFieldEncryptor([]string{testKey1Base64}, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	hash1 := encryptor.Hash("user1@example.com")
	hash2 := encryptor.Hash("user2@example.com")

	if hash1 == hash2 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestConcurrentAccess(t *testing.T) {
	encryptor, err := NewFieldEncryptor([]string{testKey1Base64, testKey2Base64}, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	// Concurrent encryption
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			plaintext := "concurrent test data"
			encrypted, err := encryptor.EncryptString(plaintext)
			if err != nil {
				errChan <- err
				return
			}

			decrypted, _, err := encryptor.DecryptString(encrypted)
			if err != nil {
				errChan <- err
				return
			}

			if decrypted != plaintext {
				errChan <- err
			}
		}(i)
	}

	// Concurrent key version changes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			version := (idx % 2) + 1
			encryptor.SetCurrentVersion(version)
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			t.Errorf("concurrent access error: %v", err)
		}
	}
}

func TestAddKey(t *testing.T) {
	encryptor, err := NewFieldEncryptor([]string{testKey1Base64}, 1, testHMACSecret)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Add new key as version 3
	err = encryptor.AddKey(3, testKey2Base64)
	if err != nil {
		t.Fatalf("failed to add key: %v", err)
	}

	// Set version to 3 and encrypt
	encryptor.SetCurrentVersion(3)
	encrypted, _ := encryptor.EncryptString("test")

	if !strings.HasPrefix(encrypted, "v3:") {
		t.Error("expected v3 prefix")
	}
}

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	if key1 == key2 {
		t.Error("generated keys should be unique")
	}

	// Keys should be valid for encryption
	_, err = NewFieldEncryptor([]string{key1, key2}, 1, testHMACSecret)
	if err != nil {
		t.Errorf("generated keys should be valid: %v", err)
	}
}
