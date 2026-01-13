package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// Common errors
var (
	ErrInvalidCiphertext = errors.New("invalid ciphertext format")
	ErrKeyNotFound       = errors.New("encryption key not found for version")
	ErrInvalidKeyLength  = errors.New("invalid key length, must be 32 bytes for AES-256")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrEncryptionFailed  = errors.New("encryption failed")
)

// FieldEncryptor handles AES-256-GCM encryption for PII fields
type FieldEncryptor struct {
	mu             sync.RWMutex
	keys           map[int][]byte // version -> key
	currentVersion int
	hmacSecret     []byte
}

// NewFieldEncryptor creates a new field encryptor
// Keys should be 32 bytes (256 bits) each, base64 encoded
func NewFieldEncryptor(keysBase64 []string, currentVersion int, hmacSecret string) (*FieldEncryptor, error) {
	if len(keysBase64) == 0 {
		return nil, errors.New("at least one encryption key is required")
	}

	keys := make(map[int][]byte)
	for i, keyB64 := range keysBase64 {
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key at index %d: %w", i, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key at index %d has invalid length %d, expected 32", i, len(key))
		}
		// Keys are 1-indexed (version 1, 2, 3...)
		keys[i+1] = key
	}

	if _, ok := keys[currentVersion]; !ok {
		return nil, fmt.Errorf("current key version %d not found in provided keys", currentVersion)
	}

	return &FieldEncryptor{
		keys:           keys,
		currentVersion: currentVersion,
		hmacSecret:     []byte(hmacSecret),
	}, nil
}

// Encrypt encrypts plaintext using the current key version
// Returns: v{version}:{nonce}:{ciphertext} (all base64 encoded)
func (e *FieldEncryptor) Encrypt(plaintext []byte) (string, error) {
	e.mu.RLock()
	key := e.keys[e.currentVersion]
	version := e.currentVersion
	e.mu.RUnlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%w: failed to generate nonce: %v", ErrEncryptionFailed, err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: v{version}:{nonce_base64}:{ciphertext_base64}
	result := fmt.Sprintf("v%d:%s:%s",
		version,
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(ciphertext),
	)

	return result, nil
}

// Decrypt decrypts ciphertext and returns the plaintext and key version used
func (e *FieldEncryptor) Decrypt(encrypted string) ([]byte, int, error) {
	parts := strings.SplitN(encrypted, ":", 3)
	if len(parts) != 3 {
		return nil, 0, ErrInvalidCiphertext
	}

	// Parse version
	if !strings.HasPrefix(parts[0], "v") {
		return nil, 0, ErrInvalidCiphertext
	}
	version, err := strconv.Atoi(parts[0][1:])
	if err != nil {
		return nil, 0, ErrInvalidCiphertext
	}

	// Decode nonce and ciphertext
	nonce, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid nonce encoding", ErrInvalidCiphertext)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid ciphertext encoding", ErrInvalidCiphertext)
	}

	// Get key for version
	e.mu.RLock()
	key, ok := e.keys[version]
	e.mu.RUnlock()
	if !ok {
		return nil, 0, fmt.Errorf("%w: version %d", ErrKeyNotFound, version)
	}

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, version, nil
}

// EncryptString encrypts a string and returns the encrypted string
func (e *FieldEncryptor) EncryptString(s string) (string, error) {
	return e.Encrypt([]byte(s))
}

// DecryptString decrypts an encrypted string
func (e *FieldEncryptor) DecryptString(encrypted string) (string, int, error) {
	plaintext, version, err := e.Decrypt(encrypted)
	if err != nil {
		return "", 0, err
	}
	return string(plaintext), version, nil
}

// Hash creates a deterministic HMAC-SHA256 hash for lookups
// SECURITY: Uses proper HMAC construction for keyed hashing
// This is one-way and cannot be reversed
func (e *FieldEncryptor) Hash(data string) string {
	mac := hmac.New(sha256.New, e.hmacSecret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// CurrentKeyVersion returns the current encryption key version
func (e *FieldEncryptor) CurrentKeyVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentVersion
}

// AddKey adds a new key version (for rotation)
func (e *FieldEncryptor) AddKey(version int, keyBase64 string) error {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}
	if len(key) != 32 {
		return ErrInvalidKeyLength
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.keys[version] = key
	return nil
}

// SetCurrentVersion sets the current key version for encryption
func (e *FieldEncryptor) SetCurrentVersion(version int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.keys[version]; !ok {
		return fmt.Errorf("%w: version %d", ErrKeyNotFound, version)
	}

	e.currentVersion = version
	return nil
}

// NeedsReEncryption checks if a ciphertext was encrypted with an old key
func (e *FieldEncryptor) NeedsReEncryption(encrypted string) bool {
	parts := strings.SplitN(encrypted, ":", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "v") {
		return true // Invalid format, needs re-encryption
	}

	version, err := strconv.Atoi(parts[0][1:])
	if err != nil {
		return true
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	return version < e.currentVersion
}

// ReEncrypt decrypts with old key and re-encrypts with current key
func (e *FieldEncryptor) ReEncrypt(encrypted string) (string, error) {
	plaintext, _, err := e.Decrypt(encrypted)
	if err != nil {
		return "", err
	}
	return e.Encrypt(plaintext)
}

// GenerateKey generates a new random 256-bit key and returns it base64 encoded
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
