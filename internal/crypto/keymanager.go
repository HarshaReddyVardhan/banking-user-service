package crypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// KeySource defines where keys are loaded from
type KeySource interface {
	GetKey(ctx context.Context, version int) ([]byte, error)
	GetCurrentVersion(ctx context.Context) (int, error)
	ListVersions(ctx context.Context) ([]int, error)
}

// KeyManager handles encryption key lifecycle and rotation
type KeyManager struct {
	mu             sync.RWMutex
	encryptor      *FieldEncryptor
	source         KeySource
	rotationDays   int
	lastRotation   time.Time
	checkInterval  time.Duration
	stopCh         chan struct{}
	onRotation     func(oldVersion, newVersion int)
}

// KeyManagerConfig holds configuration for the key manager
type KeyManagerConfig struct {
	RotationDays   int           // Days between key rotations (default: 90)
	CheckInterval  time.Duration // How often to check for rotation
	HMACSecret     string        // Secret for hash operations
	OnRotation     func(oldVersion, newVersion int)
}

// NewKeyManager creates a new key manager
func NewKeyManager(source KeySource, cfg KeyManagerConfig) (*KeyManager, error) {
	if cfg.RotationDays == 0 {
		cfg.RotationDays = 90
	}
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 1 * time.Hour
	}

	km := &KeyManager{
		source:        source,
		rotationDays:  cfg.RotationDays,
		checkInterval: cfg.CheckInterval,
		stopCh:        make(chan struct{}),
		onRotation:    cfg.OnRotation,
	}

	// Initial key load
	if err := km.loadKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load initial keys: %w", err)
	}

	return km, nil
}

// loadKeys loads all keys from the source
func (km *KeyManager) loadKeys(ctx context.Context) error {
	versions, err := km.source.ListVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to list key versions: %w", err)
	}

	currentVersion, err := km.source.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	keysBase64 := make([]string, 0, len(versions))
	for _, v := range versions {
		key, err := km.source.GetKey(ctx, v)
		if err != nil {
			return fmt.Errorf("failed to get key version %d: %w", v, err)
		}
		keysBase64 = append(keysBase64, base64.StdEncoding.EncodeToString(key))
	}

	// Create new encryptor (we need to pass hmac secret somehow)
	// For now, we'll reuse the existing encryptor's secret
	var hmacSecret string
	if km.encryptor != nil {
		hmacSecret = string(km.encryptor.hmacSecret)
	} else {
		// This should be provided during initialization
		return fmt.Errorf("HMAC secret not available")
	}

	encryptor, err := NewFieldEncryptor(keysBase64, currentVersion, hmacSecret)
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}

	km.mu.Lock()
	km.encryptor = encryptor
	km.mu.Unlock()

	return nil
}

// InitializeWithKeys initializes the key manager with provided keys
func (km *KeyManager) InitializeWithKeys(keysBase64 []string, currentVersion int, hmacSecret string) error {
	encryptor, err := NewFieldEncryptor(keysBase64, currentVersion, hmacSecret)
	if err != nil {
		return err
	}

	km.mu.Lock()
	km.encryptor = encryptor
	km.lastRotation = time.Now()
	km.mu.Unlock()

	return nil
}

// Encrypt encrypts data using the current key
func (km *KeyManager) Encrypt(plaintext []byte) (string, error) {
	km.mu.RLock()
	enc := km.encryptor
	km.mu.RUnlock()

	if enc == nil {
		return "", fmt.Errorf("key manager not initialized")
	}

	return enc.Encrypt(plaintext)
}

// Decrypt decrypts data using the appropriate key version
func (km *KeyManager) Decrypt(ciphertext string) ([]byte, int, error) {
	km.mu.RLock()
	enc := km.encryptor
	km.mu.RUnlock()

	if enc == nil {
		return nil, 0, fmt.Errorf("key manager not initialized")
	}

	return enc.Decrypt(ciphertext)
}

// EncryptString encrypts a string
func (km *KeyManager) EncryptString(s string) (string, error) {
	return km.Encrypt([]byte(s))
}

// DecryptString decrypts a string
func (km *KeyManager) DecryptString(ciphertext string) (string, int, error) {
	plaintext, version, err := km.Decrypt(ciphertext)
	if err != nil {
		return "", 0, err
	}
	return string(plaintext), version, nil
}

// Hash creates a deterministic hash for lookups
func (km *KeyManager) Hash(data string) string {
	km.mu.RLock()
	enc := km.encryptor
	km.mu.RUnlock()

	if enc == nil {
		return ""
	}

	return enc.Hash(data)
}

// NeedsReEncryption checks if data needs re-encryption with newer key
func (km *KeyManager) NeedsReEncryption(ciphertext string) bool {
	km.mu.RLock()
	enc := km.encryptor
	km.mu.RUnlock()

	if enc == nil {
		return false
	}

	return enc.NeedsReEncryption(ciphertext)
}

// ReEncrypt re-encrypts data with the current key
func (km *KeyManager) ReEncrypt(ciphertext string) (string, error) {
	km.mu.RLock()
	enc := km.encryptor
	km.mu.RUnlock()

	if enc == nil {
		return "", fmt.Errorf("key manager not initialized")
	}

	return enc.ReEncrypt(ciphertext)
}

// CurrentVersion returns the current key version
func (km *KeyManager) CurrentVersion() int {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.encryptor == nil {
		return 0
	}
	return km.encryptor.CurrentKeyVersion()
}

// RotateKey initiates a key rotation
func (km *KeyManager) RotateKey(ctx context.Context, newKeyBase64 string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.encryptor == nil {
		return fmt.Errorf("key manager not initialized")
	}

	oldVersion := km.encryptor.CurrentKeyVersion()
	newVersion := oldVersion + 1

	// Add new key
	if err := km.encryptor.AddKey(newVersion, newKeyBase64); err != nil {
		return fmt.Errorf("failed to add new key: %w", err)
	}

	// Set as current
	if err := km.encryptor.SetCurrentVersion(newVersion); err != nil {
		return fmt.Errorf("failed to set new version: %w", err)
	}

	km.lastRotation = time.Now()

	// Notify rotation callback
	if km.onRotation != nil {
		go km.onRotation(oldVersion, newVersion)
	}

	return nil
}

// StartRotationChecker starts a background goroutine that checks for rotation
func (km *KeyManager) StartRotationChecker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(km.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-km.stopCh:
				return
			case <-ticker.C:
				km.checkRotation(ctx)
			}
		}
	}()
}

// checkRotation checks if rotation is needed
func (km *KeyManager) checkRotation(ctx context.Context) {
	km.mu.RLock()
	lastRotation := km.lastRotation
	rotationDays := km.rotationDays
	km.mu.RUnlock()

	daysSinceRotation := time.Since(lastRotation).Hours() / 24
	if daysSinceRotation >= float64(rotationDays) {
		// Rotation needed - this should trigger an alert/notification
		// Actual rotation should be done through a controlled process
		// log warning about rotation needed
	}
}

// Stop stops the rotation checker
func (km *KeyManager) Stop() {
	close(km.stopCh)
}

// DaysSinceRotation returns the number of days since last rotation
func (km *KeyManager) DaysSinceRotation() float64 {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return time.Since(km.lastRotation).Hours() / 24
}

// StaticKeySource is a simple key source for non-Vault environments
type StaticKeySource struct {
	keys           map[int][]byte
	currentVersion int
}

// NewStaticKeySource creates a static key source from base64-encoded keys
func NewStaticKeySource(keysBase64 []string, currentVersion int) (*StaticKeySource, error) {
	keys := make(map[int][]byte)
	for i, keyB64 := range keysBase64 {
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key %d: %w", i, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key %d has invalid length", i)
		}
		keys[i+1] = key
	}

	return &StaticKeySource{
		keys:           keys,
		currentVersion: currentVersion,
	}, nil
}

func (s *StaticKeySource) GetKey(ctx context.Context, version int) ([]byte, error) {
	key, ok := s.keys[version]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (s *StaticKeySource) GetCurrentVersion(ctx context.Context) (int, error) {
	return s.currentVersion, nil
}

func (s *StaticKeySource) ListVersions(ctx context.Context) ([]int, error) {
	versions := make([]int, 0, len(s.keys))
	for v := range s.keys {
		versions = append(versions, v)
	}
	return versions, nil
}
