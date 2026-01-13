package crypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultKeySource loads encryption keys from HashiCorp Vault
// Expects a data structure at the path:
//
//	{
//	  "current_version": 1,
//	  "keys": {
//	    "1": "base64encodedkey...",
//	    "2": "base64encodedkey..."
//	  }
//	}
type VaultKeySource struct {
	client *vault.Client
	path   string
}

// NewVaultKeySource creates a new Vault key source
func NewVaultKeySource(address, token, path string) (*VaultKeySource, error) {
	config := vault.DefaultConfig()
	config.Address = address
	config.Timeout = 10 * time.Second

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	if token != "" {
		client.SetToken(token)
	}

	return &VaultKeySource{
		client: client,
		path:   path,
	}, nil
}

// GetKey retrieves a specific key version
func (v *VaultKeySource) GetKey(ctx context.Context, version int) ([]byte, error) {
	data, err := v.readPath(ctx)
	if err != nil {
		return nil, err
	}

	keysMap, ok := data["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret structure: 'keys' map missing")
	}

	keyVal, ok := keysMap[strconv.Itoa(version)]
	if !ok {
		return nil, fmt.Errorf("key version %d not found", version)
	}

	keyStr, ok := keyVal.(string)
	if !ok {
		return nil, fmt.Errorf("key version %d is not a string", version)
	}

	return base64.StdEncoding.DecodeString(keyStr)
}

// GetCurrentVersion returns the current key version
func (v *VaultKeySource) GetCurrentVersion(ctx context.Context) (int, error) {
	data, err := v.readPath(ctx)
	if err != nil {
		return 0, err
	}

	// Handle number which might be float64 (JSON) or json.Number
	val, ok := data["current_version"]
	if !ok {
		return 0, fmt.Errorf("current_version field missing")
	}

	switch n := val.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case string: // Should be int, but handle string just in case
		return strconv.Atoi(n)
	case interface{ Int64() (int64, error) }: // json.Number
		i, err := n.Int64()
		return int(i), err
	default:
		return 0, fmt.Errorf("current_version has unexpected type: %T", val)
	}
}

// ListVersions returns all available key versions
func (v *VaultKeySource) ListVersions(ctx context.Context) ([]int, error) {
	data, err := v.readPath(ctx)
	if err != nil {
		return nil, err
	}

	keysMap, ok := data["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret structure: 'keys' map missing")
	}

	versions := make([]int, 0, len(keysMap))
	for k := range keysMap {
		ver, err := strconv.Atoi(k)
		if err != nil {
			continue // Skip non-integer keys
		}
		versions = append(versions, ver)
	}

	return versions, nil
}

func (v *VaultKeySource) readPath(ctx context.Context) (map[string]interface{}, error) {
	// ReadWithContext handles cancellation
	secret, err := v.client.Logical().ReadWithContext(ctx, v.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read from vault: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", v.path)
	}

	// Handle KV v2 structure (data is nested in data.data)
	if secret.Data == nil {
		return nil, fmt.Errorf("secret data is nil")
	}

	// Check if this is KV v2 (has "data" and "metadata")
	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
		if _, hasMeta := secret.Data["metadata"]; hasMeta {
			return data, nil
		}
	}

	// KV v1 or simple read
	return secret.Data, nil
}
