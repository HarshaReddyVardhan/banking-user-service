package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/banking/user-service/internal/crypto"
	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/resilience"
)

// Device repository errors
var (
	ErrDeviceNotFound = errors.New("device not found")
)

// DeviceRepository handles device persistence in PostgreSQL
type DeviceRepository struct {
	pool      *pgxpool.Pool
	encryptor *crypto.FieldEncryptor
	cb        *resilience.CircuitBreaker
}

// NewDeviceRepository creates a new device repository
func NewDeviceRepository(pool *pgxpool.Pool, encryptor *crypto.FieldEncryptor, cb *resilience.CircuitBreaker) *DeviceRepository {
	return &DeviceRepository{
		pool:      pool,
		encryptor: encryptor,
		cb:        cb,
	}
}

// ListByUserID retrieves all active devices for a user
func (r *DeviceRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Device, error) {
	result, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return r.listByUserID(ctx, userID)
	})
	if err != nil {
		return nil, err
	}
	return result.([]*domain.Device), nil
}

func (r *DeviceRepository) listByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Device, error) {
	query := `
		SELECT 
			id, user_id, fingerprint_hash, device_type, os, os_version,
			app_version, device_name, last_ip_hash, last_active_at,
			is_trusted, trust_reason, created_at, deleted_at
		FROM devices
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY last_active_at DESC NULLS LAST`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	defer rows.Close()

	var devices []*domain.Device
	for rows.Next() {
		device, err := r.scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// GetByID retrieves a device by ID
func (r *DeviceRepository) GetByID(ctx context.Context, userID, deviceID uuid.UUID) (*domain.Device, error) {
	result, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return r.getByID(ctx, userID, deviceID)
	})
	if err != nil {
		return nil, err
	}
	return result.(*domain.Device), nil
}

func (r *DeviceRepository) getByID(ctx context.Context, userID, deviceID uuid.UUID) (*domain.Device, error) {
	query := `
		SELECT 
			id, user_id, fingerprint_hash, device_type, os, os_version,
			app_version, device_name, last_ip_hash, last_active_at,
			is_trusted, trust_reason, created_at, deleted_at
		FROM devices
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`

	device, err := r.scanDevice(r.pool.QueryRow(ctx, query, deviceID, userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}

	return device, nil
}

// SoftDelete marks a device as deleted
func (r *DeviceRepository) SoftDelete(ctx context.Context, userID, deviceID uuid.UUID) error {
	_, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, r.softDelete(ctx, userID, deviceID)
	})
	return err
}

func (r *DeviceRepository) softDelete(ctx context.Context, userID, deviceID uuid.UUID) error {
	query := `
		UPDATE devices SET
			deleted_at = NOW()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`

	result, err := r.pool.Exec(ctx, query, deviceID, userID)
	if err != nil {
		return fmt.Errorf("failed to soft delete device: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}

	return nil
}

// UpdateLastActive updates the last active timestamp for a device
func (r *DeviceRepository) UpdateLastActive(ctx context.Context, deviceID uuid.UUID, ipHash string) error {
	query := `
		UPDATE devices SET
			last_active_at = NOW(),
			last_ip_hash = $1
		WHERE id = $2 AND deleted_at IS NULL`

	_, err := r.pool.Exec(ctx, query, ipHash, deviceID)
	if err != nil {
		return fmt.Errorf("failed to update last active: %w", err)
	}

	return nil
}

// scanDevice scans a row into a Device struct
func (r *DeviceRepository) scanDevice(row pgx.Row) (*domain.Device, error) {
	var device domain.Device
	var osVersion, appVersion, deviceName, trustReason sql.NullString
	var lastActiveAt, deletedAt sql.NullTime

	err := row.Scan(
		&device.ID,
		&device.UserID,
		&device.FingerprintHash,
		&device.DeviceType,
		&device.OS,
		&osVersion,
		&appVersion,
		&deviceName,
		&device.LastIPHash,
		&lastActiveAt,
		&device.IsTrusted,
		&trustReason,
		&device.CreatedAt,
		&deletedAt,
	)
	if err != nil {
		return nil, err
	}

	if osVersion.Valid {
		device.OSVersion = osVersion.String
	}
	if appVersion.Valid {
		device.AppVersion = appVersion.String
	}
	if deviceName.Valid {
		device.DeviceName = deviceName.String
	}
	if trustReason.Valid {
		device.TrustReason = trustReason.String
	}
	if lastActiveAt.Valid {
		device.LastActiveAt = &lastActiveAt.Time
	}
	if deletedAt.Valid {
		device.DeletedAt = &deletedAt.Time
	}

	return &device, nil
}

// HashFingerprint creates a hash of a device fingerprint
func (r *DeviceRepository) HashFingerprint(fingerprint string) string {
	return r.encryptor.Hash(fingerprint)
}

// HashIP creates a hash of an IP address
func (r *DeviceRepository) HashIP(ip string) string {
	return r.encryptor.Hash(ip)
}
