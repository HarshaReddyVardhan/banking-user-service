package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/banking/user-service/internal/crypto"
	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/resilience"
)

// Address repository errors
var (
	ErrAddressNotFound = errors.New("address not found")
)

// AddressRepository handles address persistence in PostgreSQL
type AddressRepository struct {
	pool      *pgxpool.Pool
	encryptor *crypto.FieldEncryptor
	cb        *resilience.CircuitBreaker
}

// NewAddressRepository creates a new address repository
func NewAddressRepository(pool *pgxpool.Pool, encryptor *crypto.FieldEncryptor, cb *resilience.CircuitBreaker) *AddressRepository {
	return &AddressRepository{
		pool:      pool,
		encryptor: encryptor,
		cb:        cb,
	}
}

// ListByUserID retrieves all active addresses for a user
func (r *AddressRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Address, error) {
	result, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return r.listByUserID(ctx, userID)
	})
	if err != nil {
		return nil, err
	}
	return result.([]*domain.Address), nil
}

func (r *AddressRepository) listByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Address, error) {
	query := `
		SELECT 
			id, user_id, address_type, address_encrypted,
			is_primary, validation_status, validation_source, validated_at,
			version, encryption_key_version, created_at, updated_at, deleted_at
		FROM addresses
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY is_primary DESC, created_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses: %w", err)
	}
	defer rows.Close()

	var addresses []*domain.Address
	for rows.Next() {
		addr, err := r.scanAddress(rows)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)
	}

	return addresses, nil
}

// GetByID retrieves an address by ID
func (r *AddressRepository) GetByID(ctx context.Context, userID, addressID uuid.UUID) (*domain.Address, error) {
	result, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return r.getByID(ctx, userID, addressID)
	})
	if err != nil {
		return nil, err
	}
	return result.(*domain.Address), nil
}

func (r *AddressRepository) getByID(ctx context.Context, userID, addressID uuid.UUID) (*domain.Address, error) {
	query := `
		SELECT 
			id, user_id, address_type, address_encrypted,
			is_primary, validation_status, validation_source, validated_at,
			version, encryption_key_version, created_at, updated_at, deleted_at
		FROM addresses
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`

	addr, err := r.scanAddress(r.pool.QueryRow(ctx, query, addressID, userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAddressNotFound
		}
		return nil, err
	}

	return addr, nil
}

// Create creates a new address
func (r *AddressRepository) Create(ctx context.Context, addr *domain.Address) error {
	_, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, r.create(ctx, addr)
	})
	return err
}

func (r *AddressRepository) create(ctx context.Context, addr *domain.Address) error {
	// Encrypt address data
	addressData := addr.ToAddressData()
	dataJSON, err := json.Marshal(addressData)
	if err != nil {
		return fmt.Errorf("failed to marshal address data: %w", err)
	}

	addressEnc, err := r.encryptor.EncryptString(string(dataJSON))
	if err != nil {
		return fmt.Errorf("failed to encrypt address: %w", err)
	}

	if addr.ID == uuid.Nil {
		addr.ID = uuid.New()
	}

	// If setting as primary, unset other primaries first
	if addr.IsPrimary {
		_, err := r.pool.Exec(ctx, 
			"UPDATE addresses SET is_primary = false WHERE user_id = $1 AND deleted_at IS NULL",
			addr.UserID)
		if err != nil {
			return fmt.Errorf("failed to unset primary addresses: %w", err)
		}
	}

	query := `
		INSERT INTO addresses (
			id, user_id, address_type, address_encrypted,
			is_primary, validation_status, version, encryption_key_version,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at, updated_at`

	now := time.Now().UTC()
	err = r.pool.QueryRow(ctx, query,
		addr.ID,
		addr.UserID,
		addr.AddressType,
		addressEnc,
		addr.IsPrimary,
		domain.ValidationStatusPending,
		1, // Initial version
		r.encryptor.CurrentKeyVersion(),
		now,
		now,
	).Scan(&addr.CreatedAt, &addr.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to insert address: %w", err)
	}

	addr.Version = 1
	addr.ValidationStatus = domain.ValidationStatusPending
	return nil
}

// Update updates an address (creates new version)
func (r *AddressRepository) Update(ctx context.Context, addr *domain.Address) error {
	_, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, r.update(ctx, addr)
	})
	return err
}

func (r *AddressRepository) update(ctx context.Context, addr *domain.Address) error {
	// Encrypt address data
	addressData := addr.ToAddressData()
	dataJSON, err := json.Marshal(addressData)
	if err != nil {
		return fmt.Errorf("failed to marshal address data: %w", err)
	}

	addressEnc, err := r.encryptor.EncryptString(string(dataJSON))
	if err != nil {
		return fmt.Errorf("failed to encrypt address: %w", err)
	}

	// If setting as primary, unset other primaries
	if addr.IsPrimary {
		_, err := r.pool.Exec(ctx, 
			"UPDATE addresses SET is_primary = false WHERE user_id = $1 AND id != $2 AND deleted_at IS NULL",
			addr.UserID, addr.ID)
		if err != nil {
			return fmt.Errorf("failed to unset primary addresses: %w", err)
		}
	}

	query := `
		UPDATE addresses SET
			address_type = $1,
			address_encrypted = $2,
			is_primary = $3,
			version = version + 1,
			encryption_key_version = $4,
			updated_at = NOW()
		WHERE id = $5 AND user_id = $6 AND deleted_at IS NULL
		RETURNING version, updated_at`

	var newVersion int
	var newUpdatedAt time.Time
	err = r.pool.QueryRow(ctx, query,
		addr.AddressType,
		addressEnc,
		addr.IsPrimary,
		r.encryptor.CurrentKeyVersion(),
		addr.ID,
		addr.UserID,
	).Scan(&newVersion, &newUpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAddressNotFound
		}
		return fmt.Errorf("failed to update address: %w", err)
	}

	addr.Version = newVersion
	addr.UpdatedAt = newUpdatedAt
	return nil
}

// SoftDelete marks an address as deleted
func (r *AddressRepository) SoftDelete(ctx context.Context, userID, addressID uuid.UUID) error {
	_, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, r.softDelete(ctx, userID, addressID)
	})
	return err
}

func (r *AddressRepository) softDelete(ctx context.Context, userID, addressID uuid.UUID) error {
	query := `
		UPDATE addresses SET
			deleted_at = NOW(),
			updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`

	result, err := r.pool.Exec(ctx, query, addressID, userID)
	if err != nil {
		return fmt.Errorf("failed to soft delete address: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrAddressNotFound
	}

	return nil
}

// scanAddress scans a row into an Address struct and decrypts data
func (r *AddressRepository) scanAddress(row pgx.Row) (*domain.Address, error) {
	var addr domain.Address
	var addressEnc string
	var validationSource sql.NullString
	var validatedAt sql.NullTime
	var deletedAt sql.NullTime

	err := row.Scan(
		&addr.ID,
		&addr.UserID,
		&addr.AddressType,
		&addressEnc,
		&addr.IsPrimary,
		&addr.ValidationStatus,
		&validationSource,
		&validatedAt,
		&addr.Version,
		&addr.EncryptionKeyVersion,
		&addr.CreatedAt,
		&addr.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		return nil, err
	}

	// Decrypt address data
	decrypted, _, err := r.encryptor.DecryptString(addressEnc)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt address: %w", err)
	}

	var data domain.AddressData
	if err := json.Unmarshal([]byte(decrypted), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal address data: %w", err)
	}

	addr.FromAddressData(&data)

	if validationSource.Valid {
		addr.ValidationSource = validationSource.String
	}
	if validatedAt.Valid {
		addr.ValidatedAt = &validatedAt.Time
	}
	if deletedAt.Valid {
		addr.DeletedAt = &deletedAt.Time
	}

	return &addr, nil
}
