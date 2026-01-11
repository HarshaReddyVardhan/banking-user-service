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

// Common errors
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user with this email already exists")
	ErrOptimisticLock    = errors.New("optimistic lock conflict: user was modified")
)

// UserRepository handles user persistence in PostgreSQL
type UserRepository struct {
	pool      *pgxpool.Pool
	encryptor *crypto.FieldEncryptor
	cb        *resilience.CircuitBreaker
}

// NewUserRepository creates a new user repository
func NewUserRepository(pool *pgxpool.Pool, encryptor *crypto.FieldEncryptor, cb *resilience.CircuitBreaker) *UserRepository {
	return &UserRepository{
		pool:      pool,
		encryptor: encryptor,
		cb:        cb,
	}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	_, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, r.create(ctx, user)
	})
	return err
}

func (r *UserRepository) create(ctx context.Context, user *domain.User) error {
	// Check for existing email
	existingHash := r.encryptor.Hash(user.Email)
	var exists bool
	err := r.pool.QueryRow(ctx, 
		"SELECT EXISTS(SELECT 1 FROM users WHERE email_hash = $1 AND deleted_at IS NULL)",
		existingHash,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check existing email: %w", err)
	}
	if exists {
		return ErrUserAlreadyExists
	}

	// Encrypt PII fields
	legalNameEnc, err := r.encryptor.EncryptString(user.LegalName)
	if err != nil {
		return fmt.Errorf("failed to encrypt legal name: %w", err)
	}

	emailEnc, err := r.encryptor.EncryptString(user.Email)
	if err != nil {
		return fmt.Errorf("failed to encrypt email: %w", err)
	}
	emailHash := r.encryptor.Hash(user.Email)

	var phoneEnc, phoneHash *string
	if user.Phone != "" {
		enc, err := r.encryptor.EncryptString(user.Phone)
		if err != nil {
			return fmt.Errorf("failed to encrypt phone: %w", err)
		}
		phoneEnc = &enc
		hash := r.encryptor.Hash(user.Phone)
		phoneHash = &hash
	}

	var dobEnc *string
	if user.DOB != nil {
		enc, err := r.encryptor.EncryptString(user.DOB.Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("failed to encrypt DOB: %w", err)
		}
		dobEnc = &enc
	}

	riskFlagsJSON, err := json.Marshal(user.RiskFlags)
	if err != nil {
		return fmt.Errorf("failed to marshal risk flags: %w", err)
	}

	// Generate new ID if not set
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	query := `
		INSERT INTO users (
			id, legal_name_encrypted, email_encrypted, email_hash,
			phone_encrypted, phone_hash, dob_encrypted,
			country, status, kyc_status, kyc_reference_id, risk_flags,
			encryption_key_version, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		) RETURNING created_at, updated_at`

	now := time.Now().UTC()
	err = r.pool.QueryRow(ctx, query,
		user.ID,
		legalNameEnc,
		emailEnc,
		emailHash,
		phoneEnc,
		phoneHash,
		dobEnc,
		user.Country,
		user.Status,
		user.KYCStatus,
		user.KYCReferenceID,
		riskFlagsJSON,
		r.encryptor.CurrentKeyVersion(),
		now,
		now,
	).Scan(&user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	result, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return r.getByID(ctx, id)
	})
	if err != nil {
		return nil, err
	}
	return result.(*domain.User), nil
}

func (r *UserRepository) getByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT 
			id, legal_name_encrypted, email_encrypted, email_hash,
			phone_encrypted, phone_hash, dob_encrypted,
			country, status, kyc_status, kyc_reference_id, risk_flags,
			encryption_key_version, created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1`

	user, err := r.scanUser(ctx, r.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	result, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return r.getByEmail(ctx, email)
	})
	if err != nil {
		return nil, err
	}
	return result.(*domain.User), nil
}

func (r *UserRepository) getByEmail(ctx context.Context, email string) (*domain.User, error) {
	emailHash := r.encryptor.Hash(email)

	query := `
		SELECT 
			id, legal_name_encrypted, email_encrypted, email_hash,
			phone_encrypted, phone_hash, dob_encrypted,
			country, status, kyc_status, kyc_reference_id, risk_flags,
			encryption_key_version, created_at, updated_at, deleted_at
		FROM users
		WHERE email_hash = $1 AND deleted_at IS NULL`

	user, err := r.scanUser(ctx, r.pool.QueryRow(ctx, query, emailHash))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *domain.User, expectedUpdatedAt time.Time) error {
	_, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, r.update(ctx, user, expectedUpdatedAt)
	})
	return err
}

func (r *UserRepository) update(ctx context.Context, user *domain.User, expectedUpdatedAt time.Time) error {
	// Encrypt PII fields
	legalNameEnc, err := r.encryptor.EncryptString(user.LegalName)
	if err != nil {
		return fmt.Errorf("failed to encrypt legal name: %w", err)
	}

	emailEnc, err := r.encryptor.EncryptString(user.Email)
	if err != nil {
		return fmt.Errorf("failed to encrypt email: %w", err)
	}
	emailHash := r.encryptor.Hash(user.Email)

	var phoneEnc, phoneHash *string
	if user.Phone != "" {
		enc, err := r.encryptor.EncryptString(user.Phone)
		if err != nil {
			return fmt.Errorf("failed to encrypt phone: %w", err)
		}
		phoneEnc = &enc
		hash := r.encryptor.Hash(user.Phone)
		phoneHash = &hash
	}

	var dobEnc *string
	if user.DOB != nil {
		enc, err := r.encryptor.EncryptString(user.DOB.Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("failed to encrypt DOB: %w", err)
		}
		dobEnc = &enc
	}

	riskFlagsJSON, err := json.Marshal(user.RiskFlags)
	if err != nil {
		return fmt.Errorf("failed to marshal risk flags: %w", err)
	}

	query := `
		UPDATE users SET
			legal_name_encrypted = $1,
			email_encrypted = $2,
			email_hash = $3,
			phone_encrypted = $4,
			phone_hash = $5,
			dob_encrypted = $6,
			country = $7,
			status = $8,
			kyc_status = $9,
			kyc_reference_id = $10,
			risk_flags = $11,
			encryption_key_version = $12,
			updated_at = NOW()
		WHERE id = $13 AND updated_at = $14
		RETURNING updated_at`

	var newUpdatedAt time.Time
	err = r.pool.QueryRow(ctx, query,
		legalNameEnc,
		emailEnc,
		emailHash,
		phoneEnc,
		phoneHash,
		dobEnc,
		user.Country,
		user.Status,
		user.KYCStatus,
		user.KYCReferenceID,
		riskFlagsJSON,
		r.encryptor.CurrentKeyVersion(),
		user.ID,
		expectedUpdatedAt,
	).Scan(&newUpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOptimisticLock
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	user.UpdatedAt = newUpdatedAt
	return nil
}

// SoftDelete marks a user as deleted
func (r *UserRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	_, err := r.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, r.softDelete(ctx, id)
	})
	return err
}

func (r *UserRepository) softDelete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET
			status = 'DELETED',
			deleted_at = NOW(),
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to soft delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

// scanUser scans a row into a User struct and decrypts PII
func (r *UserRepository) scanUser(ctx context.Context, row pgx.Row) (*domain.User, error) {
	var user domain.User
	var legalNameEnc, emailEnc string
	var phoneEnc, dobEnc sql.NullString
	var emailHash string
	var phoneHash sql.NullString
	var kycRefID *uuid.UUID
	var riskFlagsJSON []byte
	var deletedAt sql.NullTime

	err := row.Scan(
		&user.ID,
		&legalNameEnc,
		&emailEnc,
		&emailHash,
		&phoneEnc,
		&phoneHash,
		&dobEnc,
		&user.Country,
		&user.Status,
		&user.KYCStatus,
		&kycRefID,
		&riskFlagsJSON,
		&user.EncryptionKeyVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		return nil, err
	}

	// Decrypt PII fields
	user.LegalName, _, err = r.encryptor.DecryptString(legalNameEnc)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt legal name: %w", err)
	}

	user.Email, _, err = r.encryptor.DecryptString(emailEnc)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt email: %w", err)
	}

	if phoneEnc.Valid {
		user.Phone, _, err = r.encryptor.DecryptString(phoneEnc.String)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt phone: %w", err)
		}
	}

	if dobEnc.Valid {
		dobStr, _, err := r.encryptor.DecryptString(dobEnc.String)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt DOB: %w", err)
		}
		dob, err := time.Parse(time.RFC3339, dobStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DOB: %w", err)
		}
		user.DOB = &dob
	}

	user.KYCReferenceID = kycRefID

	if err := json.Unmarshal(riskFlagsJSON, &user.RiskFlags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal risk flags: %w", err)
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

// Ping checks database connectivity
func (r *UserRepository) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}
