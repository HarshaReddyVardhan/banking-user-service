-- Banking User Service: Initial Schema
-- Migration: 001_init.up.sql
-- All PII fields are stored encrypted using AES-256-GCM

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- USERS TABLE
-- =============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Encrypted PII fields (HIGH sensitivity)
    legal_name_encrypted BYTEA NOT NULL,
    email_encrypted BYTEA NOT NULL,
    email_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA-256 for lookups
    phone_encrypted BYTEA,
    phone_hash VARCHAR(64), -- SHA-256 for lookups
    dob_encrypted BYTEA,
    
    -- Non-PII fields
    country VARCHAR(2) NOT NULL, -- ISO 3166-1 alpha-2
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'PENDING', 'DELETED')),
    kyc_status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (kyc_status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')),
    kyc_reference_id UUID,
    risk_flags JSONB DEFAULT '[]'::jsonb,
    
    -- Encryption metadata
    encryption_key_version INT NOT NULL DEFAULT 1,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ -- Soft delete only
);

-- Indexes for users
CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE INDEX idx_users_phone_hash ON users(phone_hash) WHERE phone_hash IS NOT NULL;
CREATE INDEX idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_kyc_status ON users(kyc_status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_country ON users(country) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at);

-- =============================================================================
-- ADDRESSES TABLE
-- =============================================================================
CREATE TABLE addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Address type
    address_type VARCHAR(20) NOT NULL
        CHECK (address_type IN ('BILLING', 'RESIDENTIAL', 'MAILING', 'TEMPORARY')),
    
    -- Encrypted compound address field (HIGH PII)
    address_encrypted BYTEA NOT NULL,
    
    -- Flags and status
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    validation_status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (validation_status IN ('PENDING', 'VALID', 'INVALID', 'UNKNOWN')),
    validation_source VARCHAR(50),
    validated_at TIMESTAMPTZ,
    
    -- Versioning for audit trail
    version INT NOT NULL DEFAULT 1,
    
    -- Encryption metadata
    encryption_key_version INT NOT NULL DEFAULT 1,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Indexes for addresses
CREATE INDEX idx_addresses_user_id ON addresses(user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_addresses_type ON addresses(user_id, address_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_addresses_primary ON addresses(user_id, is_primary) WHERE deleted_at IS NULL AND is_primary = TRUE;

-- Constraint: Only one primary address per type per user
CREATE UNIQUE INDEX idx_addresses_unique_primary 
    ON addresses(user_id, address_type) 
    WHERE deleted_at IS NULL AND is_primary = TRUE;

-- =============================================================================
-- ADDRESS HISTORY TABLE (for compliance)
-- =============================================================================
CREATE TABLE address_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address_id UUID NOT NULL, -- No FK, address might be deleted
    user_id UUID NOT NULL,
    
    -- Encrypted address snapshot
    address_encrypted BYTEA NOT NULL,
    
    -- Version info
    version INT NOT NULL,
    
    -- Change tracking
    changed_by VARCHAR(100) NOT NULL, -- Actor ID
    change_source VARCHAR(50) NOT NULL -- USER, ADMIN, SYSTEM, API
        CHECK (change_source IN ('USER', 'ADMIN', 'SYSTEM', 'API')),
    
    -- Encryption metadata
    encryption_key_version INT NOT NULL DEFAULT 1,
    
    -- Timestamp (immutable)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for address history
CREATE INDEX idx_address_history_address_id ON address_history(address_id);
CREATE INDEX idx_address_history_user_id ON address_history(user_id);
CREATE INDEX idx_address_history_created_at ON address_history(created_at);

-- =============================================================================
-- DEVICES TABLE
-- =============================================================================
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Device identification (hashed, never raw)
    fingerprint_hash VARCHAR(64) NOT NULL, -- SHA-256 of fingerprint
    
    -- Device info (safe to store)
    device_type VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN'
        CHECK (device_type IN ('MOBILE', 'TABLET', 'DESKTOP', 'WEB', 'UNKNOWN')),
    os VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN'
        CHECK (os IN ('iOS', 'ANDROID', 'WINDOWS', 'MACOS', 'LINUX', 'WEB', 'UNKNOWN')),
    os_version VARCHAR(50),
    app_version VARCHAR(20),
    device_name VARCHAR(100),
    
    -- Last activity (IP is hashed for privacy)
    last_ip_hash VARCHAR(64),
    last_active_at TIMESTAMPTZ,
    
    -- Trust status
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    trust_reason VARCHAR(100),
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Indexes for devices
CREATE INDEX idx_devices_user_id ON devices(user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_devices_fingerprint ON devices(user_id, fingerprint_hash) WHERE deleted_at IS NULL;
CREATE INDEX idx_devices_last_active ON devices(last_active_at) WHERE deleted_at IS NULL;

-- Unique constraint: one fingerprint per user
CREATE UNIQUE INDEX idx_devices_unique_fingerprint 
    ON devices(user_id, fingerprint_hash) 
    WHERE deleted_at IS NULL;

-- =============================================================================
-- AUDIT LOG BUFFER (for Kafka failures)
-- =============================================================================
CREATE TABLE audit_log_buffer (
    id BIGSERIAL PRIMARY KEY,
    event_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    flushed_at TIMESTAMPTZ, -- NULL = not yet flushed to Kafka
    retry_count INT NOT NULL DEFAULT 0
);

-- Index for unflushed events
CREATE INDEX idx_audit_buffer_unflushed 
    ON audit_log_buffer(created_at) 
    WHERE flushed_at IS NULL;

-- Index for cleanup of old flushed events
CREATE INDEX idx_audit_buffer_flushed 
    ON audit_log_buffer(flushed_at) 
    WHERE flushed_at IS NOT NULL;

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_addresses_updated_at
    BEFORE UPDATE ON addresses
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE users IS 'User profiles with encrypted PII fields';
COMMENT ON COLUMN users.email_hash IS 'SHA-256 hash for email lookups, encrypted value in email_encrypted';
COMMENT ON COLUMN users.encryption_key_version IS 'Version of encryption key used, for rotation';
COMMENT ON TABLE address_history IS 'Immutable history of address changes for compliance';
COMMENT ON TABLE audit_log_buffer IS 'Local buffer for audit events when Kafka is unavailable';
