-- Banking User Service: Rollback Initial Schema
-- Migration: 001_init.down.sql

-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_addresses_updated_at ON addresses;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS audit_log_buffer;
DROP TABLE IF EXISTS address_history;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS addresses;
DROP TABLE IF EXISTS users;

-- Drop extensions (optional, might be used by other schemas)
-- DROP EXTENSION IF EXISTS "uuid-ossp";
-- DROP EXTENSION IF EXISTS "pgcrypto";
