# Banking User Service

A banking-grade Go microservice for user profile management with PCI DSS/SOC 2 compliance.

## Features

- **User Profile Management**: Create, read, update, soft-delete user profiles
- **Address Management**: Multiple address types with versioning and history
- **Device Management**: Hashed fingerprints for fraud detection
- **User Preferences**: Flexible notification and UX settings
- **KYC Status Tracking**: Reference pointers to KYC service

## Security Features

- **AES-256-GCM Encryption**: Field-level PII encryption with key rotation
- **HMAC-Signed Audit Logs**: Tamper-proof audit trail
- **IDOR Prevention**: Ownership verification on all endpoints
- **PII-Safe Logging**: Auto-masking of emails, phones in logs
- **Rate Limiting**: Per-user, per-IP, per-resource limits

## Architecture

```
cmd/server/           # Application entrypoint
internal/
├── api/http/         # HTTP handlers and middleware
├── config/           # Configuration management
├── crypto/           # AES-256-GCM encryption, key management
├── domain/           # Business entities
├── events/           # Kafka producers
├── pkg/              # Shared utilities (logger, tracer, health)
├── repository/       # Data access (PostgreSQL, Redis, MongoDB)
├── resilience/       # Circuit breakers, fallbacks
└── service/          # Business logic
```

## Quick Start

```bash
# Build
make build

# Run locally
make run

# Run tests
make test

# Build Docker image
make docker-build

# Run with Docker
make docker-run
```

## Configuration

Environment variables (prefix: `USER_SERVICE_`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | HTTP port | 8080 |
| `DATABASE_HOST` | PostgreSQL host | localhost |
| `REDIS_HOST` | Redis host | localhost |
| `KAFKA_BROKERS` | Kafka brokers | localhost:9092 |
| `ENCRYPTION_KEYS` | Base64 AES keys | required |
| `ENCRYPTION_AUDIT_HMAC_SECRET` | HMAC secret | required |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/users/me` | Get own profile |
| PUT | `/api/v1/users/me` | Update own profile |
| DELETE | `/api/v1/users/me` | Soft delete profile |
| GET | `/api/v1/users/me/addresses` | List addresses |
| POST | `/api/v1/users/me/addresses` | Add address |
| GET | `/api/v1/users/me/devices` | List devices |
| GET | `/api/v1/users/me/preferences` | Get preferences |

## Health Endpoints

- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe (checks DB, Redis, Kafka)

## Requirements

- Go 1.22+
- PostgreSQL 14+
- Redis 7+
- MongoDB 6+ (for preferences)
- Kafka 3+

## License

MIT
