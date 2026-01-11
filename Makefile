.PHONY: build run test lint clean docker migrate

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-w -s -X main.Version=$(VERSION)"

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOLINT := golangci-lint

# Directories
CMD_DIR := ./cmd/server
BIN_DIR := ./bin
MIGRATIONS_DIR := ./migrations/postgres

# Binary name
BINARY := user-service

## build: Build the application
build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) $(CMD_DIR)

## run: Run the application
run: build
	@echo "Running $(BINARY)..."
	$(BIN_DIR)/$(BINARY)

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration ./tests/integration/...

## lint: Run linter
lint:
	@echo "Running linter..."
	$(GOLINT) run ./...

## lint-fix: Run linter with auto-fix
lint-fix:
	@echo "Running linter with auto-fix..."
	$(GOLINT) run --fix ./...

## security: Run security scanner
security:
	@echo "Running security scanner..."
	gosec ./...

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -f deployments/docker/Dockerfile -t banking/user-service:$(VERSION) .

## docker-push: Push Docker image
docker-push: docker-build
	@echo "Pushing Docker image..."
	docker push banking/user-service:$(VERSION)

## docker-run: Run Docker container locally
docker-run:
	@echo "Running Docker container..."
	docker run -p 8080:8080 -p 9090:9090 \
		-e USER_SERVICE_DATABASE_HOST=host.docker.internal \
		-e USER_SERVICE_REDIS_HOST=host.docker.internal \
		banking/user-service:$(VERSION)

## migrate-up: Run database migrations
migrate-up:
	@echo "Running migrations..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

## migrate-down: Rollback database migrations
migrate-down:
	@echo "Rolling back migrations..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

## migrate-create: Create new migration
migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $$name

## generate: Run code generation
generate:
	@echo "Running code generation..."
	$(GOCMD) generate ./...

## help: Show this help
help:
	@echo "Usage:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

# Default target
.DEFAULT_GOAL := help
