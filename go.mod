module github.com/banking/user-service

go 1.22

require (
	github.com/IBM/sarama v1.43.0
	github.com/go-playground/validator/v10 v10.18.0
	github.com/google/uuid v1.6.0
	github.com/hashicorp/vault/api v1.12.0
	github.com/jackc/pgx/v5 v5.5.3
	github.com/labstack/echo/v4 v4.11.4
	github.com/redis/go-redis/v9 v9.5.1
	github.com/sony/gobreaker v0.5.0
	github.com/spf13/viper v1.18.2
	go.mongodb.org/mongo-driver v1.14.0
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.24.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.24.0
	go.opentelemetry.io/otel/sdk v1.24.0
	go.opentelemetry.io/otel/trace v1.24.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.19.0
	google.golang.org/grpc v1.62.0
)
