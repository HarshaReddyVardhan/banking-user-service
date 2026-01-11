package tracer

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds tracing configuration
type Config struct {
	Enabled      bool
	ServiceName  string
	OTLPEndpoint string
	SampleRate   float64
	Environment  string
	Version      string
}

// Tracer wraps OpenTelemetry tracer with helper methods
type Tracer struct {
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
	enabled  bool
}

// New creates a new tracer with OTLP exporter
func New(ctx context.Context, cfg Config) (*Tracer, error) {
	if !cfg.Enabled {
		return &Tracer{
			tracer:  otel.Tracer(cfg.ServiceName),
			enabled: false,
		}, nil
	}

	// Create OTLP exporter
	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
		otlptracegrpc.WithInsecure(), // Use TLS in production
	)

	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.Version),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create sampler based on sample rate
	var sampler sdktrace.Sampler
	if cfg.SampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SampleRate <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	// Create trace provider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global provider and propagator
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Tracer{
		tracer:   provider.Tracer(cfg.ServiceName),
		provider: provider,
		enabled:  true,
	}, nil
}

// Shutdown shuts down the tracer provider
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t.provider != nil {
		return t.provider.Shutdown(ctx)
	}
	return nil
}

// StartSpan starts a new span with the given name
func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from context
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddEvent adds an event to the current span
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

// SetError records an error on the current span
func SetError(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err)
	}
}

// SetAttributes sets attributes on the current span
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

// Common attribute helpers - PII-safe!
func UserIDAttr(id string) attribute.KeyValue {
	return attribute.String("user.id", id) // UUID is safe
}

func RequestIDAttr(id string) attribute.KeyValue {
	return attribute.String("request.id", id)
}

func HTTPMethodAttr(method string) attribute.KeyValue {
	return attribute.String("http.method", method)
}

func HTTPRouteAttr(route string) attribute.KeyValue {
	return attribute.String("http.route", route)
}

func HTTPStatusAttr(status int) attribute.KeyValue {
	return attribute.Int("http.status_code", status)
}

func DBOperationAttr(op string) attribute.KeyValue {
	return attribute.String("db.operation", op)
}

func DBTableAttr(table string) attribute.KeyValue {
	return attribute.String("db.table", table)
}

func CacheHitAttr(hit bool) attribute.KeyValue {
	return attribute.Bool("cache.hit", hit)
}

func KafkaTopicAttr(topic string) attribute.KeyValue {
	return attribute.String("kafka.topic", topic)
}

// TraceID returns the trace ID from context as a string
func TraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().HasTraceID() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// SpanID returns the span ID from context as a string
func SpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().HasSpanID() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}
