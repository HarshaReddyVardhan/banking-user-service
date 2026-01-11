package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"github.com/google/uuid"

	"github.com/banking/user-service/internal/domain/audit"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/resilience"
)

// Common errors
var (
	ErrProducerClosed = errors.New("producer is closed")
	ErrBufferFull     = errors.New("event buffer is full")
)

// AuditProducer handles producing audit events to Kafka
type AuditProducer struct {
	producer   sarama.AsyncProducer
	topic      string
	cb         *resilience.CircuitBreaker
	buffer     *resilience.EventBuffer
	log        *logger.Logger
	closed     bool
	mu         sync.RWMutex
	wg         sync.WaitGroup
}

// AuditProducerConfig holds configuration for audit producer
type AuditProducerConfig struct {
	Brokers         []string
	Topic           string
	BufferSize      int
	RequireAcks     sarama.RequiredAcks
	EnableIdempotent bool
}

// NewAuditProducer creates a new audit event producer
func NewAuditProducer(cfg AuditProducerConfig, cb *resilience.CircuitBreaker, persistFn func(ctx context.Context, events []resilience.BufferedEvent) error, log *logger.Logger) (*AuditProducer, error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = cfg.RequireAcks
	config.Producer.Idempotent = cfg.EnableIdempotent
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	config.Net.MaxOpenRequests = 1 // Required for idempotent
	config.Producer.Retry.Max = 3
	config.Producer.Retry.Backoff = 100 * time.Millisecond

	producer, err := sarama.NewAsyncProducer(cfg.Brokers, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	ap := &AuditProducer{
		producer: producer,
		topic:    cfg.Topic,
		cb:       cb,
		buffer:   resilience.NewEventBuffer(cfg.BufferSize, persistFn),
		log:      log.Named("audit_producer"),
	}

	// Start success/error handlers
	ap.wg.Add(2)
	go ap.handleSuccesses()
	go ap.handleErrors()

	// Set flush function for buffer
	ap.buffer.SetFlushFunc(func(ctx context.Context, event resilience.BufferedEvent) error {
		return ap.sendDirect(event.Payload, event.Key)
	})

	return ap, nil
}

// Produce sends an audit event to Kafka
func (p *AuditProducer) Produce(ctx context.Context, event *audit.AuditEvent) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return ErrProducerClosed
	}
	p.mu.RUnlock()

	// Serialize event
	data, err := event.JSON()
	if err != nil {
		return fmt.Errorf("failed to serialize audit event: %w", err)
	}

	// Try to send through circuit breaker
	_, err = p.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, p.sendDirect(data, event.UserID)
	})

	if err != nil {
		// Circuit is open or send failed - buffer the event
		p.log.Warn("buffering audit event due to Kafka unavailability",
			logger.RequestID(event.RequestID),
		)

		bufferedEvent := resilience.BufferedEvent{
			ID:        event.EventID,
			Topic:     p.topic,
			Key:       event.UserID,
			Payload:   data,
			CreatedAt: time.Now(),
		}

		if bufferErr := p.buffer.Add(bufferedEvent); bufferErr != nil {
			p.log.Error("failed to buffer audit event",
				logger.ErrorField(bufferErr),
				logger.RequestID(event.RequestID),
			)
			return bufferErr
		}
	}

	return nil
}

func (p *AuditProducer) sendDirect(data []byte, key string) error {
	msg := &sarama.ProducerMessage{
		Topic: p.topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(data),
		Headers: []sarama.RecordHeader{
			{Key: []byte("content-type"), Value: []byte("application/json")},
		},
	}

	select {
	case p.producer.Input() <- msg:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("producer input timeout")
	}
}

func (p *AuditProducer) handleSuccesses() {
	defer p.wg.Done()
	for range p.producer.Successes() {
		// Event sent successfully
	}
}

func (p *AuditProducer) handleErrors() {
	defer p.wg.Done()
	for err := range p.producer.Errors() {
		p.log.Error("failed to send audit event to Kafka",
			logger.ErrorField(err.Err),
		)
		// The event should already be buffered
	}
}

// FlushBuffer attempts to send all buffered events
func (p *AuditProducer) FlushBuffer(ctx context.Context) (int, error) {
	if p.cb.IsOpen() {
		return 0, errors.New("circuit breaker is open")
	}
	return p.buffer.Flush(ctx)
}

// BufferSize returns the current buffer size
func (p *AuditProducer) BufferSize() int {
	return p.buffer.Size()
}

// Close closes the producer
func (p *AuditProducer) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	if err := p.producer.Close(); err != nil {
		return err
	}

	p.wg.Wait()
	return nil
}

// EventProducer handles producing domain events to Kafka
type EventProducer struct {
	producer sarama.AsyncProducer
	topic    string
	cb       *resilience.CircuitBreaker
	log      *logger.Logger
}

// NewEventProducer creates a new domain event producer
func NewEventProducer(brokers []string, topic string, cb *resilience.CircuitBreaker, log *logger.Logger) (*EventProducer, error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForLocal
	config.Producer.Return.Successes = false
	config.Producer.Return.Errors = true

	producer, err := sarama.NewAsyncProducer(brokers, config)
	if err != nil {
		return nil, err
	}

	ep := &EventProducer{
		producer: producer,
		topic:    topic,
		cb:       cb,
		log:      log.Named("event_producer"),
	}

	// Start error handler
	go ep.handleErrors()

	return ep, nil
}

// UserEvent represents a user-related domain event
type UserEvent struct {
	EventID    string    `json:"event_id"`
	EventType  string    `json:"event_type"`
	UserID     string    `json:"user_id"`
	Timestamp  time.Time `json:"timestamp"`
	Data       any       `json:"data,omitempty"`
}

// ProduceUserEvent sends a user event to Kafka
func (p *EventProducer) ProduceUserEvent(ctx context.Context, eventType string, userID uuid.UUID, data any) error {
	event := UserEvent{
		EventID:   uuid.New().String(),
		EventType: eventType,
		UserID:    userID.String(),
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	eventData, err := json.Marshal(event)
	if err != nil {
		return err
	}

	msg := &sarama.ProducerMessage{
		Topic: p.topic,
		Key:   sarama.StringEncoder(userID.String()),
		Value: sarama.ByteEncoder(eventData),
	}

	_, err = p.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		p.producer.Input() <- msg
		return nil, nil
	})

	return err
}

func (p *EventProducer) handleErrors() {
	for err := range p.producer.Errors() {
		p.log.Error("failed to send event to Kafka", logger.ErrorField(err.Err))
	}
}

// Close closes the producer
func (p *EventProducer) Close() error {
	return p.producer.Close()
}
