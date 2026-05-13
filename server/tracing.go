package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	// tracer is the global OpenTelemetry tracer for Agent Messenger.
	tracer trace.Tracer

	// tp is the trace provider, kept for shutdown.
	tp *sdktrace.TracerProvider

	// tracingEnabled indicates whether tracing is active.
	tracingEnabled bool

	// tracingMu protects initialization.
	tracingMu sync.Once
)

const (
	// tracerName is the name of the Agent Messenger tracer.
	tracerName = "github.com/Joel-Claw/agent-messenger"

	// Span names for message routing
	spanRouteMessage      = "route_message"
	spanRouteChatMessage  = "route_chat_message"
	spanRouteTyping       = "route_typing"
	spanRouteStatus       = "route_status"
	spanRouteHeartbeat    = "route_heartbeat"
	spanStoreMessage      = "store_message"
	spanDeliverMessage    = "deliver_message"
	spanOfflineEnqueue   = "offline_enqueue"
	spanPushNotify        = "push_notify"
	spanAgentConnect     = "ws.agent_connect"
	spanClientConnect    = "ws.client_connect"
	spanHTTPRequest       = "http_request"

	// Attribute keys
	attrConnType       = "messenger.conn_type"
	attrConnID         = "messenger.conn_id"
	attrDeviceID       = "messenger.device_id"
	attrConversationID = "messenger.conversation_id"
	attrMessageType    = "messenger.message_type"
	attrSenderType     = "messenger.sender_type"
	attrSenderID       = "messenger.sender_id"
	attrRecipientID    = "messenger.recipient_id"
	attrRecipientType  = "messenger.recipient_type"
	attrDelivered      = "messenger.delivered"
	attrBuffered       = "messenger.buffered"
	attrOffline        = "messenger.offline_queued"
	attrPushSent       = "messenger.push_sent"
	attrAgentStatus    = "messenger.agent_status"
	attrHeartbeat      = "messenger.heartbeat"
)

// InitTracing initializes the OpenTelemetry tracing pipeline.
// It reads OTEL_EXPORTER_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_HTTP_ENDPOINT)
// for the collector endpoint. If no endpoint is configured, tracing is disabled.
//
// Environment variables:
//   - OTEL_ENABLED: "true" to enable tracing (default: "false")
//   - OTEL_EXPORTER_OTLP_ENDPOINT: OTLP collector endpoint (e.g., "localhost:4317" for gRPC, "http://localhost:4318" for HTTP)
//   - OTEL_EXPORTER_OTLP_PROTOCOL: "grpc" or "http" (default: "grpc")
//   - OTEL_SERVICE_NAME: service name in traces (default: "agent-messenger")
//   - OTEL_SAMPLING_RATE: sampling rate 0.0-1.0 (default: "0.1" = 10%)
func InitTracing() error {
	var initErr error
	tracingMu.Do(func() {
		if os.Getenv("OTEL_ENABLED") != "true" {
			DefaultLogger.Info("tracing_disabled", map[string]interface{}{
				"reason": "OTEL_ENABLED not set to 'true'",
			})
			return
		}

		endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		if endpoint == "" {
			endpoint = os.Getenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
		}
		if endpoint == "" {
			DefaultLogger.Info("tracing_disabled", map[string]interface{}{
				"reason": "no OTEL_EXPORTER_OTLP_ENDPOINT configured",
			})
			return
		}

		serviceName := getEnvOrDefault("OTEL_SERVICE_NAME", "agent-messenger")
		protocol := getEnvOrDefault("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")

		// Create exporter
		var exporter sdktrace.SpanExporter
		var err error

		ctx := context.Background()

		if protocol == "http" {
			// HTTP exporter
			opts := []otlptracehttp.Option{
				otlptracehttp.WithEndpoint(endpoint),
			}
			if strings.HasPrefix(endpoint, "http://") {
				opts = append(opts, otlptracehttp.WithInsecure())
			}
			exporter, err = otlptracehttp.New(ctx, opts...)
		} else {
			// gRPC exporter (default)
			opts := []otlptracegrpc.Option{
				otlptracegrpc.WithEndpoint(endpoint),
			}
			// Use insecure connection for local development
			if !strings.HasSuffix(endpoint, ":443") && !strings.HasPrefix(endpoint, "https://") {
				opts = append(opts, otlptracegrpc.WithInsecure())
			}
			exporter, err = otlptracegrpc.New(ctx, opts...)
		}

		if err != nil {
			initErr = fmt.Errorf("failed to create OTLP exporter: %w", err)
			DefaultLogger.Error("tracing_init_failed", map[string]interface{}{"error": err.Error()})
			return
		}

		// Parse sampling rate
		samplingRate := 0.1 // 10% default
		if sr := os.Getenv("OTEL_SAMPLING_RATE"); sr != "" {
			if parsed, parseErr := strconv.ParseFloat(sr, 64); parseErr == nil {
				samplingRate = parsed
			}
		}

		// Create resource with service info
		res, err := resource.Merge(
			resource.Default(),
			resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String(serviceName),
				semconv.ServiceVersionKey.String(ServerVersion),
			),
		)
		if err != nil {
			initErr = fmt.Errorf("failed to create resource: %w", err)
			return
		}

		// Create trace provider with sampling
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.TraceIDRatioBased(samplingRate)),
			sdktrace.WithBatcher(exporter),
		)

		// Set global tracer provider
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))

		tracer = tp.Tracer(tracerName)
		tracingEnabled = true

		DefaultLogger.Info("tracing_initialized", map[string]interface{}{
			"endpoint":      endpoint,
			"protocol":      protocol,
			"service_name":  serviceName,
			"sampling_rate": samplingRate,
		})
	})

	return initErr
}

// ShutdownTracing gracefully shuts down the trace provider, flushing any
// pending spans to the collector.
func ShutdownTracing() {
	if tp != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			DefaultLogger.Error("tracing_shutdown_failed", map[string]interface{}{"error": err.Error()})
		}
	}
}

// IsTracingEnabled returns whether tracing is active.
func IsTracingEnabled() bool {
	return tracingEnabled
}

// StartSpan starts a new tracing span. If tracing is disabled, it returns
// a no-op span and the original context.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if !tracingEnabled || tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	ctx, span := tracer.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, span
}

// StartSpanFromRequest starts a new span from an HTTP request, extracting
// trace context from headers if present (for distributed tracing).
func StartSpanFromRequest(r *http.Request, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if !tracingEnabled || tracer == nil {
		return r.Context(), trace.SpanFromContext(r.Context())
	}
	// Propagate trace context from incoming headers
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := tracer.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, span
}

// SpanError records an error on a span and sets its status to Error.
func SpanError(span trace.Span, err error) {
	if !tracingEnabled || span == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// SpanOK marks a span as successful.
func SpanOK(span trace.Span) {
	if !tracingEnabled || span == nil {
		return
	}
	span.SetStatus(codes.Ok, "")
}

// --- Convenience functions for instrumenting specific operations ---

// TraceRouteMessage creates a span for the top-level message routing.
// It returns the span which must be ended by the caller.
func TraceRouteMessage(connType, connID string) trace.Span {
	if !tracingEnabled || tracer == nil {
		return trace.SpanFromContext(context.Background())
	}
	_, span := tracer.Start(context.Background(), spanRouteMessage,
		trace.WithAttributes(
			attribute.String(attrConnType, connType),
			attribute.String(attrConnID, connID),
		),
	)
	return span
}

// TraceChatMessage creates a span for chat message routing.
func TraceChatMessage(ctx context.Context, senderType, senderID, conversationID, recipientID string) (context.Context, trace.Span) {
	return StartSpan(ctx, spanRouteChatMessage,
		attribute.String(attrSenderType, senderType),
		attribute.String(attrSenderID, senderID),
		attribute.String(attrConversationID, conversationID),
		attribute.String(attrRecipientID, recipientID),
	)
}

// TraceStoreMessage creates a span for message persistence.
func TraceStoreMessage(ctx context.Context, conversationID, senderID string) (context.Context, trace.Span) {
	return StartSpan(ctx, spanStoreMessage,
		attribute.String(attrConversationID, conversationID),
		attribute.String(attrSenderID, senderID),
	)
}

// TraceDeliverMessage creates a span for message delivery.
func TraceDeliverMessage(ctx context.Context, recipientID, recipientType string, delivered bool) (context.Context, trace.Span) {
	return StartSpan(ctx, spanDeliverMessage,
		attribute.String(attrRecipientID, recipientID),
		attribute.String(attrRecipientType, recipientType),
		attribute.Bool(attrDelivered, delivered),
	)
}

// TraceOfflineEnqueue creates a span for offline message enqueue.
func TraceOfflineEnqueue(recipientID string) trace.Span {
	if !tracingEnabled || tracer == nil {
		return trace.SpanFromContext(context.Background())
	}
	_, span := tracer.Start(context.Background(), spanOfflineEnqueue,
		trace.WithAttributes(
			attribute.String(attrRecipientID, recipientID),
		),
	)
	return span
}

// TracePushNotify creates a span for push notification.
func TracePushNotify(userID, conversationID string, success bool) trace.Span {
	if !tracingEnabled || tracer == nil {
		return trace.SpanFromContext(context.Background())
	}
	_, span := tracer.Start(context.Background(), spanPushNotify,
		trace.WithAttributes(
			attribute.String("messenger.user_id", userID),
			attribute.String(attrConversationID, conversationID),
			attribute.Bool(attrPushSent, success),
		),
	)
	return span
}

// TraceAgentConnect creates a span for agent WebSocket connection.
func TraceAgentConnect(agentID string) trace.Span {
	if !tracingEnabled || tracer == nil {
		return trace.SpanFromContext(context.Background())
	}
	_, span := tracer.Start(context.Background(), spanAgentConnect,
		trace.WithAttributes(
			attribute.String(attrConnType, "agent"),
			attribute.String(attrConnID, agentID),
		),
	)
	return span
}

// TraceClientConnect creates a span for client WebSocket connection.
func TraceClientConnect(userID, deviceID string) trace.Span {
	if !tracingEnabled || tracer == nil {
		return trace.SpanFromContext(context.Background())
	}
	_, span := tracer.Start(context.Background(), spanClientConnect,
		trace.WithAttributes(
			attribute.String(attrConnType, "client"),
			attribute.String(attrConnID, userID),
			attribute.String(attrDeviceID, deviceID),
		),
	)
	return span
}