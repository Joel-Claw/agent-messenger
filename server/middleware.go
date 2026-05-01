package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter tracks message counts per connection ID
type RateLimiter struct {
	mu       sync.Mutex
	counters map[string]*rateCounter
	limit    int           // max messages per window
	window   time.Duration // time window
}

type rateCounter struct {
	count   int
	expires time.Time
}

// NewRateLimiter creates a rate limiter with the given limit per window
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		counters: make(map[string]*rateCounter),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

// Allow checks if a message from the given ID is within rate limits.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(id string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, ok := rl.counters[id]
	if !ok || now.After(counter.expires) {
		rl.counters[id] = &rateCounter{
			count:   1,
			expires: now.Add(rl.window),
		}
		return true
	}

	counter.count++
	if counter.count > rl.limit {
		return false
	}
	return true
}

// cleanup removes expired entries periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for id, counter := range rl.counters {
			if now.After(counter.expires) {
				delete(rl.counters, id)
			}
		}
		rl.mu.Unlock()
	}
}

// writeJSONError writes a JSON error response with the given status code
func writeJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error":  message,
		"status": http.StatusText(code),
	})
}

// isUniqueViolation checks if the error is a SQLite UNIQUE constraint violation
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// messageRateLimiter is the global rate limiter for WebSocket messages.
// 60 messages per minute = 1 per second average, allows bursts.
var messageRateLimiter = NewRateLimiter(60, time.Minute)

// userRateLimiter limits per-user message rates (independent of connections).
// This prevents a user from circumventing per-connection limits by reconnecting.
var userRateLimiter = NewRateLimiter(120, time.Minute)

// checkRateLimit checks if a connection is within rate limits.
// It checks both per-connection and per-user limits.
// If rate limited, it sends an error to the connection and returns false.
func checkRateLimit(conn *Connection) bool {
	// Check per-connection rate limit first
	if !messageRateLimiter.Allow(conn.id) {
		if ServerMetrics != nil {
			ServerMetrics.RateLimited.Add(1)
		}
		if ServerMetrics != nil {
			ServerMetrics.ErrorsTotal.Add(1)
		}
		sendError(conn, "rate limit exceeded: too many messages")
		return false
	}

	// Check per-user rate limit (uses same ID, but could use different key)
	if !userRateLimiter.Allow(conn.id) {
		if ServerMetrics != nil {
			ServerMetrics.RateLimited.Add(1)
		}
		if ServerMetrics != nil {
			ServerMetrics.ErrorsTotal.Add(1)
		}
		sendError(conn, "rate limit exceeded: user message quota reached")
		return false
	}

	return true
}

// corsMiddleware adds CORS headers for cross-origin requests (WebChat, SDKs).
// Allowed origins are configurable via CORS_ALLOWED_ORIGINS env var (comma-separated).
// Defaults to "*" (allow all) if not set, which is fine for development.
// For production, set CORS_ALLOWED_ORIGINS=https://chat.example.com,https://app.example.com
var corsAllowedOrigins = getEnvOrDefault("CORS_ALLOWED_ORIGINS", "*")

// requestIDMiddleware adds a unique request ID to each request for correlation.
// If the client sends an X-Request-ID header, it is preserved; otherwise a new
// UUID-style ID is generated. The ID is added to the response header and can be
// used by downstream handlers and loggers via r.Header.Get("X-Request-ID").
var requestIDCounter uint64

func requestIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), atomic.AddUint64(&requestIDCounter, 1))
		}
		// Set on both the request (for downstream handlers) and response (for clients)
		r.Header.Set("X-Request-ID", requestID)
		w.Header().Set("X-Request-ID", requestID)
		next(w, r)
	}
}

// accessLogMiddleware logs each HTTP request using the structured logger.
// Logs method, path, status code, duration, and request ID.
func accessLogMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")

		// Wrap ResponseWriter to capture status code
		wrapped := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next(wrapped, r)

		duration := time.Since(start)
		DefaultLogger.Info("http_request", map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms":  duration.Milliseconds(),
			"request_id":  requestID,
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		})
	}
}

// responseWriterWrapper wraps http.ResponseWriter to capture the status code.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// securityHeadersMiddleware adds security-related HTTP headers to responses.
// Applied to WebChat-served static files and API endpoints.
func securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next(w, r)
	}
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if corsAllowedOrigins == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				// Check if origin is in allowed list
				for _, allowed := range strings.Split(corsAllowedOrigins, ",") {
					allowed = strings.TrimSpace(allowed)
					if allowed == origin || allowed == "*" {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-Secret")
			w.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// ipRateLimiter tracks per-IP request rates for HTTP API endpoints.
// 300 requests per minute per IP by default, configurable via IP_RATE_LIMIT env.
var ipRateLimiter = NewRateLimiter(300, time.Minute)

// authIPLimiter applies a stricter rate limit (30/min) to auth endpoints.
var authIPLimiter = NewRateLimiter(30, time.Minute)

// ipRateLimitMiddleware limits requests per IP address for HTTP API endpoints.
// This protects against brute force attacks, credential stuffing, and general abuse.
func ipRateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !ipRateLimiter.Allow(ip) {
			if ServerMetrics != nil {
				ServerMetrics.RateLimited.Add(1)
			}
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded: too many requests from this IP")
			return
		}
		next(w, r)
	}
}

// authRateLimitMiddleware applies a stricter per-IP rate limit on auth endpoints.
func authRateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !authIPLimiter.Allow(ip) {
			if ServerMetrics != nil {
				ServerMetrics.RateLimited.Add(1)
			}
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded: too many auth attempts from this IP")
			return
		}
		next(w, r)
	}
}

// extractIP returns the client IP from the request, considering X-Forwarded-For
// and X-Real-IP headers for reverse proxy setups.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs, use first)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP in the list is the original client
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fall back to RemoteAddr (strip port)
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}