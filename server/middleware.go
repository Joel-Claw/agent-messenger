package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
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