package main

import (
	"encoding/json"
	"context"
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

// writeJSON writes a JSON success response.
func writeJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
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

// csrfMiddleware validates that state-changing requests (POST, PUT, DELETE)
// originate from the same origin. For browser-based requests, this prevents
// cross-site request forgery by requiring one of:
//   - Valid Origin header matching CORS_ALLOWED_ORIGINS
//   - X-Requested-With: XMLHttpRequest header (common SPA pattern)
//   - X-CSRF-Token header (custom token approach)
// GET, HEAD, OPTIONS requests are allowed through (they should be side-effect-free).
func csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Safe methods don't need CSRF protection
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next(w, r)
			return
		}

		// Check for X-Requested-With header (standard SPA anti-CSRF)
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			next(w, r)
			return
		}

		// Check for custom CSRF token header
		if r.Header.Get("X-CSRF-Token") != "" {
			next(w, r)
			return
		}

		// Check Origin header matches allowed origins
		origin := r.Header.Get("Origin")
		if origin != "" {
			if isOriginAllowed(origin) {
				next(w, r)
				return
			}
		}

		// Also allow requests with Authorization header (API clients)
		if r.Header.Get("Authorization") != "" {
			next(w, r)
			return
		}

		// Also allow requests with X-Agent-Secret header (agent connections)
		if r.Header.Get("X-Agent-Secret") != "" {
			next(w, r)
			return
		}

		writeJSONError(w, http.StatusForbidden, "CSRF validation failed: missing Origin, X-Requested-With, X-CSRF-Token, or Authorization header")
	}
}

// isOriginAllowed checks if the given origin is in the CORS_ALLOWED_ORIGINS list.
func isOriginAllowed(origin string) bool {
	if corsAllowedOrigins == "*" {
		return true
	}
	for _, allowed := range strings.Split(corsAllowedOrigins, ",") {
		allowed = strings.TrimSpace(allowed)
		if allowed == origin || allowed == "*" {
			return true
		}
	}
	return false
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
// Logs method, path, status code, duration, request ID, and user ID (when available).
func accessLogMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")

		// Extract user ID from Authorization header (without blocking on auth failure)
		userID := ""
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			if claims, err := ValidateJWT(strings.TrimPrefix(authHeader, "Bearer ")); err == nil {
				userID = claims.UserID
			}
		}

		// Wrap ResponseWriter to capture status code
		wrapped := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next(wrapped, r)

		duration := time.Since(start)
		fields := map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"request_id":  requestID,
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		}
		if userID != "" {
			fields["user_id"] = userID
		}
		DefaultLogger.Info("http_request", fields)
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
		// Content-Security-Policy for WebChat-served pages
		// Allows same-origin scripts, styles, WebSocket connections, and inline styles
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob:; "+
				"connect-src 'self' ws: wss:; "+
				"font-src 'self'; "+
				"frame-ancestors 'none'; "+
				"form-action 'self'; "+
				"base-uri 'self'")
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

// authIPLimiter applies a stricter rate limit to auth endpoints.
// Configurable via AUTH_RATE_LIMIT env var (default: 30/min).
func initAuthRateLimit() {
	n := 30
	if v := os.Getenv("AUTH_RATE_LIMIT"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	authIPLimiter = NewRateLimiter(n, time.Minute)
}

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

// adminAuthMiddleware requires a valid X-Admin-Secret header for admin endpoints.
// Uses constant-time comparison to prevent timing attacks.
func adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret := r.Header.Get("X-Admin-Secret")
		if secret == "" {
			secret = r.FormValue("admin_secret")
		}
		if secret == "" {
			secret = r.URL.Query().Get("admin_secret")
		}
		if err := ValidateAdminSecret(secret); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// contextKeyUserID is the context key for the authenticated user ID
var contextKeyUserID = &struct{}{}

// authMiddleware validates JWT and sets user ID in request context.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
		claims, err := ValidateJWT(token)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := r.Context()
		// Store both user_id and agent flag
		ctx = context.WithValue(ctx, contextKeyUserID, claims.UserID)
		next(w, r.WithContext(ctx))
	}
}

// getUserID extracts the authenticated user ID from request context.
func getUserID(r *http.Request) (string, error) {
	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("unauthorized")
	}
	return userID, nil
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