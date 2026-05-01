package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xForwarded string
		xRealIP    string
		expected   string
	}{
		{
			name:       "direct connection",
			remoteAddr: "192.168.1.1:54321",
			expected:   "192.168.1.1",
		},
		{
			name:       "x-forwarded-for single IP",
			remoteAddr: "10.0.0.1:8080",
			xForwarded: "203.0.113.1",
			expected:   "203.0.113.1",
		},
		{
			name:       "x-forwarded-for multiple IPs",
			remoteAddr: "10.0.0.1:8080",
			xForwarded: "203.0.113.1, 70.41.3.18, 150.172.238.178",
			expected:   "203.0.113.1",
		},
		{
			name:       "x-real-ip header",
			remoteAddr: "10.0.0.1:8080",
			xRealIP:    "198.51.100.42",
			expected:   "198.51.100.42",
		},
		{
			name:       "x-forwarded-for takes precedence over x-real-ip",
			remoteAddr: "10.0.0.1:8080",
			xForwarded: "203.0.113.1",
			xRealIP:    "198.51.100.42",
			expected:   "203.0.113.1",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwarded)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := extractIP(req)
			if ip != tt.expected {
				t.Errorf("extractIP() = %q, want %q", ip, tt.expected)
			}
		})
	}
}

func TestIPRateLimitMiddleware(t *testing.T) {
	// Create a fresh rate limiter for testing
	testLimiter := NewRateLimiter(5, time.Minute)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}

	wrapped := func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !testLimiter.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		handler(w, r)
	}

	// First 5 requests should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		rec := httptest.NewRecorder()
		wrapped(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rec := httptest.NewRecorder()
	wrapped(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate-limited request, got %d", rec.Code)
	}

	// Different IP should still work
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "5.6.7.8:12345"
	rec2 := httptest.NewRecorder()
	wrapped(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 for different IP, got %d", rec2.Code)
	}
}

func TestAuthRateLimitMiddleware(t *testing.T) {
	// Verify that authIPLimiter is stricter (30/min) than ipRateLimiter (300/min)
	if authIPLimiter.limit != 30 {
		t.Errorf("authIPLimiter limit = %d, want 30", authIPLimiter.limit)
	}
	if ipRateLimiter.limit != 300 {
		t.Errorf("ipRateLimiter limit = %d, want 300", ipRateLimiter.limit)
	}
}

func TestIPRateLimitWithXForwardedFor(t *testing.T) {
	testLimiter := NewRateLimiter(3, time.Minute)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	wrapped := func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !testLimiter.Allow(ip) {
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		handler(w, r)
	}

	// Requests from same X-Forwarded-For IP should be rate limited together
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:12345", i) // different source IPs
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		rec := httptest.NewRecorder()
		wrapped(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 4th request from different source but same forwarded IP should be limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rec := httptest.NewRecorder()
	wrapped(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate-limited forwarded IP, got %d", rec.Code)
	}
}