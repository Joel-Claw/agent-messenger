package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddlewareAllowAll(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = originalOrigins }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Expected Access-Control-Allow-Origin: *, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddlewareSpecificOrigin(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://app.example.com,https://chat.example.com"
	defer func() { corsAllowedOrigins = originalOrigins }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Allowed origin
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("Expected echo of allowed origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}

	// Disallowed origin — should not set ACAO header
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Origin", "https://evil.example.com")
	w2 := httptest.NewRecorder()
	handler(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w2.Code)
	}
	if w2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Expected no ACAO header for disallowed origin, got %s", w2.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddlewarePreflight(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = originalOrigins }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called for OPTIONS request")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected 204 for preflight, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Expected Access-Control-Allow-Methods header")
	}
	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("Expected Access-Control-Allow-Headers header")
	}
}

func TestCORSMiddlewareNoOrigin(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = originalOrigins }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Request without Origin header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Should not set CORS headers when no Origin is present
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Expected no ACAO header when no Origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}