package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRFMiddleware_SafeMethods(t *testing.T) {
	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	safeMethods := []string{"GET", "HEAD", "OPTIONS"}
	for _, method := range safeMethods {
		req := httptest.NewRequest(method, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("CSRF should allow %s requests, got %d", method, rec.Code)
		}
	}
}

func TestCSRFMiddleware_BlockWithoutHeaders(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	defer func() { corsAllowedOrigins = originalOrigins }()
	corsAllowedOrigins = "https://chat.example.com"

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// POST without any CSRF headers should be blocked
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST without CSRF headers, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AllowWithXRequestedWith(t *testing.T) {
	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(""))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for POST with X-Requested-With, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AllowWithCSRFToken(t *testing.T) {
	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(""))
	req.Header.Set("X-CSRF-Token", "some-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for POST with X-CSRF-Token, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AllowWithAuthorization(t *testing.T) {
	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/conversations/create", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer some-jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for POST with Authorization, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AllowWithAgentSecret(t *testing.T) {
	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(""))
	req.Header.Set("X-Agent-Secret", "my-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for POST with X-Agent-Secret, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AllowWithMatchingOrigin(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	defer func() { corsAllowedOrigins = originalOrigins }()
	corsAllowedOrigins = "https://chat.example.com,https://app.example.com"

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(""))
	req.Header.Set("Origin", "https://chat.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for POST with matching Origin, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_BlockWithMismatchedOrigin(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	defer func() { corsAllowedOrigins = originalOrigins }()
	corsAllowedOrigins = "https://chat.example.com"

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(""))
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST with mismatched Origin, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_WildcardOrigin(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	defer func() { corsAllowedOrigins = originalOrigins }()
	corsAllowedOrigins = "*"

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(""))
	req.Header.Set("Origin", "https://any-origin.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for POST with wildcard CORS, got %d", rec.Code)
	}
}

func TestIsOriginAllowed(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	defer func() { corsAllowedOrigins = originalOrigins }()

	tests := []struct {
		name     string
		origins  string
		origin   string
		expected bool
	}{
		{"wildcard allows all", "*", "https://anything.com", true},
		{"exact match", "https://chat.example.com", "https://chat.example.com", true},
		{"no match", "https://chat.example.com", "https://evil.com", false},
		{"multiple origins match", "https://a.com,https://b.com", "https://b.com", true},
		{"multiple origins no match", "https://a.com,https://b.com", "https://c.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corsAllowedOrigins = tt.origins
			if got := isOriginAllowed(tt.origin); got != tt.expected {
				t.Errorf("isOriginAllowed(%q) with origins=%q = %v, want %v", tt.origin, tt.origins, got, tt.expected)
			}
		})
	}
}

func TestCSRFMiddleware_AllowDELETEWithAuth(t *testing.T) {
	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=123", nil)
	req.Header.Set("Authorization", "Bearer jwt-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for DELETE with Authorization, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_BlockDELETEWithoutHeaders(t *testing.T) {
	originalOrigins := corsAllowedOrigins
	defer func() { corsAllowedOrigins = originalOrigins }()
	corsAllowedOrigins = "https://chat.example.com"

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=123", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for DELETE without CSRF headers, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_IntegrationWithLogin(t *testing.T) {
	// Test that CSRF middleware works with real auth handler
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Login POST without CSRF headers should fail
	form := url.Values{"email": {"test@example.com"}, "password": {"testpass"}}
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	csrfHandler := csrfMiddleware(corsMiddleware(handleLogin))
	csrfHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for login without CSRF headers, got %d", rec.Code)
	}

	// Login POST with X-Requested-With should pass CSRF check (but may fail auth)
	req2 := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec2 := httptest.NewRecorder()

	csrfHandler.ServeHTTP(rec2, req2)
	// Should not be 403 (may be 401/500 for auth reasons, but not CSRF-blocked)
	if rec2.Code == http.StatusForbidden {
		t.Errorf("login with X-Requested-With should not be CSRF-blocked, got %d", rec2.Code)
	}
}
