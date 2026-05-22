package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminAuthMiddleware(t *testing.T) {
	// Save and restore original adminSecret
	originalSecret := adminSecret
	defer func() { adminSecret = originalSecret }()

	// Set known test secret
	adminSecret = "test-admin-secret"

	handler := adminAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		secret     string
		setOn      string // "header", "form", "query", or empty
		expectCode int
	}{
		{
			name:       "valid secret via header",
			secret:     "test-admin-secret",
			setOn:      "header",
			expectCode: http.StatusOK,
		},
		{
			name:       "invalid secret via header",
			secret:     "wrong-secret",
			setOn:      "header",
			expectCode: http.StatusUnauthorized,
		},
		{
			name:       "missing secret",
			secret:     "",
			setOn:      "",
			expectCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/agents", nil)
			if tt.setOn == "header" {
				req.Header.Set("X-Admin-Secret", tt.secret)
			} else if tt.setOn == "query" {
				req = httptest.NewRequest("GET", "/admin/agents?admin_secret="+tt.secret, nil)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectCode {
				t.Errorf("expected status %d, got %d", tt.expectCode, rec.Code)
			}
		})
	}
}

func TestAdminAuthMiddlewareViaFormValue(t *testing.T) {
	originalSecret := adminSecret
	defer func() { adminSecret = originalSecret }()

	adminSecret = "test-admin-secret-form"

	handler := adminAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier?admin_secret=test-admin-secret-form", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid admin secret via form, got %d", rec.Code)
	}
}

func TestAdminAuthMiddlewareViaQueryParam(t *testing.T) {
	originalSecret := adminSecret
	defer func() { adminSecret = originalSecret }()

	adminSecret = "test-admin-secret-query"

	handler := adminAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?admin_secret=test-admin-secret-query", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid admin secret via query param, got %d", rec.Code)
	}
}

func TestValidateAdminSecretTimingSafe(t *testing.T) {
	originalSecret := adminSecret
	defer func() { adminSecret = originalSecret }()

	adminSecret = "test-admin-secret-timing"

	// Correct secret should succeed
	if err := ValidateAdminSecret("test-admin-secret-timing"); err != nil {
		t.Errorf("expected valid secret to pass, got error: %v", err)
	}

	// Wrong secret should fail
	if err := ValidateAdminSecret("wrong"); err == nil {
		t.Error("expected invalid secret to fail")
	}

	// Empty secret should fail
	if err := ValidateAdminSecret(""); err == nil {
		t.Error("expected empty secret to fail")
	}
}
