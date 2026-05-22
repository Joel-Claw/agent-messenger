package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// Tests for IP rate limiting middleware (0% coverage)
// ============================================================

func TestIPRateLimitMiddlewareAllowsRequests(t *testing.T) {
	saved := ipRateLimiter
	ipRateLimiter = NewRateLimiter(10, time.Minute)
	defer func() { ipRateLimiter = saved }()

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:1234"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestIPRateLimitMiddlewareBlocksExcess(t *testing.T) {
	// Create a test handler that uses ipRateLimiter directly
	saved := ipRateLimiter
	ipRateLimiter = NewRateLimiter(5, time.Minute)
	defer func() { ipRateLimiter = saved }()

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:8080"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 6th should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:8080"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

func TestIPRateLimitMiddlewareDifferentIPs(t *testing.T) {
	saved := ipRateLimiter
	ipRateLimiter = NewRateLimiter(3, time.Minute)
	defer func() { ipRateLimiter = saved }()

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// IP 1 makes 3 requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.1.1.1:8080"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("IP1 request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// IP 2 should still be allowed
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "2.2.2.2:8080"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("IP2 request: expected 200, got %d", w.Code)
	}
}

func TestAuthRateLimitMiddlewareBlocksExcess(t *testing.T) {
	saved := authIPLimiter
	authIPLimiter = NewRateLimiter(3, time.Minute)
	defer func() { authIPLimiter = saved }()

	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/auth/login", nil)
		req.RemoteAddr = "5.5.5.5:8080"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "5.5.5.5:8080"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "auth") {
		t.Errorf("expected auth-related error, got %q", resp["error"])
	}
}

func TestInitAuthRateLimitCustom(t *testing.T) {
	os.Setenv("AUTH_RATE_LIMIT", "50")
	initAuthRateLimit()
	// authIPLimiter should now have limit 50
	if !authIPLimiter.Allow("test-init-auth-key") {
		t.Error("should allow within limit")
	}
	os.Unsetenv("AUTH_RATE_LIMIT")
	// Reset for other tests
	authIPLimiter = NewRateLimiter(30, time.Minute)
}

func TestInitAuthRateLimitInvalid(t *testing.T) {
	os.Setenv("AUTH_RATE_LIMIT", "notanumber")
	initAuthRateLimit()
	// Should default to 30
	if !authIPLimiter.Allow("test-init-auth-invalid-key") {
		t.Error("should allow within default limit")
	}
	os.Unsetenv("AUTH_RATE_LIMIT")
	authIPLimiter = NewRateLimiter(30, time.Minute)
}

func TestAdminAuthMiddlewareWithHeader(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = origSecret }()

	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called with valid secret")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminAuthMiddlewareWithFormValue(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "form-secret"
	defer func() { adminSecret = origSecret }()

	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/admin/test", nil)
	req.Form = url.Values{"admin_secret": {"form-secret"}}
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called with form value secret")
	}
}

func TestAdminAuthMiddlewareWithQueryParam(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "query-secret"
	defer func() { adminSecret = origSecret }()

	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/test?admin_secret=query-secret", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called with query param secret")
	}
}

func TestAdminAuthMiddlewareUnauthorized(t *testing.T) {
	origSecret := adminSecret
	adminSecret = "real-secret"
	defer func() { adminSecret = origSecret }()

	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// No secret
	req := httptest.NewRequest("GET", "/admin/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if called {
		t.Error("handler should not be called without secret")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	// Wrong secret
	req = httptest.NewRequest("GET", "/admin/test", nil)
	req.Header.Set("X-Admin-Secret", "wrong-secret")
	w = httptest.NewRecorder()
	handler(w, req)
	if called {
		t.Error("handler should not be called with wrong secret")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddlewareValidJWT(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "authmwuser")

	called := false
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		userID, err := getUserID(r)
		if err != nil {
			t.Errorf("getUserID error: %v", err)
		}
		if userID == "" {
			t.Error("expected non-empty user ID")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called with valid JWT")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuthMiddlewareNoToken(t *testing.T) {
	called := false
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("handler should not be called without token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	called := false
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-here")
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("handler should not be called with invalid token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ============================================================
// Tests for admin rate limit tier handler (0% coverage)
// ============================================================

func TestHandleAdminRateLimitTierPost(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	form := url.Values{
		"user_id":      {"testuser1"},
		"tier":         {"pro"},
		"admin_secret": {"admin-test-secret"},
	}
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %q", resp["status"])
	}
	if resp["tier"] != "pro" {
		t.Errorf("expected tier pro, got %q", resp["tier"])
	}
}

func TestHandleAdminRateLimitTierGet(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	// Set tier first
	globalTieredLimiter.SetTier("testuser2", TierPro)

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=testuser2&admin_secret=admin-test-secret", nil)
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["tier"] != "pro" {
		t.Errorf("expected tier pro, got %v", resp["tier"])
	}
}

func TestHandleAdminRateLimitTierUnauthorized(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", nil)
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleSetRateLimitTierEnterprise(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	form := url.Values{
		"user_id":      {"entuser1"},
		"tier":         {"enterprise"},
		"admin_secret": {"admin-test-secret"},
	}
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify tier was actually set
	tier := globalTieredLimiter.GetTier("entuser1")
	if tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier, got %s", tier.Name)
	}
}

func TestHandleSetRateLimitTierUnknownTierAdmin(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	form := url.Values{
		"user_id":      {"unknowntier"},
		"tier":         {"platinum"},
		"admin_secret": {"admin-test-secret"},
	}
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSetRateLimitTierMissingFields(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	// Missing tier
	form := url.Values{
		"user_id":      {"someuser"},
		"admin_secret": {"admin-test-secret"},
	}
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing tier, got %d", w.Code)
	}

	// Missing user_id
	form = url.Values{
		"tier":         {"pro"},
		"admin_secret": {"admin-test-secret"},
	}
	req = httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing user_id, got %d", w.Code)
	}
}

func TestHandleGetRateLimitTierMissingUserIDAdmin(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?admin_secret=admin-test-secret", nil)
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing user_id, got %d", w.Code)
	}
}

func TestHandleGetRateLimitTierDefaultFree(t *testing.T) {
	setupTestDB(t)
	origSecret := adminSecret
	adminSecret = "admin-test-secret"
	defer func() { adminSecret = origSecret }()

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=unknownuser999&admin_secret=admin-test-secret", nil)
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["tier"] != "free" {
		t.Errorf("expected free tier for unknown user, got %v", resp["tier"])
	}
}

func TestHandleGetRateLimitTierWrongMethod(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/admin/rate-limit/tier", nil)
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ============================================================
// Tests for notification preferences (improve coverage)
// ============================================================

func TestGetNotificationPrefsUnauthorized(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("GET", "/notification-prefs", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestSetNotificationPrefsUnauthorized(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("POST", "/notification-prefs/set", nil)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestSetNotificationPrefsConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "notifnotfound")

	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {"nonexistent-conv-id"},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteNotificationPrefsUnauthorized(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("POST", "/notification-prefs/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestDeleteNotificationPrefsMissingID(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "notifdeluser")

	req := authPostReq("/notification-prefs/delete", token, url.Values{})
	w := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSetNotificationPrefsUpdateExisting(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "notifupdateuser")
	createTestAgentInDB(t, "notifupdateagent", "Update Bot")
	convID := createTestConversationInDB(t, token, "notifupdateagent")

	// Set muted = true
	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Update to muted = false
	req2 := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"false"},
	})
	w2 := httptest.NewRecorder()
	handleSetNotificationPrefs(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var pref NotificationPreferences
	json.Unmarshal(w2.Body.Bytes(), &pref)
	if pref.Muted {
		t.Error("expected muted=false after update")
	}
}

func TestGetNotificationPrefsMultipleConversations(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "notifmultiuser")
	createTestAgentInDB(t, "notifmultiagent1", "Multi Bot 1")
	createTestAgentInDB(t, "notifmultiagent2", "Multi Bot 2")
	convID1 := createTestConversationInDB(t, token, "notifmultiagent1")
	convID2 := createTestConversationInDB(t, token, "notifmultiagent2")

	// Mute both
	for _, convID := range []string{convID1, convID2} {
		req := authPostReq("/notification-prefs/set", token, url.Values{
			"conversation_id": {convID},
			"muted":           {"true"},
		})
		w := httptest.NewRecorder()
		handleSetNotificationPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	}

	// Get all prefs
	req := authGetReq("/notification-prefs", token)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	var prefs []NotificationPreferences
	json.Unmarshal(w.Body.Bytes(), &prefs)
	if len(prefs) != 2 {
		t.Errorf("expected 2 prefs, got %d", len(prefs))
	}
}

// ============================================================
// Tests for tracing functions (50% coverage)
// ============================================================

func TestTracingEnabledWithHTTPEndpoint(t *testing.T) {
	// Test that InitTracing handles HTTP protocol without crashing
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")

	tracingMu = sync.Once{}
	tracingEnabled = false
	tp = nil
	tracer = nil

	// This will fail to connect (no collector) but shouldn't panic
	err := InitTracing()
	// It might error or succeed depending on OTel behavior
	// The important thing is no panic
	_ = err

	// Clean up
	if tracingEnabled && tp != nil {
		ShutdownTracing()
	}

	os.Unsetenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	tracingMu = sync.Once{}
	tracingEnabled = false
	tp = nil
	tracer = nil
}

func TestTracingShutdownNoop(t *testing.T) {
	// ShutdownTracing should not panic when tracing is not enabled
	tracingEnabled = false
	tp = nil
	tracer = nil
	ShutdownTracing()
}

func TestStartSpanWithNilContext(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	ctx, span := StartSpan(nil, "test")
	if ctx != nil {
		t.Error("expected nil context when tracing disabled")
	}
	if span == nil {
		t.Error("expected non-nil no-op span")
	}
	span.End()
}

func TestStartSpanWithBackgroundContext(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	ctx, span := StartSpan(context.Background(), "test")
	// When tracing is disabled, should still get a no-op span
	if span == nil {
		t.Error("expected non-nil span")
	}
	span.End()
	_ = ctx
}

func TestSpanErrorAndOK(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	span := TraceRouteMessage("agent", "test-agent")
	// These should not panic even when tracing is disabled
	SpanError(span, os.ErrNotExist)
	SpanOK(span)
}

// ============================================================
// Tests for isConversationMuted edge cases
// ============================================================

func TestIsConversationMutedNonexistentConversation(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "mutenonexistuser")
	claims, _ := ValidateJWT(token)

	// Should return false for nonexistent conversation
	if isConversationMuted(claims.UserID, "nonexistent-conv") {
		t.Error("expected not muted for nonexistent conversation")
	}
}

func TestIsConversationMutedOtherUser(t *testing.T) {
	setupTestDB(t)
	token1 := createTestUserInDB(t, "muteowner2")
	token2 := createTestUserInDB(t, "muteother2")
	claims1, _ := ValidateJWT(token1)
	createTestAgentInDB(t, "muteagent1", "Mute Bot")
	convID := createTestConversationInDB(t, token1, "muteagent1")

	// Mute for user1
	req := authPostReq("/notification-prefs/set", token1, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Other user should not see it as muted
	claims2, _ := ValidateJWT(token2)
	if isConversationMuted(claims2.UserID, convID) {
		t.Error("other user should not see muted state")
	}

	// Owner should see it as muted
	if !isConversationMuted(claims1.UserID, convID) {
		t.Error("owner should see muted state")
	}
	_ = claims2
}

// ============================================================
// Tests for tieredRateLimitMiddleware
// ============================================================

func TestTieredRateLimitMiddlewareAuthenticated(t *testing.T) {
	setupTestDB(t)
	token := createTestUserInDB(t, "rluser")

	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Check rate limit headers
	if w.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("expected X-RateLimit-Limit header")
	}
	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("expected X-RateLimit-Remaining header")
	}
}

func TestTieredRateLimitMiddlewareUnauthenticated(t *testing.T) {
	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/conversations", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should have been called for unauthenticated request")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ============================================================
// Tests for loadTiersFromDB and persistTierToDB
// ============================================================

func TestLoadTiersFromDBEmpty(t *testing.T) {
	setupTestDB(t)

	limiter := NewTieredRateLimiter()
	err := loadTiersFromDB(limiter)
	if err != nil {
		t.Errorf("loadTiersFromDB failed: %v", err)
	}
}

func TestPersistAndLoadTiers(t *testing.T) {
	setupTestDB(t)

	// Persist a tier
	err := persistTierToDB("persist-user-1", TierPro)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	// Load from DB
	limiter := NewTieredRateLimiter()
	err = loadTiersFromDB(limiter)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	// Verify tier was loaded
	tier := limiter.GetTier("persist-user-1")
	if tier.Name != "pro" {
		t.Errorf("expected pro tier, got %s", tier.Name)
	}
}

func TestPersistEnterpriseAndLoadTiers(t *testing.T) {
	setupTestDB(t)

	err := persistTierToDB("persist-user-2", TierEnterprise)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	limiter := NewTieredRateLimiter()
	err = loadTiersFromDB(limiter)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	tier := limiter.GetTier("persist-user-2")
	if tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier, got %s", tier.Name)
	}
}

func TestPersistTierToDBNilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	err := persistTierToDB("nil-db-user", TierPro)
	if err != nil {
		t.Errorf("persistTierToDB should succeed with nil DB, got: %v", err)
	}
}

func TestLoadTiersFromDBNilDB(t *testing.T) {
	savedDB := db
	db = nil
	defer func() { db = savedDB }()

	limiter := NewTieredRateLimiter()
	err := loadTiersFromDB(limiter)
	if err != nil {
		t.Errorf("loadTiersFromDB should succeed with nil DB, got: %v", err)
	}
}

func TestLoadTiersFromDBIgnoresFree(t *testing.T) {
	setupTestDB(t)

	// Persist a free tier (should not be loaded as it's the default)
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		"free-user", "free")

	limiter := NewTieredRateLimiter()
	err := loadTiersFromDB(limiter)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	// Free tier should not be explicitly set (it's the default)
	tier := limiter.GetTier("free-user")
	if tier.Name != "free" {
		t.Errorf("expected free tier (default), got %s", tier.Name)
	}
}

// ============================================================
// Tests for writeJSONResponse and itoa
// ============================================================

// TestItoa already exists in rate_limit_tiers_test.go

func TestWriteJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type, got %s", w.Header().Get("Content-Type"))
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %q", resp["status"])
	}
}

// ============================================================
// Tests for CSRF middleware edge cases
// ============================================================

func TestCSRFMiddlewareAllowsGETRequests(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("CSRF middleware should allow GET requests")
	}
}

func TestCSRFMiddlewareAllowsPOSTWithXMLHttpRequest(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("CSRF middleware should allow POST with X-Requested-With header")
	}
}

func TestCSRFMiddlewareBlocksPOSTWithoutHeader(t *testing.T) {
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("CSRF middleware should block POST without required header")
	}
}

// ============================================================
// Tests for env helper functions
// ============================================================

// TestEnvIntOrDefault already exists in coverage_boost2_test.go

// TestEnvDurationOrDefault already exists in coverage_boost2_test.go

// ============================================================
// Helper functions for tests
// ============================================================

// createTestUserInDB creates a user in the database and returns their JWT token
func createTestUserInDB(t *testing.T, username string) string {
	t.Helper()
	form := "username=" + username + "&password=testpass123"
	req := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != 200 && w.Code != 409 {
		t.Fatalf("Failed to register user: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to login: %d %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp["token"].(string)
}

// createTestAgentInDB creates an agent in the database
func createTestAgentInDB(t *testing.T, agentID, name string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, name)
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
}

// createTestConversationInDB creates a conversation and returns its ID
func createTestConversationInDB(t *testing.T, token, agentID string) string {
	t.Helper()
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}

	conv, err := GetOrCreateConversation(claims.UserID, agentID)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	return conv.ID
}

// ipRateLimitMiddlewareWithLimiter creates an IP rate limit middleware with a custom limiter
func ipRateLimitMiddlewareWithLimiter(limiter *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	saved := ipRateLimiter
	ipRateLimiter = limiter
	defer func() { ipRateLimiter = saved }()

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

// authRateLimitMiddlewareWithLimiter creates an auth rate limit middleware with a custom limiter
func authRateLimitMiddlewareWithLimiter(limiter *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	saved := authIPLimiter
	authIPLimiter = limiter
	defer func() { authIPLimiter = saved }()

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
