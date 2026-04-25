package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTieredRateLimiterAllow(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Default (free tier): 60 req/min
	for i := 0; i < 60; i++ {
		allowed, _, _ := trl.Allow("user1")
		if !allowed {
			t.Fatalf("Request %d should be allowed under free tier", i+1)
		}
	}

	// 61st should be denied
	allowed, remaining, retryAfter := trl.Allow("user1")
	if allowed {
		t.Error("Expected 61st request to be rate limited")
	}
	if remaining != 0 {
		t.Errorf("Expected remaining=0, got %d", remaining)
	}
	if retryAfter < 1 {
		t.Errorf("Expected retryAfter >= 1, got %d", retryAfter)
	}

	// Different user should be independent
	allowed2, _, _ := trl.Allow("user2")
	if !allowed2 {
		t.Error("Different user should not be rate limited")
	}
}

func TestTieredRateLimiterSetTier(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Set pro tier (300 req/min)
	trl.SetTier("user1", TierPro)

	// Should allow up to 300 requests
	for i := 0; i < 300; i++ {
		allowed, _, _ := trl.Allow("user1")
		if !allowed {
			t.Fatalf("Request %d should be allowed under pro tier", i+1)
		}
	}

	// 301st should be denied
	allowed, _, _ := trl.Allow("user1")
	if allowed {
		t.Error("Expected 301st request to be rate limited under pro tier")
	}
}

func TestTieredRateLimiterEnterpriseTier(t *testing.T) {
	trl := NewTieredRateLimiter()

	trl.SetTier("bigcorp", TierEnterprise)

	// Should allow up to 1500 requests
	for i := 0; i < 1500; i++ {
		allowed, _, _ := trl.Allow("bigcorp")
		if !allowed {
			t.Fatalf("Request %d should be allowed under enterprise tier", i+1)
		}
	}

	allowed, _, _ := trl.Allow("bigcorp")
	if allowed {
		t.Error("Expected 1501st request to be rate limited under enterprise tier")
	}
}

func TestTieredRateLimiterGetTier(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Default is free
	tier := trl.GetTier("user1")
	if tier.Name != "free" {
		t.Errorf("Expected free tier, got %s", tier.Name)
	}

	trl.SetTier("user1", TierPro)
	tier = trl.GetTier("user1")
	if tier.Name != "pro" {
		t.Errorf("Expected pro tier, got %s", tier.Name)
	}
}

func TestTieredRateLimiterGetRemaining(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Initially full
	remaining := trl.GetRemaining("user1")
	if remaining != TierFree.Burst {
		t.Errorf("Expected %d remaining, got %d", TierFree.Burst, remaining)
	}

	// After 10 requests
	for i := 0; i < 10; i++ {
		trl.Allow("user1")
	}
	remaining = trl.GetRemaining("user1")
	if remaining != TierFree.Burst-10 {
		t.Errorf("Expected %d remaining, got %d", TierFree.Burst-10, remaining)
	}
}

func TestTieredRateLimiterWindowReset(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("user1", RateLimitTier{
		Name:   "test",
		Burst:  5,
		Window: 100 * time.Millisecond,
	})

	// Exhaust the limit
	for i := 0; i < 5; i++ {
		trl.Allow("user1")
	}
	allowed, _, _ := trl.Allow("user1")
	if allowed {
		t.Error("Should be rate limited after 5 requests")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	allowed, _, _ = trl.Allow("user1")
	if !allowed {
		t.Error("Should be allowed after window reset")
	}
}

func TestHandleSetRateLimitTier(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Set tier for a user
	form := url.Values{
		"user_id": {"usr_testuser"},
		"tier":    {"pro"},
	}
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["tier"] != "pro" {
		t.Errorf("Expected tier=pro, got %s", resp["tier"])
	}

	// Verify the tier was actually set
	tier := globalTieredLimiter.GetTier("usr_testuser")
	if tier.Name != "pro" {
		t.Errorf("Expected pro tier, got %s", tier.Name)
	}

	// Clean up
	globalTieredLimiter.SetTier("usr_testuser", TierFree)
}

func TestHandleSetRateLimitTierUnauthorized(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	form := url.Values{
		"user_id": {"usr_testuser"},
		"tier":    {"pro"},
	}
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestHandleSetRateLimitTierUnknownTier(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	form := url.Values{
		"user_id": {"usr_testuser"},
		"tier":    {"ultra"},
	}
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for unknown tier, got %d", w.Code)
	}
}

func TestHandleGetRateLimitTier(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Set a tier first
	globalTieredLimiter.SetTier("usr_gettest", TierEnterprise)

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=usr_gettest&admin_secret=admin-dev-secret", nil)
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["tier"] != "enterprise" {
		t.Errorf("Expected tier=enterprise, got %v", resp["tier"])
	}

	// Clean up
	globalTieredLimiter.SetTier("usr_gettest", TierFree)
}

func TestHandleGetRateLimitTierMissingUserID(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?admin_secret=admin-dev-secret", nil)
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestTieredRateLimitMiddleware(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Create a simple handler that returns 200
	innerHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}

	wrapped := tieredRateLimitMiddleware(innerHandler)

	// Create a user with a very low limit for testing
	token := registerUserAndGetToken(t, "midtest", "pass123")
	userID := getUserIDFromToken(t, token)

	globalTieredLimiter.SetTier(userID, RateLimitTier{
		Name:   "test",
		Burst:  3,
		Window: time.Minute,
	})
	defer globalTieredLimiter.SetTier(userID, TierFree)

	// Make 3 requests (should all succeed)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		wrapped(w, req)
		if w.Code != 200 {
			t.Errorf("Request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 4th should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	wrapped(w, req)
	if w.Code != 429 {
		t.Errorf("Expected 429 on 4th request, got %d", w.Code)
	}

	// Check rate limit headers
	if w.Header().Get("X-RateLimit-Limit") != "3" {
		t.Errorf("Expected X-RateLimit-Limit=3, got %s", w.Header().Get("X-RateLimit-Limit"))
	}
	if w.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("Expected X-RateLimit-Remaining=0, got %s", w.Header().Get("X-RateLimit-Remaining"))
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("Expected Retry-After header to be set")
	}
}

func TestTieredRateLimitMiddlewareNoAuth(t *testing.T) {
	// Without auth, should use IP-based limiting
	innerHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}
	wrapped := tieredRateLimitMiddleware(innerHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	w := httptest.NewRecorder()
	wrapped(w, req)

	// Should succeed (first request from this IP)
	if w.Code != 200 {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Should have rate limit headers
	if w.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("Expected X-RateLimit-Limit header")
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-1, "-1"},
		{-99, "-99"},
	}
	for _, tc := range tests {
		result := itoa(tc.input)
		if result != tc.expected {
			t.Errorf("itoa(%d) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestPersistTierToDB(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Persist a pro tier
	err := persistTierToDB("usr_persist_test", TierPro)
	if err != nil {
		t.Fatalf("Failed to persist tier: %v", err)
	}

	// Verify it's in the DB
	var tierName string
	db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "usr_persist_test").Scan(&tierName)
	if tierName != "pro" {
		t.Errorf("Expected tier_name=pro, got %s", tierName)
	}

	// Update to enterprise
	persistTierToDB("usr_persist_test", TierEnterprise)
	db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "usr_persist_test").Scan(&tierName)
	if tierName != "enterprise" {
		t.Errorf("Expected tier_name=enterprise after update, got %s", tierName)
	}
}

func TestLoadTiersFromDB(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()

	// Insert some tiers directly into DB
	persistTierToDB("usr_load1", TierPro)
	persistTierToDB("usr_load2", TierEnterprise)

	// Create a fresh limiter and load from DB
	trl := NewTieredRateLimiter()
	if err := loadTiersFromDB(trl); err != nil {
		t.Fatalf("Failed to load tiers: %v", err)
	}

	// Verify they loaded
	if trl.GetTier("usr_load1").Name != "pro" {
		t.Errorf("Expected pro for usr_load1, got %s", trl.GetTier("usr_load1").Name)
	}
	if trl.GetTier("usr_load2").Name != "enterprise" {
		t.Errorf("Expected enterprise for usr_load2, got %s", trl.GetTier("usr_load2").Name)
	}

	// Users not in DB should default to free
	if trl.GetTier("usr_unknown").Name != "free" {
		t.Errorf("Expected free for unknown user, got %s", trl.GetTier("usr_unknown").Name)
	}
}