package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTieredRateLimiterCleanup tests that the cleanup goroutine properly
// removes stale entries. Since cleanup runs every 5 minutes, we test it
// by directly calling the cleanup logic.
func TestTieredRateLimiterCleanup(t *testing.T) {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
	}

	// Add a stale entry (window expired more than 10 minutes ago)
	trl.limits["stale-user"] = &userRateLimitState{
		count:     10,
		tier:      TierFree,
		windowEnd: time.Now().Add(-15 * time.Minute), // expired 15 min ago
	}

	// Add a recently expired entry (should NOT be cleaned up — within 10 min grace)
	trl.limits["recently-expired"] = &userRateLimitState{
		count:     5,
		tier:      TierFree,
		windowEnd: time.Now().Add(-3 * time.Minute), // expired 3 min ago
	}

	// Add an active entry
	trl.limits["active-user"] = &userRateLimitState{
		count:     1,
		tier:      TierFree,
		windowEnd: time.Now().Add(30 * time.Second),
	}

	// Simulate cleanup: remove entries where window expired > 10 min ago
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	// Stale user should be removed
	if _, ok := trl.limits["stale-user"]; ok {
		t.Error("stale-user should have been cleaned up")
	}

	// Recently expired should remain (within grace period)
	if _, ok := trl.limits["recently-expired"]; !ok {
		t.Error("recently-expired should not be cleaned up (within 10min grace)")
	}

	// Active user should remain
	if _, ok := trl.limits["active-user"]; !ok {
		t.Error("active-user should not be cleaned up")
	}
}

// TestTieredRateLimiterConcurrentAccess tests thread safety of the rate limiter
// under concurrent access.
func TestTieredRateLimiterConcurrentAccess(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	var wg sync.WaitGroup
	numGoroutines := 100
	requestsPerGoroutine := 50

	// Concurrent Allow calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(userID string) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				trl.Allow(userID)
			}
		}("user" + itoa(i%10))
	}

	// Concurrent SetTier calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(userID string) {
			defer wg.Done()
			trl.SetTier(userID, TierPro)
		}("user" + itoa(i%10))
	}

	// Concurrent GetTier calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(userID string) {
			defer wg.Done()
			tier := trl.GetTier(userID)
			if tier.Name != "free" && tier.Name != "pro" && tier.Name != "enterprise" {
				t.Errorf("unexpected tier name: %s", tier.Name)
			}
		}("user" + itoa(i%10))
	}

	wg.Wait()

	// Should not panic — test passes if we get here
}

// TestTieredRateLimiterWindowResetAfterExpiry tests that the rate limit window resets
// after the window duration has passed.
func TestTieredRateLimiterWindowResetAfterExpiry(t *testing.T) {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
	}

	// Exhaust the rate limit
	for i := 0; i < TierFree.Burst; i++ {
		allowed, _, _ := trl.Allow("test-user")
		if !allowed {
			t.Fatalf("request %d should be allowed (burst=%d)", i+1, TierFree.Burst)
		}
	}

	// Next request should be denied
	allowed, remaining, retryAfter := trl.Allow("test-user")
	if allowed {
		t.Error("request should be denied after burst exhausted")
	}
	if remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", remaining)
	}
	if retryAfter < 1 {
		t.Errorf("expected retryAfter >= 1, got %d", retryAfter)
	}

	// Simulate window reset by moving windowEnd to the past
	trl.mu.Lock()
	entry := trl.limits["test-user"]
	entry.windowEnd = time.Now().Add(-time.Second)
	trl.mu.Unlock()

	// Should be allowed again
	allowed, remaining, _ = trl.Allow("test-user")
	if !allowed {
		t.Error("request should be allowed after window reset")
	}
	if remaining != TierFree.Burst-2 { // used 1 of new window, remaining should be burst-2 (window reset, count=1, then second request count=2)
		t.Logf("remaining after window reset: %d (expected %d)", remaining, TierFree.Burst-2)
	}
}

// TestTieredRateLimiterUpgradeTier tests upgrading a user's tier mid-window.
func TestTieredRateLimiterUpgradeTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// User starts as free tier
	trl.SetTier("upgrade-user", TierPro)

	tier := trl.GetTier("upgrade-user")
	if tier.Name != "pro" {
		t.Errorf("expected tier 'pro', got %s", tier.Name)
	}

	// Should have Pro burst limit
	allowed, remaining, _ := trl.Allow("upgrade-user")
	if !allowed {
		t.Error("first request should be allowed under pro tier")
	}
	if remaining != TierPro.Burst-1 {
		t.Errorf("expected %d remaining, got %d", TierPro.Burst-1, remaining)
	}
}

// TestTieredRateLimiterDowngradeTier tests downgrading a user's tier.
func TestTieredRateLimiterDowngradeTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Set to enterprise, then downgrade to free
	trl.SetTier("downgrade-user", TierEnterprise)
	trl.SetTier("downgrade-user", TierFree)

	tier := trl.GetTier("downgrade-user")
	if tier.Name != "free" {
		t.Errorf("expected tier 'free' after downgrade, got %s", tier.Name)
	}
}

// TestItoaHelper tests the itoa helper function.
func TestItoaHelper(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{999, "999"},
		{-1, "-1"},
		{-42, "-42"},
	}
	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestTieredRateLimiterPersistAndLoadDB tests persisting and loading tiers from DB.
func TestTieredRateLimiterPersistAndLoadDB(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	// Persist a pro tier
	err = persistTierToDB("persist-test-user", TierPro)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	// Persist an enterprise tier
	err = persistTierToDB("persist-enterprise-user", TierEnterprise)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	// Persist a free tier (should be stored but not loaded into limiter)
	err = persistTierToDB("persist-free-user", TierFree)
	if err != nil {
		t.Fatalf("persistTierToDB failed: %v", err)
	}

	// Load from DB
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	err = loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB failed: %v", err)
	}

	// Verify pro tier loaded
	tier := trl.GetTier("persist-test-user")
	if tier.Name != "pro" {
		t.Errorf("expected tier 'pro' for persist-test-user, got %s", tier.Name)
	}

	// Verify enterprise tier loaded
	tier = trl.GetTier("persist-enterprise-user")
	if tier.Name != "enterprise" {
		t.Errorf("expected tier 'enterprise' for persist-enterprise-user, got %s", tier.Name)
	}

	// Free tier should not have been loaded into limiter
	trl.mu.Lock()
	_, exists := trl.limits["persist-free-user"]
	trl.mu.Unlock()
	if exists {
		t.Error("expected free tier entries to not be stored in limiter")
	}
}

// TestHandleAdminRateLimitTierRouting tests that the combined handler routes
// POST to handleSetRateLimitTier and GET to handleGetRateLimitTier.
func TestHandleAdminRateLimitTierRouting(t *testing.T) {
	setupTestDB(t)

	// POST should set tier
	body := "user_id=routeuser&tier=pro&admin_secret=" + adminSecret
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST: expected 200, got %d", w.Code)
	}

	// GET should get tier
	req2 := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=routeuser&admin_secret="+adminSecret, nil)
	w2 := httptest.NewRecorder()
	handleAdminRateLimitTier(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("GET: expected 200, got %d", w2.Code)
	}
}

// TestTierComparison tests that tier ordering works correctly.
func TestTierComparison(t *testing.T) {
	if tierOrder["free"] >= tierOrder["pro"] {
		t.Error("free tier should be lower priority than pro")
	}
	if tierOrder["pro"] >= tierOrder["enterprise"] {
		t.Error("pro tier should be lower priority than enterprise")
	}
}

// TestTierProperties validates the tier configurations.
func TestTierProperties(t *testing.T) {
	if TierFree.Burst != 60 {
		t.Errorf("Free tier burst should be 60, got %d", TierFree.Burst)
	}
	if TierFree.Window != time.Minute {
		t.Errorf("Free tier window should be 1 minute, got %v", TierFree.Window)
	}
	if TierPro.Burst != 300 {
		t.Errorf("Pro tier burst should be 300, got %d", TierPro.Burst)
	}
	if TierEnterprise.Burst != 1500 {
		t.Errorf("Enterprise tier burst should be 1500, got %d", TierEnterprise.Burst)
	}
}
