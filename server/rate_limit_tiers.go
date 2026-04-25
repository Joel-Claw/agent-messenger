package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// RateLimitTier defines rate limits per plan/tier
type RateLimitTier struct {
	Name      string        `json:"name"`
	Burst     int           `json:"burst"`      // max requests in window
	Window    time.Duration `json:"window"`     // time window
	PerSecond float64       `json:"per_second"` // sustained rate
}

// Predefined tiers
var (
	TierFree = RateLimitTier{
		Name:      "free",
		Burst:     60,
		Window:    time.Minute,
		PerSecond: 1,
	}
	TierPro = RateLimitTier{
		Name:      "pro",
		Burst:     300,
		Window:    time.Minute,
		PerSecond: 5,
	}
	TierEnterprise = RateLimitTier{
		Name:      "enterprise",
		Burst:     1500,
		Window:    time.Minute,
		PerSecond: 25,
	}
)

// tierOrder defines the priority order (lower = more restrictive)
var tierOrder = map[string]int{
	"free":       0,
	"pro":        1,
	"enterprise": 2,
}

// userRateLimitState tracks per-user rate limit state for API tiers
type userRateLimitState struct {
	count     int
	windowEnd time.Time
	tier      RateLimitTier
}

// TieredRateLimiter manages per-user rate limiting with tier support
// for HTTP API endpoints (separate from WebSocket rate limiting).
type TieredRateLimiter struct {
	mu     sync.Mutex
	limits map[string]*userRateLimitState
}

// NewTieredRateLimiter creates a new tiered rate limiter
func NewTieredRateLimiter() *TieredRateLimiter {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
	}
	go trl.cleanup()
	return trl
}

// Allow checks if a request from the given user is allowed under their tier.
// Returns (allowed bool, remaining int, retryAfterSec int).
func (trl *TieredRateLimiter) Allow(userID string) (bool, int, int) {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	now := time.Now()
	entry, ok := trl.limits[userID]
	if !ok {
		entry = &userRateLimitState{
			tier:      TierFree,
			windowEnd: now.Add(TierFree.Window),
		}
		trl.limits[userID] = entry
	}

	// Reset window if expired
	if now.After(entry.windowEnd) {
		entry.count = 0
		entry.windowEnd = now.Add(entry.tier.Window)
	}

	entry.count++
	remaining := entry.tier.Burst - entry.count
	if remaining < 0 {
		remaining = 0
	}

	if entry.count > entry.tier.Burst {
		// Calculate seconds until window resets
		retryAfter := int(entry.windowEnd.Sub(now).Seconds()) + 1
		if retryAfter < 1 {
			retryAfter = 1
		}
		if ServerMetrics != nil {
			ServerMetrics.RateLimited.Add(1)
		}
		return false, 0, retryAfter
	}

	return true, remaining, 0
}

// SetTier sets the rate limit tier for a user
func (trl *TieredRateLimiter) SetTier(userID string, tier RateLimitTier) {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	if entry, ok := trl.limits[userID]; ok {
		entry.tier = tier
		// Reset window with new tier's window duration
		entry.count = 0
		entry.windowEnd = time.Now().Add(tier.Window)
	} else {
		trl.limits[userID] = &userRateLimitState{
			tier:      tier,
			count:     0,
			windowEnd: time.Now().Add(tier.Window),
		}
	}
}

// GetTier returns the tier for a user (defaults to Free)
func (trl *TieredRateLimiter) GetTier(userID string) RateLimitTier {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	if entry, ok := trl.limits[userID]; ok {
		return entry.tier
	}
	return TierFree
}

// GetRemaining returns the remaining requests for a user in the current window
func (trl *TieredRateLimiter) GetRemaining(userID string) int {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	entry, ok := trl.limits[userID]
	if !ok {
		return TierFree.Burst
	}
	if time.Now().After(entry.windowEnd) {
		return entry.tier.Burst
	}
	remaining := entry.tier.Burst - entry.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// cleanup removes stale entries periodically
func (trl *TieredRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		trl.mu.Lock()
		now := time.Now()
		for id, entry := range trl.limits {
			if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
				delete(trl.limits, id)
			}
		}
		trl.mu.Unlock()
	}
}

// globalTieredLimiter is the main tiered rate limiter instance for HTTP API
var globalTieredLimiter = NewTieredRateLimiter()

// tieredRateLimitMiddleware is HTTP middleware that enforces per-user tiered rate limits.
// It sets X-RateLimit-* headers on responses.
func tieredRateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract user ID from JWT if present
		var userID string
		token := r.Header.Get("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
			if claims, err := ValidateJWT(token); err == nil {
				userID = claims.UserID
			}
		}

		// If no user ID, use IP-based limiting
		if userID == "" {
			userID = "ip:" + r.RemoteAddr
		}

		allowed, remaining, retryAfter := globalTieredLimiter.Allow(userID)
		tier := globalTieredLimiter.GetTier(userID)

		// Always set rate limit headers
		w.Header().Set("X-RateLimit-Limit", itoa(tier.Burst))
		w.Header().Set("X-RateLimit-Remaining", itoa(remaining))

		if !allowed {
			w.Header().Set("Retry-After", itoa(retryAfter))
			w.Header().Set("X-RateLimit-Remaining", "0")
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			log.Printf("Tiered rate limit: %s (tier: %s)", userID, tier.Name)
			return
		}

		next(w, r)
	}
}

// loadTiersFromDB loads user rate limit tiers from the database into the in-memory limiter.
// Called on startup to restore previously set tiers.
func loadTiersFromDB(trl *TieredRateLimiter) error {
	if db == nil {
		return nil
	}
	rows, err := db.Query("SELECT user_id, tier_name FROM user_rate_limit_tiers")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, tierName string
		if err := rows.Scan(&userID, &tierName); err != nil {
			continue
		}
		var tier RateLimitTier
		switch tierName {
		case "pro":
			tier = TierPro
		case "enterprise":
			tier = TierEnterprise
			default:
			tier = TierFree
		}
		if tier.Name != "free" {
			trl.SetTier(userID, tier)
		}
	}
	return rows.Err()
}

// persistTierToDB saves a user's tier to the database for durability across restarts.
func persistTierToDB(userID string, tier RateLimitTier) error {
	if db == nil {
		return nil
	}
	if currentDriver == DriverPostgreSQL {
		_, err := db.Exec(`
			INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) 
			VALUES ($1, $2, NOW()) 
			ON CONFLICT (user_id) DO UPDATE SET tier_name = $2, updated_at = NOW()`,
			userID, tier.Name)
		return err
	}
	_, err := db.Exec(`
		INSERT OR REPLACE INTO user_rate_limit_tiers (user_id, tier_name, updated_at) 
		VALUES (?, ?, datetime('now'))`,
		userID, tier.Name)
	return err
}

// handleSetRateLimitTier handles POST /admin/rate-limit/tier
// Sets the rate limit tier for a user. Requires admin secret.
func handleSetRateLimitTier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	adminSecret := r.Header.Get("X-Admin-Secret")
	if adminSecret == "" {
		adminSecret = r.FormValue("admin_secret")
	}
	if adminSecret != getEnvOrDefault("ADMIN_SECRET", "admin-dev-secret") {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	userID := r.FormValue("user_id")
	tierName := r.FormValue("tier")
	if userID == "" || tierName == "" {
		writeJSONError(w, http.StatusBadRequest, "missing user_id or tier")
		return
	}

	var tier RateLimitTier
	switch tierName {
	case "free":
		tier = TierFree
	case "pro":
		tier = TierPro
	case "enterprise":
		tier = TierEnterprise
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown tier: "+tierName)
		return
	}

	globalTieredLimiter.SetTier(userID, tier)

	// Persist to DB for durability
	if err := persistTierToDB(userID, tier); err != nil {
		log.Printf("Warning: failed to persist rate limit tier for %s: %v", userID, err)
	}

	log.Printf("Rate limit tier set: %s -> %s", userID, tierName)

	writeJSONResponse(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"user_id": userID,
		"tier":    tierName,
	})
}

// handleGetRateLimitTier handles GET /admin/rate-limit/tier
// Gets the rate limit tier for a user. Requires admin secret.
func handleGetRateLimitTier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	adminSecret := r.Header.Get("X-Admin-Secret")
	if adminSecret == "" {
		adminSecret = r.URL.Query().Get("admin_secret")
	}
	if adminSecret != getEnvOrDefault("ADMIN_SECRET", "admin-dev-secret") {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing user_id")
		return
	}

	tier := globalTieredLimiter.GetTier(userID)
	remaining := globalTieredLimiter.GetRemaining(userID)

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"user_id":    userID,
		"tier":       tier.Name,
		"burst":      tier.Burst,
		"window_sec": int(tier.Window.Seconds()),
		"remaining":  remaining,
	})
}

// itoa converts int to string without importing strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// writeJSONResponse writes a JSON response with the given status code
func writeJSONResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

