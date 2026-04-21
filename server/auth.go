package main

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// JWT signing key - in production this should come from config/env
var jwtSecret = []byte("agent-messenger-dev-secret-change-me")

// AGENT_SECRET is the shared secret for agent authentication.
// Set via AGENT_SECRET env var. All agents authenticate with this secret.
// This replaces per-agent API keys - agents self-register on connect.
var agentSecret = getAgentSecret()

func getAgentSecret() string {
	s := os.Getenv("AGENT_SECRET")
	if s == "" {
		s = "dev-agent-secret-change-me"
		log.Println("WARNING: AGENT_SECRET not set, using dev default. Set AGENT_SECRET in production!")
	}
	return s
}

// Rate limiter for agent connections
var agentRateLimiter = &rateLimiter{
	attempts: make(map[string]*rateLimitEntry),
	mu:       sync.Mutex{},
}

type rateLimitEntry struct {
	count     int
	firstSeen time.Time
}

type rateLimiter struct {
	attempts map[string]*rateLimitEntry
	mu       sync.Mutex
}

const (
	// Max agent connection attempts per agent_id per window
	maxAgentAttempts = 10
	// Time window for rate limiting
	agentRateWindow = 1 * time.Minute
)

// Allow checks if a connection attempt from agentID is allowed.
// Returns false if rate limited.
func (r *rateLimiter) Allow(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.attempts[agentID]
	if !ok || time.Since(entry.firstSeen) > agentRateWindow {
		r.attempts[agentID] = &rateLimitEntry{count: 1, firstSeen: time.Now()}
		return true
	}

	if entry.count >= maxAgentAttempts {
		return false
	}

	entry.count++
	return true
}

// Clean removes expired entries. Call periodically.
func (r *rateLimiter) Clean() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, entry := range r.attempts {
		if time.Since(entry.firstSeen) > agentRateWindow {
			delete(r.attempts, id)
		}
	}
}

// Claims represents JWT claims for user authentication
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// ValidateAgentSecret checks the provided secret against the shared AGENT_SECRET.
// All agents authenticate with the same secret - they self-register with their agent_id on connect.
func ValidateAgentSecret(agentID string, secret string) error {
	if secret == "" {
		return errors.New("missing agent secret")
	}
	if !agentRateLimiter.Allow(agentID) {
		log.Printf("Rate limited: too many connection attempts from agent %s", agentID)
		return errors.New("rate limited: too many connection attempts")
	}
	if secret != agentSecret {
		log.Printf("Auth failed: invalid secret for agent %s", agentID)
		return errors.New("invalid agent secret")
	}
	return nil
}

// RegisterAgentOnConnect ensures an agent exists in the database when it connects.
// This is called after successful secret validation. If the agent doesn't exist,
// it's created with the provided metadata. If it already exists, only non-empty
// fields are updated (preserving previously set metadata).
func RegisterAgentOnConnect(agentID string, name string, model string, personality string, specialty string) error {
	if name == "" {
		name = agentID
	}

	// Check if agent already exists
	var existingName string
	err := db.QueryRow("SELECT name FROM agents WHERE id = ?", agentID).Scan(&existingName)
	if err == sql.ErrNoRows {
		// New agent - insert with all metadata
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			agentID, name, model, personality, specialty)
		return err
	}
	if err != nil {
		return err
	}

	// Existing agent - only update non-empty fields
	if model != "" {
		if _, err := db.Exec("UPDATE agents SET model = ? WHERE id = ?", model, agentID); err != nil {
			return err
		}
	}
	if personality != "" {
		if _, err := db.Exec("UPDATE agents SET personality = ? WHERE id = ?", personality, agentID); err != nil {
			return err
		}
	}
	if specialty != "" {
		if _, err := db.Exec("UPDATE agents SET specialty = ? WHERE id = ?", specialty, agentID); err != nil {
			return err
		}
	}
	// Always update name if provided (but not if it defaulted to agentID)
	if name != agentID {
		if _, err := db.Exec("UPDATE agents SET name = ? WHERE id = ?", name, agentID); err != nil {
			return err
		}
	}

	return nil
}

// ValidateJWT validates a JWT token and returns the parsed claims.
func ValidateJWT(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// GenerateJWT creates a new JWT for a given user. Used by login endpoint and tests.
func GenerateJWT(userID string, username string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "agent-messenger",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// HashAPIKey generates a bcrypt hash for an API key. Used to seed agent records.
func HashAPIKey(apiKey string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}