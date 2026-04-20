package main

import (
	"database/sql"
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// JWT signing key - in production this should come from config/env
var jwtSecret = []byte("agent-messenger-dev-secret-change-me")

// Claims represents JWT claims for user authentication
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// ValidateAPIKey checks the provided plaintext API key against the bcrypt hash stored in the agents table.
// Returns the agent's database ID on success, or an error on failure.
func ValidateAPIKey(agentID string, apiKey string) error {
	if apiKey == "" {
		return errors.New("empty API key")
	}

	var hash string
	err := db.QueryRow("SELECT api_key_hash FROM agents WHERE id = ?", agentID).Scan(&hash)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Auth failed: unknown agent %s", agentID)
			return errors.New("unknown agent")
		}
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(apiKey)); err != nil {
		log.Printf("Auth failed: invalid API key for agent %s", agentID)
		return errors.New("invalid API key")
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