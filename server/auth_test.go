package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB initializes an in-memory DB for unit tests that need DB access
func setupTestDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
}

// setupTestServer initializes an in-memory DB, hub, and test HTTP server
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	setupTestDB(t)

	hub = newHub()
	go hub.run()

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)
	mux.HandleFunc("/auth/user", handleRegisterUser)

	server := httptest.NewServer(mux)
	t.Cleanup(func() { server.Close() })

	return server
}

// --- Unit tests for auth functions (no DB needed) ---

func TestHashAPIKey_RoundTrip(t *testing.T) {
	apiKey := "test-api-key-12345"
	hash, err := HashAPIKey(apiKey)
	if err != nil {
		t.Fatalf("HashAPIKey failed: %v", err)
	}
	if hash == apiKey {
		t.Fatal("hash should not equal plaintext")
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}

	// Verify bcrypt match
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(apiKey)); err != nil {
		t.Fatalf("hash should match original key: %v", err)
	}
	// Wrong key should not match
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-key")); err == nil {
		t.Fatal("hash should NOT match wrong key")
	}
}

func TestGenerateJWT_RoundTrip(t *testing.T) {
	userID := "user_123"
	email := "test@example.com"

	token, err := GenerateJWT(userID, email)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}
	if claims.UserID != userID {
		t.Fatalf("expected userID %s, got %s", userID, claims.UserID)
	}
	if claims.Email != email {
		t.Fatalf("expected email %s, got %s", email, claims.Email)
	}
}

func TestValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	_, err := ValidateJWT("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	claims := &Claims{
		UserID: "user-456",
		Email:  "evil@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "agent-messenger",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("wrong-secret"))

	_, err := ValidateJWT(tokenString)
	if err == nil {
		t.Fatal("expected error for token signed with wrong secret")
	}
}

// --- Unit tests for auth functions (DB needed) ---

func TestValidateAPIKey_EmptyKey(t *testing.T) {
	setupTestDB(t)
	err := ValidateAPIKey("test-agent", "")
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
}

func TestValidateAPIKey_UnknownAgent(t *testing.T) {
	setupTestDB(t)
	err := ValidateAPIKey("nonexistent-agent", "some-key")
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
	if err.Error() != "unknown agent" {
		t.Fatalf("expected 'unknown agent' error, got: %v", err)
	}
}

func TestValidateAPIKey_ValidKey(t *testing.T) {
	setupTestDB(t)
	hash, _ := HashAPIKey("correct-key")
	db.Exec("INSERT INTO agents (id, api_key_hash, name) VALUES (?, ?, ?)", "agent-1", hash, "Agent One")

	err := ValidateAPIKey("agent-1", "correct-key")
	if err != nil {
		t.Fatalf("expected valid key to pass, got: %v", err)
	}
}

func TestValidateAPIKey_WrongKey(t *testing.T) {
	setupTestDB(t)
	hash, _ := HashAPIKey("correct-key")
	db.Exec("INSERT INTO agents (id, api_key_hash, name) VALUES (?, ?, ?)", "agent-1", hash, "Agent One")

	err := ValidateAPIKey("agent-1", "wrong-key")
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

// --- Handler tests (no DB needed - use mock server) ---

func TestHandleLogin_MissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRegisterAgent_MissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", nil)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRegisterUser_MissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/user", nil)
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	hub = newHub()
	go hub.run()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Integration tests (full HTTP server with DB) ---

func TestAgentRegisterAndConnect(t *testing.T) {
	server := setupTestServer(t)

	// Register an agent
	resp, err := http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id": {"test-agent-1"},
		"name":     {"Test Agent"},
		"api_key":  {"secret-key-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "registered" {
		t.Fatalf("expected status=registered, got %s", result["status"])
	}
}

func TestAgentConnectInvalidKey(t *testing.T) {
	server := setupTestServer(t)

	// Register agent
	http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id": {"agent-x"},
		"name":     {"Agent X"},
		"api_key":  {"correct-key"},
	})

	// Try to connect with wrong API key
	resp, err := http.Get(server.URL + "/agent/connect?agent_id=agent-x&api_key=wrong-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, body)
	}
}

func TestAgentConnectMissingKey(t *testing.T) {
	server := setupTestServer(t)

	resp, err := http.Get(server.URL + "/agent/connect?agent_id=agent-y")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAgentConnectUnknownAgent(t *testing.T) {
	server := setupTestServer(t)

	resp, err := http.Get(server.URL + "/agent/connect?agent_id=unknown&api_key=whatever")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for unknown agent, got %d: %s", resp.StatusCode, body)
	}
}

func TestUserRegisterAndLogin(t *testing.T) {
	server := setupTestServer(t)

	// Register a user
	resp, err := http.PostForm(server.URL+"/auth/user", url.Values{
		"email":    {"alice@example.com"},
		"password": {"password123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 on register, got %d: %s", resp.StatusCode, body)
	}

	// Login
	resp2, err := http.PostForm(server.URL+"/auth/login", url.Values{
		"email":    {"alice@example.com"},
		"password": {"password123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 200 on login, got %d: %s", resp2.StatusCode, body)
	}

	var loginResult map[string]string
	json.NewDecoder(resp2.Body).Decode(&loginResult)

	if loginResult["token"] == "" {
		t.Fatal("expected a JWT token in login response")
	}
	if loginResult["user_id"] == "" {
		t.Fatal("expected a user_id in login response")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	server := setupTestServer(t)

	// Register a user
	http.PostForm(server.URL+"/auth/user", url.Values{
		"email":    {"bob@example.com"},
		"password": {"correct-pass"},
	})

	// Try login with wrong password
	resp, err := http.PostForm(server.URL+"/auth/login", url.Values{
		"email":    {"bob@example.com"},
		"password": {"wrong-pass"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", resp.StatusCode)
	}
}

func TestLoginUnknownUser(t *testing.T) {
	server := setupTestServer(t)

	resp, err := http.PostForm(server.URL+"/auth/login", url.Values{
		"email":    {"nobody@example.com"},
		"password": {"whatever"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown user, got %d", resp.StatusCode)
	}
}

func TestClientConnectInvalidToken(t *testing.T) {
	server := setupTestServer(t)

	// Register user
	http.PostForm(server.URL+"/auth/user", url.Values{
		"email":    {"carol@example.com"},
		"password": {"pass123"},
	})

	// Try client connect with invalid token
	resp, err := http.Get(server.URL + "/client/connect?user_id=user_1&token=invalid-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for invalid token, got %d: %s", resp.StatusCode, body)
	}
}

func TestClientConnectMissingToken(t *testing.T) {
	server := setupTestServer(t)

	resp, err := http.Get(server.URL + "/client/connect?user_id=user_1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", resp.StatusCode)
	}
}

// Test the full auth flow: register agent -> validate API key -> register user -> login -> validate JWT
func TestFullAuthFlow(t *testing.T) {
	server := setupTestServer(t)

	// 1. Register an agent
	resp, _ := http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id": {"flow-agent"},
		"name":     {"Flow Agent"},
		"api_key":  {"flow-key-789"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent registration failed: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Validate the agent API key
	err := ValidateAPIKey("flow-agent", "flow-key-789")
	if err != nil {
		t.Fatalf("API key validation failed: %v", err)
	}

	// 3. Register a user
	resp, _ = http.PostForm(server.URL+"/auth/user", url.Values{
		"email":    {"flow@example.com"},
		"password": {"flowpass"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user registration failed: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Login
	resp, _ = http.PostForm(server.URL+"/auth/login", url.Values{
		"email":    {"flow@example.com"},
		"password": {"flowpass"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}
	var loginResult map[string]string
	json.NewDecoder(resp.Body).Decode(&loginResult)
	resp.Body.Close()

	// 5. Validate the JWT
	claims, err := ValidateJWT(loginResult["token"])
	if err != nil {
		t.Fatalf("JWT validation failed: %v", err)
	}
	if claims.Email != "flow@example.com" {
		t.Fatalf("expected email flow@example.com, got %s", claims.Email)
	}

	// 6. Verify wrong key fails
	err = ValidateAPIKey("flow-agent", "wrong-key")
	if err == nil {
		t.Fatal("expected error for wrong API key")
	}

	t.Logf("Full auth flow passed! Agent: flow-agent, User: %s, Token valid", claims.UserID)
}