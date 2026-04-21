package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)
	mux.HandleFunc("/auth/user", handleRegisterUser)
	mux.HandleFunc("/agents", handleListAgents)
	mux.HandleFunc("/admin/agents", handleAdminAgents)
	mux.HandleFunc("/conversations/create", handleCreateConversation)
	mux.HandleFunc("/conversations/list", handleListConversations)
	mux.HandleFunc("/conversations/messages", handleGetMessages)
	mux.HandleFunc("/metrics", handleMetrics)

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
	username := "testuser"

	token, err := GenerateJWT(userID, username)
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
	if claims.Username != username {
		t.Fatalf("expected username %s, got %s", username, claims.Username)
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
		Username: "evil_user",
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

func TestValidateAgentSecret_EmptySecret(t *testing.T) {
	err := ValidateAgentSecret("test-agent", "")
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestValidateAgentSecret_ValidSecret(t *testing.T) {
	err := ValidateAgentSecret("test-agent", agentSecret)
	if err != nil {
		t.Fatalf("expected valid secret to pass, got: %v", err)
	}
}

func TestValidateAgentSecret_WrongSecret(t *testing.T) {
	err := ValidateAgentSecret("test-agent", "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret")
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
	setupTestDB(t)

	// Empty body should fail - missing agent_secret
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", nil)
	req.Header.Set("X-Agent-Secret", "wrong")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	// Should be 401 (invalid secret) not 400
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid secret, got %d", w.Code)
	}

	// Valid secret but missing agent_id
	req2 := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader("name=Test"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("X-Agent-Secret", agentSecret)
	w2 := httptest.NewRecorder()
	handleRegisterAgent(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing agent_id, got %d", w2.Code)
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

func TestHandleRegisterUser_UsernameTooShort(t *testing.T) {
	setupTestDB(t)
	form := url.Values{"username": {"ab"}, "password": {"pass123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short username, got %d", w.Code)
	}
}

func TestHandleRegisterUser_UsernameTooLong(t *testing.T) {
	setupTestDB(t)
	form := url.Values{"username": {strings.Repeat("a", 51)}, "password": {"pass123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for long username, got %d", w.Code)
	}
}

func TestHandleRegisterUser_UsernameInvalidChars(t *testing.T) {
	setupTestDB(t)
	form := url.Values{"username": {"bad user!"}, "password": {"pass123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid chars, got %d", w.Code)
	}
}

func TestHandleRegisterUser_UsernameWithUnderscore(t *testing.T) {
	setupTestDB(t)
	form := url.Values{"username": {"good_user"}, "password": {"pass123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid username with underscore, got %d", w.Code)
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

	// Register an agent with AGENT_SECRET
	resp, err := http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id":     {"test-agent-1"},
		"name":         {"Test Agent"},
		"agent_secret": {agentSecret},
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

	// Register agent with AGENT_SECRET via header
	http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id":     {"agent-x"},
		"name":         {"Agent X"},
		"agent_secret": {agentSecret},
	})

	// Try to connect with wrong secret
	resp, err := http.Get(server.URL + "/agent/connect?agent_id=agent-x&agent_secret=wrong-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, body)
	}
}

func TestAgentConnectMissingSecret(t *testing.T) {
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

	resp, err := http.Get(server.URL + "/agent/connect?agent_id=unknown&agent_secret=whatever")
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
		"username": {"alice"},
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
		"username": {"alice"},
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
		"username": {"bob"},
		"password": {"correct-pass"},
	})

	// Try login with wrong password
	resp, err := http.PostForm(server.URL+"/auth/login", url.Values{
		"username": {"bob"},
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
		"username": {"nobody"},
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
		"username": {"carol"},
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

	// 1. Register an agent with AGENT_SECRET
	resp, _ := http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id":     {"flow-agent"},
		"name":         {"Flow Agent"},
		"agent_secret": {agentSecret},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent registration failed: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Validate the agent secret
	err := ValidateAgentSecret("flow-agent", agentSecret)
	if err != nil {
		t.Fatalf("Agent secret validation failed: %v", err)
	}

	// 3. Register a user
	resp, _ = http.PostForm(server.URL+"/auth/user", url.Values{
		"username": {"flowuser"},
		"password": {"flowpass"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user registration failed: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Login
	resp, _ = http.PostForm(server.URL+"/auth/login", url.Values{
		"username": {"flowuser"},
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
	if claims.Username != "flowuser" {
		t.Fatalf("expected username flowuser, got %s", claims.Username)
	}

	// 6. Verify wrong secret fails
	err = ValidateAgentSecret("flow-agent", "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong agent secret")
	}

	t.Logf("Full auth flow passed! Agent: flow-agent, User: %s, Token valid", claims.UserID)
}

func TestAgentSelfRegistration(t *testing.T) {
	server := setupTestServer(t)

	// Connect with valid secret - agent should self-register
	resp, err := http.Get(server.URL + "/agent/connect?agent_id=new-agent&agent_secret=" + url.QueryEscape(agentSecret) + "&name=New%20Agent&model=gpt-4")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should upgrade to WebSocket (101), not auth error
	// Since we can't do WS upgrade in unit test, we check for non-401 status
	// A 400 (bad request for WS upgrade) is expected here, not 401
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("expected agent to pass auth with valid secret")
	}

	// Verify the agent was created in DB
	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "new-agent").Scan(&name)
	if err != nil {
		t.Fatalf("expected agent to be self-registered, got DB error: %v", err)
	}
	if name != "New Agent" {
		t.Fatalf("expected name 'New Agent', got '%s'", name)
	}
}

func TestAgentSelfRegistrationUsesAgentIDAsName(t *testing.T) {
	server := setupTestServer(t)

	// Connect without name parameter - agent_id should be used as name
	resp, err := http.Get(server.URL + "/agent/connect?agent_id=unnamed-agent&agent_secret=" + url.QueryEscape(agentSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("expected agent to pass auth with valid secret")
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "unnamed-agent").Scan(&name)
	if err != nil {
		t.Fatalf("expected agent to be self-registered, got DB error: %v", err)
	}
	if name != "unnamed-agent" {
		t.Fatalf("expected name to default to agent_id, got '%s'", name)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}

	// Should allow up to maxAgentAttempts
	for i := 0; i < maxAgentAttempts; i++ {
		if !rl.Allow("test-agent") {
			t.Fatalf("expected attempt %d to be allowed", i+1)
		}
	}

	// Next attempt should be rate limited
	if rl.Allow("test-agent") {
		t.Fatal("expected rate limit to be enforced after max attempts")
	}

	// Different agent should not be affected
	if !rl.Allow("other-agent") {
		t.Fatal("expected different agent to not be rate limited")
	}
}

func TestRegisterAgentWithSecret(t *testing.T) {
	setupTestDB(t)

	// Register agent via header auth
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader("agent_id=header-agent&name=Header%20Agent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", agentSecret)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify agent exists
	var name string
	err := db.QueryRow("SELECT name FROM agents WHERE id = ?", "header-agent").Scan(&name)
	if err != nil {
		t.Fatalf("expected agent in DB, got: %v", err)
	}
	if name != "Header Agent" {
		t.Fatalf("expected name 'Header Agent', got '%s'", name)
	}
}

func TestRegisterAgentInvalidSecret(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader("agent_id=bad-agent&name=Bad%20Agent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid secret, got %d", w.Code)
	}
}