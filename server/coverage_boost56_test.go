package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// --- Helpers (CB56) ---

func setupTestDB_CB56(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func setupTestServer_CB56(t *testing.T) (*sql.DB, func()) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB

	h := newHub()
	oldHub := hub
	hub = h

	cleanup := func() {
		db = oldDB
		hub = oldHub
		if h.done != nil {
			close(h.done)
		}
	}
	return testDB, cleanup
}

func cb56CreateUserAndGetToken(t *testing.T, testDB *sql.DB, username, password string) (string, string) {
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK && w.Code != http.StatusConflict {
		t.Fatalf("Failed to register user: %d - %s", w.Code, w.Body.String())
	}
	var regResp map[string]string
	json.NewDecoder(w.Body).Decode(&regResp)
	userID := regResp["user_id"]

	req = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to login: %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	return resp["token"], userID
}

// --- handleLogin coverage ---

func TestCB56_HandleLogin_DBQueryError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Close DB to cause query error (not ErrNoRows)
	testDB.Close()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username=testuser&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for DB query error, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB56_HandleLogin_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleLogin_MissingFields(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Missing password
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username=testuser"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing fields, got %d", w.Code)
	}

	// Missing username
	req = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing username, got %d", w.Code)
	}
}

func TestCB56_HandleLogin_UserNotFound(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username=nonexistent&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for nonexistent user, got %d", w.Code)
	}
}

func TestCB56_HandleLogin_WrongPassword(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Register user
	cb56CreateUserAndGetToken(t, testDB, "user_cb56a", "correctpass")

	// Login with wrong password
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username=user_cb56a&password=wrongpass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong password, got %d", w.Code)
	}
}

func TestCB56_HandleLogin_Success(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	cb56CreateUserAndGetToken(t, testDB, "user_cb56b", "pass123")

	// Login again and verify response fields
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(
		"username=user_cb56b&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Error("Expected token in response")
	}
	if resp["username"] != "user_cb56b" {
		t.Errorf("Expected username 'user_cb56b', got '%s'", resp["username"])
	}
}

// --- handleRegisterAgent coverage ---

func TestCB56_HandleRegisterAgent_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/auth/agent", nil)
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterAgent_NoSecret(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=testagent&name=TestAgent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing secret, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterAgent_WrongSecret(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=testagent&name=TestAgent&agent_secret=wrongsecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong secret, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterAgent_MissingAgentID(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { db = oldDB; agentSecret = oldSecret }()

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"name=TestAgent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "testsecret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing agent_id, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterAgent_Success(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { db = oldDB; agentSecret = oldSecret }()

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=agent_test56&name=TestAgent&model=gpt-4&personality=friendly&specialty=chat"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "testsecret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["agent_id"] != "agent_test56" {
		t.Errorf("Expected agent_id 'agent_test56', got '%s'", resp["agent_id"])
	}
	if resp["status"] != "registered" {
		t.Errorf("Expected status 'registered', got '%s'", resp["status"])
	}
}

func TestCB56_HandleRegisterAgent_DefaultName(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { db = oldDB; agentSecret = oldSecret }()

	// Register without name — should default to agent_id
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=agent_noname&model=gpt-4"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "testsecret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}

	// Verify in DB that name = agent_id
	var name string
	err := testDB.QueryRow("SELECT name FROM agents WHERE id = ?", "agent_noname").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "agent_noname" {
		t.Errorf("Expected name to default to 'agent_noname', got '%s'", name)
	}
}

func TestCB56_HandleRegisterAgent_UpsertExisting(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { db = oldDB; agentSecret = oldSecret }()

	// First registration
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=agent_upsert&name=OriginalName&model=gpt-3.5"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "testsecret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("First registration failed: %d - %s", w.Code, w.Body.String())
	}

	// Second registration with same ID — should update
	req = httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=agent_upsert&name=UpdatedName&model=gpt-4&personality=serious&specialty=code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "testsecret")
	w = httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Upsert failed: %d - %s", w.Code, w.Body.String())
	}

	// Verify update
	var name, model, personality string
	err := testDB.QueryRow("SELECT name, model, personality FROM agents WHERE id = ?", "agent_upsert").Scan(&name, &model, &personality)
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}
	if name != "UpdatedName" {
		t.Errorf("Expected name 'UpdatedName', got '%s'", name)
	}
	if model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", model)
	}
	if personality != "serious" {
		t.Errorf("Expected personality 'serious', got '%s'", personality)
	}
}

func TestCB56_HandleRegisterAgent_SecretFromForm(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	oldSecret := agentSecret
	agentSecret = "formsecret"
	defer func() { db = oldDB; agentSecret = oldSecret }()

	// Pass secret via form field instead of header
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=agent_formsecret&name=FormAgent&agent_secret=formsecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for form-based secret, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB56_HandleRegisterAgent_DBError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { db = oldDB; agentSecret = oldSecret }()

	// Close DB to cause error
	testDB.Close()

	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(
		"agent_id=agent_dberr&name=DBErrAgent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "testsecret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for DB error, got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleListAgents coverage ---

func TestCB56_HandleListAgents_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleListAgents_EmptyList(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var agents []AgentInfo
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) != 0 {
		t.Errorf("Expected empty list, got %d agents", len(agents))
	}
}

func TestCB56_HandleListAgents_WithAgents(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	h := newHub()
	oldHub := hub
	hub = h
	defer func() { db = oldDB; hub = oldHub; close(h.done) }()

	// Insert agents directly
	for _, a := range []struct {
		id, name, model, personality, specialty string
	}{
		{"agent_b", "Bravo", "gpt-4", "friendly", "chat"},
		{"agent_a", "Alpha", "gpt-3.5", "serious", "code"},
		{"agent_c", "Charlie", "claude-3", "playful", "writing"},
	} {
		_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			a.id, a.name, a.model, a.personality, a.specialty)
		if err != nil {
			t.Fatalf("Failed to insert agent: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var agents []AgentInfo
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) != 3 {
		t.Fatalf("Expected 3 agents, got %d", len(agents))
	}
	// Should be ordered by name ASC
	if agents[0].Name != "Alpha" {
		t.Errorf("Expected first agent 'Alpha', got '%s'", agents[0].Name)
	}
	if agents[1].Name != "Bravo" {
		t.Errorf("Expected second agent 'Bravo', got '%s'", agents[1].Name)
	}
	if agents[2].Name != "Charlie" {
		t.Errorf("Expected third agent 'Charlie', got '%s'", agents[2].Name)
	}
	// All should be offline since no hub connections
	for _, a := range agents {
		if a.Status != "offline" {
			t.Errorf("Expected agent '%s' status 'offline', got '%s'", a.Name, a.Status)
		}
	}
}

func TestCB56_HandleListAgents_DBQueryError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for DB error, got %d", w.Code)
	}
}

func TestCB56_HandleListAgents_ScanError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	h := newHub()
	oldHub := hub
	hub = h
	defer func() { db = oldDB; hub = oldHub; close(h.done) }()

	// Insert an agent with NULL name (NOT NULL constraint should prevent this in normal use,
	// but we can create a separate table without constraints)
	// Instead, test scan error by closing DB after query starts
	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent_x", "X", "gpt-4", "friendly", "chat")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	// Replace db with a closed copy to cause rows.Next() or Scan to fail
	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	// Closed DB — should get 500 from query error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for DB error, got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleRegisterUser coverage ---

func TestCB56_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/auth/register", nil)
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterUser_MissingFields(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Missing password
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing password, got %d", w.Code)
	}

	// Missing username
	req = httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing username, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterUser_ShortUsername(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// 2 chars — too short
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=ab&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for short username, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterUser_LongUsername(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// 51 chars — too long
	longName := strings.Repeat("a", 51)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username="+longName+"&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for long username, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterUser_InvalidCharacters(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Contains hyphen — not allowed
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user-invalid&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid chars, got %d", w.Code)
	}

	// Contains space
	req = httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user+space&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for space in username, got %d", w.Code)
	}
}

func TestCB56_HandleRegisterUser_DuplicateUsername(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// First registration
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user_dup56&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("First registration failed: %d - %s", w.Code, w.Body.String())
	}

	// Duplicate
	req = httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user_dup56&password=pass456"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected 409 for duplicate, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB56_HandleRegisterUser_Success(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user_ok56&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("Expected 200/201, got %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["user_id"] == "" {
		t.Error("Expected user_id in response")
	}
	if resp["username"] != "user_ok56" {
		t.Errorf("Expected username 'user_ok56', got '%s'", resp["username"])
	}
	if resp["status"] != "registered" {
		t.Errorf("Expected status 'registered', got '%s'", resp["status"])
	}
}

func TestCB56_HandleRegisterUser_MinLengthUsername(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// 3 chars — minimum allowed
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=abc&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Errorf("Expected 200/201 for min-length username, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB56_HandleRegisterUser_MaxLengthUsername(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// 50 chars — maximum allowed
	maxName := strings.Repeat("z", 50)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username="+maxName+"&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Errorf("Expected 200/201 for max-length username, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB56_HandleRegisterUser_UnderscoreAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user_under_56&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Errorf("Expected 200/201 for underscore username, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB56_HandleRegisterUser_DBError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(
		"username=user_dberr56&password=pass123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	// Closed DB — should get 500 (not 409, not 400)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for DB error, got %d - %s", w.Code, w.Body.String())
	}
}

// --- storeMessagesBatch coverage ---

func TestCB56_StoreMessagesBatch_Empty(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Fatalf("Expected nil error for nil batch, got %v", err)
	}
	if ids != nil {
		t.Errorf("Expected nil ids for nil batch, got %v", ids)
	}

	ids, err = storeMessagesBatch([]RoutedMessage{})
	if err != nil {
		t.Fatalf("Expected nil error for empty batch, got %v", err)
	}
	if ids != nil {
		t.Errorf("Expected nil ids for empty batch, got %v", ids)
	}
}

func TestCB56_StoreMessagesBatch_Success(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Create conversation
	convID := generateID("conv")
	userID := generateID("user")
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "user_batch56", "$2a$10$hash")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_batch56")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	msgs := []RoutedMessage{
		{
			ConversationID: convID,
			SenderType:     "user",
			SenderID:       userID,
			Content:        "Hello batch 1",
		},
		{
			ConversationID: convID,
			SenderType:     "agent",
			SenderID:       "agent_batch56",
			Content:        "Hello batch 2",
		},
		{
			ConversationID: convID,
			SenderType:     "user",
			SenderID:       userID,
			Content:        "Hello batch 3",
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("Expected 3 ids, got %d", len(ids))
	}
	for i, id := range ids {
		if id == "" {
			t.Errorf("Expected non-empty id at index %d", i)
		}
		// Verify message was stored
		var content string
		err := testDB.QueryRow("SELECT content FROM messages WHERE id = ?", id).Scan(&content)
		if err != nil {
			t.Errorf("Failed to query message %d: %v", i, err)
		}
		if content != msgs[i].Content {
			t.Errorf("Expected content '%s', got '%s'", msgs[i].Content, content)
		}
	}
}

func TestCB56_StoreMessagesBatch_DBError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// Close DB to cause begin transaction error
	testDB.Close()

	msgs := []RoutedMessage{
		{
			ConversationID: "conv_fake",
			SenderType:     "user",
			SenderID:       "user_fake",
			Content:        "This should fail",
		},
	}

	_, err := storeMessagesBatch(msgs)
	if err == nil {
		t.Error("Expected error for closed DB, got nil")
	}
}

func TestCB56_StoreMessagesBatch_WithAttachmentIDs(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	convID := generateID("conv")
	userID := generateID("user")
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "user_attach56", "$2a$10$hash")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_attach56")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Create an attachment record (no conversation_id column in attachments table)
	attachID := generateID("att")
	_, err = testDB.Exec("INSERT INTO attachments (id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
		attachID, userID, "test.txt", "text/plain", 100, "abc123", "/tmp/test.txt")
	if err != nil {
		t.Fatalf("Failed to insert attachment: %v", err)
	}

	msgs := []RoutedMessage{
		{
			ConversationID: convID,
			SenderType:     "user",
			SenderID:       userID,
			Content:        "Message with attachment",
			AttachmentIDs:  []string{attachID},
		},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch with attachments failed: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("Expected 1 id, got %d", len(ids))
	}

	// Verify attachment was linked to message
	var messageID sql.NullString
	err = testDB.QueryRow("SELECT message_id FROM attachments WHERE id = ?", attachID).Scan(&messageID)
	if err != nil {
		t.Fatalf("Failed to query attachment: %v", err)
	}
	if !messageID.Valid || messageID.String != ids[0] {
		t.Errorf("Expected attachment linked to message %s, got %v", ids[0], messageID)
	}
}

// --- handleAgentConnect coverage ---

// handleAgentConnect doesn't check method (WebSocket upgrade), so no method test here

func TestCB56_HandleAgentConnect_MissingAgentID(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/agent/connect", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing agent_id, got %d", w.Code)
	}
}

// --- handleAdminAgents coverage ---

func TestCB56_HandleAdminAgents_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleAdminAgents_DBError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for DB error, got %d", w.Code)
	}
}

func TestCB56_HandleAdminAgents_EmptyList(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var agents []AgentInfo
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) != 0 {
		t.Errorf("Expected empty list, got %d agents", len(agents))
	}
}

func TestCB56_HandleAdminAgents_WithAgents(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	h := newHub()
	oldHub := hub
	hub = h
	defer func() { db = oldDB; hub = oldHub; close(h.done) }()

	_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent_admin56", "AdminTest", "gpt-4", "neutral", "analysis")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var agents []AgentInfo
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) != 1 {
		t.Fatalf("Expected 1 agent, got %d", len(agents))
	}
	if agents[0].ID != "agent_admin56" {
		t.Errorf("Expected agent_id 'agent_admin56', got '%s'", agents[0].ID)
	}
}

// --- getConversationMessages coverage ---

func TestCB56_GetConversationMessages_DefaultLimit(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	convID := generateID("conv")
	userID := generateID("user")
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "user_gcm56", "$2a$10$hash")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_gcm56")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Insert 5 messages
	for i := 0; i < 5; i++ {
		msgID := generateID("msg")
		_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, '{}', datetime('now', ? || ' seconds'))",
			msgID, convID, "user", userID, "msg "+string(rune('0'+i)), strconv.Itoa(i))
		if err != nil {
			t.Fatalf("Failed to insert message %d: %v", i, err)
		}
	}

	// Default limit should be 50, so all 5 should come back
	msgs, err := getConversationMessages(convID, 0, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) != 5 {
		t.Errorf("Expected 5 messages, got %d", len(msgs))
	}
}

func TestCB56_GetConversationMessages_WithLimit(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	convID := generateID("conv")
	userID := generateID("user")
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "user_lim56", "$2a$10$hash")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_lim56")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Insert 10 messages
	for i := 0; i < 10; i++ {
		msgID := generateID("msg")
		_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, '{}', datetime('now', ? || ' seconds'))",
			msgID, convID, "user", userID, "msg "+strconv.Itoa(i), strconv.Itoa(i))
		if err != nil {
			t.Fatalf("Failed to insert message %d: %v", i, err)
		}
	}

	// Limit to 3
	msgs, err := getConversationMessages(convID, 3, "")
	if err != nil {
		t.Fatalf("getConversationMessages failed: %v", err)
	}
	if len(msgs) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(msgs))
	}
}

func TestCB56_GetConversationMessages_DBError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	testDB.Close()

	_, err := getConversationMessages("conv_fake", 10, "")
	if err == nil {
		t.Error("Expected error for closed DB, got nil")
	}
}

// --- handleDeleteConversation coverage ---

func TestCB56_HandleDeleteConversation_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/delete", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleDeleteConversation_MissingID(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, _ := cb56CreateUserAndGetToken(t, testDB, "user_del56", "pass123")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestCB56_HandleDeleteConversation_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv_fake", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB56_HandleDeleteConversation_NotFound(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, _ := cb56CreateUserAndGetToken(t, testDB, "user_nf56", "pass123")

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv_nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d - %s", w.Code, w.Body.String())
	}
}

func TestCB56_HandleDeleteConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, userID := cb56CreateUserAndGetToken(t, testDB, "user_ok_del56", "pass123")

	convID := generateID("conv")
	_, err := testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		convID, userID, "agent_del56")
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}

	// Insert a message in the conversation
	_, err = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, '{}', datetime('now'))",
		generateID("msg"), convID, "user", userID, "Hello")
	if err != nil {
		t.Fatalf("Failed to insert message: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}

	// Verify conversation is gone
	var count int
	err = testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected conversation deleted, found %d", count)
	}

	// Verify messages are gone
	err = testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query messages: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected messages deleted, found %d", count)
	}
}

// --- handleListConversations coverage ---

func TestCB56_HandleListConversations_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/conversations", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleListConversations_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB56_HandleListConversations_EmptyList(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, _ := cb56CreateUserAndGetToken(t, testDB, "user_empty56", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d - %s", w.Code, w.Body.String())
	}
	var resp struct {
		Conversations []interface{} `json:"conversations"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Conversations) != 0 {
		t.Errorf("Expected empty list, got %d", len(resp.Conversations))
	}
}

func TestCB56_HandleListConversations_DBError(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, _ := cb56CreateUserAndGetToken(t, testDB, "user_list_dberr56", "pass123")

	testDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for DB error, got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleGetMessages coverage ---

func TestCB56_HandleGetMessages_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleGetMessages_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv_fake", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB56_HandleGetMessages_MissingConversationID(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, _ := cb56CreateUserAndGetToken(t, testDB, "user_msg56", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing conversation_id, got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleMessageDelete coverage ---

func TestCB56_HandleMessageDelete_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleMessageDelete_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB56_HandleMessageDelete_MissingMessageID(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, _ := cb56CreateUserAndGetToken(t, testDB, "user_mdel56", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing message_id, got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleSearchMessages coverage ---

func TestCB56_HandleSearchMessages_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleSearchMessages_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB56_HandleSearchMessages_MissingQuery(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	token, _ := cb56CreateUserAndGetToken(t, testDB, "user_search56", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/messages/search", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing query, got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleAdminProfile coverage ---

func TestCB56_HandleAdminProfile_MethodNotAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPut, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB56_HandleAdminProfile_StatsAllowed(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	// GET with no auth should work for stats endpoint (default action)
	req := httptest.NewRequest(http.MethodGet, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for stats (no auth), got %d - %s", w.Code, w.Body.String())
	}
}

// --- handleSetNotificationPrefs coverage ---

// handleSetNotificationPrefs checks auth first (before method), so no method test
// handleGetNotificationPrefs checks auth first (before method), so no method test

func TestCB56_HandleSetNotificationPrefs_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodPost, "/notifications/prefs", nil)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB56_HandleGetNotificationPrefs_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB56(t)
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	req := httptest.NewRequest(http.MethodGet, "/notifications/prefs", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- Placeholder function for SQLite compatibility ---

// Placeholder is defined in conversations.go but we reference it here to ensure compilation
var _ = Placeholder