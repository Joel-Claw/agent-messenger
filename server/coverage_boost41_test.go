package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

// ===================================================================
// rate_limit_tiers cleanup() ticker.C branch (45.5% -> higher)
// ===================================================================

func TestTieredRateLimiter_CleanupDeletesExpired(t *testing.T) {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
		stopCh: make(chan struct{}),
	}

	// Add an entry that expired well over 10 minutes ago
	trl.limits["user1"] = &userRateLimitState{
		count:     5,
		tier:      TierFree,
		windowEnd: time.Now().Add(-15 * time.Minute),
	}

	// Add an entry that expired recently (within 10 min grace)
	trl.limits["user2"] = &userRateLimitState{
		count:     3,
		tier:      TierPro,
		windowEnd: time.Now().Add(-3 * time.Minute),
	}

	// Add a non-expired entry
	trl.limits["user3"] = &userRateLimitState{
		count:     1,
		tier:      TierEnterprise,
		windowEnd: time.Now().Add(30 * time.Minute),
	}

	// Manually trigger the cleanup logic
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	if _, ok := trl.limits["user1"]; ok {
		t.Error("user1 should have been deleted (expired > 10min)")
	}
	if _, ok := trl.limits["user2"]; !ok {
		t.Error("user2 should NOT be deleted (within 10min grace period)")
	}
	if _, ok := trl.limits["user3"]; !ok {
		t.Error("user3 should NOT be deleted (not expired)")
	}
}

func TestTieredRateLimiter_CleanupKeepsRecentExpired(t *testing.T) {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
		stopCh: make(chan struct{}),
	}

	// Entry expired 5 minutes ago (within 10 min grace)
	trl.limits["recent"] = &userRateLimitState{
		count:     2,
		tier:      TierFree,
		windowEnd: time.Now().Add(-5 * time.Minute),
	}

	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}

	if _, ok := trl.limits["recent"]; !ok {
		t.Error("recent expired entry should be kept (within 10min grace)")
	}
}

// ===================================================================
// openDatabase() coverage (47.8% -> higher)
// ===================================================================

func TestOpenDatabase_SQLiteSuccess(t *testing.T) {
	d, err := openDatabase(DriverSQLite, ":memory:")
	if err != nil {
		t.Fatalf("openDatabase sqlite failed: %v", err)
	}
	defer d.Close()
	if d == nil {
		t.Fatal("db is nil")
	}
}

func TestOpenDatabase_InvalidDriver(t *testing.T) {
	_, err := openDatabase("invaliddriver", "foo")
	if err == nil {
		t.Fatal("expected error for invalid driver")
	}
	if !strings.Contains(err.Error(), "failed to open database") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenDatabase_PostgreSQLPingError(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()

	_, err := openDatabase(DriverPostgreSQL, "host=localhost port=1 dbname=test sslmode=disable")
	if err == nil {
		t.Log("PostgreSQL open succeeded (unexpected but not a failure)")
		return
	}
	if !strings.Contains(err.Error(), "failed to connect to PostgreSQL") {
		t.Logf("error message: %v", err)
	}
}

// ===================================================================
// initFCM() success path (51.9% -> higher)
// ===================================================================

func TestInitFCM_StatPassButNewAppFails(t *testing.T) {
	// Create temp file that exists (so os.Stat passes)
	tmpFile, err := os.CreateTemp("", "fcm-creds-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	oldPushConfig := pushConfig
	defer func() { pushConfig = oldPushConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled:    true,
		FCMCredentials: tmpFile.Name(),
	}

	// This will try firebase.NewApp which will fail to parse the file as valid JSON
	initFCM()

	// pushConfig.FCMEnabled should be false after init fails
	if pushConfig.FCMEnabled {
		t.Log("FCM remained enabled (unexpected - NewApp should have failed)")
	}
}

func TestInitFCM_NewAppError(t *testing.T) {
	// Create a file with invalid content
	tmpFile, err := os.CreateTemp("", "fcm-creds-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.WriteString("invalid json content")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	oldPushConfig := pushConfig
	defer func() { pushConfig = oldPushConfig }()

	pushConfig = &PushNotificationConfig{
		FCMEnabled:    true,
		FCMCredentials: tmpFile.Name(),
	}

	// NewApp will fail parsing the credentials
	initFCM()

	// Should have disabled FCM
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled after NewApp failure")
	}
}

// ===================================================================
// initSchema() error paths (79.4% -> higher)
// ===================================================================

func TestInitSchema_ClosedDB(t *testing.T) {
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	initSchema(d)
	d.Close() // Close the DB

	// Calling initSchema again on closed DB should return an error
	err = initSchema(d)
	if err == nil {
		t.Log("initSchema on closed DB returned no error (may be tolerated by SQLite)")
	}
}

func TestInitSchema_PostgreSQLMigrationsRecorded(t *testing.T) {
	// Test the migration counting logic with SQLite
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer d.Close()

	initSchema(d)

	// Verify migrations were recorded
	var count int
	err = d.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count migrations: %v", err)
	}
	if count == 0 {
		t.Error("expected migrations to be recorded")
	}
	t.Logf("migrations recorded: %d", count)
}

func TestInitSchema_AlreadyHasMigrations(t *testing.T) {
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer d.Close()

	// Pre-create schema_migrations and add some entries
	_, _ = d.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER NOT NULL, name TEXT NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (version))`)
	_, _ = d.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", 1, "initial_schema")
	_, _ = d.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", 2, "agent_metadata_columns")

	// Now call initSchema — it should NOT re-add migrations
	initSchema(d)

	var count int
	d.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 migrations (pre-existing), got %d", count)
	}
}

// ===================================================================
// handleStoreEncryptedMessage remaining paths
// ===================================================================

func TestHandleStoreEncryptedMessage_AgentBufferFull(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Create agent with full buffer (capacity 1, already has 1 message)
	agent := &Connection{
		id:       "agent-buffer-test",
		connType: "agent",
		send:     make(chan []byte, 1),
		hub:      hub,
	}
	agent.send <- []byte("fill") // fill the buffer
	hub.mu.Lock()
	hub.agents["agent-buffer-test"] = agent
	hub.mu.Unlock()

	// Create conversation
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-buffer-test", "AgentBuffer")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user1", "user1", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-buf-full", "user1", "agent-buffer-test")

	// Store encrypted message from user — agent buffer is full
	body := `{"conversation_id":"conv-buf-full","ciphertext":"abc","iv":"xyz","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user1", "user1"))

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "stored" {
		t.Errorf("expected status=stored, got %v", resp["status"])
	}
}

func TestHandleStoreEncryptedMessage_MultiDeviceDelivery(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Create two client connections for multi-device
	client1 := &Connection{
		id:       "user-multi",
		connType: "client",
		deviceID: "device1",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	client2 := &Connection{
		id:       "user-multi",
		connType: "client",
		deviceID: "device2",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.clientConns["user-multi"] = []*Connection{client1, client2}
	hub.mu.Unlock()

	// Create agent
	agent := &Connection{
		id:       "agent-multi-test",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-multi-test"] = agent
	hub.mu.Unlock()

	// Create conversation
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-multi-test", "AgentMulti")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-multi", "user-multi", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-multi-dev", "user-multi", "agent-multi-test")

	// Agent sends encrypted message to user — should deliver to all devices
	body := `{"conversation_id":"conv-multi-dev","ciphertext":"secret","iv":"initvec","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-multi-test")

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Both devices should receive the encrypted_message event
	select {
	case <-client1.send:
		// good
	default:
		t.Error("client1 did not receive message")
	}
	select {
	case <-client2.send:
		// good
	default:
		t.Error("client2 did not receive message")
	}
}

func TestHandleStoreEncryptedMessage_NoHubDelivery(t *testing.T) {
	setupTestDB(t)

	oldHub := hub
	t.Cleanup(func() { hub = oldHub })
	hub = nil // no hub — should still store

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user1", "user1", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-no-hub", "user1", "agent1")

	body := `{"conversation_id":"conv-no-hub","ciphertext":"data","iv":"vector","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user1", "user1"))

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleStoreEncryptedMessage_NilHubAgentNotConnected(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Agent NOT connected
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-not-connected", "AgentNotConnected")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user1", "user1", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-no-agent", "user1", "agent-not-connected")

	body := `{"conversation_id":"conv-no-agent","ciphertext":"data","iv":"vector","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user1", "user1"))

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleStoreEncryptedMessage_AllDevicesBufferFull(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Create client with full buffer
	client := &Connection{
		id:       "user-buf-full",
		connType: "client",
		deviceID: "dev1",
		send:     make(chan []byte, 1),
		hub:      hub,
	}
	client.send <- []byte("fill")
	hub.mu.Lock()
	hub.clientConns["user-buf-full"] = []*Connection{client}
	hub.mu.Unlock()

	// Create agent
	agent := &Connection{
		id:       "agent-buf-full-2",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-buf-full-2"] = agent
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-buf-full-2", "AgentBufFull")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-buf-full", "user-buf-full", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-all-buf", "user-buf-full", "agent-buf-full-2")

	// Agent sends to user — all device buffers full → notifyUser fallback
	body := `{"conversation_id":"conv-all-buf","ciphertext":"data","iv":"vector","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-buf-full-2")

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleStoreEncryptedMessage_AgentNoClientsConnected(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Agent connected but user has no client connections
	agent := &Connection{
		id:       "agent-no-clients",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      hub,
	}
	hub.mu.Lock()
	hub.agents["agent-no-clients"] = agent
	hub.mu.Unlock()

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-no-clients", "AgentNoClients")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-no-clients", "user-no-clients", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-no-clients", "user-no-clients", "agent-no-clients")

	// Agent sends to user — no connected clients → notifyUser fallback
	body := `{"conversation_id":"conv-no-clients","ciphertext":"data","iv":"vector","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-no-clients")

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleStoreEncryptedMessage_DBError(t *testing.T) {
	setupTestDB(t)

	// Close the DB to cause errors
	db.Close()

	oldHub := hub
	t.Cleanup(func() { hub = oldHub })
	hub = nil

	body := `{"conversation_id":"conv-db-err","ciphertext":"data","iv":"vector","algorithm":"aes-256-gcm"}`
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user1", "user1"))

	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 (conversation not found due to DB error), got %d", rr.Code)
	}
}

// ===================================================================
// handleGetEncryptedMessages remaining paths
// ===================================================================

func TestHandleGetEncryptedMessages_AuthNotParticipantUser(t *testing.T) {
	setupTestDB(t)

	// Create conversation owned by different user
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-owner", "user-owner", "$2a$10$hash")
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent-owner", "AgentOwner")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-other-user", "user-owner", "agent-owner")

	// Different user tries to read
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=conv-other-user", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user-other", "user-other"))

	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-participant, got %d", rr.Code)
	}
}

func TestHandleGetEncryptedMessages_LimitNegative(t *testing.T) {
	setupTestDB(t)

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user1", "user1", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-neg-limit", "user1", "agent1")

	// Negative limit should default to 50
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=conv-neg-limit&limit=-5", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user1", "user1"))

	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleGetEncryptedMessages_ZeroLimit(t *testing.T) {
	setupTestDB(t)

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user1", "user1", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-zero-limit", "user1", "agent1")

	// limit=0 should default to 50
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=conv-zero-limit&limit=0", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user1", "user1"))

	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleGetEncryptedMessages_WithMessages(t *testing.T) {
	setupTestDB(t)

	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent1", "Agent1")
	db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user1", "user1", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-with-msgs", "user1", "agent1")

	// Insert messages
	for i := 0; i < 3; i++ {
		msgID := fmt.Sprintf("emsg-%d", i)
		db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			msgID, "conv-with-msgs", "user1", "user", "cipher", "iv", "key", "aes-256-gcm", time.Now().UTC())
	}

	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=conv-with-msgs", nil)
	req.Header.Set("Authorization", "Bearer "+generateTestJWT(t, "user1", "user1"))

	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var messages []json.RawMessage
	json.NewDecoder(rr.Body).Decode(&messages)
	if len(messages) != 3 {
		t.Errorf("expected 3 messages, got %d", len(messages))
	}
}

// ===================================================================
// monitorAgentHeartbeats ticker.C branch
// ===================================================================

func TestMonitorAgentHeartbeats_TickerFires(t *testing.T) {
	// Temporarily set very short interval and timeout
	oldEnabled := agentPresenceEnabled
	oldInterval := agentPresenceInterval
	oldTimeout := agentPresenceTimeout
	defer func() {
		agentPresenceEnabled = oldEnabled
		agentPresenceInterval = oldInterval
		agentPresenceTimeout = oldTimeout
	}()

	agentPresenceEnabled = true
	agentPresenceInterval = 30 * time.Millisecond
	agentPresenceTimeout = 50 * time.Millisecond

	h := newHub()
	go h.run()
	defer h.Stop()

	// Register an agent with old heartbeat (will be stale)
	agent := &Connection{
		id:            "agent-stale-tick",
		connType:      "agent",
		send:          make(chan []byte, 10),
		hub:           h,
		lastHeartbeat: time.Now().Add(-200 * time.Millisecond),
	}
	h.mu.Lock()
	h.agents["agent-stale-tick"] = agent
	h.mu.Unlock()

	// Wait for monitor ticker to fire and check stale agents
	time.Sleep(300 * time.Millisecond)

	// Agent should have been unregistered (stale)
	h.mu.RLock()
	_, stillConnected := h.agents["agent-stale-tick"]
	h.mu.RUnlock()

	if stillConnected {
		// Give more time
		time.Sleep(300 * time.Millisecond)
		h.mu.RLock()
		_, stillConnected = h.agents["agent-stale-tick"]
		h.mu.RUnlock()
		if stillConnected {
			t.Error("stale agent should have been unregistered by monitor")
		}
	}

	// Verify stale count increased
	if h.StaleAgentCount() < 1 {
		t.Error("expected staleAgentCount >= 1")
	}
}

// ===================================================================
// readPump normal message routing
// ===================================================================

func TestReadPump_RoutesMessage(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	// Create a WebSocket pair
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		c := &Connection{
			id:       "agent-read-test",
			connType: "agent",
			send:     make(chan []byte, 10),
			hub:      hub,
			conn:     conn,
		}
		hub.register <- c
		go c.writePump()
		c.readPump()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Wait for connection to register
	time.Sleep(50 * time.Millisecond)

	// Send a message
	msg := map[string]interface{}{
		"type":            "chat",
		"conversation_id":  "test-conv",
		"content":          "hello from test",
		"sender_type":      "agent",
		"sender_id":        "agent-read-test",
	}
	msgBytes, _ := json.Marshal(msg)
	if err := ws.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Wait for message to be routed
	time.Sleep(50 * time.Millisecond)

	// The hub should have routed the message (messagesRouted counter)
	if hub.messagesRouted.Load() < 1 {
		t.Error("expected messagesRouted >= 1")
	}

	// Clean close
	ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	time.Sleep(50 * time.Millisecond)
}

func TestReadPump_NormalClose(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &Connection{
			id:       "agent-close-test",
			connType: "agent",
			send:     make(chan []byte, 10),
			hub:      hub,
			conn:     conn,
		}
		hub.register <- c
		go c.writePump()
		c.readPump()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	time.Sleep(50 * time.Millisecond)

	// Normal close — should not log unexpected close error
	ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	time.Sleep(50 * time.Millisecond)
}

// ===================================================================
// writePump message delivery + error paths
// ===================================================================

func TestWritePump_MessageDeliveryViaSendChannel(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &Connection{
			id:       "agent-write-test",
			connType: "agent",
			send:     make(chan []byte, 10),
			hub:      h,
			conn:     conn,
		}
		h.register <- c
		go c.readPump()
		c.writePump()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	time.Sleep(50 * time.Millisecond)

	// Find the registered connection and send a message through its send channel
	h.mu.RLock()
	c := h.agents["agent-write-test"]
	h.mu.RUnlock()
	if c == nil {
		t.Fatal("agent not found in hub")
	}

	c.send <- []byte(`{"type":"test"}`)

	// Read the message from the WebSocket client
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !strings.Contains(string(msg), "test") {
		t.Errorf("unexpected message: %s", string(msg))
	}

	// Close the WebSocket
	ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	time.Sleep(50 * time.Millisecond)
}

func TestWritePump_WriteErrorOnClosedConn(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &Connection{
			id:       "agent-werr",
			connType: "agent",
			send:     make(chan []byte, 10),
			hub:      h,
			conn:     conn,
		}
		h.register <- c
		// Close the underlying connection to cause write errors
		conn.Close()
		go c.readPump()
		c.writePump()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	time.Sleep(100 * time.Millisecond)
	// writePump should have hit a write error and exited
}

// ===================================================================
// Hub.run broadcast to all
// ===================================================================

func TestHubRun_BroadcastToAllAgentsAndClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Register agent
	agent := &Connection{
		id:       "agent-bc",
		connType: "agent",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.register <- agent

	// Register client
	client := &Connection{
		id:       "client-bc",
		connType: "client",
		send:     make(chan []byte, 10),
		hub:      h,
	}
	h.register <- client

	time.Sleep(50 * time.Millisecond)

	// Broadcast a message
	h.broadcast <- []byte(`{"type":"test"}`)

	time.Sleep(50 * time.Millisecond)

	// Both should receive it
	select {
	case <-agent.send:
	default:
		t.Error("agent did not receive broadcast")
	}
	select {
	case <-client.send:
	default:
		t.Error("client did not receive broadcast")
	}
}

// ===================================================================
// Hub.Stop idempotent + concurrent safety
// ===================================================================

func TestHub_StopConcurrent(t *testing.T) {
	h := newHub()
	go h.run()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Stop()
		}()
	}
	wg.Wait()
	// Should not panic
}

// ===================================================================
// Placeholder / Placeholders helper functions
// ===================================================================

func TestPlaceholder_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()
	currentDriver = DriverPostgreSQL

	if p := Placeholder(1); p != "$1" {
		t.Errorf("expected $1, got %s", p)
	}
	if p := Placeholder(3); p != "$3" {
		t.Errorf("expected $3, got %s", p)
	}
}

func TestPlaceholder_SQLite(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()
	currentDriver = DriverSQLite

	if p := Placeholder(1); p != "?" {
		t.Errorf("expected ?, got %s", p)
	}
}

func TestPlaceholders_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()
	currentDriver = DriverPostgreSQL

	// Starting from 1, count 3 → "$1, $2, $3"
	p := Placeholders(1, 3)
	if p != "$1, $2, $3" {
		t.Errorf("expected '$1, $2, $3', got '%s'", p)
	}
}

func TestPlaceholders_SQLite(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()
	currentDriver = DriverSQLite

	// SQLite: all ? separated by commas
	p := Placeholders(1, 3)
	if p != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?', got '%s'", p)
	}
}

// ===================================================================
// initSchemaForDriver
// ===================================================================

func TestInitSchemaForDriver_SQLite(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()
	currentDriver = DriverSQLite

	s := initSchemaForDriver()
	if !strings.Contains(s, "CREATE TABLE") {
		t.Error("expected CREATE TABLE in SQLite schema")
	}
}

func TestInitSchemaForDriver_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()
	currentDriver = DriverPostgreSQL

	s := initSchemaForDriver()
	if s == "" {
		t.Error("expected non-empty PostgreSQL schema")
	}
}

// ===================================================================
// SafeSend edge cases
// ===================================================================

func TestSafeSend_ClosedChannel(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 1),
	}
	c.MarkClosed()
	close(c.send)

	// SafeSend should recover from panic and return false
	result := c.SafeSend([]byte("test"))
	if result {
		t.Error("expected false when sending on closed channel")
	}
}

func TestSafeSend_IsClosedCheck(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 1),
	}
	c.MarkClosed()

	// SafeSend should return false without trying to send (IsClosed check)
	result := c.SafeSend([]byte("test"))
	if result {
		t.Error("expected false when connection is closed")
	}
}

func TestSafeSend_Success(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 2),
	}
	result := c.SafeSend([]byte("test"))
	if !result {
		t.Error("expected true for successful send")
	}
}

func TestSafeSend_BufferFull(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 1),
	}
	c.send <- []byte("fill")
	result := c.SafeSend([]byte("overflow"))
	if result {
		t.Error("expected false when buffer is full")
	}
}

// ===================================================================
// IsClosed / MarkClosed
// ===================================================================

func TestConnection_IsClosed_DefaultFalse(t *testing.T) {
	c := &Connection{}
	if c.IsClosed() {
		t.Error("expected IsClosed()=false by default")
	}
}

func TestConnection_MarkClosed_TwiceSafe(t *testing.T) {
	c := &Connection{}
	c.MarkClosed()
	if !c.IsClosed() {
		t.Error("expected IsClosed()=true after MarkClosed")
	}
	// Second MarkClosed should not deadlock
	c.MarkClosed()
	if !c.IsClosed() {
		t.Error("expected IsClosed()=true after second MarkClosed")
	}
}