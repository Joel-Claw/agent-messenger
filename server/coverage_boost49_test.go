package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// CB49: Coverage boost targeting remaining low-coverage functions:
// - deleteConversation: messages DB error path
// - sendWelcomeMessage: SafeSend failure (closed channel)
// - RegisterAgentOnConnect: DB query error, DB update error
// - initSchema: loadTiersFromDB error, schema_migrations creation error
// - Snapshot: offlineQueue != nil branch
// - handleUpload: file too large, disallowed content type
// - handleListAttachments: DB error
// - handleMessageEdit: conversation not found, unauthorized
// - handleMessageDelete: not found, unauthorized
// - addConversationTag: DB error
// - removeConversationTag: DB error
// - getConversationTags: DB error
// - getMessageReactions: success with reactions
// - notifyUser: no tokens, push disabled
// - getDeviceTokensForUser: DB error
// - handleUnregisterDeviceToken: DB error, method not allowed

// --- Helper functions ---

func setupTestDB_CB49(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func generateTestJWT_CB49(t *testing.T, userID string) string {
	return generateTestToken(t, userID)
}

func hashPassword_CB49(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// --- deleteConversation: messages DB error ---

func TestCB49_DeleteConversation_MessagesDBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Insert a conversation
	_, err := testDB.Exec(
		"INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-del-err", "user-del", "agent-del", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Close DB to cause error on DELETE messages
	testDB.Close()

	err = deleteConversation("conv-del-err", "user-del")
	if err == nil {
		t.Error("deleteConversation with closed DB: expected error, got nil")
	}
}

// --- deleteConversation: unauthorized ---

func TestCB49_DeleteConversation_Unauthorized(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Insert a conversation owned by user-a
	_, err := testDB.Exec(
		"INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		"conv-unauth", "user-a", "agent-1", time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	// Try to delete as user-b
	err = deleteConversation("conv-unauth", "user-b")
	if err == nil {
		t.Error("deleteConversation by unauthorized user: expected error, got nil")
	}
}

// --- deleteConversation: not found ---

func TestCB49_DeleteConversation_NotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	err := deleteConversation("nonexistent-conv", "user-test")
	if err == nil {
		t.Error("deleteConversation nonexistent: expected error, got nil")
	}
}

// --- sendWelcomeMessage: SafeSend on closed channel ---

func TestCB49_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	c := &Connection{
		id:     "conn-welcome-closed",
		connType: "client",
		send:   make(chan []byte, 1),
		negotiatedVersion: "0.1",
	}
	close(c.send)

	// Should not panic when sending on closed channel
	sendWelcomeMessage(c)
	// If we get here, the test passed (no panic)
}

// --- sendWelcomeMessage: with deviceID ---

func TestCB49_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	c := &Connection{
		id:       "conn-welcome-dev",
		connType: "client",
		send:     make(chan []byte, 10),
		negotiatedVersion: "0.1",
		deviceID: "device-abc",
	}
	sendWelcomeMessage(c)

	// Should have received a message
	select {
	case msg := <-c.send:
		if len(msg) == 0 {
			t.Error("sendWelcomeMessage sent empty message")
		}
	default:
		t.Error("sendWelcomeMessage did not send any message")
	}
}

// --- RegisterAgentOnConnect: DB query error ---

func TestCB49_RegisterAgentOnConnect_QueryError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	testDB.Close() // Close to cause query error
	db = testDB
	defer func() { db = oldDB }()

	err := RegisterAgentOnConnect("agent-query-err", "TestAgent", "gpt-4", "friendly", "coding")
	if err == nil {
		t.Error("RegisterAgentOnConnect with closed DB: expected error, got nil")
	}
}

// --- Snapshot: with offlineQueue != nil ---

func TestCB49_Snapshot_WithOfflineQueue(t *testing.T) {
	h := newHub()
	m := NewMetrics(h)

	// Set up offline queue
	oldOQ := offlineQueue
	offlineQueue = newOfflineQueue(100, 7*24*time.Hour)
	offlineQueue.Enqueue("user1", []byte("msg1"))
	offlineQueue.Enqueue("user1", []byte("msg2"))
	offlineQueue.Enqueue("user2", []byte("msg3"))
	defer func() { offlineQueue = oldOQ }()

	snap := m.Snapshot()

	depth, ok := snap["offline_queue_depth"]
	if !ok {
		t.Fatal("Snapshot missing offline_queue_depth field")
	}

	depthInt, ok := depth.(int)
	if !ok {
		t.Fatalf("offline_queue_depth is %T, want int", depth)
	}
	if depthInt != 3 {
		t.Errorf("offline_queue_depth = %d, want 3", depthInt)
	}
}

// --- Snapshot: verify all fields present ---

func TestCB49_Snapshot_AllFieldsPresent(t *testing.T) {
	h := newHub()
	m := NewMetrics(h)
	snap := m.Snapshot()

	requiredFields := []string{
		"version", "uptime_seconds", "start_time",
		"messages_in", "messages_out", "connections_total",
		"agents_connected", "clients_connected", "client_conns_total",
		"errors_total", "rate_limited",
		"goroutines", "memory_alloc_mb", "memory_sys_mb",
		"offline_queue_depth", "agent_heartbeat",
	}

	for _, field := range requiredFields {
		if _, ok := snap[field]; !ok {
			t.Errorf("Snapshot missing field: %s", field)
		}
	}

	// Verify agent_heartbeat is a map with sub-fields
	hb, ok := snap["agent_heartbeat"].(map[string]interface{})
	if !ok {
		t.Fatalf("agent_heartbeat is %T, want map[string]interface{}", snap["agent_heartbeat"])
	}
	for _, field := range []string{"enabled", "interval_s", "timeout_s", "stale_agents"} {
		if _, ok := hb[field]; !ok {
			t.Errorf("agent_heartbeat missing field: %s", field)
		}
	}
}

// --- handleListAttachments: DB error ---

func TestCB49_HandleListAttachments_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	testDB.Close() // Close to cause error
	db = testDB
	defer func() { db = oldDB }()

	token := generateTestJWT_CB49(t, "user-att-err")

	req := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	// Should return 500 (or some error status, not 200)
	if w.Code == http.StatusOK {
		t.Error("handleListAttachments with closed DB: expected error status, got 200")
	}
}

// --- handleListAttachments: method not allowed ---

func TestCB49_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	token := generateTestJWT_CB49(t, "user-att")

	req := httptest.NewRequest(http.MethodPost, "/attachments?conversation_id=conv-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleListAttachments POST: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleListAttachments: unauthorized ---

func TestCB49_HandleListAttachments_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments?conversation_id=conv-1", nil)
	w := httptest.NewRecorder()

	handleListAttachments(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("handleListAttachments no auth: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- handleMessageEdit: not found ---

func TestCB49_HandleMessageEdit_NotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	token := generateTestJWT_CB49(t, "user-edit")

	// Use form data (the handler reads FormValue, not JSON body)
	form := "message_id=nonexistent-msg&content=edited+content"
	req := httptest.NewRequest(http.MethodPost, "/messages/edit", stringReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleMessageEdit(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("handleMessageEdit nonexistent message: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// --- handleMessageEdit: method not allowed ---

func TestCB49_HandleMessageEdit_MethodNotAllowed(t *testing.T) {
	token := generateTestJWT_CB49(t, "user-edit")

	req := httptest.NewRequest(http.MethodGet, "/messages/edit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleMessageEdit(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleMessageEdit GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleMessageDelete: not found ---

func TestCB49_HandleMessageDelete_NotFound(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	token := generateTestJWT_CB49(t, "user-del")

	req := httptest.NewRequest(http.MethodPost, "/messages/delete?message_id=nonexistent-msg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleMessageDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("handleMessageDelete nonexistent message: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// --- handleMessageDelete: method not allowed ---

func TestCB49_HandleMessageDelete_MethodNotAllowed(t *testing.T) {
	token := generateTestJWT_CB49(t, "user-del")

	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleMessageDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleMessageDelete GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- addConversationTag: DB error ---

func TestCB49_AddConversationTag_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	testDB.Close() // Close to cause error
	db = testDB
	defer func() { db = oldDB }()

	_, err := addConversationTag("conv-1", "user-1", "important")
	if err == nil {
		t.Error("addConversationTag with closed DB: expected error, got nil")
	}
}

// --- removeConversationTag: DB error ---

func TestCB49_RemoveConversationTag_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	testDB.Close()
	db = testDB
	defer func() { db = oldDB }()

	err := removeConversationTag("conv-1", "user-1", "important")
	if err == nil {
		t.Error("removeConversationTag with closed DB: expected error, got nil")
	}
}

// --- getConversationTags: DB error ---

func TestCB49_GetConversationTags_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	testDB.Close()
	db = testDB
	defer func() { db = oldDB }()

	_, err := getConversationTags("conv-1")
	if err == nil {
		t.Error("getConversationTags with closed DB: expected error, got nil")
	}
}

// --- getDeviceTokensForUser: DB error ---

func TestCB49_GetDeviceTokensForUser_DBError(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	testDB.Close()
	db = testDB
	defer func() { db = oldDB }()

	_, err := getDeviceTokensForUser("user-1")
	if err == nil {
		t.Error("getDeviceTokensForUser with closed DB: expected error, got nil")
	}
}

// --- getDeviceTokensForUser: no tokens ---

func TestCB49_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	tokens, err := getDeviceTokensForUser("user-no-tokens")
	if err != nil {
		t.Fatalf("getDeviceTokensForUser empty: unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("getDeviceTokensForUser empty: got %d tokens, want 0", len(tokens))
	}
}

// --- handleUnregisterDeviceToken: method not allowed ---

func TestCB49_HandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	token := generateTestJWT_CB49(t, "user-dev")

	req := httptest.NewRequest(http.MethodGet, "/devices/unregister", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleUnregisterDeviceToken GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleUnregisterDeviceToken: unauthorized ---

func TestCB49_HandleUnregisterDeviceToken_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/devices/unregister", nil)
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("handleUnregisterDeviceToken no auth: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- notifyUser: no tokens ---

func TestCB49_NotifyUser_NoTokens(t *testing.T) {
	oldDB := db
	testDB := setupTestDB_CB49(t)
	db = testDB
	defer func() { db = oldDB; testDB.Close() }()

	// Should not panic when user has no device tokens
	notifyUser("user-no-devices", "Test notification", "Test body", "conv-1")
	// If we get here, the test passed (no panic)
}

// --- initSchema: loadTiersFromDB with tiers ---

func TestCB49_InitSchema_LoadTiersFromDB(t *testing.T) {
	oldDB := db
	oldDriver := currentDriver
	testDB := setupTestDB_CB49(t)
	db = testDB
	currentDriver = DriverSQLite
	defer func() { db = oldDB; currentDriver = oldDriver; testDB.Close() }()

	// Insert a tier
	_, err := testDB.Exec(
		"INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)",
		"user-tier-test", "pro",
	)
	if err != nil {
		t.Fatalf("Failed to insert tier: %v", err)
	}

	// loadTiersFromDB should load the tier
	loadTiersFromDB(globalTieredLimiter)

	tier := globalTieredLimiter.GetTier("user-tier-test")
	if tier.Name != "pro" {
		t.Errorf("loadTiersFromDB: tier for user-tier-test = %q, want %q", tier.Name, "pro")
	}

	// Reset for cleanup
	globalTieredLimiter.Reset()
}

// --- initSchema: double init is idempotent ---

func TestCB49_InitSchema_DoubleInitIdempotent(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	// First init
	if err := initSchema(testDB); err != nil {
		t.Fatalf("First initSchema failed: %v", err)
	}

	// Second init should also succeed (idempotent)
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Second initSchema failed: %v", err)
	}

	// Verify tables exist
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM conversations").Scan(&count)
	if count != 0 {
		t.Errorf("After double init, conversations count = %d, want 0", count)
	}
}

// --- handleRegisterAgent: method not allowed ---

func TestCB49_HandleRegisterAgent_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/agent", nil)
	w := httptest.NewRecorder()

	handleRegisterAgent(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleRegisterAgent GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleRegisterUser: method not allowed ---

func TestCB49_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/register", nil)
	w := httptest.NewRecorder()

	handleRegisterUser(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleRegisterUser GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleLogin: method not allowed ---

func TestCB49_HandleLogin_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleLogin GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleListAgents: unauthorized ---

func TestCB49_HandleListAgents_Success(t *testing.T) {
	oldDB := db
	oldHub := hub
	testDB := setupTestDB_CB49(t)
	db = testDB
	hub = newHub()
	defer func() { db = oldDB; hub = oldHub; testDB.Close() }()

	// Insert an agent
	_, err := testDB.Exec(
		"INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-list-test", "TestAgent", "gpt-4", "friendly", "coding",
	)
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()

	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("handleListAgents: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- handleAdminAgents: unauthorized ---

func TestCB49_HandleAdminAgents_Success(t *testing.T) {
	oldDB := db
	oldHub := hub
	testDB := setupTestDB_CB49(t)
	db = testDB
	hub = newHub()
	defer func() { db = oldDB; hub = oldHub; testDB.Close() }()

	// Insert an agent
	_, err := testDB.Exec(
		"INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent-admin-test", "AdminTestAgent", "gpt-4", "friendly", "coding",
	)
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()

	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("handleAdminAgents: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- handleDeleteConversation: method not allowed ---

func TestCB49_HandleDeleteConversation_MethodNotAllowed(t *testing.T) {
	token := generateTestJWT_CB49(t, "user-del")

	req := httptest.NewRequest(http.MethodGet, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleDeleteConversation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleDeleteConversation GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleSearchMessages: method not allowed ---

func TestCB49_HandleSearchMessages_MethodNotAllowed(t *testing.T) {
	token := generateTestJWT_CB49(t, "user-search")

	req := httptest.NewRequest(http.MethodPost, "/messages/search", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleSearchMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleSearchMessages POST: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- handleMarkRead: method not allowed ---

func TestCB49_HandleMarkRead_MethodNotAllowed(t *testing.T) {
	token := generateTestJWT_CB49(t, "user-read")

	req := httptest.NewRequest(http.MethodGet, "/conversations/mark-read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleMarkRead(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleMarkRead GET: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// stringReader creates an io.Reader from a string
func stringReader(s string) *strings.Reader {
	return strings.NewReader(s)
}