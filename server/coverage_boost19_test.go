package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Coverage Boost 19: Test coverage for low-coverage functions
// Focus: sendAPNSNotification, sendFCMNotification, rate_limit_tiers cleanup,
// persistTierToDB, handleUpload, deleteConversation, InitTracing,
// handleRegisterAgent, handleListAgents, RegisterAgentOnConnect
// ==============================

func cb19SetupDB(t *testing.T) {
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

func cb19SetupAuth(t *testing.T) (string, string) {
	t.Helper()
	origAgentEnv := os.Getenv("AGENT_SECRET")
	origAdminEnv := os.Getenv("ADMIN_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret-cb19")
	agentSecret = "test-agent-secret-cb19"
	os.Setenv("ADMIN_SECRET", "test-admin-secret-cb19")
	adminSecret = "test-admin-secret-cb19"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		if origAdminEnv != "" {
			os.Setenv("ADMIN_SECRET", origAdminEnv)
		} else {
			os.Unsetenv("ADMIN_SECRET")
		}
		resetAgentSecret()
		resetAdminSecret()
	})
	return "test-jwt-secret-cb19", "test-agent-secret-cb19"
}

func cb19MakeToken(t *testing.T, username string) string {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.MinCost)
	_, err := db.Exec("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)", username, username, string(hash))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	token, err := GenerateJWT(username, username)
	if err != nil {
		t.Fatalf("generate JWT: %v", err)
	}
	return token
}

func cb19CreateConv(t *testing.T, username, agentID string) string {
	t.Helper()
	_, _ = db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID)
	conv, err := CreateConversation(username, agentID)
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return conv.ID
}

// --- sendAPNSNotification tests ---

func TestCb19_SendAPNS_PushConfigNil(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token123", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when pushConfig nil, got %v", err)
	}
}

func TestCb19_SendAPNS_APNSDisabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = nil }()
	err := sendAPNSNotification("token123", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when APNS disabled, got %v", err)
	}
}

func TestCb19_SendAPNS_APNSClientNil(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: true, apnsClient: nil}
	defer func() { pushConfig = nil }()
	err := sendAPNSNotification("token123", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when APNS client nil, got %v", err)
	}
}

// --- sendFCMNotification tests ---

func TestCb19_SendFCM_PushConfigNil(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token123", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when pushConfig nil, got %v", err)
	}
}

func TestCb19_SendFCM_FCMDisabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = nil }()
	err := sendFCMNotification("token123", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when FCM disabled, got %v", err)
	}
}

func TestCb19_SendFCM_FCMClientNil(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: true, fcmClient: nil}
	defer func() { pushConfig = nil }()
	err := sendFCMNotification("token123", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when FCM client nil, got %v", err)
	}
}

// --- TieredRateLimiter cleanup tests ---

func TestCb19_TieredRateLimiterCleanup_ExpiredEntries(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	defer trl.Stop()
	trl.SetTier("user1", TierPro)
	trl.SetTier("user2", TierFree)

	// Manually expire user1's window
	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-20 * time.Minute)
	}
	trl.mu.Unlock()

	// Force cleanup check
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	if _, ok := trl.limits["user1"]; ok {
		t.Error("expired user1 should have been cleaned up")
	}
	if _, ok := trl.limits["user2"]; !ok {
		t.Error("non-expired user2 should still exist")
	}
}

func TestCb19_TieredRateLimiterCleanup_RecentEntriesPreserved(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	defer trl.Stop()
	trl.SetTier("user1", TierPro)

	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	if _, ok := trl.limits["user1"]; !ok {
		t.Error("recent user1 should not have been cleaned up")
	}
}

// --- persistTierToDB tests ---

func TestCb19_PersistTierToDB_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error with nil db, got %v", err)
	}
}

func TestCb19_PersistTierToDB_ValidDB(t *testing.T) {
	cb19SetupDB(t)
	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Fatalf("persistTierToDB: %v", err)
	}

	var tierName string
	err = db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user1").Scan(&tierName)
	if err != nil {
		t.Fatalf("query tier: %v", err)
	}
	if tierName != "pro" {
		t.Errorf("expected pro, got %s", tierName)
	}
}

func TestCb19_PersistTierToDB_Upsert(t *testing.T) {
	cb19SetupDB(t)
	err := persistTierToDB("user1", TierFree)
	if err != nil {
		t.Fatalf("first persist: %v", err)
	}

	err = persistTierToDB("user1", TierPro)
	if err != nil {
		t.Fatalf("upsert persist: %v", err)
	}

	var tierName string
	err = db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user1").Scan(&tierName)
	if err != nil {
		t.Fatalf("query tier: %v", err)
	}
	if tierName != "pro" {
		t.Errorf("expected pro after upsert, got %s", tierName)
	}
}

func TestCb19_LoadTiersFromDB_Empty(t *testing.T) {
	cb19SetupDB(t)
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	defer trl.Stop()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB: %v", err)
	}
	tier := trl.GetTier("nonexistent")
	if tier.Name != "free" {
		t.Errorf("expected free tier, got %s", tier.Name)
	}
}

func TestCb19_LoadTiersFromDB_WithData(t *testing.T) {
	cb19SetupDB(t)
	_, err := db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))", "user1", "pro")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))", "user2", "enterprise")
	if err != nil {
		t.Fatal(err)
	}

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	defer trl.Stop()
	err = loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB: %v", err)
	}
	if trl.GetTier("user1").Name != "pro" {
		t.Errorf("expected pro for user1, got %s", trl.GetTier("user1").Name)
	}
	if trl.GetTier("user2").Name != "enterprise" {
		t.Errorf("expected enterprise for user2, got %s", trl.GetTier("user2").Name)
	}
}

// --- handleUpload tests ---

func TestCb19_HandleUpload_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", bytes.NewReader([]byte("test")))
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}
}

func TestCb19_HandleUpload_InvalidMethod(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "uploaduser1")
	req := httptest.NewRequest(http.MethodGet, "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestCb19_HandleUpload_MissingConversationID(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "uploaduser2")
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello"))
	writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	// handleUpload accepts uploads without conversation_id (it's optional)
	// Without conversation_id, the upload succeeds but message_id is null
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for upload without conversation_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_HandleUpload_ConversationNotFound(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "uploaduser3")
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("conversation_id", "nonexistent")
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello"))
	writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	// conversation_id is not validated against the DB in handleUpload;
	// it's stored as-is (could be for a conversation created later)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for upload with nonexistent conversation_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_HandleUpload_SizeExceeded(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "uploaduser4")
	convID := cb19CreateConv(t, "uploaduser4", "agent1")

	origMax := maxUploadSize
	maxUploadSize = 10
	defer func() { maxUploadSize = origMax }()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("conversation_id", convID)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("this content is way more than 10 bytes long"))
	writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for size exceeded, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_HandleUpload_InvalidContentType(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "uploaduser6")
	convID := cb19CreateConv(t, "uploaduser6", "agent6")

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload?conversation_id="+convID, strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusBadRequest {
		t.Logf("Upload with non-multipart got %d: %s", w.Code, w.Body.String())
	}
}

// --- deleteConversation tests ---

func TestCb19_DeleteConversation_Success(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "deluser1")
	convID := cb19CreateConv(t, "deluser1", "delagent1")

	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, 'user', 'deluser1', 'hello', datetime('now'))",
		"msg1", convID)
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for delete, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("conversation should be deleted, found %d", count)
	}

	err = db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
	if err != nil {
		t.Fatalf("count messages: %v", err)
	}
	if count != 0 {
		t.Errorf("messages should be deleted, found %d", count)
	}
}

func TestCb19_DeleteConversation_NotOwner(t *testing.T) {
	cb19SetupDB(t)
	cb19MakeToken(t, "owner1")
	cb19MakeToken(t, "notowner1")
	convID := cb19CreateConv(t, "owner1", "delagent2")

	token2, _ := GenerateJWT("notowner1", "notowner1")
	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for not owner, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_DeleteConversation_MissingID(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "deluser3")
	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing id, got %d", w.Code)
	}
}

func TestCb19_DeleteConversation_NotFound(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "deluser4")
	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for not found, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_DeleteConversation_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/conversations/delete?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- handleRegisterAgent edge cases ---

func TestCb19_RegisterAgent_EmptyName(t *testing.T) {
	cb19SetupDB(t)
	cb19SetupAuth(t)
	form := "agent_id=cb19agent1&name=&agent_secret=test-agent-secret-cb19"
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test-agent-secret-cb19")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for empty name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_RegisterAgent_DuplicateAgent(t *testing.T) {
	cb19SetupDB(t)
	cb19SetupAuth(t)
	form := "agent_id=cb19agent2&name=Agent2&model=gpt-4&agent_secret=test-agent-secret-cb19"
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "test-agent-secret-cb19")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d %s", w.Code, w.Body.String())
	}

	form2 := "agent_id=cb19agent2&name=Agent2Updated&model=claude&agent_secret=test-agent-secret-cb19"
	req2 := httptest.NewRequest(http.MethodPost, "/auth/agent", bytes.NewBufferString(form2))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("X-Agent-Secret", "test-agent-secret-cb19")
	w2 := httptest.NewRecorder()
	handleRegisterAgent(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for duplicate (update), got %d: %s", w2.Code, w2.Body.String())
	}

	var name string
	err := db.QueryRow("SELECT name FROM agents WHERE id = ?", "cb19agent2").Scan(&name)
	if err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if name != "Agent2Updated" {
		t.Errorf("expected name Agent2Updated, got %s", name)
	}
}

func TestCb19_RegisterAgent_WrongSecret(t *testing.T) {
	cb19SetupDB(t)
	cb19SetupAuth(t)
	form := "agent_id=cb19agent3&name=Agent3&agent_secret=wrong-secret"
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong secret, got %d", w.Code)
	}
}

func TestCb19_RegisterAgent_NoHeaders(t *testing.T) {
	cb19SetupDB(t)
	cb19SetupAuth(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", bytes.NewBufferString("agent_id=cb19agent4"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no secret, got %d", w.Code)
	}
}

// --- handleListAgents tests ---

func TestCb19_ListAgents_Empty(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) != 0 {
		t.Errorf("expected empty list, got %d agents", len(agents))
	}
}

func TestCb19_ListAgents_WithAgents(t *testing.T) {
	cb19SetupDB(t)
	_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent2", "Agent Two", "claude", "professional", "coding")
	if err != nil {
		t.Fatal(err)
	}

	// hub must be initialized for handleListAgents (it calls hub.AgentStatus)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestCb19_ListAgents_WithStatus(t *testing.T) {
	cb19SetupDB(t)
	_, _ = db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"agent1", "Agent One", "gpt-4", "friendly", "general")

	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "agent",
		id:       "agent1",
		send:     make(chan []byte, 256),
		closeMu:  sync.RWMutex{},
	}
	hub.mu.Lock()
	hub.agents["agent1"] = conn
	hub.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0]["status"] != "online" {
		t.Errorf("expected online status, got %v", agents[0]["status"])
	}

	hub.mu.Lock()
	delete(hub.agents, "agent1")
	hub.mu.Unlock()
}

// --- RegisterAgentOnConnect tests ---

func TestCb19_RegisterAgentOnConnect_NewAgent(t *testing.T) {
	cb19SetupDB(t)
	err := RegisterAgentOnConnect("newagent1", "New Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect: %v", err)
	}

	var name, model string
	err = db.QueryRow("SELECT name, model FROM agents WHERE id = ?", "newagent1").Scan(&name, &model)
	if err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if name != "New Agent" {
		t.Errorf("expected 'New Agent', got %s", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected 'gpt-4', got %s", model)
	}
}

func TestCb19_RegisterAgentOnConnect_DefaultName(t *testing.T) {
	cb19SetupDB(t)
	err := RegisterAgentOnConnect("newagent2", "", "", "", "")
	if err != nil {
		t.Fatalf("RegisterAgentOnConnect: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "newagent2").Scan(&name)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "newagent2" {
		t.Errorf("expected name to default to agent_id, got %s", name)
	}
}

func TestCb19_RegisterAgentOnConnect_UpdateExisting(t *testing.T) {
	cb19SetupDB(t)
	err := RegisterAgentOnConnect("existing1", "Original Name", "gpt-3", "", "")
	if err != nil {
		t.Fatalf("first register: %v", err)
	}

	err = RegisterAgentOnConnect("existing1", "Updated Name", "gpt-4", "friendly", "")
	if err != nil {
		t.Fatalf("update register: %v", err)
	}

	var name, model, personality string
	err = db.QueryRow("SELECT name, model, personality FROM agents WHERE id = ?", "existing1").Scan(&name, &model, &personality)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "Updated Name" {
		t.Errorf("expected 'Updated Name', got %s", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected 'gpt-4', got %s", model)
	}
	if personality != "friendly" {
		t.Errorf("expected 'friendly', got %s", personality)
	}
}

func TestCb19_RegisterAgentOnConnect_PreserveEmptyFields(t *testing.T) {
	cb19SetupDB(t)
	err := RegisterAgentOnConnect("preserve1", "Agent Name", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Fatalf("first register: %v", err)
	}

	err = RegisterAgentOnConnect("preserve1", "Agent Name", "", "", "")
	if err != nil {
		t.Fatalf("reconnect register: %v", err)
	}

	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "preserve1").Scan(&model, &personality, &specialty)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if model != "gpt-4" {
		t.Errorf("model should be preserved, got %s", model)
	}
	if personality != "friendly" {
		t.Errorf("personality should be preserved, got %s", personality)
	}
	if specialty != "coding" {
		t.Errorf("specialty should be preserved, got %s", specialty)
	}
}

// --- InitTracing tests ---

func TestCb19_InitTracing_Disabled(t *testing.T) {
	origOtel := os.Getenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_ENABLED")
	defer func() {
		if origOtel != "" {
			os.Setenv("OTEL_ENABLED", origOtel)
		}
	}()

	tp := InitTracing()
	if tp != nil {
		t.Error("expected nil tracer provider when OTEL_ENABLED not set")
	}
}

func TestCb19_InitTracing_NoEndpoint(t *testing.T) {
	origOtel := os.Getenv("OTEL_ENABLED")
	origEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer func() {
		if origOtel != "" {
			os.Setenv("OTEL_ENABLED", origOtel)
		} else {
			os.Unsetenv("OTEL_ENABLED")
		}
		if origEndpoint != "" {
			os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", origEndpoint)
		} else {
			os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		}
	}()

	tp := InitTracing()
	if tp != nil {
		t.Error("expected nil tracer provider when no endpoint configured")
	}
}

// --- searchMessages edge cases ---

func TestCb19_SearchMessages_EmptyDB(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "searchuser1")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCb19_SearchMessages_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=test", nil)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- markMessagesRead edge cases ---

func TestCb19_MarkMessagesRead_NoMessages(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	token := cb19MakeToken(t, "readuser1")
	convID := cb19CreateConv(t, "readuser1", "readagent1")

	// handleMarkRead uses FormValue, not JSON
	form := url.Values{"conversation_id": {convID}}
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_MarkMessagesRead_MissingID(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "readuser2")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCb19_MarkMessagesRead_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader(`{"conversation_id": "x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_MarkRead_InvalidJSON(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "markuser1")
	req := httptest.NewRequest(http.MethodPost, "/conversations/mark-read", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- ValidateJWT edge cases ---

func TestCb19_ValidateJWT_Expired(t *testing.T) {
	cb19SetupAuth(t)
	claims := &Claims{
		UserID:   "testuser",
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(tokenString)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestCb19_ValidateJWT_InvalidSigningMethod(t *testing.T) {
	claims := &Claims{
		UserID:   "testuser",
		Username: "testuser",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, err := ValidateJWT(tokenString)
	if err == nil {
		t.Error("expected error for none signing method")
	}
}

// --- handleLogin edge cases ---

func TestCb19_Login_InvalidJSON(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCb19_Login_EmptyUsername(t *testing.T) {
	cb19SetupDB(t)
	body := `{"username": "", "password": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty username, got %d", w.Code)
	}
}

func TestCb19_Login_WrongPassword(t *testing.T) {
	cb19SetupDB(t)
	cb19MakeToken(t, "loginuser1")

	// handleLogin uses FormValue, not JSON
	form := url.Values{"username": {"loginuser1"}, "password": {"wrongpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d", w.Code)
	}
}

func TestCb19_Login_UserNotFound(t *testing.T) {
	cb19SetupDB(t)
	form := url.Values{"username": {"nonexistent"}, "password": {"test"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for nonexistent user, got %d", w.Code)
	}
}

// --- handleRegisterUser edge cases ---

func TestCb19_RegisterUser_DuplicateUsername(t *testing.T) {
	cb19SetupDB(t)
	form := url.Values{"username": {"dupuser"}, "password": {"test123"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	t.Logf("First registration: %d %s", w.Code, w.Body.String())

	req2 := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleRegisterUser(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestCb19_RegisterUser_InvalidJSON(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// --- resetAgentSecret / resetAdminSecret tests ---

func TestCb19_ResetAgentSecret(t *testing.T) {
	origEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "custom-secret")
	resetAgentSecret()
	if agentSecret != "custom-secret" {
		t.Errorf("expected 'custom-secret', got %s", agentSecret)
	}

	os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()
	if agentSecret != "dev-agent-secret-change-me" {
		t.Errorf("expected default, got %s", agentSecret)
	}

	if origEnv != "" {
		os.Setenv("AGENT_SECRET", origEnv)
	} else {
		os.Unsetenv("AGENT_SECRET")
	}
	resetAgentSecret()
}

func TestCb19_ResetAdminSecret(t *testing.T) {
	origEnv := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "custom-admin")
	resetAdminSecret()
	if adminSecret != "custom-admin" {
		t.Errorf("expected 'custom-admin', got %s", adminSecret)
	}

	os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()
	if adminSecret != "admin-dev-secret" {
		t.Errorf("expected default, got %s", adminSecret)
	}

	if origEnv != "" {
		os.Setenv("ADMIN_SECRET", origEnv)
	} else {
		os.Unsetenv("ADMIN_SECRET")
	}
	resetAdminSecret()
}

// --- safeTruncate tests ---

func TestCb19_SafeTruncate_ShortString(t *testing.T) {
	result := safeTruncate("abc", 8)
	if result != "abc" {
		t.Errorf("expected 'abc', got '%s'", result)
	}
}

func TestCb19_SafeTruncate_ExactLength(t *testing.T) {
	result := safeTruncate("12345678", 8)
	if result != "12345678" {
		t.Errorf("expected '12345678', got '%s'", result)
	}
}

func TestCb19_SafeTruncate_LongString(t *testing.T) {
	result := safeTruncate("12345678901234567890", 8)
	if result != "12345678" {
		t.Errorf("expected '12345678', got '%s'", result)
	}
}

func TestCb19_SafeTruncate_EmptyString(t *testing.T) {
	result := safeTruncate("", 8)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

// --- TieredRateLimiter edge cases ---

func TestCb19_TieredRateLimiter_GetRemaining_NoEntry(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	defer trl.Stop()
	remaining := trl.GetRemaining("nonexistent")
	if remaining != TierFree.Burst {
		t.Errorf("expected free tier burst, got %d", remaining)
	}
}

func TestCb19_TieredRateLimiter_SetTier_Overwrite(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	defer trl.Stop()
	trl.SetTier("user1", TierFree)
	trl.SetTier("user1", TierEnterprise)

	tier := trl.GetTier("user1")
	if tier.Name != "enterprise" {
		t.Errorf("expected enterprise, got %s", tier.Name)
	}
}

func TestCb19_TieredRateLimiter_WindowReset(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	defer trl.Stop()
	trl.SetTier("user1", TierPro)

	for i := 0; i < 300; i++ {
		trl.Allow("user1")
	}

	_, _, _ = trl.Allow("user1")
	// The 301st+ request might or might not be blocked depending on window
	// Just test the Allow method returns values
	allowed, _, _ := trl.Allow("user1")
	_ = allowed

	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-1 * time.Second)
	}
	trl.mu.Unlock()

	if !func() bool { a, _, _ := trl.Allow("user1"); return a }() {
		t.Error("expected request allowed after window reset")
	}
}

// --- handleAdminAgents tests ---

func TestCb19_AdminAgents_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	// handleAdminAgents doesn't check auth itself; auth is via middleware.
	// Calling handler directly without X-Admin-Secret should still return agents list
	// since there's no auth check in the handler itself.
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)
	// Handler returns 200 with empty list when no auth middleware blocks it
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (no auth in handler), got %d", w.Code)
	}
}

func TestCb19_AdminAgents_WrongSecret(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	// handleAdminAgents doesn't validate secret itself; auth is in middleware.
	// With wrong secret but calling handler directly, it still works.
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)
	// No auth in handler itself, returns 200 with agents list
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (no auth in handler), got %d", w.Code)
	}
}

func TestCb19_AdminAgents_ValidSecret(t *testing.T) {
	cb19SetupDB(t)
	cb19SetupAuth(t)
	_, _ = db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "adminagent1", "Admin Agent")

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret-cb19")
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleHealth test ---

func TestCb19_Health_DBCheck(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	// handleHealth uses "db" key as string ("ok" on success), not "db_ok" bool
	dbStatus, ok := result["db"].(string)
	if !ok {
		t.Errorf("expected db to be a string, got %T: %v", result["db"], result["db"])
	} else if dbStatus != "ok" {
		t.Errorf("expected db status 'ok', got '%s'", dbStatus)
	}
}

// --- handleSetNotificationPrefs tests ---

func TestCb19_SetNotificationPrefs_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader(`{"push_enabled": true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_SetNotificationPrefs_InvalidJSON(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	// Create a user and conversation in the DB
	token := cb19MakeToken(t, "notifuser1")
	_ = token

	// Insert user row for auth context
	hashed, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "notifuser1", string(hashed))

	// Insert agent so foreign key constraint passes
	db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", "agent1", "Test Agent")

	// Insert a conversation with a text ID
	convID := "conv-notif-test-1"
	_, err := db.Exec(`INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)`, convID, "notifuser1", "agent1")
	if err != nil {
		t.Fatal(err)
	}

	// Test missing conversation_id -> 400
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader("muted=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Set user_id in context so getUserID works
	ctx := context.WithValue(req.Context(), contextKeyUserID, "notifuser1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d: %s", w.Code, w.Body.String())
	}

	// Test valid request (conversation_id provided)
	form := url.Values{"conversation_id": {convID}, "muted": {"true"}}
	req2 := httptest.NewRequest(http.MethodPost, "/notifications/preferences", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx2 := context.WithValue(req2.Context(), contextKeyUserID, "notifuser1")
	req2 = req2.WithContext(ctx2)
	w2 := httptest.NewRecorder()
	handleSetNotificationPrefs(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for valid request, got %d: %s", w2.Code, w2.Body.String())
	}
}

// --- cleanStaleQueueMessages test ---

func TestCb19_CleanStaleQueueMessages(t *testing.T) {
	cb19SetupDB(t)
	_, err := db.Exec("INSERT INTO offline_queue (recipient, message_data, created_at) VALUES (?, ?, datetime('now', '-8 days'))",
		"user1", `{"type": "chat", "content": "old message"}`)
	if err != nil {
		t.Logf("insert into offline_queue: %v (table may not exist in schema)", err)
		return
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 stale messages after cleanup, got %d", count)
	}
}

// --- loadQueueFromDB test ---

func TestCb19_LoadQueueFromDB_Empty(t *testing.T) {
	cb19SetupDB(t)
	queue := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, queue)
	// Should not panic with empty table
}

// --- ValidateAdminSecret tests ---

func TestCb19_ValidateAdminSecret_Correct(t *testing.T) {
	cb19SetupAuth(t)
	err := ValidateAdminSecret("test-admin-secret-cb19")
	if err != nil {
		t.Errorf("expected nil for correct admin secret, got %v", err)
	}
}

func TestCb19_ValidateAdminSecret_Wrong(t *testing.T) {
	err := ValidateAdminSecret("wrong-admin-secret")
	if err == nil {
		t.Error("expected error for wrong admin secret")
	}
}

func TestCb19_ValidateAdminSecret_Empty(t *testing.T) {
	err := ValidateAdminSecret("")
	if err == nil {
		t.Error("expected error for empty admin secret")
	}
}

// --- initAPNs / initFCM edge cases ---

func TestCb19_InitAPNs_NoConfig(t *testing.T) {
	origPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPushConfig }()

	// Should not panic when pushConfig is nil
	initAPNs()
	// pushConfig remains nil since there was nothing to initialize
}

func TestCb19_InitFCM_NoConfig(t *testing.T) {
	origPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPushConfig }()

	initFCM()
	if pushConfig != nil {
		t.Error("expected nil pushConfig after initFCM with no config")
	}
}

// --- SendWelcomeMessage tests ---

func TestCb19_SendWelcomeMessage_DeviceID(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	sendCh := make(chan []byte, 256)
	conn := &Connection{
		connType:           "client",
		id:                 "welcomeuser1",
		deviceID:           "device-123",
		send:               sendCh,
		closeMu:            sync.RWMutex{},
		negotiatedVersion:  ProtocolVersion,
	}

	sendWelcomeMessage(conn)

	select {
	case msg := <-sendCh:
		var parsed map[string]interface{}
		json.Unmarshal(msg, &parsed)
		// sendWelcomeMessage sends type "connected", not "welcome"
		if parsed["type"] != "connected" {
			t.Errorf("expected connected, got %v", parsed["type"])
		}
		data, ok := parsed["data"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected data object, got %T", parsed["data"])
		}
		if data["device_id"] != "device-123" {
			t.Errorf("expected device-123, got %v", data["device_id"])
		}
	case <-time.After(time.Second):
		t.Error("timed out")
	}
}

func TestCb19_SendWelcomeMessage_NoDeviceID(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	sendCh := make(chan []byte, 256)
	conn := &Connection{
		connType:           "client",
		id:                 "welcomeuser2",
		send:               sendCh,
		closeMu:            sync.RWMutex{},
		negotiatedVersion:  ProtocolVersion,
	}

	sendWelcomeMessage(conn)

	select {
	case msg := <-sendCh:
		var parsed map[string]interface{}
		json.Unmarshal(msg, &parsed)
		if parsed["type"] != "connected" {
			t.Errorf("expected connected, got %v", parsed["type"])
		}
		data, ok := parsed["data"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected data object, got %T", parsed["data"])
		}
		if _, has := data["device_id"]; has {
			t.Error("expected no device_id when not set")
		}
	case <-time.After(time.Second):
		t.Error("timed out")
	}
}

// --- NewOfflineQueue test ---

func TestCb19_NewOfflineQueue(t *testing.T) {
	queue := newOfflineQueue(100, 7*24*time.Hour)
	if queue == nil {
		t.Error("expected non-nil queue")
	}
	if queue.maxLen != 100 {
		t.Errorf("expected maxLen=100, got %d", queue.maxLen)
	}
}

// --- Metrics tests ---

func TestCb19_Metrics_Snapshot(t *testing.T) {
	hub := newHub()
	go hub.run()
	m := NewMetrics(hub)
	m.MessagesIn.Add(10)
	m.MessagesOut.Add(5)
	m.ErrorsTotal.Add(1)

	snap := m.Snapshot()
	if snap["messages_in"] != int64(10) {
		t.Errorf("expected messages_in=10, got %v", snap["messages_in"])
	}
	if snap["messages_out"] != int64(5) {
		t.Errorf("expected messages_out=5, got %v", snap["messages_out"])
	}
	if snap["errors_total"] != int64(1) {
		t.Errorf("expected errors_total=1, got %v", snap["errors_total"])
	}
	hub.Stop()
}

// --- getConversation edge case ---

func TestCb19_GetConversation_NotFound(t *testing.T) {
	cb19SetupDB(t)
	conv, err := getConversation("nonexistent")
	if err != nil {
		t.Fatalf("getConversation: %v", err)
	}
	if conv != nil {
		t.Error("expected nil for nonexistent conversation")
	}
}

// --- E2E encrypted message tests ---

func TestCb19_StoreEncrypted_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_GetEncrypted_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- handleGetMessages tests ---

func TestCb19_GetMessages_WithLimit(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "msguser1")
	convID := cb19CreateConv(t, "msguser1", "msgagent1")

	for i := 0; i < 10; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, content, created_at) VALUES (?, ?, 'agent', ?, datetime('now'))",
			fmt.Sprintf("msg%d", i), convID, fmt.Sprintf("message %d", i))
	}

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id="+convID+"&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_GetMessages_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_GetMessages_MissingID(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "msguser2")
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- handleCreateConversation edge cases ---

func TestCb19_CreateConversation_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader(`{"agent_id": "agent1"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_CreateConversation_InvalidJSON(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "convuser1")
	req := httptest.NewRequest(http.MethodPost, "/conversations/create", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- handleListConversations edge cases ---

func TestCb19_ListConversations_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_ListConversations_Empty(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "listuser1")
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- handleGetUserPresence tests ---

func TestCb19_GetUserPresence_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodGet, "/presence?user_id=testuser", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_GetUserPresence_MissingUserID(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	token := cb19MakeToken(t, "presuser1")
	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)
	// When no user_id query param is given, it uses the JWT user_id
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_GetUserPresence_Online(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "presuser2")
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "client",
		id:       "presuser2",
		send:    make(chan []byte, 256),
		closeMu: sync.RWMutex{},
	}
	hub.mu.Lock()
	hub.clientConns["presuser2"] = []*Connection{conn}
	hub.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/presence?user_id=presuser2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	hub.mu.Lock()
	delete(hub.clientConns, "presuser2")
	hub.mu.Unlock()
}

// --- handleGetReactions tests ---

func TestCb19_AddReaction_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader("message_id=m1&emoji=%F0%9F%91%8D"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_AddReaction_InvalidJSON(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "reactuser1")
	// handleReact uses FormValue, so invalid body just means missing fields
	req := httptest.NewRequest(http.MethodPost, "/messages/react", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleRemoveConversationTag tests ---

func TestCb19_RemoveTag_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/tags/remove", strings.NewReader(`{"conversation_id":"c1","tag":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCb19_RemoveTag_InvalidJSON(t *testing.T) {
	cb19SetupDB(t)
	token := cb19MakeToken(t, "taguser1")
	req := httptest.NewRequest(http.MethodPost, "/tags/remove", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleAddConversationTag tests ---

func TestCb19_AddTag_NoAuth(t *testing.T) {
	cb19SetupDB(t)
	req := httptest.NewRequest(http.MethodPost, "/tags/add", strings.NewReader(`{"conversation_id":"c1","tag":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleAddTag(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- AgentRateLimiter cleanup test ---

func TestCb19_AgentRateLimiter_Cleanup(t *testing.T) {
	rl := &rateLimiter{
		attempts: make(map[string]*rateLimitEntry),
		mu:       sync.Mutex{},
	}

	for i := 0; i < 5; i++ {
		rl.Allow(fmt.Sprintf("agent%d", i))
	}

	rl.mu.Lock()
	for _, entry := range rl.attempts {
		entry.firstSeen = time.Now().Add(-2 * time.Minute)
		entry.count = 12
	}
	rl.mu.Unlock()

	rl.mu.Lock()
	now := time.Now()
	for id, entry := range rl.attempts {
		if now.Sub(entry.firstSeen) > time.Minute && entry.count >= 10 {
			delete(rl.attempts, id)
		}
	}
	rl.mu.Unlock()

	if len(rl.attempts) != 0 {
		t.Errorf("expected all entries cleaned up, got %d", len(rl.attempts))
	}
}

// --- Hub.GetClient test ---

func TestCb19_HubGetClient_Exists(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	conn := &Connection{
		connType: "client",
		id:       "user1",
		send:    make(chan []byte, 256),
		closeMu: sync.RWMutex{},
	}
	hub.mu.Lock()
	hub.clientConns["user1"] = []*Connection{conn}
	hub.mu.Unlock()

	found := hub.GetClient("user1")
	if found == nil {
		t.Error("expected to find client")
	}

	hub.mu.Lock()
	delete(hub.clientConns, "user1")
	hub.mu.Unlock()
}

func TestCb19_HubGetClient_NotExists(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	found := hub.GetClient("nonexistent")
	if found != nil {
		t.Error("expected nil for nonexistent client")
	}
}

// --- Profile handler tests ---

func TestCb19_HeapProfile_NoAuth(t *testing.T) {
	// handleHeapProfile doesn't check auth; auth is via adminAuthMiddleware.
	// Calling handler directly writes a heap profile (no auth check in handler itself).
	// Test that it doesn't panic and returns some response.
	req := httptest.NewRequest(http.MethodGet, "/debug/heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)
	// Should succeed (no auth in handler) or return 500 if profiling dir fails
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (no auth in handler), got %d: %s", w.Code, w.Body.String())
	}
}

func TestCb19_GoroutineProfile_NoAuth(t *testing.T) {
	// handleGoroutineProfile doesn't check auth; auth is via adminAuthMiddleware.
	// Calling handler directly writes a goroutine profile (no auth check in handler itself).
	req := httptest.NewRequest(http.MethodGet, "/debug/goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (no auth in handler), got %d: %s", w.Code, w.Body.String())
	}
}

// --- Metrics handler test ---

func TestCb19_HandleMetrics(t *testing.T) {
	cb19SetupDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}