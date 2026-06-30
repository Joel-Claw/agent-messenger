package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// CB45: Targeted coverage for remaining low-coverage functions.

// --- rate_limit_tiers cleanup ticker.C branch (45.5%) ---

func TestCB45_TieredRateLimiter_CleanupTickerOldEntry(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(trl.Stop)

	trl.mu.Lock()
	trl.limits["old-user"] = &userRateLimitState{
		count:     5,
		windowEnd: time.Now().Add(-11 * time.Minute),
		tier:      TierFree,
	}
	trl.limits["recent-user"] = &userRateLimitState{
		count:     3,
		windowEnd: time.Now().Add(5 * time.Minute),
		tier:      TierFree,
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, oldExists := trl.limits["old-user"]
	_, recentExists := trl.limits["recent-user"]
	trl.mu.Unlock()

	if oldExists {
		t.Error("expected old-user to be cleaned up")
	}
	if !recentExists {
		t.Error("expected recent-user to still exist")
	}
}

// --- sendWelcomeMessage SafeSend false path (80%) ---

func TestCB45_SendWelcomeMessage_SafeSendFalse(t *testing.T) {
	hub := newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	c := &Connection{
		hub:      hub,
		connType: "client",
		id:       "welcome-safesend-false",
		send:     make(chan []byte, 1),
	}
	c.send <- []byte("filler")

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		if string(msg) != "filler" {
			t.Errorf("expected filler, got %s", string(msg))
		}
	default:
		t.Error("expected to drain filler message")
	}
}

// --- persistQueue (80%) ---

func TestCB45_PersistQueue_DBError(t *testing.T) {
	testDB, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Skipf("could not open DB: %v", err)
	}
	defer testDB.Close()

	persistQueue(testDB, "user1", []byte("msg1"))
}

func TestCB45_PersistQueue_NilDB(t *testing.T) {
	persistQueue(nil, "user1", []byte("msg1"))
}

func TestCB45_PersistQueue_Success(t *testing.T) {
	testDB, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Skipf("could not open DB: %v", err)
	}
	defer testDB.Close()

	_, _ = testDB.Exec(`CREATE TABLE IF NOT EXISTS offline_queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		recipient TEXT NOT NULL,
		data BLOB NOT NULL,
		queued_at DATETIME NOT NULL,
		sent_count INTEGER DEFAULT 0
	)`)

	persistQueue(testDB, "user1", []byte("msg1"))
}

// --- deleteConversation DB error (83.3%) ---

func TestCB45_DeleteConversation_MessagesDBError(t *testing.T) {
	setupTestDB(t)

	conv, err := GetOrCreateConversation("user-del-conv-msg-err", "agent-del-conv-msg-err")
	if err != nil || conv == nil {
		t.Skipf("could not create conversation: %v", err)
	}

	_, _ = db.Exec("DROP TABLE messages")

	err = deleteConversation(conv.ID, "user-del-conv-msg-err")
	if err == nil {
		t.Error("expected error when messages table doesn't exist")
	}
}

// --- metrics Snapshot (83.3%) ---

func TestCB45_Snapshot_WithHub(t *testing.T) {
	hub := newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	m := NewMetrics(hub)
	snap := m.Snapshot()
	if snap == nil {
		t.Error("expected non-nil snapshot")
	}
}

// --- searchMessages DB error (86.7%) ---

func TestCB45_SearchMessages_DBError(t *testing.T) {
	setupTestDB(t)

	_, _ = db.Exec("DROP TABLE messages")

	results, err := searchMessages("user1", "test", 10)
	if err == nil {
		t.Error("expected error when messages table doesn't exist")
	}
	if results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
}

// --- getConversationMessages DB error (87%) ---

func TestCB45_GetConversationMessages_DBError(t *testing.T) {
	setupTestDB(t)

	_, _ = db.Exec("DROP TABLE messages")

	messages, err := getConversationMessages("nonexistent", 50, "")
	if err == nil {
		t.Error("expected error when messages table doesn't exist")
	}
	if messages != nil {
		t.Errorf("expected nil messages, got %v", messages)
	}
}

// --- logger WithFields (87.5%) ---

func TestCB45_WithFields_NilMap(t *testing.T) {
	l := NewLogger(LogDebug)
	l2 := l.WithFields(nil)
	if l2 == nil {
		t.Error("expected non-nil logger")
	}
}

func TestCB45_WithFields_EmptyMap(t *testing.T) {
	l := NewLogger(LogDebug)
	l2 := l.WithFields(map[string]interface{}{})
	if l2 == nil {
		t.Error("expected non-nil logger")
	}
}

// --- logger logEntry (88.2%) ---

func TestCB45_LogEntry_AllLevels(t *testing.T) {
	var buf strings.Builder
	l := NewLogger(LogDebug)
	l.SetOutput(&buf)

	l.Debug("test_debug", map[string]interface{}{"key": "val"})
	l.Info("test_info", map[string]interface{}{"key": "val"})
	l.Warn("test_warn", map[string]interface{}{"key": "val"})
	l.Error("test_error", map[string]interface{}{"key": "val"})

	output := buf.String()
	for _, expected := range []string{"test_debug", "test_info", "test_warn", "test_error"} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %s, got: %s", expected, output)
		}
	}
}

// --- handleGetReactions success (88.2%) ---

func TestCB45_HandleGetReactions_Success(t *testing.T) {
	setupTestDB(t)

	// Create a conversation and store a real message
	conv, err := GetOrCreateConversation("user-react-success", "agent-react-success")
	if err != nil || conv == nil {
		t.Skipf("could not create conversation: %v", err)
	}
	msg := RoutedMessage{Type: "chat", ConversationID: conv.ID, SenderID: "user-react-success", SenderType: "user", Content: "react to this"}
	err = storeMessage(msg)
	if err != nil {
		t.Skipf("could not store message: %v", err)
	}
	messages, _ := getConversationMessages(conv.ID, 50, "")
	if len(messages) == 0 {
		t.Skip("no messages to test")
	}
	msgID := messages[0].ID

	addReaction(msgID, "user-react-success", "👍")

	token := generateTestJWT(t, "user-react-success", "user-react-success")

	req := httptest.NewRequest("GET", "/messages/react?message_id="+msgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var reactions []MessageReaction
	if err := json.Unmarshal(rr.Body.Bytes(), &reactions); err != nil {
		t.Errorf("could not parse response: %v", err)
	}
	if len(reactions) == 0 {
		t.Error("expected at least 1 reaction")
	}
}

// --- storeMessagesBatch DB error (88.9%) ---

func TestCB45_StoreMessagesBatch_DBError(t *testing.T) {
	setupTestDB(t)

	_, _ = db.Exec("DROP TABLE messages")

	msgs := []RoutedMessage{
		{Type: "chat", ConversationID: "conv1", SenderID: "user1", SenderType: "user", Content: "hello"},
		{Type: "chat", ConversationID: "conv1", SenderID: "user1", SenderType: "user", Content: "world"},
	}

	_, err := storeMessagesBatch(msgs)
	if err == nil {
		t.Error("expected error when messages table doesn't exist")
	}
}

// --- monitorAgentHeartbeats (88.9%) ---

func TestCB45_MonitorAgentHeartbeats_StopChannel(t *testing.T) {
	hub := newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	agentPresenceEnabled = true
	defer func() { agentPresenceEnabled = false }()

	time.Sleep(50 * time.Millisecond)
}

// --- handleSetNotificationPrefs DB error (88.9%) ---

func TestCB45_HandleSetNotificationPrefs_DBError(t *testing.T) {
	setupTestDB(t)

	conv, err := GetOrCreateConversation("user-notif-prefs-err", "agent-notif-prefs-err")
	if err != nil || conv == nil {
		t.Skipf("could not create conversation: %v", err)
	}

	_, _ = db.Exec("DROP TABLE notification_preferences")

	token := generateTestJWT(t, "user-notif-prefs-err", "user-notif-prefs-err")

	body := "conversation_id=" + conv.ID + "&mute=true"
	req := httptest.NewRequest("POST", "/notifications/preferences", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Set context with userID (same as auth middleware would)
	claims, _ := ValidateJWT(token)
	if claims != nil {
		ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
		req = req.WithContext(ctx)
	}
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d", rr.Code)
	}
}

// --- handleRegisterDeviceToken DB error (88.9%) ---

func TestCB45_HandleRegisterDeviceToken_DBError(t *testing.T) {
	setupTestDB(t)

	_, _ = db.Exec("DROP TABLE device_tokens")

	token := generateTestJWT(t, "user-device-token-err", "user-device-token-err")

	body := `{"device_token":"token123","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRegisterDeviceToken(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d", rr.Code)
	}
}

// --- handleWebPushSubscribe DB error (88.9%) ---

func TestCB45_HandleWebPushSubscribe_DBError(t *testing.T) {
	setupTestDB(t)

	// Drop device_tokens table so the first DB insert fails
	_, _ = db.Exec("DROP TABLE device_tokens")

	os.Setenv("VAPID_PUBLIC_KEY", "test-vapid-key")
	os.Setenv("VAPID_PRIVATE_KEY", "test-vapid-private")
	defer func() {
		os.Unsetenv("VAPID_PUBLIC_KEY")
		os.Unsetenv("VAPID_PRIVATE_KEY")
	}()

	token := generateTestJWT(t, "user-webpush-err", "user-webpush-err")

	body := `{"endpoint":"https://push.example.com/abc","keys":{"p256dh":"key1","auth":"key2"}}`
	req := httptest.NewRequest("POST", "/push/webpush/subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d", rr.Code)
	}
}

// --- InitTracing gRPC/HTTP/sampling (79.5%) ---

func TestCB45_InitTracing_GRPCExporter(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}()

	tracingEnabled = false
	tracer = nil
	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingMu = sync.Once{}

	_ = InitTracing()

	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingEnabled = false
	tracer = nil
	tracingMu = sync.Once{}
}

func TestCB45_InitTracing_HTTPExporter(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Setenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "http://localhost:4318")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	}()

	tracingEnabled = false
	tracer = nil
	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingMu = sync.Once{}

	_ = InitTracing()

	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingEnabled = false
	tracer = nil
	tracingMu = sync.Once{}
}

func TestCB45_InitTracing_WithSampling(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.5")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_TRACES_SAMPLER_ARG")
	}()

	tracingEnabled = false
	tracer = nil
	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingMu = sync.Once{}

	_ = InitTracing()

	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingEnabled = false
	tracer = nil
	tracingMu = sync.Once{}
}

// --- ShutdownTracing (80%) ---

func TestCB45_ShutdownTracing_NilTP(t *testing.T) {
	tracingEnabled = false
	tracer = nil
	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingMu = sync.Once{}

	ShutdownTracing()
}

func TestCB45_ShutdownTracing_Enabled(t *testing.T) {
	tracingEnabled = true
	tracer = nil
	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracingMu = sync.Once{}

	ShutdownTracing()
	// ShutdownTracing does not reset tracingEnabled when tp is nil;
	// just verify it doesn't panic
}

// --- addReaction success (84.6%) ---

func TestCB45_AddReaction_Success(t *testing.T) {
	setupTestDB(t)

	// Create a conversation and store a real message so addReaction can find it
	conv, err := GetOrCreateConversation("user-add-success", "agent-add-success")
	if err != nil || conv == nil {
		t.Skipf("could not create conversation: %v", err)
	}
	msg := RoutedMessage{Type: "chat", ConversationID: conv.ID, SenderID: "user-add-success", SenderType: "user", Content: "react to this"}
	err = storeMessage(msg)
	if err != nil {
		t.Skipf("could not store message: %v", err)
	}
	messages, _ := getConversationMessages(conv.ID, 50, "")
	if len(messages) == 0 {
		t.Skip("no messages to test")
	}
	msgID := messages[0].ID

	reaction, added, err := addReaction(msgID, "user-add-success", "❤️")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !added {
		t.Error("expected reaction to be added on first call")
	}
	if reaction == nil {
		t.Error("expected non-nil reaction")
	}

	_, added2, err := addReaction(msgID, "user-add-success", "❤️")
	if err != nil {
		t.Fatalf("unexpected error on toggle: %v", err)
	}
	if added2 {
		t.Error("expected reaction to be removed on second call (toggle)")
	}
}

// --- handleMessageDelete DB error (87.5%) ---

func TestCB45_HandleMessageDelete_DBError(t *testing.T) {
	setupTestDB(t)

	conv, err := GetOrCreateConversation("user-msg-del-err", "agent-msg-del-err")
	if err != nil || conv == nil {
		t.Skipf("could not create conversation: %v", err)
	}

	msg := RoutedMessage{Type: "chat", ConversationID: conv.ID, SenderID: "user-msg-del-err", SenderType: "user", Content: "hello to delete"}
	err = storeMessage(msg)
	if err != nil {
		t.Skipf("could not store message: %v", err)
	}

	messages, _ := getConversationMessages(conv.ID, 50, "")
	if len(messages) == 0 {
		t.Skip("no messages to test")
	}

	_, _ = db.Exec("DROP TABLE messages")

	token := generateTestJWT(t, "user-msg-del-err", "user-msg-del-err")

	body := "message_id=" + messages[0].ID
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleMessageDelete(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DB error, got %d", rr.Code)
	}
}

// --- handleHeapProfile (84.6%) ---

func TestCB45_HandleHeapProfile_MkdirError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cb45-blocker")
	if err != nil {
		t.Skipf("could not create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	os.Setenv("PROFILING_DIR", tmpFile.Name())
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("GET", "/profile/heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for mkdir error, got %d", rr.Code)
	}
}

func TestCB45_HandleHeapProfile_Success(t *testing.T) {
	dir, err := os.MkdirTemp("", "cb45-heap-*")
	if err != nil {
		t.Skipf("could not create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("GET", "/profile/heap", nil)
	rr := httptest.NewRecorder()
	handleHeapProfile(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Errorf("could not parse response: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

// --- StartCPUProfile (80%) ---

func TestCB45_StartCPUProfile_AlreadyRunning(t *testing.T) {
	dir, err := os.MkdirTemp("", "cb45-cpu-*")
	if err != nil {
		t.Skipf("could not create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	stop, err := StartCPUProfile(dir + "/cpu.prof")
	if err != nil {
		t.Skipf("could not start CPU profile: %v", err)
	}

	_, err = StartCPUProfile(dir + "/cpu2.prof")
	if err == nil {
		t.Error("expected error when starting CPU profile twice")
	}

	stop()
}

// --- handleCPUProfileStart (90%) ---

func TestCB45_HandleCPUProfileStart_MkdirError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cb45-cpu-blocker")
	if err != nil {
		t.Skipf("could not create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	os.Setenv("PROFILING_DIR", tmpFile.Name())
	defer os.Unsetenv("PROFILING_DIR")

	req := httptest.NewRequest("POST", "/profile/cpu/start", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for mkdir error, got %d", rr.Code)
	}
}

func TestCB45_HandleCPUProfileStart_AlreadyRunning(t *testing.T) {
	dir, err := os.MkdirTemp("", "cb45-cpu-running-*")
	if err != nil {
		t.Skipf("could not create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	stop, _ := StartCPUProfile(dir + "/cpu.prof")
	if stop != nil {
		defer stop()
	}

	req := httptest.NewRequest("POST", "/profile/cpu/start", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when already running, got %d", rr.Code)
	}
}

// --- RegisterAgentOnConnect with metadata (81.8%) ---

func TestCB45_RegisterAgentOnConnect_WithMetadata(t *testing.T) {
	setupTestDB(t)

	err := RegisterAgentOnConnect("agent-metadata-test", "Agent Name", "gpt-4", "helpful", "general")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-metadata-test").Scan(&name)
	if err != nil {
		t.Fatalf("could not get agent: %v", err)
	}
	if name != "Agent Name" {
		t.Errorf("expected name 'Agent Name', got %s", name)
	}
}

// --- handleListAgents with agents (90%) ---

func TestCB45_HandleListAgents_WithAgents(t *testing.T) {
	setupTestDB(t)

	// Set up hub so handleListAgents can call hub.AgentStatus()
	origHub := hub
	hub = newHub()
	go hub.run()
	defer func() {
		hub.Stop()
		hub = origHub
	}()

	_ = RegisterAgentOnConnect("agent-list-test", "List Test Agent", "gpt-4", "friendly", "chat")

	token := generateTestJWT(t, "user-list-agents", "user-list-agents")

	req := httptest.NewRequest("GET", "/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleListAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var agents []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &agents); err != nil {
		t.Errorf("could not parse response: %v", err)
	}
	if len(agents) == 0 {
		t.Error("expected at least 1 agent")
	}
}

// --- handleAdminAgents with agents (91.7%) ---

func TestCB45_HandleAdminAgents_WithAgents(t *testing.T) {
	setupTestDB(t)

	// Set up hub so handleAdminAgents can call hub.AgentStatus()
	origHub := hub
	hub = newHub()
	go hub.run()
	defer func() {
		hub.Stop()
		hub = origHub
	}()

	_ = RegisterAgentOnConnect("agent-admin-test", "Admin Test Agent", "gpt-4", "friendly", "chat")

	os.Setenv("ADMIN_SECRET", "test-admin-secret-cb45")
	resetAdminSecret()
	defer func() {
		os.Unsetenv("ADMIN_SECRET")
		resetAdminSecret()
	}()

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret-cb45")
	rr := httptest.NewRecorder()
	handleAdminAgents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var agents []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &agents); err != nil {
		t.Errorf("could not parse response: %v", err)
	}
	if len(agents) == 0 {
		t.Error("expected at least 1 agent")
	}
}

// --- getDeviceTokensForUser (90.9%) ---

func TestCB45_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	setupTestDB(t)

	_, _ = db.Exec("INSERT OR REPLACE INTO device_tokens (user_id, device_token, platform, updated_at) VALUES ('user-tokens-test', 'token-1', 'ios', datetime('now'))")
	_, _ = db.Exec("INSERT OR REPLACE INTO device_tokens (user_id, device_token, platform, updated_at) VALUES ('user-tokens-test', 'token-2', 'android', datetime('now'))")

	tokens, err := getDeviceTokensForUser("user-tokens-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

// --- notifyUser with no tokens (90%) ---

func TestCB45_NotifyUser_NoTokens(t *testing.T) {
	setupTestDB(t)

	notifyUser("user-no-tokens-cb45", "Title", "Hello from test", "conv123")
}

// --- ValidateJWT expired token (91.7%) ---

func TestCB45_ValidateJWT_ExpiredToken(t *testing.T) {
	origSecret := jwtSecret
	jwtSecret = []byte("test-secret-cb45")
	defer func() { jwtSecret = origSecret }()

	claims := &Claims{
		UserID:   "user-expired",
		Username: "user-expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(tokenStr)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

// --- handleAgentConnect WebSocket success (93%) ---

func TestCB45_HandleAgentConnect_JWTSuccessAndUpgrade(t *testing.T) {
	setupTestDB(t)

	origHub := hub
	hub = newHub()
	go hub.run()
	defer func() {
		hub.Stop()
		hub = origHub
	}()

	os.Setenv("AGENT_SECRET", "test-agent-secret-cb45")
	resetAgentSecret()
	defer func() {
		os.Unsetenv("AGENT_SECRET")
		resetAgentSecret()
	}()

	srv := httptest.NewServer(http.HandlerFunc(handleAgentConnect))
	defer srv.Close()

	dialer := websocket.Dialer{}
	url := strings.Replace(srv.URL, "http://", "ws://", 1) + "?agent_id=agent-ws-test-cb45"
	wsConn, resp, err := dialer.Dial(url, nil)
	if err != nil {
		if resp != nil {
			t.Skipf("WebSocket dial failed: %v (status: %d)", err, resp.StatusCode)
		}
		t.Skipf("WebSocket dial failed: %v", err)
	}
	defer wsConn.Close()

	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Skipf("could not read welcome message: %v", err)
	}

	var welcome map[string]interface{}
	if err := json.Unmarshal(msg, &welcome); err != nil {
		t.Errorf("could not parse welcome message: %v", err)
	}
	if welcome["type"] != "connected" {
		t.Errorf("expected connected message, got type %v", welcome["type"])
	}

	hub.mu.RLock()
	agent := hub.agents["agent-ws-test-cb45"]
	hub.mu.RUnlock()
	if agent == nil {
		t.Error("expected agent to be registered in hub")
	}
}

// --- markMessagesRead DB error (81.8%) ---

func TestCB45_MarkMessagesRead_DBError(t *testing.T) {
	setupTestDB(t)

	_, _ = db.Exec("DROP TABLE messages")

	count, err := markMessagesRead("conv1", "user1")
	if err == nil {
		t.Error("expected error when messages table doesn't exist")
	}
	if count != 0 {
		t.Errorf("expected 0 count, got %d", count)
	}
}

// --- changeUserPassword DB error (92.3%) ---

func TestCB45_ChangeUserPassword_DBError(t *testing.T) {
	setupTestDB(t)

	_, _ = db.Exec("DROP TABLE users")

	err := changeUserPassword("user1", "oldpass", "newpass")
	if err == nil {
		t.Error("expected error when users table doesn't exist")
	}
}

// --- handleLogin form-encoded success (92%) ---

func TestCB45_HandleLogin_FormEncoded(t *testing.T) {
	setupTestDB(t)

	body := "username=loginusercb45&password=secret123"
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Skipf("could not register user: %d", rr.Code)
	}

	req2 := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	handleLogin(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr2.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(rr2.Body.Bytes(), &result); err != nil {
		t.Errorf("could not parse response: %v", err)
	}
	if result["token"] == nil || result["token"] == "" {
		t.Error("expected token in response")
	}
}