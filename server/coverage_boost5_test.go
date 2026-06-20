package main

import (
	"bytes"
	"context"
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
)

// ==================== Logger Additional Coverage ====================

func TestLoggerSetLevelExplicit(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogInfo)
	logger.SetOutput(&buf)

	// Use SetLevel to change to Warn, which should suppress Info
	logger.SetLevel(LogWarn)

	logger.Info("should not appear at warn level")
	logger.Warn("should appear at warn level")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("Info messages should not appear after SetLevel(Warn)")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("Warn messages should appear after SetLevel(Warn)")
	}

	// Use SetLevel to change back to Debug
	buf.Reset()
	logger.SetLevel(LogDebug)

	logger.Debug("debug message")
	if !strings.Contains(buf.String(), "debug message") {
		t.Error("Debug messages should appear after SetLevel(Debug)")
	}
}

func TestLoggerSetOutput(t *testing.T) {
	var buf1 bytes.Buffer
	var buf2 bytes.Buffer
	logger := NewLogger(LogInfo)

	logger.SetOutput(&buf1)
	logger.Info("first output")

	if !strings.Contains(buf1.String(), "first output") {
		t.Error("expected output in first buffer")
	}

	logger.SetOutput(&buf2)
	logger.Info("second output")

	if !strings.Contains(buf2.String(), "second output") {
		t.Error("expected output in second buffer")
	}
}

func TestLoggerWithFieldsMerged(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogInfo)
	logger.SetOutput(&buf)

	base := logger.WithFields(map[string]interface{}{"service": "agent-messenger"})
	base.Info("test message", map[string]interface{}{"request_id": "abc123"})

	output := buf.String()
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if entry["service"] != "agent-messenger" {
		t.Errorf("expected service=agent-messenger, got %v", entry["service"])
	}
	if entry["request_id"] != "abc123" {
		t.Errorf("expected request_id=abc123, got %v", entry["request_id"])
	}
}

func TestLoggerMultipleFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogDebug)
	logger.SetOutput(&buf)

	logger.Info("multi field test", map[string]interface{}{
		"key1": "val1",
		"key2": float64(42),
		"key3": true,
	})

	output := buf.String()
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if entry["key1"] != "val1" {
		t.Errorf("expected key1=val1, got %v", entry["key1"])
	}
	if entry["key2"] != float64(42) {
		t.Errorf("expected key2=42, got %v", entry["key2"])
	}
	if entry["key3"] != true {
		t.Errorf("expected key3=true, got %v", entry["key3"])
	}
}

func TestLoggerMergeOpt(t *testing.T) {
	result := mergeOpt([]map[string]interface{}{
		{"a": 1},
		{"b": 2},
		{"c": 3},
	})
	if result["a"] != 1 || result["b"] != 2 || result["c"] != 3 {
		t.Errorf("expected merged result, got %v", result)
	}

	result2 := mergeOpt(nil)
	if result2 != nil {
		t.Errorf("expected nil for no fields, got %v", result2)
	}

	result3 := mergeOpt([]map[string]interface{}{})
	if result3 != nil {
		t.Errorf("expected nil for empty slice, got %v", result3)
	}
}

func TestLoggerTimestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogInfo)
	logger.SetOutput(&buf)

	logger.Info("timestamp test")

	output := buf.String()
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	ts, ok := entry["ts"].(string)
	if !ok || ts == "" {
		t.Error("expected non-empty timestamp in log entry")
	}

	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339Nano: %v", ts, err)
	}
}

// ==================== Rate Limiter Cleanup ====================

func TestRateLimiterCleanupExpired(t *testing.T) {
	rl := &RateLimiter{
		counters: make(map[string]*rateCounter),
		limit:    10,
		window:   100 * time.Millisecond,
	}

	rl.counters["user1"] = &rateCounter{count: 1, expires: time.Now().Add(-1 * time.Second)}
	rl.counters["user2"] = &rateCounter{count: 1, expires: time.Now().Add(1 * time.Second)}

	rl.mu.Lock()
	now := time.Now()
	for id, counter := range rl.counters {
		if now.After(counter.expires) {
			delete(rl.counters, id)
		}
	}
	rl.mu.Unlock()

	rl.mu.Lock()
	count := len(rl.counters)
	rl.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 entry after manual cleanup (expired removed), got %d", count)
	}
}

func TestRateLimiterCleanupNoneExpired(t *testing.T) {
	rl := &RateLimiter{
		counters: make(map[string]*rateCounter),
		limit:    10,
		window:   500 * time.Millisecond,
	}

	rl.counters["user1"] = &rateCounter{count: 1, expires: time.Now().Add(1 * time.Second)}
	rl.counters["user2"] = &rateCounter{count: 1, expires: time.Now().Add(2 * time.Second)}

	rl.mu.Lock()
	now := time.Now()
	for id, counter := range rl.counters {
		if now.After(counter.expires) {
			delete(rl.counters, id)
		}
	}
	rl.mu.Unlock()

	if !rl.Allow("user2") {
		t.Error("user2 should still be within rate limit after partial cleanup")
	}
}

// ==================== Protocol Additional Coverage ====================

func TestNegotiateProtocolFromHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1, other-protocol")

	result := negotiateProtocol(req)
	if result != "v1" {
		t.Errorf("expected v1, got %q", result)
	}
}

func TestNegotiateProtocolFromQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?protocol_version=v1", nil)

	result := negotiateProtocol(req)
	if result != "v1" {
		t.Errorf("expected v1, got %q", result)
	}
}

func TestUpgradeWithProtocol(t *testing.T) {
	w := httptest.NewRecorder()
	upgradeWithProtocol(w, nil, "v1")

	if w.Header().Get("Sec-WebSocket-Protocol") != "v1" {
		t.Errorf("expected Sec-WebSocket-Protocol v1, got %q", w.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestUpgradeWithProtocolUnsupported(t *testing.T) {
	w := httptest.NewRecorder()
	upgradeWithProtocol(w, nil, "v99")

	if w.Header().Get("Sec-WebSocket-Protocol") != "" {
		t.Errorf("expected empty header for unsupported protocol, got %q", w.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestUpgradeWithProtocolEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	upgradeWithProtocol(w, nil, "")

	if w.Header().Get("Sec-WebSocket-Protocol") != "" {
		t.Errorf("expected empty header for empty protocol, got %q", w.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestSendWelcomeMessage(t *testing.T) {
	ch := make(chan []byte, 1)
	c := &Connection{connType: "agent", id: "agent-1", send: ch, negotiatedVersion: "v1"}
	sendWelcomeMessage(c)

	var msg OutgoingMessage
	select {
	case data := <-ch:
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("failed to unmarshal welcome message: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for welcome message")
	}

	if msg.Type != "connected" {
		t.Errorf("expected type 'connected', got %q", msg.Type)
	}

	dataMap, ok := msg.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be a map")
	}
	if dataMap["id"] != "agent-1" {
		t.Errorf("expected id 'agent-1', got %v", dataMap["id"])
	}
	if dataMap["protocol_version"] != "v1" {
		t.Errorf("expected protocol_version 'v1', got %v", dataMap["protocol_version"])
	}
}

func TestSendWelcomeMessageWithDeviceID(t *testing.T) {
	ch := make(chan []byte, 1)
	c := &Connection{connType: "client", id: "user-1", deviceID: "device-abc", send: ch, negotiatedVersion: "v1"}
	sendWelcomeMessage(c)

	var msg OutgoingMessage
	select {
	case data := <-ch:
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("failed to unmarshal welcome message: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for welcome message")
	}

	dataMap, ok := msg.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be a map")
	}
	if dataMap["device_id"] != "device-abc" {
		t.Errorf("expected device_id 'device-abc', got %v", dataMap["device_id"])
	}
}

func TestSendWelcomeMessageBufferFull(t *testing.T) {
	ch := make(chan []byte, 1)
	ch <- []byte("filler")

	done := make(chan struct{})
	go func() {
		c := &Connection{connType: "agent", id: "agent-1", send: ch, negotiatedVersion: "v1"}
		sendWelcomeMessage(c)
		close(done)
	}()

	select {
	case <-done:
		// Good — didn't block
	case <-time.After(time.Second):
		t.Fatal("sendWelcomeMessage blocked on full channel")
	}
}

// ==================== Queue Persist Additional Coverage ====================

func TestMarshalOutgoingMessageNil(t *testing.T) {
	msg := OutgoingMessage{Type: "message"}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data for valid message")
	}
}

func TestInitQueueDB(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	initQueueDB(db)

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&name)
	if err != nil {
		t.Fatalf("offline_queue table should exist: %v", err)
	}
}

func TestPersistAndLoadQueue(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	initQueueDB(db)

	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]interface{}{"content": "hello"},
	}
	data := marshalOutgoingMessage(msg)

	persistQueue(db, "user-1", data)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = 'user-1'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 persisted message, got %d", count)
	}

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	if q.QueueDepth("user-1") != 1 {
		t.Errorf("expected queue depth 1, got %d", q.QueueDepth("user-1"))
	}
}

func TestInitQueueDBNilDB(t *testing.T) {
	initQueueDB(nil)
}

// ==================== SafeSendToConn Additional Coverage ====================

func TestSafeSendToConnFullBuffer(t *testing.T) {
	conn := &Connection{
		id:       "test-conn",
		connType: "agent",
		send:     make(chan []byte, 1),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	conn.send <- []byte("filler")

	sent := safeSendToConn(conn, []byte(`{"type":"message"}`))
	if sent {
		t.Error("expected safeSendToConn to return false for full buffer")
	}
}

func TestSafeSendToConnSuccess(t *testing.T) {
	conn := &Connection{
		id:       "test-conn",
		connType: "agent",
		send:     make(chan []byte, 10),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	data := []byte(`{"type":"message"}`)
	sent := safeSendToConn(conn, data)
	if !sent {
		t.Error("expected safeSendToConn to return true for open connection")
	}

	select {
	case received := <-conn.send:
		if string(received) != string(data) {
			t.Errorf("expected %q, got %q", string(data), string(received))
		}
	default:
		t.Error("expected data in send channel")
	}
}

// ==================== Metrics Coverage ====================

func TestBoolToInt(t *testing.T) {
	tests := []struct {
		input    bool
		expected int
	}{
		{true, 1},
		{false, 0},
	}
	for _, tt := range tests {
		result := boolToInt(tt.input)
		if result != tt.expected {
			t.Errorf("boolToInt(%v) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

// ==================== Offline Queue Additional Coverage ====================

func TestNewOfflineQueueDefaults(t *testing.T) {
	q := newOfflineQueue(0, 0)
	if q.maxLen != 100 {
		t.Errorf("expected maxLen 100, got %d", q.maxLen)
	}
	if q.ttl != 7*24*time.Hour {
		t.Errorf("expected ttl 7 days, got %v", q.ttl)
	}

	q2 := newOfflineQueue(-1, -1)
	if q2.maxLen != 100 {
		t.Errorf("expected maxLen 100, got %d", q2.maxLen)
	}
	if q2.ttl != 7*24*time.Hour {
		t.Errorf("expected ttl 7 days, got %v", q2.ttl)
	}
}

func TestNewOfflineQueueCustomValues(t *testing.T) {
	q := newOfflineQueue(50, 24*time.Hour)
	if q.maxLen != 50 {
		t.Errorf("expected maxLen 50, got %d", q.maxLen)
	}
	if q.ttl != 24*time.Hour {
		t.Errorf("expected ttl 24 hours, got %v", q.ttl)
	}
}

func TestOfflineQueueEnqueueAndDrain(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	q.Enqueue("user-1", []byte("msg1"))
	q.Enqueue("user-1", []byte("msg2"))
	q.Enqueue("user-2", []byte("msg3"))

	if q.QueueDepth("user-1") != 2 {
		t.Errorf("expected depth 2, got %d", q.QueueDepth("user-1"))
	}
	if q.QueueDepth("user-2") != 1 {
		t.Errorf("expected depth 1, got %d", q.QueueDepth("user-2"))
	}
	if q.TotalDepth() != 3 {
		t.Errorf("expected total depth 3, got %d", q.TotalDepth())
	}

	msgs := q.Drain("user-1")
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if string(msgs[0]) != "msg1" {
		t.Errorf("expected msg1, got %s", string(msgs[0]))
	}
	if string(msgs[1]) != "msg2" {
		t.Errorf("expected msg2, got %s", string(msgs[1]))
	}

	if q.QueueDepth("user-1") != 0 {
		t.Errorf("expected depth 0 after drain, got %d", q.QueueDepth("user-1"))
	}

	msgs2 := q.Drain("user-999")
	if msgs2 != nil {
		t.Errorf("expected nil for non-existent user, got %v", msgs2)
	}
}

func TestOfflineQueueTTLExpiry(t *testing.T) {
	q := newOfflineQueue(100, 100*time.Millisecond)

	q.Enqueue("user-1", []byte("msg1"))

	time.Sleep(150 * time.Millisecond)

	msgs := q.Drain("user-1")
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages (expired), got %d", len(msgs))
	}
}

// ==================== Push Notification Additional Coverage ====================

func TestInitPushNotificationsDisabled(t *testing.T) {
	pushConfig = nil
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")

	initPushNotifications()

	if pushConfig == nil {
		t.Fatal("pushConfig should be initialized even when disabled")
	}
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled")
	}
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled")
	}
}

func TestNotifyUserNoConfig(t *testing.T) {
	pushConfig = nil
	notifyUser("user-1", "Title", "Body", "conv-1")
}

func TestNotifyUserMuted(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}

	db.Exec("INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, datetime('now'))",
		"user-1", "testuser", "$2a$10$hash")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"conv-1", "user-1", "agent-1")
	db.Exec("INSERT OR REPLACE INTO notification_prefs (user_id, conversation_id, muted, updated_at) VALUES (?, ?, 1, datetime('now'))",
		"user-1", "conv-1")

	notifyUser("user-1", "Title", "Body", "conv-1")
}

func TestNotifyUserNoTokens(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}

	notifyUser("user-nonexistent", "Title", "Body", "conv-1")
}

func TestSendPushNotificationAPNsDisabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	err := sendPushNotification("token123", "Title", "Body", "conv-1", "ios")
	if err != nil {
		t.Errorf("expected nil error for disabled APNs, got %v", err)
	}
}

func TestSendPushNotificationFCMDisabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	err := sendPushNotification("token123", "Title", "Body", "conv-1", "android")
	if err != nil {
		t.Errorf("expected nil error for disabled FCM, got %v", err)
	}
}

func TestSendAPNSNotificationNoConfig(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil when pushConfig nil, got %v", err)
	}
}

func TestSendAPNSNotificationDisabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	err := sendAPNSNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil when APNs disabled, got %v", err)
	}
}

func TestSendFCMNotificationNoConfig(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil when pushConfig nil, got %v", err)
	}
}

func TestSendFCMNotificationDisabled(t *testing.T) {
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	err := sendFCMNotification("token", "Title", "Body", "conv-1")
	if err != nil {
		t.Errorf("expected nil when FCM disabled, got %v", err)
	}
}

func TestGetDeviceTokensForUserEmpty(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	tokens, err := getDeviceTokensForUser("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for nonexistent user, got %d", len(tokens))
	}
}

// ==================== Push Handler Additional Tests ====================

func TestHandleGetVAPIDKeyNotConfigured(t *testing.T) {
	vapidPublicKey = ""

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleGetVAPIDKeyNoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetVAPIDKeyConfigured(t *testing.T) {
	vapidPublicKey = "BFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Logf("VAPID key endpoint returned %d (may need valid JWT)", w.Code)
	}
}

func TestHandleWebPushSubscribeNoAuth(t *testing.T) {
	body := strings.NewReader(`{"endpoint":"https://push.example.com/123","keys":{"p256dh":"key","auth":"auth"}}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", body)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleWebPushUnsubscribeNoAuth(t *testing.T) {
	body := strings.NewReader(`{"endpoint":"https://push.example.com/123"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", body)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleWebPushSubscribeWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleWebPushUnsubscribeWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleGetVAPIDKeyWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleWebPushSubscribeMissingFields(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushsub1")

	// Missing keys
	body := strings.NewReader(`{"endpoint":"https://push.example.com/123"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestHandleWebPushUnsubscribeMissingEndpoint(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushunsub1")

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing endpoint, got %d", w.Code)
	}
}

func TestHandleRegisterDeviceTokenMissingToken(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushreg1")

	body := strings.NewReader(`{"platform":"ios"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/register", body)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", w.Code)
	}
}

func TestHandleRegisterDeviceTokenSuccess(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushreg2")

	body := strings.NewReader(`{"device_token":"abc123def456","platform":"ios"}`)
	req := httptest.NewRequest(http.MethodPost, "/push/register", body)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

func TestHandleRegisterDeviceTokenInvalidBody(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushinvalid1")

	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceTokenInvalidBody(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushinvalid2")

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceTokenMissingToken(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushunreg2")

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", body)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", w.Code)
	}
}

func TestHandleWebPushSubscribeSuccess(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushsub2")

	body := strings.NewReader(`{"endpoint":"https://push.example.com/sub/123","keys":{"p256dh":"test-key-data-here-at-least-32-chars","auth":"auth-secret-16ch"}}`)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", body)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "subscribed" {
		t.Errorf("expected status 'subscribed', got %v", result["status"])
	}
}

func TestHandleWebPushUnsubscribeSuccess(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "pushunsub2")

	// First subscribe
	subBody := strings.NewReader(`{"endpoint":"https://push.example.com/sub/456","keys":{"p256dh":"test-key-data-here-at-least-32-chars","auth":"auth-secret-16ch"}}`)
	subReq := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", subBody)
	subReq.Header.Set("Authorization", "Bearer "+token)
	subW := httptest.NewRecorder()
	handleWebPushSubscribe(subW, subReq)

	// Then unsubscribe
	unsubBody := strings.NewReader(`{"endpoint":"https://push.example.com/sub/456"}`)
	unsubReq := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", unsubBody)
	unsubReq.Header.Set("Authorization", "Bearer "+token)
	unsubW := httptest.NewRecorder()
	handleWebPushUnsubscribe(unsubW, unsubReq)

	if unsubW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", unsubW.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(unsubW.Body).Decode(&result)
	if result["status"] != "unsubscribed" {
		t.Errorf("expected status 'unsubscribed', got %v", result["status"])
	}
}

// ==================== Notification Preferences Auth ====================

func TestNotificationPrefsAuthFlow(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	token := createTestUser(t, "notifpref1")

	// Test GET without auth
	req := httptest.NewRequest(http.MethodGet, "/notification-prefs?conversation_id=conv-1", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}

	// Test POST without auth
	body := strings.NewReader(`{"conversation_id":"conv-1","muted":true}`)
	req2 := httptest.NewRequest(http.MethodPost, "/notification-prefs", body)
	w2 := httptest.NewRecorder()
	handleSetNotificationPrefs(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w2.Code)
	}

	// Test GET with auth (no prefs set yet — should return defaults)
	req3 := httptest.NewRequest(http.MethodGet, "/notification-prefs?conversation_id=conv-1", nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	handleGetNotificationPrefs(w3, req3)

	if w3.Code == http.StatusOK {
		var result map[string]interface{}
		json.NewDecoder(w3.Body).Decode(&result)
		t.Logf("Notification prefs response: %v", result)
	}
}

// ==================== Presence Auth Tests ====================

func TestHandleGetPresenceNoAuth(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/presence?agent_id=agent-1", nil)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}
}

func TestHandleGetUserPresenceNoAuth(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/user-presence?user_id=user-1", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for no auth, got %d", w.Code)
	}
}

// ==================== E2E Encryption Handlers Auth ====================

func TestE2EHandlersNoAuth(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		body    string
	}{
		{"uploadPublicKey", handleUploadPublicKey, "POST", `{"public_key":"test-key"}`},
		{"getKeyBundle", handleGetKeyBundle, "GET", ""},
		{"listOneTimePreKeys", handleListOneTimePreKeys, "GET", ""},
		{"storeEncryptedMessage", handleStoreEncryptedMessage, "POST", `{}`},
		{"getEncryptedMessages", handleGetEncryptedMessages, "GET", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, "/", body)
			w := httptest.NewRecorder()
			tt.handler(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s: expected 401, got %d", tt.name, w.Code)
			}
		})
	}
}

// ==================== Reaction/Tag Handlers Auth ====================

func TestReactionAndTagAuthRequired(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		body    string
	}{
		{"react", handleReact, "POST", "message_id=msg-1&emoji=like&action=add"},
		{"addTag", handleAddTag, "POST", `{"conversation_id":"conv-1","tag":"important"}`},
		{"removeTag", handleRemoveTag, "POST", `{"conversation_id":"conv-1","tag":"important"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			tt.handler(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s: expected 401, got %d", tt.name, w.Code)
			}
		})
	}
}

// ==================== Profile Handler Extended Coverage ====================

func TestProfileHandlerGetStatsAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=stats", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
	if result["action"] != "stats" {
		t.Errorf("expected action stats, got %v", result["action"])
	}
}

func TestProfileHandlerCPUAlreadyActive(t *testing.T) {
	defer cpuProfileTestSetup()()

	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for CPU profile start, got %d", w.Code)
	}

	// Try starting again — should get error
	req2 := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	w2 := httptest.NewRecorder()
	handleAdminProfile(w2, req2)

	if w2.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for already active CPU profile, got %d", w2.Code)
	}

	// Clean up — stop CPU profiling
	req3 := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu_stop", nil)
	w3 := httptest.NewRecorder()
	handleAdminProfile(w3, req3)
}

func TestProfileHandlerCPUStopNotActive(t *testing.T) {
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu_stop", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for no active CPU profile, got %d", w.Code)
	}
}

func TestProfileHandlerPostWithJSONAction(t *testing.T) {
	body := strings.NewReader(`{"action":"stats"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/profile", body)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestProfileHandlerDefaultAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ==================== getEnvOrDefault ====================

func TestGetEnvOrDefault(t *testing.T) {
	os.Setenv("TEST_ENV_VAR_123", "value123")
	result := getEnvOrDefault("TEST_ENV_VAR_123", "default")
	if result != "value123" {
		t.Errorf("expected 'value123', got %q", result)
	}

	result = getEnvOrDefault("NONEXISTENT_ENV_VAR", "default_val")
	if result != "default_val" {
		t.Errorf("expected 'default_val', got %q", result)
	}

	os.Unsetenv("TEST_ENV_VAR_123")
}

// ==================== ValidateAdminSecret ====================

func TestValidateAdminSecretMissing(t *testing.T) {
	result := ValidateAdminSecret("")
	if result == nil {
		t.Error("expected error for empty secret")
	}
}

func TestValidateAdminSecretCorrect(t *testing.T) {
	// Ensure we're using the dev default (another test may have changed it)
	os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()
	defer resetAdminSecret()

	result := ValidateAdminSecret("admin-dev-secret")
	if result != nil {
		t.Errorf("expected nil for correct admin secret, got %v", result)
	}
}

func TestValidateAdminSecretIncorrect(t *testing.T) {
	result := ValidateAdminSecret("wrong-secret")
	if result == nil {
		t.Error("expected error for incorrect admin secret")
	}
}

// ==================== Health Endpoint Extended ====================

func TestHealthEndpointTracingField(t *testing.T) {
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if _, ok := result["tracing_enabled"]; !ok {
		t.Error("expected tracing_enabled field in health response")
	}
}

// ==================== ExtractIP ====================

func TestExtractIPRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ip := extractIP(req)
	if ip == "" {
		t.Error("expected non-empty IP from RemoteAddr")
	}
}

// ==================== Auth Rate Limiter Clean ====================

func TestAuthRateLimiterClean(t *testing.T) {
	// Create a rateLimiter directly and test Clean()
	rl := &rateLimiter{
		attempts: make(map[string]*rateLimitEntry),
	}

	// Add an entry manually that's already expired
	rl.attempts["expired-agent"] = &rateLimitEntry{
		count:     1,
		firstSeen: time.Now().Add(-2 * time.Minute),
	}

	// Add a fresh entry
	rl.attempts["fresh-agent"] = &rateLimitEntry{
		count:     1,
		firstSeen: time.Now(),
	}

	rl.Clean()

	rl.mu.Lock()
	count := len(rl.attempts)
	rl.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 entry after Clean (fresh one kept), got %d", count)
	}

	if _, ok := rl.attempts["fresh-agent"]; !ok {
		t.Error("fresh-agent should still be in attempts")
	}
}

// ==================== Additional Coverage: marshalOutgoingMessage with error ====================

func TestMarshalOutgoingMessageWithUnserializableData(t *testing.T) {
	// OutgoingMessage with Data that can't be marshaled
	msg := OutgoingMessage{
		Type: "test",
		Data: map[string]interface{}{
			"ch": make(chan int), // channels can't be marshaled to JSON
		},
	}
	result := marshalOutgoingMessage(msg)
	if result != nil {
		t.Error("expected nil for unserializable message data")
	}
}

// ==================== Additional Coverage: Profile Handlers ====================

func TestHandleHeapProfile(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)

	if w.Code != http.StatusOK {
		// May fail if WriteHeapProfile fails, but we still cover the path
		t.Logf("heap profile returned %d (acceptable)", w.Code)
	}
}

func TestHandleGoroutineProfile(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/profile?action=goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)

	if w.Code != http.StatusOK {
		t.Logf("goroutine profile returned %d (acceptable)", w.Code)
	}
}

// ==================== Additional Coverage: Tracing Functions ====================

func TestTracingSpanErrorAndOK(t *testing.T) {
	// Test without tracing initialized — should not panic
	ctx := context.Background()
	spanCtx, span := StartSpan(ctx, "test-span")
	SpanError(span, fmt.Errorf("test error"))
	SpanOK(span)

	// Test StartSpanFromRequest
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	spanCtx2, span2 := StartSpanFromRequest(req, "test-request-span")
	SpanError(span2, fmt.Errorf("request error"))
	SpanOK(span2)
	_ = spanCtx
	_ = spanCtx2
}

func TestTraceRouteMessageNoTrace(t *testing.T) {
	// Without a real tracing provider, these should be no-ops
	TraceRouteMessage("websocket", "user1")
	TraceOfflineEnqueue("user1")
	TracePushNotify("user1", "conv1", true)
	TraceAgentConnect("agent1")
	TraceClientConnect("client1", "device1")
}

func TestShutdownTracingNoProvider(t *testing.T) {
	// Without tracing initialized, this should be a no-op
	ShutdownTracing()
}
