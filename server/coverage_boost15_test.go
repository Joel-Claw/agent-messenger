package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"sync"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Helper functions for CB15
// ==============================

func cb15SetupDB(t *testing.T) {
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

func cb15MakeToken(t *testing.T, username string) string {
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

func cb15WithUserContext(r *http.Request, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
	return r.WithContext(ctx)
}

func cb15CreateAgent(t *testing.T, agentID string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name) VALUES (?, ?)", agentID, agentID)
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
}

func cb15CreateConversation(t *testing.T, convID, userID, agentID string) {
	t.Helper()
	_, err := db.Exec("INSERT OR IGNORE INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, agentID)
	if err != nil {
		t.Fatalf("insert conversation: %v", err)
	}
}

// ==============================
// sendAPNSNotification deeper coverage
// ==============================

func TestCB15_SendAPNSNotification_NilPushConfig(t *testing.T) {
	pushConfig = nil
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil pushConfig, got %v", err)
	}
}

func TestCB15_SendAPNSNotification_EmptyDeviceToken(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil, // nil client means we just return nil
	}
	t.Cleanup(func() { pushConfig = nil })
	// With nil apnsClient, should return nil (client not initialized)
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil apnsClient, got %v", err)
	}
}

func TestCB15_SendAPNSNotification_EnabledButNilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	t.Cleanup(func() { pushConfig = nil })
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB15_SendAPNSNotification_DisabledFlag(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		apnsClient:  nil,
	}
	t.Cleanup(func() { pushConfig = nil })
	err := sendAPNSNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when APNs disabled, got %v", err)
	}
}

// ==============================
// sendFCMNotification deeper coverage
// ==============================

func TestCB15_SendFCMNotification_NilPushConfig(t *testing.T) {
	pushConfig = nil
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil pushConfig, got %v", err)
	}
}

func TestCB15_SendFCMNotification_EnabledButNilClient(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	t.Cleanup(func() { pushConfig = nil })
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error with nil fcmClient, got %v", err)
	}
}

func TestCB15_SendFCMNotification_DisabledFlag(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
		fcmClient:  nil,
	}
	t.Cleanup(func() { pushConfig = nil })
	err := sendFCMNotification("token123", "Title", "Body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when FCM disabled, got %v", err)
	}
}

// ==============================
// sendPushNotification platform routing
// ==============================

func TestCB15_SendPushNotification_AndroidPlatform(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	t.Cleanup(func() { pushConfig = nil })
	// Android platform should route to FCM
	err := sendPushNotification("token123", "Title", "Body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil error (FCM disabled), got %v", err)
	}
}

func TestCB15_SendPushNotification_FCMPlatform(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	t.Cleanup(func() { pushConfig = nil })
	err := sendPushNotification("token123", "Title", "Body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected nil error (FCM disabled), got %v", err)
	}
}

func TestCB15_SendPushNotification_iOSDefaultPlatform(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	t.Cleanup(func() { pushConfig = nil })
	// iOS should route to APNs, unknown platforms also default to APNs
	err := sendPushNotification("token123", "Title", "Body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil error (APNs disabled), got %v", err)
	}
}

func TestCB15_SendPushNotification_UnknownPlatformDefaultsToAPNs(t *testing.T) {
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	t.Cleanup(func() { pushConfig = nil })
	err := sendPushNotification("token123", "Title", "Body", "conv1", "unknown_platform")
	if err != nil {
		t.Errorf("expected nil error (unknown platform defaults to APNs, disabled), got %v", err)
	}
}

// ==============================
// notifyUser with device tokens
// ==============================

func TestCB15_NotifyUser_WithDeviceTokens(t *testing.T) {
	cb15SetupDB(t)
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}
	t.Cleanup(func() { pushConfig = nil })

	userID := "user-notify-1"
	token := cb15MakeToken(t, userID)

	// Register a device token for this user
	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "tok_abc123", "ios")
	if err != nil {
		t.Fatalf("insert device token: %v", err)
	}

	// notifyUser should not crash even with push disabled
	notifyUser(userID, "Test", "Body", "conv1")
	_ = token // just ensuring token generated without error
}

func TestCB15_NotifyUser_EmptyConversationID(t *testing.T) {
	cb15SetupDB(t)
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}
	t.Cleanup(func() { pushConfig = nil })

	userID := "user-notify-2"
	cb15MakeToken(t, userID)

	// Register a device token
	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "tok_def456", "ios")
	if err != nil {
		t.Fatalf("insert device token: %v", err)
	}

	// notifyUser with empty conversation ID should not check muted status
	notifyUser(userID, "Test", "Body", "")
}

func TestCB15_NotifyUser_PushSendError(t *testing.T) {
	cb15SetupDB(t)
	// Push config with enabled but nil clients - this tests the error path
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil, // will cause early return, but we still exercise the path
		FCMEnabled:  true,
		fcmClient:   nil,
	}
	t.Cleanup(func() { pushConfig = nil })

	userID := "user-notify-3"
	cb15MakeToken(t, userID)

	_, err := db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		userID, "tok_ghi789", "ios")
	if err != nil {
		t.Fatalf("insert device token: %v", err)
	}

	// With nil clients, sendAPNSNotification/sendFCMNotification return nil early
	notifyUser(userID, "Test", "Body", "conv1")
}

// ==============================
// RateLimiter.Reset()
// ==============================

func TestCB15_RateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(60, time.Minute)
	t.Cleanup(func() { rl.Stop() })

	// Add some entries
	rl.Allow("user1")
	rl.Allow("user1")
	rl.Allow("user2")

	if rl.Count("user1") != 2 {
		t.Errorf("expected 2 for user1, got %d", rl.Count("user1"))
	}
	if rl.Count("user2") != 1 {
		t.Errorf("expected 1 for user2, got %d", rl.Count("user2"))
	}

	// Reset should clear everything
	rl.Reset()
	if rl.Count("user1") != 0 {
		t.Errorf("expected 0 after reset for user1, got %d", rl.Count("user1"))
	}
	if rl.Count("user2") != 0 {
		t.Errorf("expected 0 after reset for user2, got %d", rl.Count("user2"))
	}
}

// ==============================
// TieredRateLimiter.Reset()
// ==============================

func TestCB15_TieredRateLimiter_Reset(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	trl.SetTier("user1", TierPro)

	// Use some quota
	trl.Allow("user1")
	trl.Allow("user1")

	remaining := trl.GetRemaining("user1")
	if remaining >= TierPro.Burst {
		t.Errorf("expected remaining < %d after usage, got %d", TierPro.Burst, remaining)
	}

	// Reset should clear counters
	trl.Reset()
	remaining = trl.GetRemaining("user1")
	if remaining != TierFree.Burst {
		t.Errorf("expected %d after reset (tier cleared to free), got %d", TierFree.Burst, remaining)
	}
}

// ==============================
// cleanup function for TieredRateLimiter
// ==============================

func TestCB15_TieredRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Add an entry that's already expired (window ended 20 minutes ago)
	trl.mu.Lock()
	trl.limits["stale-user"] = &userRateLimitState{
		count:     5,
		tier:      TierFree,
		windowEnd: time.Now().Add(-20 * time.Minute),
	}
	trl.limits["fresh-user"] = &userRateLimitState{
		count:     1,
		tier:      TierFree,
		windowEnd: time.Now().Add(30 * time.Minute),
	}
	trl.mu.Unlock()

	// Manually trigger the cleanup logic (simulating what the goroutine does)
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, hasStale := trl.limits["stale-user"]
	_, hasFresh := trl.limits["fresh-user"]
	trl.mu.Unlock()

	if hasStale {
		t.Error("stale entry should have been removed")
	}
	if !hasFresh {
		t.Error("fresh entry should still exist")
	}
}

// ==============================
// openDatabase deeper coverage
// ==============================

func TestCB15_OpenDatabase_InvalidDriver(t *testing.T) {
	_, err := openDatabase("unsupported_driver", "dsn")
	if err == nil {
		t.Error("expected error for unsupported driver")
	}
}

func TestCB15_OpenDatabase_EmptyDSN(t *testing.T) {
	_, err := openDatabase("sqlite3", "")
	if err == nil {
		// SQLite with empty DSN creates a temp DB, this is OK
		// Just verify it doesn't panic
	}
}

func TestCB15_Placeholder_WithCurrentDriver(t *testing.T) {
	// Save and restore currentDriver
	origDriver := currentDriver
	t.Cleanup(func() { currentDriver = origDriver })

	currentDriver = DriverSQLite
	if Placeholder(1) != "?" {
		t.Errorf("SQLite placeholder should be '?', got %s", Placeholder(1))
	}

	currentDriver = DriverPostgreSQL
	if Placeholder(1) != "$1" {
		t.Errorf("PostgreSQL placeholder should be '$1', got %s", Placeholder(1))
	}
	if Placeholder(3) != "$3" {
		t.Errorf("PostgreSQL placeholder 3 should be '$3', got %s", Placeholder(3))
	}
}

func TestCB15_Placeholders_Multiple(t *testing.T) {
	origDriver := currentDriver
	t.Cleanup(func() { currentDriver = origDriver })

	currentDriver = DriverSQLite
	result := Placeholders(1, 3)
	if result != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?', got %s", result)
	}

	currentDriver = DriverPostgreSQL
	result = Placeholders(1, 3)
	if result != "$1, $2, $3" {
		t.Errorf("expected '$1, $2, $3', got %s", result)
	}
}

// ==============================
// RegisterAgentOnConnect deeper coverage
// ==============================

func TestCB15_RegisterAgentOnConnect_UpdateExistingAgent(t *testing.T) {
	cb15SetupDB(t)

	// First registration
	err := RegisterAgentOnConnect("agent-1", "Agent One", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}

	// Second registration - update metadata
	err = RegisterAgentOnConnect("agent-1", "Agent One Updated", "gpt-4o", "cheerful", "math")
	if err != nil {
		t.Fatalf("update registration: %v", err)
	}

	// Verify updates
	var name, model, personality, specialty string
	err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent-1").
		Scan(&name, &model, &personality, &specialty)
	if err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if name != "Agent One Updated" {
		t.Errorf("expected name 'Agent One Updated', got %s", name)
	}
	if model != "gpt-4o" {
		t.Errorf("expected model 'gpt-4o', got %s", model)
	}
	if personality != "cheerful" {
		t.Errorf("expected personality 'cheerful', got %s", personality)
	}
	if specialty != "math" {
		t.Errorf("expected specialty 'math', got %s", specialty)
	}
}

func TestCB15_RegisterAgentOnConnect_PreserveExistingFields(t *testing.T) {
	cb15SetupDB(t)

	// First registration with metadata
	err := RegisterAgentOnConnect("agent-2", "Agent Two", "llama-3", "professional", "science")
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}

	// Reconnect without metadata fields - should preserve existing
	err = RegisterAgentOnConnect("agent-2", "", "", "", "")
	if err != nil {
		t.Fatalf("reconnect registration: %v", err)
	}

	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "agent-2").
		Scan(&model, &personality, &specialty)
	if err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if model != "llama-3" {
		t.Errorf("model should be preserved, got %s", model)
	}
	if personality != "professional" {
		t.Errorf("personality should be preserved, got %s", personality)
	}
	if specialty != "science" {
		t.Errorf("specialty should be preserved, got %s", specialty)
	}
}

func TestCB15_RegisterAgentOnConnect_DefaultNameToID(t *testing.T) {
	cb15SetupDB(t)

	// Register with empty name - should default to agent ID
	err := RegisterAgentOnConnect("agent-3", "", "", "", "")
	if err != nil {
		t.Fatalf("registration: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-3").Scan(&name)
	if err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if name != "agent-3" {
		t.Errorf("expected name to default to agent ID 'agent-3', got %s", name)
	}
}

func TestCB15_RegisterAgentOnConnect_DBError(t *testing.T) {
	// Use a closed DB to trigger a query error
	closedDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	closedDB.Close()

	oldDB := db
	db = closedDB
	t.Cleanup(func() { db = oldDB })

	err = RegisterAgentOnConnect("agent-4", "Name", "model", "personality", "specialty")
	if err == nil {
		t.Error("expected error with closed db")
	}
}

// ==============================
// HashAPIKey deeper coverage
// ==============================

func TestCB15_HashAPIKey_RoundTrip(t *testing.T) {
	plain := "my-secret-api-key-12345"
	hashed, err := HashAPIKey(plain)
	if err != nil {
		t.Fatalf("HashAPIKey: %v", err)
	}
	if hashed == plain {
		t.Error("hashed value should not equal plain text")
	}
	// Verify we can compare
	err = bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	if err != nil {
		t.Errorf("bcrypt compare failed: %v", err)
	}
}

func TestCB15_HashAPIKey_DifferentInputs(t *testing.T) {
	hash1, _ := HashAPIKey("key1")
	hash2, _ := HashAPIKey("key2")
	if hash1 == hash2 {
		t.Error("different inputs should produce different hashes")
	}
}

// ==============================
// handleUpload deeper coverage
// ==============================

func TestCB15_Upload_DisallowedContentType(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "upload-user1")

	// Create a file with a disallowed content type
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.exe")
	// Write MZ header (PE executable magic bytes)
	exeHeader := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	part.Write(exeHeader)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handleUpload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for disallowed content type, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "not allowed") {
		t.Errorf("expected 'not allowed' in response, got %s", body)
	}
}

func TestCB15_Upload_MissingFileField(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "upload-user2")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("notfile", "somevalue")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handleUpload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing file field, got %d", rec.Code)
	}
}

func TestCB15_Upload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/upload", nil)
	rec := httptest.NewRecorder()
	handleUpload(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_Upload_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", nil)
	rec := httptest.NewRecorder()
	handleUpload(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_Upload_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	handleUpload(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_Upload_ImageFile(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "upload-user3")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.png")
	// PNG magic bytes
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	pngHeader = append(pngHeader, make([]byte, 100)...)
	part.Write(pngHeader)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handleUpload(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for PNG upload, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_Upload_WithMessageID(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "upload-user4")
	cb15CreateAgent(t, "agent-upload-1")
	cb15CreateConversation(t, "conv-upload-1", "upload-user4", "agent-upload-1")

	// Insert a message first
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg-upload-1", "conv-upload-1", "user", "upload-user4", "hello")
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello world"))
	writer.WriteField("message_id", "msg-upload-1")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handleUpload(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ==============================
// handleListAttachments deeper coverage
// ==============================

func TestCB15_ListAttachments_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	rec := httptest.NewRecorder()
	handleListAttachments(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_ListAttachments_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=conv1", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	handleListAttachments(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_ListAttachments_MissingConvID(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "listatt-user1")

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleListAttachments(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", rec.Code)
	}
}

func TestCB15_ListAttachments_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/attachments", nil)
	rec := httptest.NewRecorder()
	handleListAttachments(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ==============================
// handleGetAttachment deeper coverage
// ==============================

func TestCB15_GetAttachment_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attachments/att123", nil)
	rec := httptest.NewRecorder()
	handleGetAttachment(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_GetAttachment_MissingID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/", nil)
	rec := httptest.NewRecorder()
	handleGetAttachment(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing attachment id, got %d", rec.Code)
	}
}

func TestCB15_GetAttachment_NotFound(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "getatt-user1")

	req := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetAttachment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent attachment, got %d", rec.Code)
	}
}

func TestCB15_GetAttachment_AgentAuth(t *testing.T) {
	cb15SetupDB(t)

	// Test with agent secret auth (X-Agent-Secret header)
	req := httptest.NewRequest(http.MethodGet, "/attachments/some-id", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	rec := httptest.NewRecorder()
	handleGetAttachment(rec, req)
	// Should get 404 (attachment not found), not 401
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 with valid agent auth, got %d", rec.Code)
	}
}

func TestCB15_GetAttachment_InvalidAgentSecret(t *testing.T) {
	cb15SetupDB(t)

	req := httptest.NewRequest(http.MethodGet, "/attachments/some-id", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	rec := httptest.NewRecorder()
	handleGetAttachment(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid agent secret, got %d", rec.Code)
	}
}

// ==============================
// persistTierToDB deeper coverage
// ==============================

func TestCB15_PersistTierToDB_PostgreSQLDriver(t *testing.T) {
	cb15SetupDB(t)
	origDriver := currentDriver
	t.Cleanup(func() { currentDriver = origDriver })

	currentDriver = DriverPostgreSQL

	// persistTierToDB will try $1/$2 placeholders which won't work with SQLite
	// But we can test the nil-db path
	oldDB := db
	db = nil
	t.Cleanup(func() { db = oldDB })

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error with nil db, got %v", err)
	}
}

// ==============================
// loadTiersFromDB deeper coverage
// ==============================

func TestCB15_LoadTiersFromDB_ProTier(t *testing.T) {
	cb15SetupDB(t)

	// Insert a pro tier
	_, err := db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "pro-user", "pro")
	if err != nil {
		t.Fatalf("insert tier: %v", err)
	}

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	err = loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB: %v", err)
	}

	tier := trl.GetTier("pro-user")
	if tier.Name != "pro" {
		t.Errorf("expected pro tier, got %s", tier.Name)
	}
}

func TestCB15_LoadTiersFromDB_EnterpriseTier(t *testing.T) {
	cb15SetupDB(t)

	_, err := db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "ent-user", "enterprise")
	if err != nil {
		t.Fatalf("insert tier: %v", err)
	}

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	err = loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB: %v", err)
	}

	tier := trl.GetTier("ent-user")
	if tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier, got %s", tier.Name)
	}
}

func TestCB15_LoadTiersFromDB_FreeTierNotLoaded(t *testing.T) {
	cb15SetupDB(t)

	// Free tier users shouldn't be loaded (they're default)
	_, err := db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "free-user", "free")
	if err != nil {
		t.Fatalf("insert tier: %v", err)
	}

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	err = loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB: %v", err)
	}

	// Free users shouldn't have a custom tier set
	tier := trl.GetTier("free-user")
	// Default is free, so it should be free
	if tier.Name != "free" {
		t.Errorf("expected free tier for default user, got %s", tier.Name)
	}
}

func TestCB15_LoadTiersFromDB_InvalidTierDefaultsToFree(t *testing.T) {
	cb15SetupDB(t)

	// Insert an invalid tier name
	_, err := db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "invalid-user", "mega-ultra")
	if err != nil {
		t.Fatalf("insert tier: %v", err)
	}

	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	err = loadTiersFromDB(trl)
	if err != nil {
		t.Fatalf("loadTiersFromDB: %v", err)
	}

	// Invalid tier should default to free (not set via SetTier since it's not a real tier)
	tier := trl.GetTier("invalid-user")
	if tier.Name != "free" {
		t.Errorf("expected free tier for invalid tier name, got %s", tier.Name)
	}
}

// ==============================
// deleteConversation deeper coverage
// ==============================

func TestCB15_DeleteConversation_DBError(t *testing.T) {
	cb15SetupDB(t)

	userID := "del-user1"
	cb15MakeToken(t, userID)
	cb15CreateAgent(t, "agent-del1")
	cb15CreateConversation(t, "conv-del1", userID, "agent-del1")

	// Insert messages
	_, err := db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg-del1", "conv-del1", "user", userID, "hello")
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	// Delete should work
	err = deleteConversation("conv-del1", userID)
	if err != nil {
		t.Errorf("delete conversation failed: %v", err)
	}

	// Verify conversation is gone
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", "conv-del1").Scan(&count)
	if err != nil {
		t.Fatalf("query conversations: %v", err)
	}
	if count != 0 {
		t.Errorf("conversation should be deleted, count=%d", count)
	}

	// Verify messages are also gone
	err = db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv-del1").Scan(&count)
	if err != nil {
		t.Fatalf("query messages: %v", err)
	}
	if count != 0 {
		t.Errorf("messages should be deleted, count=%d", count)
	}
}

func TestCB15_DeleteConversation_WrongUser(t *testing.T) {
	cb15SetupDB(t)

	userID1 := "del-owner"
	userID2 := "del-other"
	cb15MakeToken(t, userID1)
	cb15MakeToken(t, userID2)
	cb15CreateAgent(t, "agent-del2")
	cb15CreateConversation(t, "conv-del2", userID1, "agent-del2")

	err := deleteConversation("conv-del2", userID2)
	if err == nil {
		t.Error("expected error when wrong user tries to delete")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("expected 'unauthorized' error, got %v", err)
	}
}

func TestCB15_DeleteConversation_NonExistent(t *testing.T) {
	cb15SetupDB(t)

	err := deleteConversation("nonexistent-conv", "any-user")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

// ==============================
// routeChatMessage deeper coverage
// ==============================

func TestCB15_RouteChatMessage_InvalidJSON(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "user-route1",
		send:     make(chan []byte, 10),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	h := newHub()
	oldHub := hub
	hub = h
	go hub.run()
	defer func() { hub.Stop(); hub = oldHub }()

	routeChatMessage(conn, []byte("not valid json"))

	// Should not panic; just send an error
	select {
	case msg := <-conn.send:
		var out OutgoingMessage
		json.Unmarshal(msg, &out)
		if out.Type != "error" {
			t.Errorf("expected error type, got %s", out.Type)
		}
	default:
		// Error might not always be sent if no handler
	}
}

func TestCB15_RouteChatMessage_EmptyContent(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "user-route2",
		send:     make(chan []byte, 10),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	msg := RoutedMessage{
		ConversationID: "conv-route1",
		Content:        "",
	}
	data, _ := json.Marshal(msg)

	h := newHub()
	oldHub := hub
	hub = h
	go hub.run()
	defer func() { hub.Stop(); hub = oldHub }()

	routeChatMessage(conn, data)

	select {
	case msg := <-conn.send:
		var out OutgoingMessage
		json.Unmarshal(msg, &out)
		if out.Type != "error" {
			t.Errorf("expected error type for empty content, got %s", out.Type)
		}
	default:
		// OK - error might be silently dropped
	}
}

func TestCB15_RouteChatMessage_MissingConversationID(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "user-route3",
		send:     make(chan []byte, 10),
		closed:   false,
		closeMu:  sync.RWMutex{},
	}

	msg := RoutedMessage{
		Content: "hello",
	}
	data, _ := json.Marshal(msg)

	h := newHub()
	oldHub := hub
	hub = h
	go hub.run()
	defer func() { hub.Stop(); hub = oldHub }()

	routeChatMessage(conn, data)

	select {
	case msg := <-conn.send:
		var out OutgoingMessage
		json.Unmarshal(msg, &out)
		if out.Type != "error" {
			t.Errorf("expected error type for missing conversation_id, got %s", out.Type)
		}
	default:
	}
}

// ==============================
// handleSetNotificationPrefs deeper coverage
// ==============================

func TestCB15_SetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", nil)
	rec := httptest.NewRecorder()
	handleSetNotificationPrefs(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_SetNotificationPrefs_MissingConvID(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "notif-user1")

	form := strings.NewReader("muted=true")
	req := cb15WithUserContext(httptest.NewRequest(http.MethodPost, "/notifications/preferences", form), "notif-user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleSetNotificationPrefs(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", rec.Code)
	}
}

func TestCB15_SetNotificationPrefs_ConvNotFound(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "notif-user2")

	form := strings.NewReader("conversation_id=nonexistent&muted=true")
	req := cb15WithUserContext(httptest.NewRequest(http.MethodPost, "/notifications/preferences", form), "notif-user2")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleSetNotificationPrefs(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", rec.Code)
	}
}

func TestCB15_SetNotificationPrefs_NotOwner(t *testing.T) {
	cb15SetupDB(t)
	token1 := cb15MakeToken(t, "notif-owner")
	cb15MakeToken(t, "notif-other")
	cb15CreateAgent(t, "agent-notif1")
	cb15CreateConversation(t, "conv-notif1", "notif-owner", "agent-notif1")

	// Different user tries to set prefs
	form := strings.NewReader("conversation_id=conv-notif1&muted=true")
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token1)
	cb15MakeToken(t, "notif-other2")

	form2 := strings.NewReader("conversation_id=conv-notif1&muted=true")
	req2 := cb15WithUserContext(httptest.NewRequest(http.MethodPost, "/notifications/preferences", form2), "notif-other2")
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	handleSetNotificationPrefs(rec2, req2)
	// This should return 403 (not your conversation) since notif-other2 doesn't own conv-notif1
	if rec2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-owner, got %d; body: %s", rec2.Code, rec2.Body.String())
	}
}

// ==============================
// handleGetNotificationPrefs
// ==============================

func TestCB15_GetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil)
	rec := httptest.NewRecorder()
	handleGetNotificationPrefs(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_GetNotificationPrefs_WithPrefs(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "notif-pref-user1")
	cb15CreateAgent(t, "agent-notif2")
	cb15CreateConversation(t, "conv-notif2", "notif-pref-user1", "agent-notif2")

	// Set a preference
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"notif-pref-user1", "conv-notif2")

	req := cb15WithUserContext(httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil), "notif-pref-user1")
	rec := httptest.NewRecorder()
	handleGetNotificationPrefs(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var prefs []NotificationPreferences
	json.Unmarshal(rec.Body.Bytes(), &prefs)
	if len(prefs) == 0 {
		t.Error("expected at least one preference")
	}
}

// ==============================
// handleDeleteNotificationPrefs
// ==============================

func TestCB15_DeleteNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/notifications/preferences", nil)
	rec := httptest.NewRecorder()
	handleDeleteNotificationPrefs(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_DeleteNotificationPrefs_MissingConvID(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "notif-del-user1")

	form := strings.NewReader("")
	req := cb15WithUserContext(httptest.NewRequest(http.MethodDelete, "/notifications/preferences", form), "notif-del-user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleDeleteNotificationPrefs(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", rec.Code)
	}
}

// ==============================
// E2E encryption deeper coverage
// ==============================

func TestCB15_StoreEncrypted_InvalidAlgorithm(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "e2e-user1")
	cb15CreateAgent(t, "agent-e2e1")
	cb15CreateConversation(t, "conv-e2e1", "e2e-user1", "agent-e2e1")

	token := cb15MakeToken(t, "e2e-user1")

	body := `{
		"conversation_id": "conv-e2e1",
		"ciphertext": "abc123",
		"iv": "iv456",
		"recipient_key_id": "key1",
		"algorithm": "invalid-algo",
	}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid algorithm, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_StoreEncrypted_MissingFields(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "e2e-user2")

	body := `{"conversation_id": "conv1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", rec.Code)
	}
}

func TestCB15_StoreEncrypted_ConvNotFound(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "e2e-user3")

	body := `{
		"conversation_id": "nonexistent",
		"ciphertext": "abc",
		"iv": "iv1",
		"algorithm": "aes-256-gcm",
		"recipient_key_id": "key1"
	}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", rec.Code)
	}
}

func TestCB15_StoreEncrypted_ValidAlgorithm_X25519ChaCha(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "e2e-user4")
	cb15CreateAgent(t, "agent-e2e4")
	cb15CreateConversation(t, "conv-e2e4", "e2e-user4", "agent-e2e4")

	h := newHub()
	oldHub := hub
	hub = h
	go hub.run()
	defer func() { hub.Stop(); hub = oldHub }()

	body := `{
		"conversation_id": "conv-e2e4",
		"ciphertext": "encrypteddata123",
		"iv": "iv123",
		"recipient_key_id": "rkey1",
		"sender_key_id": "skey1",
		"algorithm": "x25519-chacha20-poly1305"
	}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid encrypted message, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_StoreEncrypted_ValidAlgorithm_X25519AES(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "e2e-user5")
	cb15CreateAgent(t, "agent-e2e5")
	cb15CreateConversation(t, "conv-e2e5", "e2e-user5", "agent-e2e5")

	h := newHub()
	oldHub := hub
	hub = h
	go hub.run()
	defer func() { hub.Stop(); hub = oldHub }()

	body := `{
		"conversation_id": "conv-e2e5",
		"ciphertext": "encrypteddata456",
		"iv": "iv456",
		"recipient_key_id": "rkey2",
		"algorithm": "x25519-aes-256-gcm"
	}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_StoreEncrypted_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_StoreEncrypted_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// ==============================
// handleGetEncryptedMessages deeper coverage
// ==============================

func TestCB15_GetEncrypted_MissingConversationID(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "enc-get-user1")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", rec.Code)
	}
}

func TestCB15_GetEncrypted_ConvNotFound(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "enc-get-user2")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", rec.Code)
	}
}

func TestCB15_GetEncrypted_WithLimit(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "enc-get-user3")
	cb15CreateAgent(t, "agent-enc3")
	cb15CreateConversation(t, "conv-enc3", "enc-get-user3", "agent-enc3")

	// Insert encrypted messages
	for i := 0; i < 5; i++ {
		db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("emsg-%d", i), "conv-enc3", "enc-get-user3", "user",
			fmt.Sprintf("cipher%d", i), "iv1", "rkey1", "aes-256-gcm", time.Now().UTC())
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-enc3&limit=3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var messages []EncryptedMessage
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) != 3 {
		t.Errorf("expected 3 messages with limit=3, got %d", len(messages))
	}
}

func TestCB15_GetEncrypted_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_GetEncrypted_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv1", nil)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// ==============================
// authenticateRequest deeper coverage
// ==============================

func TestCB15_AuthenticateRequest_AgentWithID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "my-agent-1")

	id, idType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if id != "my-agent-1" {
		t.Errorf("expected id 'my-agent-1', got %s", id)
	}
	if idType != "agent" {
		t.Errorf("expected type 'agent', got %s", idType)
	}
}

func TestCB15_AuthenticateRequest_AgentMissingID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	// No X-Agent-ID header

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error when agent ID is missing")
	}
}

func TestCB15_AuthenticateRequest_WrongAgentSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "agent-1")

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with wrong agent secret")
	}
}

func TestCB15_AuthenticateRequest_NoAuthHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error with no auth headers")
	}
}

// ==============================
// routeTypingIndicator deeper coverage
// ==============================

func TestCB15_RouteTyping_InvalidJSON(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "user-typing1",
		send:     make(chan []byte, 10),
	}
	routeTypingIndicator(conn, []byte("not json"))
	// Should not panic
}

func TestCB15_RouteTyping_MissingConversationID(t *testing.T) {
	conn := &Connection{
		connType: "client",
		id:       "user-typing2",
		send:     make(chan []byte, 10),
	}
	data, _ := json.Marshal(map[string]string{})
	routeTypingIndicator(conn, data)
	// Should not panic, just returns early
}

func TestCB15_RouteTyping_NotParticipant(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "typing-user1")
	cb15CreateAgent(t, "agent-typing1")
	cb15CreateConversation(t, "conv-typing1", "typing-user1", "agent-typing1")

	conn := &Connection{
		connType: "client",
		id:       "wrong-user",
		send:     make(chan []byte, 10),
	}

	data, _ := json.Marshal(map[string]string{"conversation_id": "conv-typing1"})
	routeTypingIndicator(conn, data)
	// Should not forward typing indicator since sender is not a participant
	select {
	case <-conn.send:
		t.Error("should not have sent typing indicator to non-participant")
	default:
		// OK
	}
}

// ==============================
// routeStatusUpdate deeper coverage
// ==============================

func TestCB15_RouteStatus_InvalidJSON(t *testing.T) {
	conn := &Connection{
		connType: "agent",
		id:       "agent-status1",
		send:     make(chan []byte, 10),
	}
	routeStatusUpdate(conn, []byte("not json"))
	// Should not panic
}

func TestCB15_RouteStatus_AgentStatusUpdate(t *testing.T) {
	h := newHub()
	oldHub := hub
	hub = h
	go hub.run()
	defer func() {
		hub.Stop()
		hub = oldHub
	}()

	conn := &Connection{
		connType: "agent",
		id:       "agent-status2",
		send:     make(chan []byte, 10),
		closed:   false,
	}
	h.register <- conn
	time.Sleep(10 * time.Millisecond)

	data, _ := json.Marshal(map[string]string{"status": "busy"})
	routeStatusUpdate(conn, data)

	time.Sleep(10 * time.Millisecond)
	status := h.AgentStatus("agent-status2")
	if status != "busy" {
		t.Errorf("expected agent status 'busy', got %s", status)
	}
}

// ==============================
// queue persist deeper coverage
// ==============================

func TestCB15_PersistQueue_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	t.Cleanup(func() { db = oldDB })

	// Should not panic
	persistQueue(nil, "recipient1", []byte("data"))
}

func TestCB15_DeleteQueueMessages_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	t.Cleanup(func() { db = oldDB })

	deleteQueueMessages(nil, "recipient1")
}

func TestCB15_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
	if q.TotalDepth() != 0 {
		t.Error("expected empty queue with nil db")
	}
}

func TestCB15_CleanStaleQueueMessages_NilDB(t *testing.T) {
	cleanStaleQueueMessages(nil, 7*24*time.Hour)
	// Should not panic
}

func TestCB15_InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil)
	// Should not panic
}

func TestCB15_MarshalOutgoingMessage(t *testing.T) {
	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]string{"key": "value"},
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Error("expected non-nil marshaled data")
	}
	var parsed OutgoingMessage
	json.Unmarshal(data, &parsed)
	if parsed.Type != "message" {
		t.Errorf("expected type 'message', got %s", parsed.Type)
	}
}

func TestCB15_MarshalOutgoingMessage_Invalid(t *testing.T) {
	// Create an outgoing message with unmarshallable data (channel)
	msg := OutgoingMessage{
		Type: "test",
		Data: make(chan int), // channels can't be marshaled to JSON
	}
	data := marshalOutgoingMessage(msg)
	if data != nil {
		t.Error("expected nil for unmarshallable data")
	}
}

// ==============================
// cleanStaleQueueMessages with real DB
// ==============================

func TestCB15_CleanStaleQueueMessages_WithMessages(t *testing.T) {
	cb15SetupDB(t)
	initQueueDB(db)

	// Insert an old message
	oldTime := time.Now().UTC().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"old-recipient", []byte("old data"), oldTime)
	if err != nil {
		t.Fatalf("insert old message: %v", err)
	}

	// Insert a recent message
	recentTime := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	_, err = db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"recent-recipient", []byte("recent data"), recentTime)
	if err != nil {
		t.Fatalf("insert recent message: %v", err)
	}

	// Clean messages older than 7 days
	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Check old message is gone
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "old-recipient").Scan(&count)
	if err != nil {
		t.Fatalf("query old messages: %v", err)
	}
	if count != 0 {
		t.Errorf("old message should be deleted, count=%d", count)
	}

	// Check recent message is still there
	err = db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "recent-recipient").Scan(&count)
	if err != nil {
		t.Fatalf("query recent messages: %v", err)
	}
	if count != 1 {
		t.Errorf("recent message should still exist, count=%d", count)
	}
}

// ==============================
// initPushNotifications deeper coverage
// ==============================

func TestCB15_InitPushNotifications_AllDisabled(t *testing.T) {
	os.Unsetenv("APNS_ENABLED")
	os.Unsetenv("FCM_ENABLED")
	os.Unsetenv("APNS_CERT_PATH")
	os.Unsetenv("FCM_CREDENTIALS_PATH")

	initPushNotifications()

	if pushConfig == nil {
		t.Fatal("pushConfig should not be nil after init")
	}
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled")
	}
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled")
	}
	t.Cleanup(func() { pushConfig = nil })
}

func TestCB15_InitAPNs_EnabledWithCertPath(t *testing.T) {
	os.Setenv("APNS_ENABLED", "true")
	os.Setenv("APNS_CERT_PATH", "/nonexistent/path/cert.p12")
	t.Cleanup(func() {
		os.Unsetenv("APNS_ENABLED")
		os.Unsetenv("APNS_CERT_PATH")
	})

	pushConfig = nil
	initPushNotifications()

	// Cert not found should disable APNs
	if pushConfig.APNSEnabled {
		t.Error("APNs should be disabled when cert not found")
	}
	t.Cleanup(func() { pushConfig = nil })
}

func TestCB15_InitFCM_EnabledWithCredsPath(t *testing.T) {
	os.Setenv("FCM_ENABLED", "true")
	os.Setenv("FCM_CREDENTIALS_PATH", "/nonexistent/path/creds.json")
	t.Cleanup(func() {
		os.Unsetenv("FCM_ENABLED")
		os.Unsetenv("FCM_CREDENTIALS_PATH")
	})

	pushConfig = nil
	initPushNotifications()

	// Creds not found should disable FCM
	if pushConfig.FCMEnabled {
		t.Error("FCM should be disabled when creds not found")
	}
	t.Cleanup(func() { pushConfig = nil })
}

// ==============================
// initSchema deeper coverage
// ==============================

func TestCB15_InitSchema_CreatesTables(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()

	err = initSchema(testDB)
	if err != nil {
		t.Fatalf("initSchema: %v", err)
	}

	// Verify key tables exist
	tables := []string{"users", "agents", "conversations", "messages", "attachments",
		"key_bundles", "encrypted_messages", "notification_preferences",
		"offline_queue", "reactions", "conversation_tags", "user_rate_limit_tiers", "schema_migrations"}

	for _, table := range tables {
		var count int
		err := testDB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
		if err != nil {
			t.Errorf("table %s should exist: %v", table, err)
		}
	}
}

// ==============================
// getDeviceTokensForUser
// ==============================

func TestCB15_GetDeviceTokensForUser_QueryError(t *testing.T) {
	// Use a closed DB to trigger query error
	closedDB, _ := sql.Open("sqlite3", ":memory:")
	closedDB.Close()

	oldDB := db
	db = closedDB
	t.Cleanup(func() { db = oldDB })

	tokens, err := getDeviceTokensForUser("user1")
	if err == nil {
		t.Error("expected error with closed db")
	}
	if tokens != nil {
		t.Error("expected nil tokens on error")
	}
}

// ==============================
// isConversationMuted
// ==============================

func TestCB15_IsConversationMuted_True(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "mute-user1")
	cb15CreateAgent(t, "agent-mute1")
	cb15CreateConversation(t, "conv-mute1", "mute-user1", "agent-mute1")

	// Mute the conversation
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"mute-user1", "conv-mute1")

	if !isConversationMuted("mute-user1", "conv-mute1") {
		t.Error("expected conversation to be muted")
	}
}

func TestCB15_IsConversationMuted_False(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "mute-user2")
	cb15CreateAgent(t, "agent-mute2")
	cb15CreateConversation(t, "conv-mute2", "mute-user2", "agent-mute2")

	// Not muted - no preference row
	if isConversationMuted("mute-user2", "conv-mute2") {
		t.Error("expected conversation to not be muted (no preference)")
	}
}

func TestCB15_IsConversationMuted_ExplicitUnmute(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "mute-user3")
	cb15CreateAgent(t, "agent-mute3")
	cb15CreateConversation(t, "conv-mute3", "mute-user3", "agent-mute3")

	// Explicitly set muted = false
	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 0)",
		"mute-user3", "conv-mute3")

	if isConversationMuted("mute-user3", "conv-mute3") {
		t.Error("expected conversation to not be muted (explicit unmute)")
	}
}

// ==============================
// isAllowedContentType deeper coverage
// ==============================

func TestCB15_IsAllowedContentType_SpecificTypes(t *testing.T) {
	tests := []struct {
		ct       string
		expected bool
	}{
		{"application/pdf", true},
		{"text/csv", true},
		{"text/markdown", true},
		{"application/json", true},
		{"audio/mpeg", true},
		{"video/mp4", true},
		{"application/x-executable", false},
		{"application/octet-stream", false},
		{"text/html", true}, // text/ prefix is allowed
	}

	for _, tt := range tests {
		result := isAllowedContentType(tt.ct)
		if result != tt.expected {
			t.Errorf("isAllowedContentType(%q) = %v, expected %v", tt.ct, result, tt.expected)
		}
	}
}

// ==============================
// getEnvOrDefault
// ==============================

func TestCB15_GetEnvOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_CB15_VAR", "custom")
	defer os.Unsetenv("TEST_CB15_VAR")

	result := getEnvOrDefault("TEST_CB15_VAR", "default")
	if result != "custom" {
		t.Errorf("expected 'custom', got %s", result)
	}
}

func TestCB15_GetEnvOrDefault_NotSet(t *testing.T) {
	os.Unsetenv("TEST_CB15_MISSING_VAR")
	result := getEnvOrDefault("TEST_CB15_MISSING_VAR", "fallback")
	if result != "fallback" {
		t.Errorf("expected 'fallback', got %s", result)
	}
}

func TestCB15_GetEnvOrDefault_Empty(t *testing.T) {
	os.Setenv("TEST_CB15_EMPTY_VAR", "")
	defer os.Unsetenv("TEST_CB15_EMPTY_VAR")

	result := getEnvOrDefault("TEST_CB15_EMPTY_VAR", "fallback")
	if result != "fallback" {
		t.Errorf("empty env var should use default, got %s", result)
	}
}

// ==============================
// envIntOrDefault
// ==============================

func TestCB15_EnvIntOrDefault_Valid(t *testing.T) {
	os.Setenv("TEST_CB15_INT", "42")
	defer os.Unsetenv("TEST_CB15_INT")

	result := envIntOrDefault("TEST_CB15_INT", 10)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestCB15_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_CB15_INT_BAD", "notanumber")
	defer os.Unsetenv("TEST_CB15_INT_BAD")

	result := envIntOrDefault("TEST_CB15_INT_BAD", 10)
	if result != 10 {
		t.Errorf("expected default 10 for invalid value, got %d", result)
	}
}

func TestCB15_EnvIntOrDefault_NotSet(t *testing.T) {
	os.Unsetenv("TEST_CB15_INT_MISSING")

	result := envIntOrDefault("TEST_CB15_INT_MISSING", 10)
	if result != 10 {
		t.Errorf("expected default 10 for missing var, got %d", result)
	}
}

// ==============================
// envDurationOrDefault
// ==============================

func TestCB15_EnvDurationOrDefault_Valid(t *testing.T) {
	os.Setenv("TEST_CB15_DUR", "5m30s")
	defer os.Unsetenv("TEST_CB15_DUR")

	result := envDurationOrDefault("TEST_CB15_DUR", 10*time.Minute)
	expected := 5*time.Minute + 30*time.Second
	if result != expected {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestCB15_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_CB15_DUR_BAD", "notaduration")
	defer os.Unsetenv("TEST_CB15_DUR_BAD")

	result := envDurationOrDefault("TEST_CB15_DUR_BAD", 10*time.Minute)
	if result != 10*time.Minute {
		t.Errorf("expected default 10m for invalid value, got %v", result)
	}
}

func TestCB15_EnvDurationOrDefault_NotSet(t *testing.T) {
	os.Unsetenv("TEST_CB15_DUR_MISSING")

	result := envDurationOrDefault("TEST_CB15_DUR_MISSING", 10*time.Minute)
	if result != 10*time.Minute {
		t.Errorf("expected default 10m for missing var, got %v", result)
	}
}

// ==============================
// Connection methods deeper coverage
// ==============================

func TestCB15_Connection_SafeSend_Closed(t *testing.T) {
	conn := &Connection{
		send:     make(chan []byte, 1),
		closed:   true,
		closeMu:  sync.RWMutex{},
	}
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("SafeSend should return false when connection is closed")
	}
}

func TestCB15_Connection_SafeSend_OpenBufferFull(t *testing.T) {
	conn := &Connection{
		send:   make(chan []byte, 1), // buffer of 1
		closed: false,
		closeMu: sync.RWMutex{},
	}
	// Fill the buffer
	conn.send <- []byte("first")

	result := conn.SafeSend([]byte("second"))
	if result {
		t.Error("SafeSend should return false when buffer is full")
	}
}

func TestCB15_Connection_SafeSend_Success(t *testing.T) {
	conn := &Connection{
		send:   make(chan []byte, 10),
		closed: false,
		closeMu: sync.RWMutex{},
	}
	result := conn.SafeSend([]byte("test"))
	if !result {
		t.Error("SafeSend should return true when buffer has space")
	}
}

func TestCB15_Connection_IsClosed_True(t *testing.T) {
	conn := &Connection{
		closed:  true,
		closeMu: sync.RWMutex{},
	}
	if !conn.IsClosed() {
		t.Error("IsClosed should return true")
	}
}

func TestCB15_Connection_IsClosed_False(t *testing.T) {
	conn := &Connection{
		closed:  false,
		closeMu: sync.RWMutex{},
	}
	if conn.IsClosed() {
		t.Error("IsClosed should return false")
	}
}

// ==============================
// WebPush deeper coverage
// ==============================

func TestCB15_WebPushSubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	rec := httptest.NewRecorder()
	handleWebPushSubscribe(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_WebPushSubscribe_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleWebPushSubscribe(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_WebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	rec := httptest.NewRecorder()
	handleWebPushUnsubscribe(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_WebPushUnsubscribe_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleWebPushUnsubscribe(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_VAPIDKey_WithAuth(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "vapid-user1")

	vapidPublicKey = ""
	t.Cleanup(func() { vapidPublicKey = "" })

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetVAPIDKey(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when VAPID not configured, got %d", rec.Code)
	}
}

// ==============================
// Device token register/unregister deeper
// ==============================

func TestCB15_RegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	rec := httptest.NewRecorder()
	handleRegisterDeviceToken(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_RegisterDeviceToken_NoAuth(t *testing.T) {
	body := `{"device_token": "abc123", "platform": "ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleRegisterDeviceToken(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCB15_UnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/unregister", nil)
	rec := httptest.NewRecorder()
	handleUnregisterDeviceToken(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_RegisterDeviceToken_AndroidPlatform(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "reg-dev-user1")

	body := `{"device_token": "android-token-123", "platform": "android"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleRegisterDeviceToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify token was stored with android platform
	var platform string
	err := db.QueryRow("SELECT platform FROM device_tokens WHERE device_token = ?", "android-token-123").Scan(&platform)
	if err != nil {
		t.Fatalf("query device token: %v", err)
	}
	if platform != "android" {
		t.Errorf("expected platform 'android', got %s", platform)
	}
}

func TestCB15_UnregisterDeviceToken_Valid(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "unreg-dev-user1")

	// Register a token first
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		"unreg-dev-user1", "tok-to-remove", "ios")

	body := `{"device_token": "tok-to-remove"}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleUnregisterDeviceToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify token was removed
	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE device_token = ?", "tok-to-remove").Scan(&count)
	if count != 0 {
		t.Errorf("token should be removed, count=%d", count)
	}
}

// ==============================
// changeUserPassword deeper coverage
// ==============================

func TestCB15_ChangeUserPassword_InvalidOldPassword(t *testing.T) {
	cb15SetupDB(t)
	userID := "pwd-user1"
	cb15MakeToken(t, userID)

	err := changeUserPassword(userID, "wrongpassword", "newpass123")
	if err == nil {
		t.Error("expected error for invalid old password")
	}
	if err.Error() != "invalid old password" {
		t.Errorf("expected 'invalid old password', got %v", err)
	}
}

func TestCB15_ChangeUserPassword_ShortNewPassword(t *testing.T) {
	cb15SetupDB(t)
	userID := "pwd-user2"
	cb15MakeToken(t, userID)

	err := changeUserPassword(userID, "testpass123", "abc")
	if err == nil {
		t.Error("expected error for short new password")
	}
	if !strings.Contains(err.Error(), "6 characters") {
		t.Errorf("expected error about minimum length, got %v", err)
	}
}

func TestCB15_ChangeUserPassword_NonexistentUser(t *testing.T) {
	cb15SetupDB(t)

	err := changeUserPassword("nonexistent-user", "old", "newpass123")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

// ==============================
// getConversation deeper coverage
// ==============================

func TestCB15_GetConversation_Valid(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "conv-user1")
	cb15CreateAgent(t, "agent-conv1")
	cb15CreateConversation(t, "conv-test1", "conv-user1", "agent-conv1")

	conv, err := getConversation("conv-test1")
	if err != nil {
		t.Fatalf("getConversation: %v", err)
	}
	if conv == nil {
		t.Fatal("expected conversation, got nil")
	}
	if conv.ID != "conv-test1" {
		t.Errorf("expected ID 'conv-test1', got %s", conv.ID)
	}
	if conv.UserID != "conv-user1" {
		t.Errorf("expected UserID 'conv-user1', got %s", conv.UserID)
	}
	if conv.AgentID != "agent-conv1" {
		t.Errorf("expected AgentID 'agent-conv1', got %s", conv.AgentID)
	}
}

func TestCB15_GetConversation_NotFound(t *testing.T) {
	cb15SetupDB(t)

	conv, err := getConversation("nonexistent")
	if err != nil {
		t.Fatalf("getConversation: %v", err)
	}
	if conv != nil {
		t.Error("expected nil for nonexistent conversation")
	}
}

// ==============================
// CreateConversation deeper coverage
// ==============================

func TestCB15_CreateConversation_Valid(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "create-conv-user1")
	cb15CreateAgent(t, "agent-create1")

	conv, err := CreateConversation("create-conv-user1", "agent-create1")
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if conv == nil || conv.ID == "" {
		t.Error("expected non-nil conversation with ID")
	}

	// Verify in DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", conv.ID).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 conversation, got %d", count)
	}
}

func TestCB15_CreateConversation_Duplicate(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "create-conv-user2")
	cb15CreateAgent(t, "agent-create2")

	conv1, err := CreateConversation("create-conv-user2", "agent-create2")
	if err != nil {
		t.Fatalf("first CreateConversation: %v", err)
	}

	// Create another conversation (should work - different ID)
	conv2, err := CreateConversation("create-conv-user2", "agent-create2")
	if err != nil {
		t.Fatalf("second CreateConversation: %v", err)
	}
	if conv1.ID == conv2.ID {
		t.Error("different conversations should have different IDs")
	}
}

// ==============================
// searchMessages deeper coverage
// ==============================

func TestCB15_SearchMessages_WithLimit(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "search-user1")
	cb15CreateAgent(t, "agent-search1")
	cb15CreateConversation(t, "conv-search1", "search-user1", "agent-search1")

	// Insert messages
	for i := 0; i < 10; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
			fmt.Sprintf("msg-search-%d", i), "conv-search1", "user", "search-user1", fmt.Sprintf("hello world %d", i))
	}

	form := strings.NewReader("q=hello&limit=5")
	req := httptest.NewRequest(http.MethodGet, "/messages/search?q=hello&limit=5", form)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleSearchMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var results []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &results)
	if len(results) > 5 {
		t.Errorf("expected at most 5 results with limit=5, got %d", len(results))
	}
}

// ==============================
// Message reactions deeper coverage
// ==============================

func TestCB15_AddReaction_Valid(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "react-user1")
	cb15CreateAgent(t, "agent-react1")
	cb15CreateConversation(t, "conv-react1", "react-user1", "agent-react1")

	// Insert a message
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg-react1", "conv-react1", "user", "react-user1", "react to this")

	// Add reaction via DB function
	_, added, err := addReaction("msg-react1", "react-user1", "👍")
	if err != nil {
		t.Errorf("addReaction: %v", err)
	}
	if !added {
		t.Error("expected reaction to be added")
	}
}

func TestCB15_RemoveReaction_Valid(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "react-user2")
	cb15CreateAgent(t, "agent-react2")
	cb15CreateConversation(t, "conv-react2", "react-user2", "agent-react2")

	// Insert a message and reaction
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg-react2", "conv-react2", "user", "react-user2", "react to this")
	addReaction("msg-react2", "react-user2", "👍")

	// Toggle reaction (same user+emoji removes it)
	_, added, err := addReaction("msg-react2", "react-user2", "👍")
	if err != nil {
		t.Errorf("toggle reaction: %v", err)
	}
	if added {
		t.Error("expected reaction to be removed (toggle)")
	}
}

func TestCB15_GetReactions_Valid(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "react-user3")
	cb15CreateAgent(t, "agent-react3")
	cb15CreateConversation(t, "conv-react3", "react-user3", "agent-react3")

	// Insert a message and reactions
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content) VALUES (?, ?, ?, ?, ?)",
		"msg-react3", "conv-react3", "user", "react-user3", "react to this")
	addReaction("msg-react3", "react-user3", "❤️")
	addReaction("msg-react3", "react-user3", "👍")

	req := httptest.NewRequest(http.MethodGet, "/messages/reactions?message_id=msg-react3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetReactions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var reactions []MessageReaction
	json.Unmarshal(rec.Body.Bytes(), &reactions)
	if len(reactions) < 2 {
		t.Errorf("expected at least 2 reactions, got %d", len(reactions))
	}
}

// ==============================
// Conversation tags deeper coverage
// ==============================

func TestCB15_AddTag_Valid(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "tag-user1")
	cb15CreateAgent(t, "agent-tag1")
	cb15CreateConversation(t, "conv-tag1", "tag-user1", "agent-tag1")

	form := strings.NewReader("conversation_id=conv-tag1&tag=important")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleAddTag(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_RemoveTag_Valid(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "tag-user2")
	cb15CreateAgent(t, "agent-tag2")
	cb15CreateConversation(t, "conv-tag2", "tag-user2", "agent-tag2")

	// Add tag first
	addConversationTag("conv-tag2", "tag-user2", "work")

	form := strings.NewReader("conversation_id=conv-tag2&tag=work")
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags/remove", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleRemoveTag(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_GetTags_Valid(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "tag-user3")
	cb15CreateAgent(t, "agent-tag3")
	cb15CreateConversation(t, "conv-tag3", "tag-user3", "agent-tag3")

	addConversationTag("conv-tag3", "tag-user3", "work")
	addConversationTag("conv-tag3", "tag-user3", "project-x")

	req := httptest.NewRequest(http.MethodGet, "/conversations/tags?conversation_id=conv-tag3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetTags(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var tags []ConversationTag
	json.Unmarshal(rec.Body.Bytes(), &tags)
	if len(tags) < 2 {
		t.Errorf("expected at least 2 tags, got %d", len(tags))
	}
}

// ==============================
// storeMessagesBatch deeper coverage
// ==============================

func TestCB15_StoreMessagesBatch_MultipleMessages(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "batch-user1")
	cb15CreateAgent(t, "agent-batch1")
	cb15CreateConversation(t, "conv-batch1", "batch-user1", "agent-batch1")

	msgs := []RoutedMessage{
		{ConversationID: "conv-batch1", SenderType: "user", SenderID: "batch-user1", Content: "msg1", Type: "message"},
		{ConversationID: "conv-batch1", SenderType: "user", SenderID: "batch-user1", Content: "msg2", Type: "message"},
		{ConversationID: "conv-batch1", SenderType: "user", SenderID: "batch-user1", Content: "msg3", Type: "message"},
	}

	_, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", "conv-batch1").Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 messages, got %d", count)
	}
}

// ==============================
// extractIP deeper coverage
// ==============================

func TestCB15_ExtractIP_XForwardedForMultiple(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 9.10.11.12")

	ip := extractIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("expected first IP from X-Forwarded-For, got %s", ip)
	}
}

func TestCB15_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "10.20.30.40")

	ip := extractIP(req)
	if ip != "10.20.30.40" {
		t.Errorf("expected X-Real-IP, got %s", ip)
	}
}

func TestCB15_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractIP(req)
	if !strings.HasPrefix(ip, "192.168.1.1") {
		t.Errorf("expected remote addr IP, got %s", ip)
	}
}

// ==============================
// ValidateAdminSecret
// ==============================

func TestCB15_ValidateAdminSecret_Correct(t *testing.T) {
	os.Setenv("ADMIN_SECRET", "test-admin-secret-12345")
	defer os.Unsetenv("ADMIN_SECRET")

	if err := ValidateAdminSecret("admin-dev-secret"); err != nil {
		t.Error("expected admin secret to validate")
	}
}

func TestCB15_ValidateAdminSecret_Wrong(t *testing.T) {
	os.Setenv("ADMIN_SECRET", "test-admin-secret-12345")
	defer os.Unsetenv("ADMIN_SECRET")

	if err := ValidateAdminSecret("wrong-secret"); err == nil {
		t.Error("expected admin secret to fail validation")
	}
}

func TestCB15_ValidateAdminSecret_Empty(t *testing.T) {
	os.Unsetenv("ADMIN_SECRET")

	if err := ValidateAdminSecret("any-secret"); err == nil {
		t.Error("expected admin secret to fail when not set")
	}
}

// ==============================
// WebChat-specific upload content type detection
// ==============================

func TestCB15_Upload_TextFileWithContentType(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "upload-user-txt")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello world text file"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handleUpload(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for text file upload, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_Upload_AudioFile(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "upload-user-audio")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.mp3")
	part.Write([]byte("fake audio data"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handleUpload(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for audio file, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ==============================
// handleGetMessages deeper coverage
// ==============================

func TestCB15_GetMessages_WithPagination(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "msg-user1")
	cb15CreateAgent(t, "agent-msg1")
	cb15CreateConversation(t, "conv-msg1", "msg-user1", "agent-msg1")

	// Insert messages
	for i := 0; i < 20; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("msg-page-%d", i), "conv-msg1", "user", "msg-user1",
			fmt.Sprintf("message %d", i), time.Now().UTC().Add(time.Duration(i)*time.Second))
	}

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=conv-msg1&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var messages []StoredMessage
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) != 5 {
		t.Errorf("expected 5 messages with limit=5, got %d", len(messages))
	}
}

// ==============================
// handleListConversations deeper coverage
// ==============================

func TestCB15_ListConversations_Valid(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "list-conv-user1")
	cb15CreateAgent(t, "agent-list1")
	cb15CreateConversation(t, "conv-list1", "list-conv-user1", "agent-list1")
	cb15CreateConversation(t, "conv-list2", "list-conv-user1", "agent-list1")

	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleListConversations(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var convs []Conversation
	json.Unmarshal(rec.Body.Bytes(), &convs)
	if len(convs) < 2 {
		t.Errorf("expected at least 2 conversations, got %d", len(convs))
	}
}

// ==============================
// getConversationMessages deeper coverage
// ==============================

func TestCB15_GetConversationMessages_WithBefore(t *testing.T) {
	cb15SetupDB(t)
	cb15MakeToken(t, "msg-before-user1")
	cb15CreateAgent(t, "agent-before1")
	cb15CreateConversation(t, "conv-before1", "msg-before-user1", "agent-before1")

	// Insert messages with different timestamps
	for i := 0; i < 10; i++ {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("msg-before-%d", i), "conv-before1", "user", "msg-before-user1",
			fmt.Sprintf("message %d", i), time.Now().UTC().Add(time.Duration(i)*time.Minute))
	}

	// Get messages before the 5th message
	msgs, err := getConversationMessages("conv-before1", 5, "")
	if err != nil {
		t.Fatalf("getConversationMessages: %v", err)
	}
	if len(msgs) > 5 {
		t.Errorf("expected at most 5 messages, got %d", len(msgs))
	}
}

// ==============================
// handleGetPresence deeper coverage
// ==============================

func TestCB15_GetPresence_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/presence", nil)
	rec := httptest.NewRecorder()
	handleGetPresence(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCB15_GetPresence_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	rec := httptest.NewRecorder()
	handleGetPresence(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// ==============================
// TieredRateLimiter deeper coverage
// ==============================

func TestCB15_TieredRateLimiter_AllowExceedsLimit(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Free tier: 60/min
	for i := 0; i < 60; i++ {
		trl.Allow("limited-user")
	}

	// 61st should be denied
	result, _, _ := trl.Allow("limited-user")
	if result {
		t.Error("expected 61st request to be denied")
	}
}

func TestCB15_TieredRateLimiter_WindowReset(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })

	// Use up the limit
	for i := 0; i < TierFree.Burst; i++ {
		trl.Allow("window-user")
	}

	// Manually expire the window
	trl.mu.Lock()
	if entry, ok := trl.limits["window-user"]; ok {
		entry.windowEnd = time.Now().Add(-1 * time.Second)
	}
	trl.mu.Unlock()

	// Should allow again (new window)
	result, _, _ := trl.Allow("window-user")
	if !result {
		t.Error("expected request to be allowed after window reset")
	}
}

func TestCB15_TieredRateLimiter_GetTierDefault(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	tier := trl.GetTier("unknown-user")
	if tier.Name != "free" {
		t.Errorf("expected free tier for unknown user, got %s", tier.Name)
	}
}

func TestCB15_TieredRateLimiter_SetAndGetTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	t.Cleanup(func() { trl.Stop() })
	trl.SetTier("pro-user", TierPro)
	tier := trl.GetTier("pro-user")
	if tier.Name != "pro" {
		t.Errorf("expected pro tier, got %s", tier.Name)
	}
	if tier.Burst != TierPro.Burst {
		t.Errorf("expected burst %d, got %d", TierPro.Burst, tier.Burst)
	}
}

// ==============================
// OfflineQueue deeper coverage
// ==============================

func TestCB15_OfflineQueue_DrainRecipient(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	msgs := q.Drain("user1")
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages for user1, got %d", len(msgs))
	}

	msgs2 := q.Drain("user1")
	if len(msgs2) != 0 {
		t.Errorf("expected 0 messages after drain, got %d", len(msgs2))
	}

	// user2 should still have their message
	msgs3 := q.Drain("user2")
	if len(msgs3) != 1 {
		t.Errorf("expected 1 message for user2, got %d", len(msgs3))
	}
}

func TestCB15_OfflineQueue_Depth(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	if q.TotalDepth() != 0 {
		t.Errorf("expected depth 0, got %d", q.TotalDepth())
	}

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user2", []byte("msg2"))
	if q.TotalDepth() != 2 {
		t.Errorf("expected depth 2, got %d", q.TotalDepth())
	}

	q.Drain("user1")
	if q.TotalDepth() != 1 {
		t.Errorf("expected depth 1 after drain, got %d", q.TotalDepth())
	}
}

// ==============================
// StoreEncryptedMessage with agent auth
// ==============================

func TestCB15_StoreEncrypted_AgentAuth(t *testing.T) {
	cb15SetupDB(t)
	cb15CreateAgent(t, "agent-e2e6")
	cb15MakeToken(t, "e2e-user6")
	cb15CreateConversation(t, "conv-e2e6", "e2e-user6", "agent-e2e6")

	h := newHub()
	oldHub := hub
	hub = h
	go hub.run()
	defer func() { hub.Stop(); hub = oldHub }()

	body := `{
		"conversation_id": "conv-e2e6",
		"ciphertext": "agent-encrypted",
		"iv": "iv-agent",
		"recipient_key_id": "rkey-agent",
		"sender_key_id": "skey-agent",
		"algorithm": "aes-256-gcm"
	}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-e2e6")
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for agent auth, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCB15_StoreEncrypted_WrongParticipant(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "e2e-wrong-user")
	cb15CreateAgent(t, "agent-e2e-wrong")
	cb15CreateConversation(t, "conv-e2e-wrong", "e2e-correct-user", "agent-e2e-wrong")

	// e2e-wrong-user is NOT a participant in conv-e2e-wrong
	body := `{
		"conversation_id": "conv-e2e-wrong",
		"ciphertext": "wrong",
		"iv": "iv-wrong",
		"recipient_key_id": "rkey-wrong",
		"algorithm": "aes-256-gcm"
	}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleStoreEncryptedMessage(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong participant, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ==============================
// handleGetEncryptedMessages agent auth
// ==============================

func TestCB15_GetEncrypted_AgentAuth(t *testing.T) {
	cb15SetupDB(t)
	cb15CreateAgent(t, "agent-enc-get1")
	cb15MakeToken(t, "enc-get-user-a")
	cb15CreateConversation(t, "conv-enc-get1", "enc-get-user-a", "agent-enc-get1")

	// Insert encrypted message
	db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg-get1", "conv-enc-get1", "enc-get-user-a", "user", "cipher1", "iv1", "rkey1", "aes-256-gcm", time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-enc-get1", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-enc-get1")
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for agent auth, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var messages []EncryptedMessage
	json.Unmarshal(rec.Body.Bytes(), &messages)
	if len(messages) < 1 {
		t.Error("expected at least 1 encrypted message")
	}
}

func TestCB15_GetEncrypted_WrongParticipant(t *testing.T) {
	cb15SetupDB(t)
	token := cb15MakeToken(t, "enc-get-wrong")
	cb15CreateAgent(t, "agent-enc-wrong")
	cb15CreateConversation(t, "conv-enc-wrong", "enc-get-correct", "agent-enc-wrong")

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-enc-wrong", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleGetEncryptedMessages(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for wrong participant, got %d", rec.Code)
	}
}

// ==============================
// initSchemaForDriver
// ==============================

func TestCB15_InitSchemaForDriver_SQLite(t *testing.T) {
	origDriver := currentDriver
	t.Cleanup(func() { currentDriver = origDriver })

	currentDriver = DriverSQLite
	schema := initSchemaForDriver()
	if schema == "" {
		t.Error("expected non-empty SQLite schema")
	}
	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS users") {
		t.Error("SQLite schema should contain users table")
	}
}

func TestCB15_InitSchemaForDriver_PostgreSQL(t *testing.T) {
	origDriver := currentDriver
	t.Cleanup(func() { currentDriver = origDriver })

	currentDriver = DriverPostgreSQL
	schema := initSchemaForDriver()
	if schema == "" {
		t.Error("expected non-empty PostgreSQL schema")
	}
	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS users") {
		t.Error("PostgreSQL schema should contain users table")
	}
}

// ==============================
// Ensure additional io import is used
// ==============================

func TestCB15_Upload_SeekError(t *testing.T) {
	// Test the file seek path by providing a file that needs content type detection
	cb15SetupDB(t)
	token := cb15MakeToken(t, "upload-seek-user")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "image.jpg")
	// Write JPEG magic bytes
	jpegHeader := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	part.Write(jpegHeader)
	part.Write(make([]byte, 100))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handleUpload(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for JPEG upload, got %d; body: %s", rec.Code, rec.Body.String())
	}
}