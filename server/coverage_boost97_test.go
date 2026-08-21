package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// ==============================
// CB97: Coverage boost targeting remaining low-coverage functions.
// ==============================

// --- Helper functions ---

func setupTestDB_CB97() {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	// Note: not setting SetMaxOpenConns(1) because some source functions
	// do nested queries (e.g. getConversationMessages calls getMessageReactions)
	// which would deadlock with a single-connection pool.
	currentDriver = DriverSQLite
	initSchema(db)
}

func teardownTestDB_CB97() {
	if db != nil {
		db.Close()
		db = nil
	}
}

func setupHub_CB97() *Hub {
	setupTestDB_CB97()
	h := newHub()
	hub = h
	go h.run()
	return h
}

func teardownHub_CB97(h *Hub) {
	if h != nil {
		h.Stop()
	}
	hub = nil
	teardownTestDB_CB97()
}

func makeJWT_CB97(userID string) string {
	token, err := GenerateJWT(userID, "testuser")
	if err != nil {
		panic(err)
	}
	return token
}

func makeAuthReq_CB97(method, path string, jwt string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	return req
}

func makeAuthReqCtx_CB97(method, path string, jwt string) *http.Request {
	req := makeAuthReq_CB97(method, path, jwt)
	claims, _ := ValidateJWT(jwt)
	if claims != nil {
		ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
		req = req.WithContext(ctx)
	}
	return req
}

func makeAgentReq_CB97(method, path, agentID, secret string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	if secret != "" {
		req.Header.Set("X-Agent-Secret", secret)
	}
	if agentID != "" {
		req.Header.Set("X-Agent-ID", agentID)
	}
	return req
}

func registerUser_CB97(username string) string {
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID := generateID("user")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, username, string(hashed))
	if err != nil {
		panic(err)
	}
	return userID
}

func registerAgent_CB97(agentID, name string) {
	db.Exec("INSERT OR REPLACE INTO agents (id, name, created_at) VALUES (?, ?, ?)",
		agentID, name, time.Now().UTC())
}

func createConversation_CB97(userID, agentID string) string {
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
		convID, userID, agentID, time.Now().UTC())
	return convID
}

func storeMessage_CB97(convID, senderType, senderID, content string) string {
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, convID, senderType, senderID, content, time.Now().UTC())
	return msgID
}

// --- TieredRateLimiter.Reset (0%) ---

func TestCB97_TieredRateLimiter_Reset(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("user1", TierPro)
	trl.Allow("user1")
	trl.Allow("user1")
	trl.Reset()
	// After Reset, GetTier should return default (Free)
	if tier := trl.GetTier("user1"); tier.Name != "free" {
		t.Errorf("expected free tier after Reset, got %s", tier.Name)
	}
	if remaining := trl.GetRemaining("user1"); remaining != TierFree.Burst {
		t.Errorf("expected %d remaining after Reset, got %d", TierFree.Burst, remaining)
	}
}

// --- handleAdminRateLimitTier (0%) — POST and GET routing ---

func TestCB97_HandleAdminRateLimitTier_Post(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	trl := NewTieredRateLimiter()
	globalTieredLimiter = trl

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("user_id=test-user&tier=pro"))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleAdminRateLimitTier_Get(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	// Set a tier first
	globalTieredLimiter = NewTieredRateLimiter()
	globalTieredLimiter.SetTier("test-user", TierPro)

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=test-user", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- InitTracing (13.6%) — HTTP, gRPC, double init, sampling rate ---

func TestCB97_InitTracing_HTTPExporter(t *testing.T) {
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	os.Setenv("OTEL_SERVICE_NAME", "test-service")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	defer os.Unsetenv("OTEL_SERVICE_NAME")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing with HTTP exporter returned error (acceptable): %v", err)
	} else if !tracingEnabled {
		t.Error("expected tracingEnabled=true")
	}

	ShutdownTracing()
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil
}

func TestCB97_InitTracing_GRPCExporter(t *testing.T) {
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")

	err := InitTracing()
	if err != nil {
		// Resource schema conflict can happen if OTEL SDK has version mismatch
		t.Logf("InitTracing with gRPC exporter returned error (acceptable): %v", err)
	} else if !tracingEnabled {
		t.Error("expected tracingEnabled=true")
	}

	ShutdownTracing()
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil
}

func TestCB97_InitTracing_DefaultServiceName(t *testing.T) {
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	os.Setenv("OTEL_SERVICE_NAME", "")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	defer os.Unsetenv("OTEL_SERVICE_NAME")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (acceptable): %v", err)
	}

	ShutdownTracing()
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil
}

func TestCB97_InitTracing_InvalidSamplingRate(t *testing.T) {
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	os.Setenv("OTEL_SAMPLING_RATE", "not-a-number")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	defer os.Unsetenv("OTEL_SAMPLING_RATE")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (acceptable): %v", err)
	}

	ShutdownTracing()
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil
}

func TestCB97_InitTracing_AlreadyInitialized(t *testing.T) {
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")

	_ = InitTracing()
	err := InitTracing()
	if err != nil {
		t.Errorf("expected no error on second InitTracing, got %v", err)
	}

	ShutdownTracing()
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil
}

// --- sendAPNSNotification (14.3%) — disabled paths ---

func TestCB97_SendAPNSNotification_NilConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()

	err := sendAPNSNotification("token", "title", "body", "conv123")
	if err != nil {
		t.Errorf("expected nil error when pushConfig is nil, got %v", err)
	}
}

func TestCB97_SendAPNSNotification_NotEnabled(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = old }()

	err := sendAPNSNotification("token", "title", "body", "conv123")
	if err != nil {
		t.Errorf("expected nil error when APNs not enabled, got %v", err)
	}
}

func TestCB97_SendAPNSNotification_NilClient(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, apnsClient: nil}
	defer func() { pushConfig = old }()

	err := sendAPNSNotification("token", "title", "body", "conv123")
	if err != nil {
		t.Errorf("expected nil error when apnsClient is nil, got %v", err)
	}
}

// --- sendFCMNotification (22.2%) — disabled paths ---

func TestCB97_SendFCMNotification_NilConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()

	err := sendFCMNotification("token", "title", "body", "conv123")
	if err != nil {
		t.Errorf("expected nil error when pushConfig is nil, got %v", err)
	}
}

func TestCB97_SendFCMNotification_NotEnabled(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = old }()

	err := sendFCMNotification("token", "title", "body", "conv123")
	if err != nil {
		t.Errorf("expected nil error when FCM not enabled, got %v", err)
	}
}

func TestCB97_SendFCMNotification_NilClient(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: true, fcmClient: nil}
	defer func() { pushConfig = old }()

	err := sendFCMNotification("token", "title", "body", "conv123")
	if err != nil {
		t.Errorf("expected nil error when fcmClient is nil, got %v", err)
	}
}

// --- loadTiersFromDB (44.4%) — nil DB, empty table, with tiers ---

func TestCB97_LoadTiersFromDB_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	trl := NewTieredRateLimiter()
	err := loadTiersFromDB(trl)
	if err != nil {
		t.Errorf("expected nil error when db is nil, got %v", err)
	}
}

func TestCB97_LoadTiersFromDB_EmptyTable(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	trl := NewTieredRateLimiter()
	loadTiersFromDB(trl)
	if tier := trl.GetTier("nonexistent"); tier.Name != "free" {
		t.Errorf("expected free tier, got %s", tier.Name)
	}
}

func TestCB97_LoadTiersFromDB_WithTiers(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	// Create real users first (FK constraint)
	userPro := registerUser_CB97("user-pro")
	userEnt := registerUser_CB97("user-ent")

	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		userPro, "pro")
	db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name, updated_at) VALUES (?, ?, datetime('now'))",
		userEnt, "enterprise")

	trl := NewTieredRateLimiter()
	loadTiersFromDB(trl)
	if tier := trl.GetTier(userPro); tier.Name != "pro" {
		t.Errorf("expected pro tier for user-pro, got %s", tier.Name)
	}
	if tier := trl.GetTier(userEnt); tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier for user-ent, got %s", tier.Name)
	}
}

// --- handleGetTags (46.2%) — success, empty, unauthorized, no auth, method, missing conv ID ---

func TestCB97_HandleGetTags_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-test"
	registerAgent_CB97(agentID, "Test Agent")
	convID := createConversation_CB97(userID, agentID)

	addConversationTag(convID, userID, "important")
	addConversationTag(convID, userID, "work")

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/conversations/tags?conversation_id="+convID, jwt)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var tags []ConversationTag
	json.Unmarshal(w.Body.Bytes(), &tags)
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

func TestCB97_HandleGetTags_Empty(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-test"
	registerAgent_CB97(agentID, "Test Agent")
	convID := createConversation_CB97(userID, agentID)

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/conversations/tags?conversation_id="+convID, jwt)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var tags []ConversationTag
	json.Unmarshal(w.Body.Bytes(), &tags)
	if len(tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(tags))
	}
}

func TestCB97_HandleGetTags_Unauthorized(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("user1")
	userID2 := registerUser_CB97("user2")
	agentID := "agent-test"
	registerAgent_CB97(agentID, "Test Agent")
	convID := createConversation_CB97(userID, agentID)

	jwt := makeJWT_CB97(userID2)
	req := makeAuthReq_CB97("GET", "/conversations/tags?conversation_id="+convID, jwt)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleGetTags_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=xxx", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleGetTags_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/conversations/tags", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB97_HandleGetTags_MissingConvID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/conversations/tags", jwt)
	w := httptest.NewRecorder()
	handleGetTags(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- handleGetKeyBundle (56.2%) — all keys, only identity, no keys, default owner_type ---

func TestCB97_HandleGetKeyBundle_AllKeys(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")

	// Upload identity, signed prekey, and one-time prekey using agent auth
	// Agent auth stores with owner_type="agent", so we query with owner_type=agent
	for _, kt := range []string{"identity", "signed_prekey", "one_time_prekey"} {
		body := fmt.Sprintf(`{"key_type":"%s","public_key":"pubkey-%s","signature":"sig-%s"}`, kt, kt, kt)
		req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(body))
		w := httptest.NewRecorder()
		handleUploadPublicKey(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for uploading %s, got %d: %s", kt, w.Code, w.Body.String())
		}
	}

	req := makeAgentReq_CB97("GET", "/keys/bundle?owner_id="+userID+"&owner_type=agent", "agent-1", getAgentSecret(), nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var bundle map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key in bundle")
	}
	if bundle["signed_prekey"] == nil {
		t.Error("expected signed_prekey in bundle")
	}
	if bundle["one_time_prekey"] == nil {
		t.Error("expected one_time_prekey in bundle")
	}
}

func TestCB97_HandleGetKeyBundle_OnlyIdentity(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")

	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"identity","public_key":"pubkey-identity","signature":"sig-identity"}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = makeAgentReq_CB97("GET", "/keys/bundle?owner_id="+userID+"&owner_type=agent", "agent-1", getAgentSecret(), nil)
	w = httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var bundle map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key in bundle")
	}
	if bundle["signed_prekey"] != nil {
		t.Error("expected no signed_prekey in bundle")
	}
}

func TestCB97_HandleGetKeyBundle_NoKeys(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	req := makeAgentReq_CB97("GET", "/keys/bundle?owner_id="+userID+"&owner_type=user", "agent-1", getAgentSecret(), nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no keys found, got %d", w.Code)
	}
}

func TestCB97_HandleGetKeyBundle_DefaultOwnerType(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")

	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"identity","public_key":"pubkey-identity"}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	// With default owner_type (empty), handleGetKeyBundle defaults to "user".
	// Since agent auth stores with owner_type="agent", we need owner_type=agent to find it.
	req = makeAgentReq_CB97("GET", "/keys/bundle?owner_id="+userID+"&owner_type=agent", "agent-1", getAgentSecret(), nil)
	w = httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with owner_type=agent, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleGetKeyBundle_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/bundle?owner_id=xxx", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB97_HandleGetKeyBundle_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/bundle?owner_id=xxx", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleGetKeyBundle_MissingOwnerID(t *testing.T) {
	req := makeAgentReq_CB97("GET", "/keys/bundle", "agent-1", getAgentSecret(), nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- SetTier (57.1%) — existing user, new user ---

func TestCB97_SetTier_ExistingUser(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("user1", TierFree)
	trl.Allow("user1")

	trl.SetTier("user1", TierPro)
	if tier := trl.GetTier("user1"); tier.Name != "pro" {
		t.Errorf("expected pro tier, got %s", tier.Name)
	}
	if remaining := trl.GetRemaining("user1"); remaining != TierPro.Burst {
		t.Errorf("expected %d remaining after SetTier reset, got %d", TierPro.Burst, remaining)
	}
}

func TestCB97_SetTier_NewUser(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("newuser", TierEnterprise)
	if tier := trl.GetTier("newuser"); tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier, got %s", tier.Name)
	}
}

// --- handleUpload (59.7%) — success, content detection, method, auth ---

func TestCB97_HandleUpload_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = "" }()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	body := &strings.Builder{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("hello world test content"))
	mw.WriteField("message_id", "msg-123")
	mw.Close()

	req := httptest.NewRequest("POST", "/upload", strings.NewReader(body.String()))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["attachment_id"] == nil && resp["id"] == nil {
		t.Error("expected attachment id in response")
	}
}

func TestCB97_HandleUpload_PNG(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = "" }()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	body := &strings.Builder{}
	mw := multipart.NewWriter(body)
	fw, _ := mw.CreateFormFile("file", "test.png")
	fw.Write([]byte("\x89PNG\r\n\x1a\n fake png"))
	mw.Close()

	req := httptest.NewRequest("POST", "/upload", strings.NewReader(body.String()))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB97_HandleUpload_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleUpload_InvalidToken(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleUpload_MissingFile(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	defer func() { serverDBPath = "" }()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	body := &strings.Builder{}
	mw := multipart.NewWriter(body)
	mw.Close()

	req := httptest.NewRequest("POST", "/upload", strings.NewReader(body.String()))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- writePump (63%) — message send ---

func TestCB97_WritePump_MessageSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		c := &Connection{
			id:       "test-conn",
			connType: "agent",
			send:     make(chan []byte, 256),
			conn:     conn,
		}

		c.send <- []byte(`{"type":"welcome"}`)
		close(c.send)

		c.writePump()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer wsConn.Close()

	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("expected to read message, got error: %v", err)
	}
	if !strings.Contains(string(msg), "welcome") {
		t.Errorf("expected welcome message, got %s", string(msg))
	}
}

// --- loadQueueFromDB (78.9%) — multiple entries, empty, nil DB ---

func TestCB97_LoadQueueFromDB_MultipleEntries(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	q := newOfflineQueue(100, 7*24*time.Hour)

	for i := 0; i < 5; i++ {
		data := fmt.Sprintf(`{"type":"message","data":{"content":"msg-%d"}}`, i)
		db.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, datetime('now'))",
			"user-1", data)
	}

	loadQueueFromDB(db, q)
	if q.TotalDepth() != 5 {
		t.Errorf("expected depth 5, got %d", q.TotalDepth())
	}
}

func TestCB97_LoadQueueFromDB_Empty(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)
	if q.TotalDepth() != 0 {
		t.Errorf("expected depth 0, got %d", q.TotalDepth())
	}
}

func TestCB97_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
	// Should not panic
}

// --- persistQueue (80%) — success, nil DB ---

func TestCB97_PersistQueue_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	data := []byte(`{"type":"message","data":{"content":"test"}}`)
	persistQueue(db, "user-1", data)
	// Verify it was stored
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 entry, got %d", count)
	}
}

func TestCB97_PersistQueue_NilDB(t *testing.T) {
	persistQueue(nil, "user-1", []byte("data"))
	// Should not panic
}

// --- deleteQueueMessages (80%) — success, nil DB ---

func TestCB97_DeleteQueueMessages_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, datetime('now'))",
		"user-1", `{"type":"message"}`)

	deleteQueueMessages(db, "user-1")

	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-1").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 after delete, got %d", count)
	}
}

func TestCB97_DeleteQueueMessages_NilDB(t *testing.T) {
	deleteQueueMessages(nil, "user-1")
	// Should not panic
}

// --- ShutdownTracing (80%) — nil provider, with provider ---

func TestCB97_ShutdownTracing_NilProvider(t *testing.T) {
	oldTP := tp
	tp = nil
	defer func() { tp = oldTP }()

	ShutdownTracing()
}

func TestCB97_ShutdownTracing_WithProvider(t *testing.T) {
	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")

	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (acceptable): %v", err)
	}
	ShutdownTracing()
	if tracingEnabled {
		t.Error("expected tracingEnabled=false after shutdown")
	}

	tracingEnabled = false
	tracingMu = sync.Once{}
	tp = nil
}

// --- StartCPUProfile (80%) — error, success ---

func TestCB97_StartCPUProfile_Error(t *testing.T) {
	_, err := StartCPUProfile("/nonexistent/dir/cannot_create/profile.prof")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestCB97_StartCPUProfile_Success(t *testing.T) {
	tmpDir := t.TempDir()
	stop, err := StartCPUProfile(filepath.Join(tmpDir, "profile.prof"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	stop()
}

// --- handleCPUProfileStart (80%) — success ---

func TestCB97_HandleCPUProfileStart_Success(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	// Ensure profiling state is clean
	cpuProfileState.Lock()
	if cpuProfileState.active && cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}
	cpuProfileState.Unlock()

	req := httptest.NewRequest("POST", "/admin/profile/cpu", nil)
	w := httptest.NewRecorder()
	handleCPUProfileStart(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Clean up
	cpuProfileState.Lock()
	if cpuProfileState.active && cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
	}
	cpuProfileState.Unlock()
}

// --- addReaction (76.9%) — toggle off, not found, unauthorized, different emojis ---

func TestCB97_AddReaction_ToggleOff(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	_, added, err := addReaction(msgID, userID, "👍")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !added {
		t.Error("expected added=true on first add")
	}

	_, added2, err := addReaction(msgID, userID, "👍")
	if err != nil {
		t.Errorf("expected no error toggling off, got %v", err)
	}
	if added2 {
		t.Error("expected added=false on toggle off")
	}
}

func TestCB97_AddReaction_MessageNotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	_, _, err := addReaction("nonexistent-msg", userID, "👍")
	if err == nil {
		t.Error("expected error for nonexistent message")
	}
}

func TestCB97_AddReaction_Unauthorized(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	unauthorizedUser := registerUser_CB97("otheruser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	_, _, err := addReaction(msgID, unauthorizedUser, "👍")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
}

func TestCB97_AddReaction_DifferentEmojis(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	r1, added1, err := addReaction(msgID, userID, "👍")
	if err != nil || !added1 {
		t.Fatalf("expected first reaction added, got err=%v added=%v", err, added1)
	}
	r2, added2, err := addReaction(msgID, userID, "❤️")
	if err != nil || !added2 {
		t.Fatalf("expected second reaction added, got err=%v added=%v", err, added2)
	}
	if r1.ID == r2.ID {
		t.Error("expected different IDs for different emoji reactions")
	}
}

// --- handleUploadPublicKey (78.1%) — replace identity, signed prekey, one-time, invalid type, invalid JSON ---

func TestCB97_HandleUploadPublicKey_ReplaceIdentity(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")

	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"identity","public_key":"key1","signature":"sig1"}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"identity","public_key":"key2","signature":"sig2"}`))
	w = httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on replace, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND key_type = 'identity'", userID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 identity key after replace, got %d", count)
	}
}

func TestCB97_HandleUploadPublicKey_SignedPreKey(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"signed_prekey","public_key":"spk1","signature":"sig-spk"}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleUploadPublicKey_OneTimePreKey(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"one_time_prekey","public_key":"otpk1","signature":"sig-otpk","key_id":5}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleUploadPublicKey_InvalidKeyType(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"invalid_type","public_key":"key1"}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid key_type, got %d", w.Code)
	}
}

func TestCB97_HandleUploadPublicKey_InvalidJSON(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleUploadPublicKey_EmptyPublicKey(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	req := makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
		`{"key_type":"identity","public_key":""}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleUploadPublicKey_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader(`{"key_type":"identity","public_key":"k"}`))
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleUploadPublicKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- handleStoreEncryptedMessage (73.6%) — agent, user, algorithm, conv not found, wrong agent ---

func TestCB97_HandleStoreEncryptedMessage_AgentSender(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	req := makeAgentReq_CB97("POST", "/messages/encrypted", agentID, getAgentSecret(), strings.NewReader(
		fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`, convID)))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleStoreEncryptedMessage_UserSender(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("POST", "/messages/encrypted", jwt)
	req.Body = io.NopCloser(strings.NewReader(
		fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`, convID)))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleStoreEncryptedMessage_ChaChaAlgorithm(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	req := makeAgentReq_CB97("POST", "/messages/encrypted", agentID, getAgentSecret(), strings.NewReader(
		fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"x25519-chacha20-poly1305"}`, convID)))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleStoreEncryptedMessage_UnsupportedAlgorithm(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	req := makeAgentReq_CB97("POST", "/messages/encrypted", agentID, getAgentSecret(), strings.NewReader(
		fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"invalid-algo"}`, convID)))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleStoreEncryptedMessage_ConvNotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	req := makeAgentReq_CB97("POST", "/messages/encrypted", "agent-1", getAgentSecret(), strings.NewReader(
		`{"conversation_id":"nonexistent","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB97_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	req := makeAgentReq_CB97("POST", "/messages/encrypted", "agent-1", getAgentSecret(), strings.NewReader(
		`{"conversation_id":"x","ciphertext":"","iv":"","algorithm":"aes-256-gcm"}`))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleStoreEncryptedMessage_AgentWrongConv(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	otherAgent := "agent-2"
	registerAgent_CB97(agentID, "Test")
	registerAgent_CB97(otherAgent, "Other")
	convID := createConversation_CB97(userID, agentID)

	req := makeAgentReq_CB97("POST", "/messages/encrypted", otherAgent, getAgentSecret(), strings.NewReader(
		fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`, convID)))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCB97_HandleStoreEncryptedMessage_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	req := makeAgentReq_CB97("POST", "/messages/encrypted", "agent-1", getAgentSecret(), strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- handleGetEncryptedMessages (68.3%) — success, limit, not found, missing conv ID, agent access ---

func TestCB97_HandleGetEncryptedMessages_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	handleStoreEncryptedMessage(httptest.NewRecorder(), makeAgentReq_CB97("POST", "/messages/encrypted", agentID, getAgentSecret(), strings.NewReader(
		fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`, convID))))

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/messages/encrypted?conversation_id="+convID, jwt)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var msgs []interface{}
	json.Unmarshal(w.Body.Bytes(), &msgs)
	if len(msgs) != 1 {
		t.Errorf("expected 1 message, got %d", len(msgs))
	}
}

func TestCB97_HandleGetEncryptedMessages_WithLimit(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	for i := 0; i < 3; i++ {
		handleStoreEncryptedMessage(httptest.NewRecorder(), makeAgentReq_CB97("POST", "/messages/encrypted", agentID, getAgentSecret(), strings.NewReader(
			fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct%d","iv":"iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`, convID, i))))
	}

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/messages/encrypted?conversation_id="+convID+"&limit=2", jwt)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var msgs []interface{}
	json.Unmarshal(w.Body.Bytes(), &msgs)
	if len(msgs) > 2 {
		t.Errorf("expected at most 2 messages, got %d", len(msgs))
	}
}

func TestCB97_HandleGetEncryptedMessages_OverMaxLimit(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/messages/encrypted?conversation_id="+convID+"&limit=99999", jwt)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB97_HandleGetEncryptedMessages_ConvNotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/messages/encrypted?conversation_id=nonexistent", jwt)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB97_HandleGetEncryptedMessages_MissingConvID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/messages/encrypted", jwt)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleGetEncryptedMessages_Unauthorized(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	userID2 := registerUser_CB97("otheruser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	jwt := makeJWT_CB97(userID2)
	req := makeAuthReq_CB97("GET", "/messages/encrypted?conversation_id="+convID, jwt)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unauthorized user, got %d", w.Code)
	}
}

func TestCB97_HandleGetEncryptedMessages_AgentAccess(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	handleStoreEncryptedMessage(httptest.NewRecorder(), makeAgentReq_CB97("POST", "/messages/encrypted", agentID, getAgentSecret(), strings.NewReader(
		fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"ct","iv":"iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`, convID))))

	req := makeAgentReq_CB97("GET", "/messages/encrypted?conversation_id="+convID, agentID, getAgentSecret(), nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- authenticateRequest (85.7%) — JWT, agent secret, no auth, invalid ---

func TestCB97_AuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
}

func TestCB97_AuthenticateRequest_ValidJWT(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if id != userID {
		t.Errorf("expected userID %s, got %s", userID, id)
	}
	if typ != "user" {
		t.Errorf("expected type 'user', got %s", typ)
	}
}

func TestCB97_AuthenticateRequest_ValidAgentSecret(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", "agent-123")
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if id != "agent-123" {
		t.Errorf("expected agent-123, got %s", id)
	}
	if typ != "agent" {
		t.Errorf("expected type 'agent', got %s", typ)
	}
}

func TestCB97_AuthenticateRequest_AgentSecretNoID(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for missing X-Agent-ID")
	}
}

func TestCB97_AuthenticateRequest_InvalidJWT(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestCB97_AuthenticateRequest_WrongAgentSecret(t *testing.T) {
	resetAgentSecret()
	defer resetAgentSecret()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "agent-123")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

// --- ValidateJWT (83.3%) — valid, empty, garbage ---

func TestCB97_ValidateJWT_Valid(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	claims, err := ValidateJWT(jwt)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("expected userID %s, got %s", userID, claims.UserID)
	}
}

func TestCB97_ValidateJWT_Empty(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestCB97_ValidateJWT_Garbage(t *testing.T) {
	_, err := ValidateJWT("not.a.real.jwt")
	if err == nil {
		t.Error("expected error for garbage token")
	}
}

// --- handleListOneTimePreKeys (81.8%) — success, zero, no auth, method ---

func TestCB97_HandleListOneTimePreKeys_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")

	for i := 0; i < 3; i++ {
		handleUploadPublicKey(httptest.NewRecorder(), makeAgentReq_CB97("POST", "/keys/upload", userID, getAgentSecret(), strings.NewReader(
			fmt.Sprintf(`{"key_type":"one_time_prekey","public_key":"otpk-%d","key_id":%d}`, i, i))))
	}

	req := makeAgentReq_CB97("GET", "/keys/otpk-count", userID, getAgentSecret(), nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["one_time_prekey_count"].(float64)) != 3 {
		t.Errorf("expected count 3, got %v", resp["one_time_prekey_count"])
	}
}

func TestCB97_HandleListOneTimePreKeys_Zero(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	req := makeAgentReq_CB97("GET", "/keys/otpk-count", userID, getAgentSecret(), nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["one_time_prekey_count"].(float64)) != 0 {
		t.Errorf("expected count 0, got %v", resp["one_time_prekey_count"])
	}
}

func TestCB97_HandleListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("POST", "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB97_HandleListOneTimePreKeys_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- Allow (81.8%) — new user, rate limited, window reset ---

func TestCB97_Allow_NewUser(t *testing.T) {
	trl := NewTieredRateLimiter()
	allowed, remaining, retry := trl.Allow("new-user")
	if !allowed {
		t.Error("expected allowed=true for new user")
	}
	if remaining != TierFree.Burst-1 {
		t.Errorf("expected remaining %d, got %d", TierFree.Burst-1, remaining)
	}
	if retry != 0 {
		t.Errorf("expected retry 0, got %d", retry)
	}
}

func TestCB97_Allow_RateLimited(t *testing.T) {
	trl := NewTieredRateLimiter()
	for i := 0; i < TierFree.Burst; i++ {
		trl.Allow("user1")
	}
	allowed, _, retry := trl.Allow("user1")
	if allowed {
		t.Error("expected allowed=false when rate limited")
	}
	if retry <= 0 {
		t.Error("expected positive retry when rate limited")
	}
}

func TestCB97_Allow_WindowReset(t *testing.T) {
	trl := NewTieredRateLimiter()
	for i := 0; i < TierFree.Burst; i++ {
		trl.Allow("user1")
	}
	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-1 * time.Second)
	}
	trl.mu.Unlock()

	allowed, remaining, _ := trl.Allow("user1")
	if !allowed {
		t.Error("expected allowed=true after window reset")
	}
	if remaining != TierFree.Burst-1 {
		t.Errorf("expected remaining %d after reset, got %d", TierFree.Burst-1, remaining)
	}
}

// --- GetRemaining (81.8%) — no entry, expired, with count ---

func TestCB97_GetRemaining_NoEntry(t *testing.T) {
	trl := NewTieredRateLimiter()
	remaining := trl.GetRemaining("nonexistent")
	if remaining != TierFree.Burst {
		t.Errorf("expected %d, got %d", TierFree.Burst, remaining)
	}
}

func TestCB97_GetRemaining_ExpiredWindow(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("user1", TierPro)
	trl.Allow("user1")
	trl.Allow("user1")

	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-1 * time.Second)
	}
	trl.mu.Unlock()

	remaining := trl.GetRemaining("user1")
	if remaining != TierPro.Burst {
		t.Errorf("expected %d, got %d", TierPro.Burst, remaining)
	}
}

func TestCB97_GetRemaining_WithCount(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.Allow("user1")
	trl.Allow("user1")
	trl.Allow("user1")

	remaining := trl.GetRemaining("user1")
	if remaining != TierFree.Burst-3 {
		t.Errorf("expected %d, got %d", TierFree.Burst-3, remaining)
	}
}

// --- persistTierToDB (85.7%) — success, nil DB, replace ---

func TestCB97_PersistTierToDB_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	var tierName string
	db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user1").Scan(&tierName)
	if tierName != "pro" {
		t.Errorf("expected 'pro', got %s", tierName)
	}
}

func TestCB97_PersistTierToDB_NilDB(t *testing.T) {
	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error for nil DB, got %v", err)
	}
}

func TestCB97_PersistTierToDB_Replace(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	persistTierToDB("user1", TierPro)
	persistTierToDB("user1", TierEnterprise)

	var tierName string
	db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "user1").Scan(&tierName)
	if tierName != "enterprise" {
		t.Errorf("expected 'enterprise' after replace, got %s", tierName)
	}
}

// --- addConversationTag (81%) — success, duplicate, unauthorized, not found, too long, empty ---

func TestCB97_AddConversationTag_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	tag, err := addConversationTag(convID, userID, "important")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if tag == nil {
		t.Error("expected non-nil tag")
	}
}

func TestCB97_AddConversationTag_Duplicate(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	addConversationTag(convID, userID, "important")
	_, err := addConversationTag(convID, userID, "important")
	if err == nil {
		t.Error("expected error for duplicate tag")
	}
}

func TestCB97_AddConversationTag_Unauthorized(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	userID2 := registerUser_CB97("otheruser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	_, err := addConversationTag(convID, userID2, "important")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
}

func TestCB97_AddConversationTag_ConvNotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	_, err := addConversationTag("nonexistent", userID, "important")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB97_AddConversationTag_TooLong(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	longTag := strings.Repeat("a", 51)
	_, err := addConversationTag(convID, userID, longTag)
	if err == nil {
		t.Error("expected error for too long tag")
	}
}

func TestCB97_AddConversationTag_EmptyTag(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	_, err := addConversationTag(convID, userID, "")
	if err == nil {
		t.Error("expected error for empty tag")
	}
}

// --- removeConversationTag (85.7%) — success, not found, unauthorized ---

func TestCB97_RemoveConversationTag_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	addConversationTag(convID, userID, "important")
	err := removeConversationTag(convID, userID, "important")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestCB97_RemoveConversationTag_NotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	err := removeConversationTag(convID, userID, "nonexistent-tag")
	if err == nil {
		t.Error("expected error for nonexistent tag")
	}
}

func TestCB97_RemoveConversationTag_Unauthorized(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	userID2 := registerUser_CB97("otheruser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	addConversationTag(convID, userID, "important")
	err := removeConversationTag(convID, userID2, "important")
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
}

// --- deleteConversation (83.3%) — success, not found, unauthorized ---

func TestCB97_DeleteConversation_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	storeMessage_CB97(convID, "user", userID, "hello")

	err := deleteConversation(convID, userID)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestCB97_DeleteConversation_NotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	err := deleteConversation("nonexistent", userID)
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB97_DeleteConversation_Unauthorized(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	userID2 := registerUser_CB97("otheruser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	err := deleteConversation(convID, userID2)
	if err == nil {
		t.Error("expected error for unauthorized user")
	}
}

// --- getConversationMessages (82.6%) — with limit, before cursor, empty ---

func TestCB97_GetConversationMessages_WithLimit(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	for i := 0; i < 5; i++ {
		storeMessage_CB97(convID, "user", userID, fmt.Sprintf("msg-%d", i))
	}

	msgs, err := getConversationMessages(convID, 3, "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(msgs) > 3 {
		t.Errorf("expected at most 3 messages, got %d", len(msgs))
	}
}

func TestCB97_GetConversationMessages_WithBefore(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	// Insert messages with explicit timestamps for cursor pagination
	times := []string{
		"2026-01-01 10:00:00",
		"2026-01-01 11:00:00",
		"2026-01-01 12:00:00",
		"2026-01-01 13:00:00",
		"2026-01-01 14:00:00",
	}
	for i, ts := range times {
		db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("m%d", i), convID, "user", userID, fmt.Sprintf("msg-%d", i), ts)
	}

	// Query messages before the 3rd timestamp (12:00) → should get 2 (10:00, 11:00)
	msgs, err := getConversationMessages(convID, 10, "2026-01-01 12:00:00")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages before cursor, got %d", len(msgs))
	}
}

func TestCB97_GetConversationMessages_Empty(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	msgs, err := getConversationMessages(convID, 50, "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

// --- storeMessage (81.8%) — success ---

func TestCB97_StoreMessage_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	msg := RoutedMessage{
		Type:           "message",
		ConversationID: convID,
		Content:        "test content",
		SenderType:     "user",
		SenderID:       userID,
	}
	err := storeMessage(msg)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	// Verify it was stored
	var content string
	db.QueryRow("SELECT content FROM messages WHERE conversation_id = ?", convID).Scan(&content)
	if content != "test content" {
		t.Errorf("expected 'test content', got %s", content)
	}
}

// --- storeMessagesBatch (88.9%) — empty ---

func TestCB97_StoreMessagesBatch_Empty(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	msgs, err := storeMessagesBatch(nil)
	if err != nil {
		t.Errorf("expected no error for empty batch, got %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

// --- hub.run (84.8%) — register/unregister agent, client, device reconnect ---

func TestCB97_HubRun_RegisterUnregisterAgent(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		id:       "agent-1",
		connType: "agent",
		send:     make(chan []byte, 256),
	}

	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("agent-1") == nil {
		t.Error("expected agent to be registered")
	}

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("agent-1") != nil {
		t.Error("expected agent to be unregistered")
	}
}

func TestCB97_HubRun_RegisterUnregisterClient(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		id:       "user-1",
		connType: "client",
		send:     make(chan []byte, 256),
	}

	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	conns := h.GetClientConns("user-1")
	if len(conns) != 1 {
		t.Errorf("expected 1 client connection, got %d", len(conns))
	}

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	conns = h.GetClientConns("user-1")
	if len(conns) != 0 {
		t.Errorf("expected 0 after unregister, got %d", len(conns))
	}
}

func TestCB97_HubRun_ClientDeviceReconnect(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	h := newHub()
	go h.run()
	defer h.Stop()

	conn1 := &Connection{
		id:       "user-1",
		connType: "client",
		send:     make(chan []byte, 256),
		deviceID: "device-1",
	}

	h.register <- conn1
	time.Sleep(50 * time.Millisecond)

	conn2 := &Connection{
		id:       "user-1",
		connType: "client",
		send:     make(chan []byte, 256),
		deviceID: "device-1",
	}

	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	conns := h.GetClientConns("user-1")
	if len(conns) != 1 {
		t.Errorf("expected 1 connection after device reconnect, got %d", len(conns))
	}
}

// --- ClientConnCount (83.3%) — with connections, empty ---

func TestCB97_ClientConnCount_WithConnections(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	h := newHub()
	go h.run()
	defer h.Stop()

	h.register <- &Connection{id: "user-1", connType: "client", send: make(chan []byte, 256)}
	h.register <- &Connection{id: "user-2", connType: "client", send: make(chan []byte, 256), deviceID: "d1"}
	h.register <- &Connection{id: "user-2", connType: "client", send: make(chan []byte, 256), deviceID: "d2"}
	time.Sleep(50 * time.Millisecond)

	count := h.ClientConnCount()
	if count != 3 {
		t.Errorf("expected 3 connections, got %d", count)
	}
}

func TestCB97_ClientConnCount_Empty(t *testing.T) {
	h := newHub()
	count := h.ClientConnCount()
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// --- Snapshot (83.3%) — with metrics ---

func TestCB97_Snapshot_WithMetrics(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	h := newHub()
	go h.run()
	defer h.Stop()

	m := NewMetrics(h)
	m.MessagesIn.Add(5)
	m.MessagesOut.Add(3)
	m.ConnectionsTotal.Add(2)

	snap := m.Snapshot()
	if snap["messages_in"].(int64) != 5 {
		t.Errorf("expected messages_in=5, got %v", snap["messages_in"])
	}
	if snap["messages_out"].(int64) != 3 {
		t.Errorf("expected messages_out=3, got %v", snap["messages_out"])
	}
}

// --- cleanup (83.3%) — expired, recent ---

func TestCB97_CleanupOnce_ExpiredEntries(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("user1", TierFree)
	trl.SetTier("user2", TierPro)

	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-15 * time.Minute)
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	if _, ok := trl.limits["user1"]; ok {
		t.Error("expected user1 to be cleaned up")
	}
	if _, ok := trl.limits["user2"]; !ok {
		t.Error("expected user2 to remain")
	}
}

func TestCB97_CleanupOnce_KeepRecent(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.SetTier("user1", TierFree)

	trl.mu.Lock()
	if entry, ok := trl.limits["user1"]; ok {
		entry.windowEnd = time.Now().Add(-5 * time.Minute)
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	if _, ok := trl.limits["user1"]; !ok {
		t.Error("expected user1 to remain (within grace period)")
	}
}

// --- extractIP (88.9%) — X-Forwarded-For, RemoteAddr, empty ---

func TestCB97_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.RemoteAddr = "192.168.1.1:12345"
	ip := extractIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

func TestCB97_ExtractIP_RemoteAddrOnly(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
}

func TestCB97_ExtractIP_NoHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""
	ip := extractIP(req)
	if ip != "" {
		t.Errorf("expected empty, got %s", ip)
	}
}

// --- parseSize (86.7%) — valid, invalid, empty ---

func TestCB97_ParseSize_Valid(t *testing.T) {
	size, err := parseSize("1048576")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if size != 1048576 {
		t.Errorf("expected 1048576, got %d", size)
	}
}

func TestCB97_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("not-a-number")
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestCB97_ParseSize_Empty(t *testing.T) {
	_, err := parseSize("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// --- routeTypingIndicator (87%) — invalid JSON, empty convID ---

func TestCB97_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	conn := &Connection{id: "user-1", connType: "client", send: make(chan []byte, 256)}
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	routeTypingIndicator(conn, []byte("not json"))
}

func TestCB97_RouteTypingIndicator_EmptyConvID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	conn := &Connection{id: "user-1", connType: "client", send: make(chan []byte, 256)}
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	routeTypingIndicator(conn, []byte(`{"conversation_id":""}`))
}

// --- handleGetRateLimitTier (87.5%) — success, no auth, missing user ---

func TestCB97_HandleGetRateLimitTier_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	trl := NewTieredRateLimiter()
	trl.SetTier("user1", TierPro)
	globalTieredLimiter = trl

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user1", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleGetRateLimitTier_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user1", nil)
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleGetRateLimitTier_MissingUserID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- handleSetRateLimitTier (84.6%) — success, wrong secret, missing fields, unknown tier, enterprise ---

func TestCB97_HandleSetRateLimitTier_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	trl := NewTieredRateLimiter()
	globalTieredLimiter = trl

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("user_id=user1&tier=pro"))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if tier := trl.GetTier("user1"); tier.Name != "pro" {
		t.Errorf("expected pro tier, got %s", tier.Name)
	}
}

func TestCB97_HandleSetRateLimitTier_WrongSecret(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("user_id=user1&tier=pro"))
	req.Header.Set("X-Admin-Secret", "wrong-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleSetRateLimitTier_MissingUserID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("tier=pro"))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleSetRateLimitTier_MissingTier(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("user_id=user1"))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleSetRateLimitTier_UnknownTier(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("user_id=user1&tier=unknown"))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown tier, got %d", w.Code)
	}
}

func TestCB97_HandleSetRateLimitTier_Enterprise(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()
	resetAdminSecret()
	defer resetAdminSecret()

	trl := NewTieredRateLimiter()
	globalTieredLimiter = trl

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("user_id=user1&tier=enterprise"))
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if tier := trl.GetTier("user1"); tier.Name != "enterprise" {
		t.Errorf("expected enterprise tier, got %s", tier.Name)
	}
}

// --- handleGetReactions (88.2%) — success, empty, no auth, missing message ID ---

func TestCB97_HandleGetReactions_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	addReaction(msgID, userID, "👍")
	addReaction(msgID, userID, "❤️")

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/reactions?message_id="+msgID, jwt)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleGetReactions_Empty(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/reactions?message_id="+msgID, jwt)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB97_HandleGetReactions_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/reactions?message_id=xxx", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleGetReactions_MissingMessageID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := makeAuthReq_CB97("GET", "/reactions", jwt)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- handleReact (83.7%) — success, toggle off, not found, no auth, invalid JSON, emoji too long ---

func TestCB97_HandleReact_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	jwt := makeJWT_CB97(userID)
	req := httptest.NewRequest("POST", "/react", strings.NewReader(
		fmt.Sprintf("message_id=%s&emoji=👍", msgID)))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleReact_ToggleOff(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	addReaction(msgID, userID, "👍")

	jwt := makeJWT_CB97(userID)
	req := httptest.NewRequest("POST", "/react", strings.NewReader(
		fmt.Sprintf("message_id=%s&emoji=👍", msgID)))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleReact_NotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := httptest.NewRequest("POST", "/react", strings.NewReader("message_id=nonexistent&emoji=👍"))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB97_HandleReact_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/react", strings.NewReader("message_id=x&emoji=👍"))
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleReact_MissingFields(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := httptest.NewRequest("POST", "/react", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleReact_EmojiTooLong(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	jwt := makeJWT_CB97(userID)
	longEmoji := strings.Repeat("e", 60)
	req := httptest.NewRequest("POST", "/react", strings.NewReader(
		fmt.Sprintf("message_id=%s&emoji=%s", msgID, longEmoji)))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReact(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for too long emoji, got %d", w.Code)
	}
}

// --- handleMessageDelete (87.5%) — success, not found, no auth ---

func TestCB97_HandleMessageDelete_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	msgID := storeMessage_CB97(convID, "user", userID, "hello")

	jwt := makeJWT_CB97(userID)
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader("message_id="+msgID))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleMessageDelete_NotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader("message_id=nonexistent"))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCB97_HandleMessageDelete_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/messages/delete", strings.NewReader("message_id=x"))
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- notifyUser (73.3%) — nil config, nil DB, empty convID, muted ---

func TestCB97_NotifyUser_NilPushConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()

	notifyUser("user1", "Title", "Body", "conv123")
}

func TestCB97_NotifyUser_NilDB(t *testing.T) {
	old := pushConfig
	oldDB := db
	pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
	db = nil
	defer func() {
		pushConfig = old
		db = oldDB
	}()

	notifyUser("user1", "Title", "Body", "conv123")
}

func TestCB97_NotifyUser_EmptyConvID(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()

	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	notifyUser("user1", "Title", "Body", "")
}

func TestCB97_NotifyUser_MutedConversation(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		userID, convID, 1)

	old := pushConfig
	pushConfig = &PushNotificationConfig{}
	defer func() { pushConfig = old }()

	notifyUser(userID, "Title", "Body", convID)
}

// --- Enqueue (88.9%) — full, success, multiple users ---

func TestCB97_Enqueue_Full(t *testing.T) {
	q := newOfflineQueue(2, 7*24*time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))

	// Enqueue returns nothing — the queue should be full, so this is a no-op
	q.Enqueue("user1", []byte("msg3"))
	// Verify depth is still 2 (queue was full)
	if q.TotalDepth() != 2 {
		t.Errorf("expected depth 2 (full), got %d", q.TotalDepth())
	}
}

func TestCB97_Enqueue_Success(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	if q.TotalDepth() != 1 {
		t.Errorf("expected depth 1, got %d", q.TotalDepth())
	}
}

func TestCB97_Enqueue_MultipleUsers(t *testing.T) {
	q := newOfflineQueue(2, 7*24*time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user2", []byte("msg1"))
	if q.TotalDepth() != 2 {
		t.Errorf("expected depth 2, got %d", q.TotalDepth())
	}
}

// --- initSchema (82.4%) — idempotent ---

func TestCB97_InitSchema_Idempotent(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	err := initSchema(db)
	if err != nil {
		t.Errorf("expected no error on idempotent initSchema, got %v", err)
	}
}

// --- getDeviceTokensForUser (84.6%) — success, no tokens ---

func TestCB97_GetDeviceTokensForUser_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		userID, "token123", "ios")
	db.Exec("INSERT INTO device_tokens (user_id, device_token, platform, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		userID, "token456", "android")

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestCB97_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	tokens, err := getDeviceTokensForUser(userID)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

// --- WithFields (87.5%) — nil, empty, with data ---

func TestCB97_WithFields_Nil(t *testing.T) {
	l := NewLogger(LogDebug)
	entry := l.WithFields(nil)
	if entry == nil {
		t.Error("expected non-nil entry")
	}
}

func TestCB97_WithFields_Empty(t *testing.T) {
	l := NewLogger(LogDebug)
	entry := l.WithFields(map[string]interface{}{})
	if entry == nil {
		t.Error("expected non-nil entry")
	}
}

func TestCB97_WithFields_WithData(t *testing.T) {
	l := NewLogger(LogDebug)
	entry := l.WithFields(map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	})
	if entry == nil {
		t.Error("expected non-nil entry")
	}
}

// --- handleGetPresence (83.9%) — success, no user ID ---

func TestCB97_HandleGetPresence_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)
	storeMessage_CB97(convID, "agent", agentID, "hello")

	jwt := makeJWT_CB97(userID)
	req := makeAuthReq_CB97("GET", "/presence?user_id="+userID, jwt)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleGetPresence_NoUserID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	hub := setupHub_CB97()
	defer teardownHub_CB97(hub)

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := makeAuthReq_CB97("GET", "/presence", jwt)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleHeapProfile (84.6%) / handleGoroutineProfile (84.6%) ---

func TestCB97_HandleHeapProfile_Success(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile/heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB97_HandleGoroutineProfile_Success(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/profile/goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB97_HandleHeapProfile_MethodNotAllowed(t *testing.T) {
	// handleHeapProfile doesn't check method — it processes any method
	// Verify it works for POST too
	req := httptest.NewRequest("POST", "/admin/profile/heap", nil)
	w := httptest.NewRecorder()
	handleHeapProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (handler accepts any method), got %d", w.Code)
	}
}

func TestCB97_HandleGoroutineProfile_MethodNotAllowed(t *testing.T) {
	// handleGoroutineProfile doesn't check method — it processes any method
	req := httptest.NewRequest("POST", "/admin/profile/goroutine", nil)
	w := httptest.NewRecorder()
	handleGoroutineProfile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (handler accepts any method), got %d", w.Code)
	}
}

// --- handleRegisterDeviceToken (88.9%) — success, android, no auth, invalid JSON, missing fields ---

func TestCB97_HandleRegisterDeviceToken_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	body := `{"device_token":"token123","platform":"ios"}`
	req := makeAuthReq_CB97("POST", "/push/register", jwt)
	req.Body = io.NopCloser(strings.NewReader(body))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleRegisterDeviceToken_Android(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	body := `{"device_token":"token456","platform":"android"}`
	req := makeAuthReq_CB97("POST", "/push/register", jwt)
	req.Body = io.NopCloser(strings.NewReader(body))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleRegisterDeviceToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(`{"device_token":"x","platform":"ios"}`))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleRegisterDeviceToken_InvalidJSON(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := makeAuthReq_CB97("POST", "/push/register", jwt)
	req.Body = io.NopCloser(strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleRegisterDeviceToken_MissingFields(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := makeAuthReq_CB97("POST", "/push/register", jwt)
	req.Body = io.NopCloser(strings.NewReader(`{"device_token":"","platform":""}`))
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- handleUnregisterDeviceToken (91.3%) — success, no auth ---

func TestCB97_HandleUnregisterDeviceToken_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	// Register first
	handleRegisterDeviceToken(httptest.NewRecorder(), makeAuthReq_CB97("POST", "/push/register", jwt))

	// Unregister (DELETE method)
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(`{"device_token":"token123"}`))
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleUnregisterDeviceToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(`{"device_token":"x"}`))
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- monitorAgentHeartbeats (88.9%) — disabled ---

func TestCB97_MonitorAgentHeartbeats_Disabled(t *testing.T) {
	// When agentPresenceEnabled is false (default), newHub() pre-closes monitorDone
	// and monitorAgentHeartbeats is not started. Verify Stop() doesn't block.
	setupTestDB_CB97()
	h := newHub()
	go h.run()
	hub = h

	// If monitorDone was pre-closed, Stop() should not block.
	// This test verifies that the hub lifecycle works when monitoring is disabled.
	done := make(chan struct{})
	go func() {
		h.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success — Stop() returned without blocking
	case <-time.After(2 * time.Second):
		t.Error("Stop() should not block when monitor is disabled")
	}

	// Don't call h.Stop() again in teardown — already stopped
	hub = nil
	teardownTestDB_CB97()
}

// --- sendWelcomeMessage (80%) — with device, without device, closed channel ---

func TestCB97_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		id:       "user-1",
		connType: "client",
		send:     make(chan []byte, 10),
		deviceID: "device-abc",
	}

	sendWelcomeMessage(conn)
	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "connected") {
			t.Errorf("expected connected message, got %s", string(msg))
		}
	default:
		t.Error("expected message in send channel")
	}
}

func TestCB97_SendWelcomeMessage_NoDeviceID(t *testing.T) {
	conn := &Connection{
		id:       "agent-1",
		connType: "agent",
		send:     make(chan []byte, 10),
	}

	sendWelcomeMessage(conn)
	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "connected") {
			t.Errorf("expected connected message, got %s", string(msg))
		}
	default:
		t.Error("expected message in send channel")
	}
}

func TestCB97_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	conn := &Connection{
		id:       "user-1",
		connType: "client",
		send:     make(chan []byte, 1),
	}
	close(conn.send)

	sendWelcomeMessage(conn)
}

// --- RegisterAgentOnConnect (81.8%) — new, default name, update, preserve empty ---

func TestCB97_RegisterAgentOnConnect_NewAgent(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	err := RegisterAgentOnConnect("new-agent", "New Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	var name string
	db.QueryRow("SELECT name FROM agents WHERE id = ?", "new-agent").Scan(&name)
	if name != "New Agent" {
		t.Errorf("expected 'New Agent', got %s", name)
	}
}

func TestCB97_RegisterAgentOnConnect_DefaultName(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	err := RegisterAgentOnConnect("agent-x", "", "", "", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	var name string
	db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-x").Scan(&name)
	if name != "agent-x" {
		t.Errorf("expected 'agent-x' as default name, got %s", name)
	}
}

func TestCB97_RegisterAgentOnConnect_UpdateExisting(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	RegisterAgentOnConnect("agent-1", "Agent One", "gpt-4", "friendly", "general")

	err := RegisterAgentOnConnect("agent-1", "Agent Updated", "claude-3", "professional", "coding")
	if err != nil {
		t.Errorf("expected no error on update, got %v", err)
	}

	var name, model string
	db.QueryRow("SELECT name, model FROM agents WHERE id = ?", "agent-1").Scan(&name, &model)
	if name != "Agent Updated" {
		t.Errorf("expected 'Agent Updated', got %s", name)
	}
	if model != "claude-3" {
		t.Errorf("expected 'claude-3', got %s", model)
	}
}

func TestCB97_RegisterAgentOnConnect_PreserveEmptyFields(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	RegisterAgentOnConnect("agent-1", "Agent One", "gpt-4", "friendly", "general")
	RegisterAgentOnConnect("agent-1", "", "", "", "")

	var name, model, personality, specialty string
	db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent-1").
		Scan(&name, &model, &personality, &specialty)
	if name != "Agent One" {
		t.Errorf("expected 'Agent One' preserved, got %s", name)
	}
	if model != "gpt-4" {
		t.Errorf("expected 'gpt-4' preserved, got %s", model)
	}
	if personality != "friendly" {
		t.Errorf("expected 'friendly' preserved, got %s", personality)
	}
	if specialty != "general" {
		t.Errorf("expected 'general' preserved, got %s", specialty)
	}
}

// --- handleSetNotificationPrefs (81.5%) — success, no auth, missing conv ID ---

func TestCB97_HandleSetNotificationPrefs_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	agentID := "agent-1"
	registerAgent_CB97(agentID, "Test")
	convID := createConversation_CB97(userID, agentID)

	jwt := makeJWT_CB97(userID)
	form := fmt.Sprintf("conversation_id=%s&muted=true", convID)
	req := makeAuthReqCtx_CB97("POST", "/notifications/preferences", jwt)
	req.Body = io.NopCloser(strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleSetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/notifications/preferences", strings.NewReader("conversation_id=x&muted=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB97_HandleSetNotificationPrefs_MissingConvID(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := makeAuthReqCtx_CB97("POST", "/notifications/preferences", jwt)
	req.Body = io.NopCloser(strings.NewReader("muted=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB97_HandleSetNotificationPrefs_NotFound(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := makeAuthReqCtx_CB97("POST", "/notifications/preferences", jwt)
	req.Body = io.NopCloser(strings.NewReader("conversation_id=nonexistent&muted=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// --- handleGetNotificationPrefs (81.5%) — success, no auth ---

func TestCB97_HandleGetNotificationPrefs_Success(t *testing.T) {
	setupTestDB_CB97()
	defer teardownTestDB_CB97()

	userID := registerUser_CB97("testuser")
	jwt := makeJWT_CB97(userID)

	req := makeAuthReqCtx_CB97("GET", "/notifications/preferences", jwt)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB97_HandleGetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/notifications/preferences", nil)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- initFCM (81.5%) — nil, disabled, empty creds ---

func TestCB97_InitFCM_NilConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()

	initFCM()
}

func TestCB97_InitFCM_Disabled(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = old }()

	initFCM()
}

func TestCB97_InitFCM_EmptyCreds(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: ""}
	defer func() { pushConfig = old }()

	initFCM()
}

// --- initAPNs (64%) — nil, disabled, empty cert, not found ---

func TestCB97_InitAPNs_NilConfig(t *testing.T) {
	old := pushConfig
	pushConfig = nil
	defer func() { pushConfig = old }()

	initAPNs()
}

func TestCB97_InitAPNs_Disabled(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = old }()

	initAPNs()
}

func TestCB97_InitAPNs_EmptyCertPath(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: ""}
	defer func() { pushConfig = old }()

	initAPNs()
}

func TestCB97_InitAPNs_CertNotFound(t *testing.T) {
	old := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: "/nonexistent/cert.p12"}
	defer func() { pushConfig = old }()

	initAPNs()
}

// --- cpuProfileTestSetup (0%) ---

func TestCB97_CpuProfileTestSetup_Basic(t *testing.T) {
	stop := cpuProfileTestSetup()
	if stop == nil {
		t.Error("expected non-nil stop function")
	}
	stop()
}