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
)

// ==============================
// CB102: Coverage boost targeting 0% functions.
// Targets:
//   - handleUploadPublicKey (0%): POST /keys/upload — method, auth, invalid JSON, missing key, invalid type, identity replace, success
//   - handleGetKeyBundle (0%): GET /keys/bundle — method, auth, missing owner_id, no identity key, success with bundle, one-time prekey consumption
//   - handleListOneTimePreKeys (0%): GET /keys/otpk-count — method, auth, count
//   - handleStoreEncryptedMessage (0%): POST /messages/encrypted — method, auth, invalid JSON, missing fields, invalid algorithm, conv not found, unauthorized, success user, success agent
//   - handleGetEncryptedMessages (0%): GET /messages/encrypted — method, auth, missing conv_id, conv not found, unauthorized, success, with limit
//   - authenticateRequest (0%): JWT, agent secret, missing agent ID, no auth
//   - handleAddTag (0%): POST /conversations/tags/add — method, auth, missing fields, success, duplicate, not found, unauthorized, too long
//   - handleRemoveTag (0%): POST /conversations/tags/remove — method, auth, missing fields, success, not found, unauthorized
//   - handleGetTags (0%): GET /conversations/tags — method, auth, missing conv_id, success, unauthorized
//   - addConversationTag (0%): success, not found, unauthorized, too long, duplicate
//   - removeConversationTag (0%): success, not found, unauthorized, tag not found
//   - getConversationTags (0%): success, empty
//   - handleReact (0%): POST /messages/react — method, auth, missing fields, emoji too long, success, toggle off, not found, unauthorized
//   - handleGetReactions (0%): GET /messages/reactions — method, auth, missing message_id, not found, unauthorized, success
//   - addReaction (34.6%): toggle, DB errors
//   - getMessageReactions (54.5%): success, empty
//   - handleGetPresence (0%): GET /presence — method, auth, success with agents, DB error
//   - handleGetUserPresence (0%): GET /presence/user — method, auth, success online, offline with last seen
//   - handleGetVAPIDKey (0%): GET /push/vapid-key — method, auth, not configured, success
//   - handleWebPushSubscribe (0%): POST /push/web-subscribe — method, auth, invalid JSON, missing fields, success
//   - handleWebPushUnsubscribe (0%): POST /push/web-unsubscribe — method, auth, invalid JSON, missing endpoint, success
//   - csrfMiddleware (0%): GET, XHR, CSRF token, Origin allowed, Origin not allowed, Authorization, X-Agent-Secret, fail
//   - isOriginAllowed (0%): wildcard, specific, no match
//   - requestIDMiddleware (0%): generate, preserve
//   - accessLogMiddleware (0%): basic, with user ID
//   - securityHeadersMiddleware (0%): headers set
//   - corsMiddleware (0%): wildcard, specific, preflight
//   - ipRateLimitMiddleware (0%): allowed, rate limited
//   - authRateLimitMiddleware (0%): allowed, rate limited
//   - adminAuthMiddleware (0%): missing, form, query, wrong, success
//   - authMiddleware (0%): valid, invalid, missing
//   - extractIP (0%): X-Forwarded-For, X-Real-IP, RemoteAddr
//   - responseWriterWrapper (0%): WriteHeader
//   - handleAdminProfile (0%): method, unknown action, stats, gc, heap, goroutine, cpu start/stop
//   - handleCPUProfileStart (0%): success, already active
//   - handleCPUProfileStop (0%): success, not active
//   - handleForceGC (0%): success
//   - handleMemoryStats (0%): success
//   - writeProfileError (0%): error with detail
//   - SetGCPercent (0%): set and verify
//   - SetMemoryLimit (0%): set and verify
//   - CaptureProfile (0%): with dir, without dir
//   - ForceGC (0%): basic
//   - handleRegisterAgent (0%): method, auth, missing fields, success
//   - ensureUploadDir (0%): success, error
//   - handleGetAttachment (0%): method, auth, not found, success
//   - handleListAttachments (0%): method, auth, conv not found, success
//   - Reset (auth.go 0%): rate limiter reset
//   - ValidateAdminSecret (0%): empty, wrong, dev default, env
//   - resetAdminSecret (0%): reset
//   - Placeholders (0%): SQLite, PostgreSQL
//   - envIntOrDefault (0%): with env, default
//   - envDurationOrDefault (0%): with env, default
//   - routeMessage (0%): unknown type, typing, status, heartbeat, chat
//   - routeTypingIndicator (0%): conv not found, agent offline, success
//   - Purge (0%): purge all
//   - QueueDepth (0%): depth
//   - deleteQueueMessages (0%): nil DB, success
//   - initQueueDB (0%): nil DB, success
//   - cleanStaleQueueMessages (0%): nil DB, success, deletes old
//   - marshalOutgoingMessage (0%): success, nil
//   - Reset (rate_limit_tiers 0%): tiered limiter reset
//   - Stop (rate_limit_tiers 0%): tiered limiter stop
//   - Allow (rate_limit_tiers 0%): allow, deny
//   - SetTier (0%): set tier
//   - GetTier (0%): get tier
//   - GetRemaining (0%): get remaining
//   - tieredRateLimitMiddleware (0%): allowed, rate limited, no auth
//   - persistTierToDB (0%): success, nil DB
//   - handleSetRateLimitTier (0%): admin auth, success
//   - handleGetRateLimitTier (0%): admin auth, success
//   - itoa (0%): basic
//   - writeJSONResponse (0%): basic
//   - handleAdminRateLimitTier (0%): set, get, unknown
//   - Logger SetLevel (0%): set level
//   - Logger SetOutput (0%): set output
//   - Logger Debug (0%): debug level
//   - GetClient (0%): found, not found
//   - initAuthRateLimit (0%): env, default
//   - StartCPUProfile (0%): success, error
// ==============================

// --- Helpers ---

func setupTestDB_CB102() {
	var err error
	db, err = sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		panic(err)
	}
	currentDriver = DriverSQLite
	initSchema(db)
}

func teardownTestDB_CB102() {
	if db != nil {
		db.Close()
	}
	db = nil
}

func resetGlobals_CB102() {
	hub = nil
	offlineQueue = nil
	pushConfig = nil
	tracingEnabled = false
	tracer = nil
	tp = nil
	tracingMu = sync.Once{}
	agentPresenceEnabled = false
	agentPresenceInterval = 30 * time.Second
	agentPresenceTimeout = 90 * time.Second
	serverDBPath = ""
	vapidPublicKey = ""
	corsAllowedOrigins = "*"
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()
}

func setupHub_CB102() *Hub {
	h := newHub()
	hub = h
	go h.run()
	return h
}

func teardownHub_CB102(h *Hub) {
	if h != nil {
		h.Stop()
	}
	hub = nil
}

func makeJWTReq_CB102(method, path string, body io.Reader, userID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	token, _ := GenerateJWT(userID, "testuser")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func makeAgentAuthReq_CB102(method, path string, body io.Reader, agentID string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	req.Header.Set("X-Agent-ID", agentID)
	return req
}

// --- E2E: handleUploadPublicKey ---

func TestCB102_HandleUploadPublicKey_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/keys/upload", nil)
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleUploadPublicKey_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/keys/upload", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleUploadPublicKey_InvalidJSON(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeAgentAuthReq_CB102("POST", "/keys/upload", strings.NewReader("not json"), "agent1")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleUploadPublicKey_MissingPublicKey(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"key_type":"identity"}`)
	req := makeAgentAuthReq_CB102("POST", "/keys/upload", body, "agent1")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleUploadPublicKey_InvalidKeyType(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"key_type":"bad","public_key":"abc123"}`)
	req := makeAgentAuthReq_CB102("POST", "/keys/upload", body, "agent1")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleUploadPublicKey_IdentitySuccess(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"key_type":"identity","public_key":"base64key123"}`)
	req := makeAgentAuthReq_CB102("POST", "/keys/upload", body, "agent1")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["key_type"] != "identity" {
		t.Errorf("expected key_type=identity, got %v", resp["key_type"])
	}
}

func TestCB102_HandleUploadPublicKey_IdentityReplace(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	// First upload
	body1 := strings.NewReader(`{"key_type":"identity","public_key":"key1"}`)
	req1 := makeAgentAuthReq_CB102("POST", "/keys/upload", body1, "agent1")
	rr1 := httptest.NewRecorder()
	handleUploadPublicKey(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first upload failed: %d", rr1.Code)
	}
	// Second upload (replace)
	body2 := strings.NewReader(`{"key_type":"identity","public_key":"key2"}`)
	req2 := makeAgentAuthReq_CB102("POST", "/keys/upload", body2, "agent1")
	rr2 := httptest.NewRecorder()
	handleUploadPublicKey(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("replace upload failed: %d", rr2.Code)
	}
	// Verify only one identity key exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE owner_id='agent1' AND owner_type='agent' AND key_type='identity'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 identity key, got %d", count)
	}
}

func TestCB102_HandleUploadPublicKey_OneTimePreKeySuccess(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"key_type":"one_time_prekey","public_key":"otpk1","key_id":1}`)
	req := makeAgentAuthReq_CB102("POST", "/keys/upload", body, "agent1")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleUploadPublicKey_UserAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"key_type":"identity","public_key":"userkey1"}`)
	req := makeJWTReq_CB102("POST", "/keys/upload", body, "user1")
	rr := httptest.NewRecorder()
	handleUploadPublicKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["owner_type"] != "user" {
		t.Errorf("expected owner_type=user, got %v", resp["owner_type"])
	}
}

// --- E2E: handleGetKeyBundle ---

func TestCB102_HandleGetKeyBundle_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/keys/bundle", nil)
	rr := httptest.NewRecorder()
	handleGetKeyBundle(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetKeyBundle_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/keys/bundle?owner_id=user1", nil)
	rr := httptest.NewRecorder()
	handleGetKeyBundle(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetKeyBundle_MissingOwnerID(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/keys/bundle", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetKeyBundle(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleGetKeyBundle_NoIdentityKey(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/keys/bundle?owner_id=nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetKeyBundle(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleGetKeyBundle_SuccessWithBundle(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	// Upload identity key
	body := strings.NewReader(`{"key_type":"identity","public_key":"idkey1"}`)
	req1 := makeAgentAuthReq_CB102("POST", "/keys/upload", body, "agent1")
	rr1 := httptest.NewRecorder()
	handleUploadPublicKey(rr1, req1)
	// Upload signed prekey
	body2 := strings.NewReader(`{"key_type":"signed_prekey","public_key":"spk1","signature":"sig1"}`)
	req2 := makeAgentAuthReq_CB102("POST", "/keys/upload", body2, "agent1")
	rr2 := httptest.NewRecorder()
	handleUploadPublicKey(rr2, req2)
	// Get bundle
	req3 := makeJWTReq_CB102("GET", "/keys/bundle?owner_id=agent1&owner_type=agent", nil, "user1")
	rr3 := httptest.NewRecorder()
	handleGetKeyBundle(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr3.Code)
	}
	var bundle map[string]interface{}
	json.NewDecoder(rr3.Body).Decode(&bundle)
	if bundle["identity_key"] == nil {
		t.Error("expected identity_key in bundle")
	}
	if bundle["signed_prekey"] == nil {
		t.Error("expected signed_prekey in bundle")
	}
}

func TestCB102_HandleGetKeyBundle_OneTimePreKeyConsumed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	// Upload identity + otpk
	handleUploadPublicKey(httptest.NewRecorder(), makeAgentAuthReq_CB102("POST", "/keys/upload", strings.NewReader(`{"key_type":"identity","public_key":"idkey"}`), "agent1"))
	handleUploadPublicKey(httptest.NewRecorder(), makeAgentAuthReq_CB102("POST", "/keys/upload", strings.NewReader(`{"key_type":"one_time_prekey","public_key":"otpk1","key_id":1}`), "agent1"))
	// Get bundle (should consume otpk)
	req := makeJWTReq_CB102("GET", "/keys/bundle?owner_id=agent1&owner_type=agent", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetKeyBundle(rr, req)
	var bundle map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&bundle)
	if bundle["one_time_prekey"] == nil {
		t.Error("expected one_time_prekey in first fetch")
	}
	// Second fetch should NOT have otpk (consumed)
	req2 := makeJWTReq_CB102("GET", "/keys/bundle?owner_id=agent1&owner_type=agent", nil, "user1")
	rr2 := httptest.NewRecorder()
	handleGetKeyBundle(rr2, req2)
	var bundle2 map[string]interface{}
	json.NewDecoder(rr2.Body).Decode(&bundle2)
	if bundle2["one_time_prekey"] != nil {
		t.Error("one_time_prekey should be consumed (nil) on second fetch")
	}
}

// --- E2E: handleListOneTimePreKeys ---

func TestCB102_HandleListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/keys/otpk-count", nil)
	rr := httptest.NewRecorder()
	handleListOneTimePreKeys(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleListOneTimePreKeys_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/keys/otpk-count", nil)
	rr := httptest.NewRecorder()
	handleListOneTimePreKeys(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleListOneTimePreKeys_Count(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	// Upload 3 otpks
	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"key_type":"one_time_prekey","public_key":"otpk%d","key_id":%d}`, i, i)
		handleUploadPublicKey(httptest.NewRecorder(), makeAgentAuthReq_CB102("POST", "/keys/upload", strings.NewReader(body), "agent1"))
	}
	req := makeAgentAuthReq_CB102("GET", "/keys/otpk-count", nil, "agent1")
	rr := httptest.NewRecorder()
	handleListOneTimePreKeys(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]int
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["one_time_prekey_count"] != 3 {
		t.Errorf("expected 3 otpk, got %d", resp["one_time_prekey_count"])
	}
}

// --- E2E: handleStoreEncryptedMessage ---

func TestCB102_HandleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/messages/encrypted", nil)
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/messages/encrypted", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("POST", "/messages/encrypted", strings.NewReader("bad"), "user1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"conversation_id":"conv1","ciphertext":"abc"}`)
	req := makeJWTReq_CB102("POST", "/messages/encrypted", body, "user1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_InvalidAlgorithm(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"conversation_id":"conv1","ciphertext":"abc","iv":"iv1","algorithm":"bad-algo","recipient_key_id":"key1"}`)
	req := makeJWTReq_CB102("POST", "/messages/encrypted", body, "user1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"conversation_id":"nonexistent","ciphertext":"abc","iv":"iv1","algorithm":"aes-256-gcm","recipient_key_id":"key1"}`)
	req := makeJWTReq_CB102("POST", "/messages/encrypted", body, "user1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_UnauthorizedUser(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	// Create conversation for user1
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	body := strings.NewReader(fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"iv1","algorithm":"aes-256-gcm","recipient_key_id":"key1"}`, convID))
	req := makeJWTReq_CB102("POST", "/messages/encrypted", body, "wronguser")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_SuccessUser(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	body := strings.NewReader(fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"iv1","algorithm":"aes-256-gcm","recipient_key_id":"key1"}`, convID))
	req := makeJWTReq_CB102("POST", "/messages/encrypted", body, "user1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_SuccessAgent(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	body := strings.NewReader(fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"iv1","algorithm":"x25519-aes-256-gcm","recipient_key_id":"key1"}`, convID))
	req := makeAgentAuthReq_CB102("POST", "/messages/encrypted", body, "agent1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleStoreEncryptedMessage_ChaChaAlgorithm(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	body := strings.NewReader(fmt.Sprintf(`{"conversation_id":"%s","ciphertext":"abc","iv":"iv1","algorithm":"x25519-chacha20-poly1305","recipient_key_id":"key1"}`, convID))
	req := makeJWTReq_CB102("POST", "/messages/encrypted", body, "user1")
	rr := httptest.NewRecorder()
	handleStoreEncryptedMessage(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for chacha algorithm, got %d", rr.Code)
	}
}

// --- E2E: handleGetEncryptedMessages ---

func TestCB102_HandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/messages/encrypted", nil)
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetEncryptedMessages_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/messages/encrypted?conversation_id=conv1", nil)
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetEncryptedMessages_MissingConvID(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/messages/encrypted", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleGetEncryptedMessages_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/messages/encrypted?conversation_id=nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleGetEncryptedMessages_Unauthorized(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	req := makeJWTReq_CB102("GET", "/messages/encrypted?conversation_id="+convID, nil, "wronguser")
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unauthorized user, got %d", rr.Code)
	}
}

func TestCB102_HandleGetEncryptedMessages_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	// Store an encrypted message
	msgID := generateID("emsg")
	db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, 'user1', 'user', 'cipher', 'iv', 'key1', 'aes-256-gcm', ?)`, msgID, convID, time.Now().UTC())
	req := makeJWTReq_CB102("GET", "/messages/encrypted?conversation_id="+convID, nil, "user1")
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var msgs []EncryptedMessage
	json.NewDecoder(rr.Body).Decode(&msgs)
	if len(msgs) != 1 {
		t.Errorf("expected 1 message, got %d", len(msgs))
	}
}

func TestCB102_HandleGetEncryptedMessages_WithLimit(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	for i := 0; i < 5; i++ {
		msgID := generateID("emsg")
		db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, 'user1', 'user', 'cipher', 'iv', 'key1', 'aes-256-gcm', ?)`, msgID, convID, time.Now().UTC())
	}
	req := makeJWTReq_CB102("GET", "/messages/encrypted?conversation_id="+convID+"&limit=2", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var msgs []EncryptedMessage
	json.NewDecoder(rr.Body).Decode(&msgs)
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages with limit=2, got %d", len(msgs))
	}
}

func TestCB102_HandleGetEncryptedMessages_AgentAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	req := makeAgentAuthReq_CB102("GET", "/messages/encrypted?conversation_id="+convID, nil, "agent1")
	rr := httptest.NewRecorder()
	handleGetEncryptedMessages(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for agent auth, got %d", rr.Code)
	}
}

// --- authenticateRequest ---

func TestCB102_AuthenticateRequest_JWT(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/test", nil, "user123")
	ownerID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ownerID != "user123" || ownerType != "user" {
		t.Errorf("expected user123/user, got %s/%s", ownerID, ownerType)
	}
}

func TestCB102_AuthenticateRequest_AgentSecret(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeAgentAuthReq_CB102("GET", "/test", nil, "agent456")
	ownerID, ownerType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ownerID != "agent456" || ownerType != "agent" {
		t.Errorf("expected agent456/agent, got %s/%s", ownerID, ownerType)
	}
}

func TestCB102_AuthenticateRequest_MissingAgentID(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	_, _, err := authenticateRequest(req)
	if err == nil || !strings.Contains(err.Error(), "X-Agent-ID") {
		t.Errorf("expected X-Agent-ID error, got %v", err)
	}
}

func TestCB102_AuthenticateRequest_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/test", nil)
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
}

func TestCB102_AuthenticateRequest_InvalidJWT(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

// --- Tags: addConversationTag ---

func TestCB102_AddConversationTag_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	tag, err := addConversationTag(convID, "user1", "important")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if tag == nil || tag.Tag != "important" {
		t.Errorf("expected tag 'important', got %v", tag)
	}
}

func TestCB102_AddConversationTag_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	_, err := addConversationTag("nonexistent", "user1", "tag1")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestCB102_AddConversationTag_Unauthorized(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	_, err := addConversationTag(convID, "wronguser", "tag1")
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestCB102_AddConversationTag_TooLong(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	longTag := strings.Repeat("a", 51)
	_, err := addConversationTag(convID, "user1", longTag)
	if err == nil || !strings.Contains(err.Error(), "1-50") {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestCB102_AddConversationTag_Duplicate(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	addConversationTag(convID, "user1", "tag1")
	_, err := addConversationTag(convID, "user1", "tag1")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected duplicate error, got %v", err)
	}
}

func TestCB102_AddConversationTag_EmptyTag(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	_, err := addConversationTag(convID, "user1", "")
	if err == nil {
		t.Error("expected error for empty tag")
	}
}

// --- Tags: removeConversationTag ---

func TestCB102_RemoveConversationTag_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	addConversationTag(convID, "user1", "tag1")
	err := removeConversationTag(convID, "user1", "tag1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCB102_RemoveConversationTag_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	err := removeConversationTag("nonexistent", "user1", "tag1")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestCB102_RemoveConversationTag_Unauthorized(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	addConversationTag(convID, "user1", "tag1")
	err := removeConversationTag(convID, "wronguser", "tag1")
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected unauthorized, got %v", err)
	}
}

func TestCB102_RemoveConversationTag_TagNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	err := removeConversationTag(convID, "user1", "nonexistent_tag")
	if err == nil || !strings.Contains(err.Error(), "tag not found") {
		t.Errorf("expected tag not found, got %v", err)
	}
}

// --- Tags: getConversationTags ---

func TestCB102_GetConversationTags_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	addConversationTag(convID, "user1", "tag1")
	addConversationTag(convID, "user1", "tag2")
	tags, err := getConversationTags(convID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

func TestCB102_GetConversationTags_Empty(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	tags, err := getConversationTags(convID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(tags))
	}
}

// --- Tags: handleAddTag ---

func TestCB102_HandleAddTag_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/conversations/tags/add", nil)
	rr := httptest.NewRecorder()
	handleAddTag(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleAddTag_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("conversation_id=conv1&tag=test")
	req := httptest.NewRequest("POST", "/conversations/tags/add", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAddTag(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleAddTag_MissingFields(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("conversation_id=conv1")
	req := makeJWTReq_CB102("POST", "/conversations/tags/add", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAddTag(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleAddTag_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	form := strings.NewReader("conversation_id="+convID+"&tag=important")
	req := makeJWTReq_CB102("POST", "/conversations/tags/add", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAddTag(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleAddTag_Duplicate(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	addConversationTag(convID, "user1", "tag1")
	form := strings.NewReader("conversation_id="+convID+"&tag=tag1")
	req := makeJWTReq_CB102("POST", "/conversations/tags/add", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAddTag(rr, req)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

func TestCB102_HandleAddTag_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("conversation_id=nonexistent&tag=test")
	req := makeJWTReq_CB102("POST", "/conversations/tags/add", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAddTag(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleAddTag_TooLong(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	longTag := strings.Repeat("a", 51)
	form := strings.NewReader("conversation_id="+convID+"&tag="+longTag)
	req := makeJWTReq_CB102("POST", "/conversations/tags/add", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleAddTag(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for too long tag, got %d", rr.Code)
	}
}

// --- Tags: handleRemoveTag ---

func TestCB102_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/conversations/tags/remove", nil)
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleRemoveTag_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("conversation_id=conv1&tag=test")
	req := httptest.NewRequest("POST", "/conversations/tags/remove", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleRemoveTag_MissingFields(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("conversation_id=conv1")
	req := makeJWTReq_CB102("POST", "/conversations/tags/remove", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleRemoveTag_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	addConversationTag(convID, "user1", "tag1")
	form := strings.NewReader("conversation_id="+convID+"&tag=tag1")
	req := makeJWTReq_CB102("POST", "/conversations/tags/remove", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleRemoveTag_TagNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	form := strings.NewReader("conversation_id="+convID+"&tag=nonexistent")
	req := makeJWTReq_CB102("POST", "/conversations/tags/remove", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRemoveTag(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// --- Tags: handleGetTags ---

func TestCB102_HandleGetTags_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/conversations/tags", nil)
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetTags_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=conv1", nil)
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetTags_MissingConvID(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/conversations/tags", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleGetTags_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	addConversationTag(convID, "user1", "tag1")
	addConversationTag(convID, "user1", "tag2")
	req := makeJWTReq_CB102("GET", "/conversations/tags?conversation_id="+convID, nil, "user1")
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var tags []ConversationTag
	json.NewDecoder(rr.Body).Decode(&tags)
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}
}

func TestCB102_HandleGetTags_Unauthorized(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	req := makeJWTReq_CB102("GET", "/conversations/tags?conversation_id="+convID, nil, "wronguser")
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetTags_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/conversations/tags?conversation_id=nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetTags(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for nonexistent conv, got %d", rr.Code)
	}
}

// --- Reactions: handleReact ---

func TestCB102_HandleReact_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/messages/react", nil)
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleReact_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("message_id=msg1&emoji=👍")
	req := httptest.NewRequest("POST", "/messages/react", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleReact_MissingFields(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("message_id=msg1")
	req := makeJWTReq_CB102("POST", "/messages/react", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleReact_EmojiTooLong(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("message_id=msg1&emoji=verylongemojistring")
	req := makeJWTReq_CB102("POST", "/messages/react", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleReact_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'agent1', 'agent', 'hello', ?)", msgID, convID, time.Now().UTC())
	form := strings.NewReader("message_id="+msgID+"&emoji=👍")
	req := makeJWTReq_CB102("POST", "/messages/react", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleReact_ToggleOff(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'agent1', 'agent', 'hello', ?)", msgID, convID, time.Now().UTC())
	// First react
	form1 := strings.NewReader("message_id="+msgID+"&emoji=👍")
	req1 := makeJWTReq_CB102("POST", "/messages/react", form1, "user1")
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleReact(httptest.NewRecorder(), req1)
	// Toggle off
	form2 := strings.NewReader("message_id="+msgID+"&emoji=👍")
	req2 := makeJWTReq_CB102("POST", "/messages/react", form2, "user1")
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	handleReact(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr2.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr2.Body).Decode(&resp)
	if resp["status"] != "reaction_removed" {
		t.Errorf("expected reaction_removed, got %v", resp["status"])
	}
}

func TestCB102_HandleReact_MessageNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	form := strings.NewReader("message_id=nonexistent&emoji=👍")
	req := makeJWTReq_CB102("POST", "/messages/react", form, "user1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleReact_Unauthorized(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'agent1', 'agent', 'hello', ?)", msgID, convID, time.Now().UTC())
	form := strings.NewReader("message_id="+msgID+"&emoji=👍")
	req := makeJWTReq_CB102("POST", "/messages/react", form, "wronguser")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleReact(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --- Reactions: handleGetReactions ---

func TestCB102_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/messages/reactions", nil)
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetReactions_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/messages/reactions?message_id=msg1", nil)
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetReactions_MissingMessageID(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/messages/reactions", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleGetReactions_MessageNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/messages/reactions?message_id=nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleGetReactions_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'agent1', 'agent', 'hello', ?)", msgID, convID, time.Now().UTC())
	addReaction(msgID, "user1", "👍")
	req := makeJWTReq_CB102("GET", "/messages/reactions?message_id="+msgID, nil, "user1")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var reactions []MessageReaction
	json.NewDecoder(rr.Body).Decode(&reactions)
	if len(reactions) != 1 {
		t.Errorf("expected 1 reaction, got %d", len(reactions))
	}
}

func TestCB102_HandleGetReactions_Unauthorized(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'agent1', 'agent', 'hello', ?)", msgID, convID, time.Now().UTC())
	req := makeJWTReq_CB102("GET", "/messages/reactions?message_id="+msgID, nil, "wronguser")
	rr := httptest.NewRecorder()
	handleGetReactions(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --- addReaction: additional coverage ---

func TestCB102_AddReaction_MessageNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	_, _, err := addReaction("nonexistent", "user1", "👍")
	if err == nil || !strings.Contains(err.Error(), "message not found") {
		t.Errorf("expected message not found, got %v", err)
	}
}

func TestCB102_AddReaction_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, 'nonexistent', 'user1', 'user', 'hello', ?)", msgID, time.Now().UTC())
	_, _, err := addReaction(msgID, "user1", "👍")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestCB102_AddReaction_Unauthorized(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'agent1', 'agent', 'hello', ?)", msgID, convID, time.Now().UTC())
	_, _, err := addReaction(msgID, "wronguser", "👍")
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected unauthorized, got %v", err)
	}
}

func TestCB102_AddReaction_AgentCanReact(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	msgID := generateID("msg")
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'user1', 'user', 'hello', ?)", msgID, convID, time.Now().UTC())
	_, added, err := addReaction(msgID, "agent1", "👍")
	if err != nil || !added {
		t.Errorf("expected agent to react successfully, got err=%v added=%v", err, added)
	}
}

// --- getMessageReactions ---

func TestCB102_GetMessageReactions_Empty(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	msgID := generateID("msg")
	reactions, err := getMessageReactions(msgID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(reactions) != 0 {
		t.Errorf("expected 0 reactions, got %d", len(reactions))
	}
}

// --- Presence: handleGetPresence ---

func TestCB102_HandleGetPresence_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/presence", nil)
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetPresence_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/presence", nil)
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetPresence_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	// Register an agent in DB
	db.Exec("INSERT INTO agents (id, name, status, created_at) VALUES ('agent1', 'Agent One', 'online', ?)", time.Now().UTC())
	req := makeJWTReq_CB102("GET", "/presence", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var agents []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&agents)
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

func TestCB102_HandleGetPresence_Empty(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	req := makeJWTReq_CB102("GET", "/presence", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetPresence(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var agents []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&agents)
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

// --- Presence: handleGetUserPresence ---

func TestCB102_HandleGetUserPresence_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/presence/user", nil)
	rr := httptest.NewRecorder()
	handleGetUserPresence(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetUserPresence_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/presence/user", nil)
	rr := httptest.NewRecorder()
	handleGetUserPresence(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetUserPresence_Online(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	// Register a client connection for user1
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)
	req := makeJWTReq_CB102("GET", "/presence/user?user_id=user1", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetUserPresence(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["online"] != true {
		t.Errorf("expected online=true, got %v", resp["online"])
	}
}

func TestCB102_HandleGetUserPresence_OfflineWithLastSeen(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	// Insert a message from user1 to have a last_seen
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	db.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, 'user1', 'user', 'hello', ?)", generateID("msg"), convID, time.Now().UTC())
	req := makeJWTReq_CB102("GET", "/presence/user?user_id=user1", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetUserPresence(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["online"] != false {
		t.Errorf("expected online=false, got %v", resp["online"])
	}
}

func TestCB102_HandleGetUserPresence_DefaultToSelf(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	req := makeJWTReq_CB102("GET", "/presence/user", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetUserPresence(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- Push: handleGetVAPIDKey ---

func TestCB102_HandleGetVAPIDKey_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/push/vapid-key", nil)
	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetVAPIDKey_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/push/vapid-key", nil)
	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetVAPIDKey_NotConfigured(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	vapidPublicKey = ""
	req := makeJWTReq_CB102("GET", "/push/vapid-key", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleGetVAPIDKey_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	vapidPublicKey = "test-vapid-key-12345"
	req := makeJWTReq_CB102("GET", "/push/vapid-key", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetVAPIDKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["public_key"] != "test-vapid-key-12345" {
		t.Errorf("expected test-vapid-key-12345, got %s", resp["public_key"])
	}
}

// --- Push: handleWebPushSubscribe ---

func TestCB102_HandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/push/web-subscribe", nil)
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushSubscribe_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushSubscribe_InvalidJSON(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("POST", "/push/web-subscribe", strings.NewReader("bad"), "user1")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"endpoint":"https://push.example.com/abc"}`)
	req := makeJWTReq_CB102("POST", "/push/web-subscribe", body, "user1")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushSubscribe_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{"endpoint":"https://push.example.com/abc","keys":{"p256dh":"p256dh_key","auth":"auth_key"}}`)
	req := makeJWTReq_CB102("POST", "/push/web-subscribe", body, "user1")
	rr := httptest.NewRecorder()
	handleWebPushSubscribe(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- Push: handleWebPushUnsubscribe ---

func TestCB102_HandleWebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/push/web-unsubscribe", nil)
	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushUnsubscribe_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushUnsubscribe_InvalidJSON(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("POST", "/push/web-unsubscribe", strings.NewReader("bad"), "user1")
	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	body := strings.NewReader(`{}`)
	req := makeJWTReq_CB102("POST", "/push/web-unsubscribe", body, "user1")
	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleWebPushUnsubscribe_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	// First subscribe
	body := strings.NewReader(`{"endpoint":"https://push.example.com/abc","keys":{"p256dh":"p256dh_key","auth":"auth_key"}}`)
	handleWebPushSubscribe(httptest.NewRecorder(), makeJWTReq_CB102("POST", "/push/web-subscribe", body, "user1"))
	// Then unsubscribe
	body2 := strings.NewReader(`{"endpoint":"https://push.example.com/abc"}`)
	req := makeJWTReq_CB102("POST", "/push/web-unsubscribe", body2, "user1")
	rr := httptest.NewRecorder()
	handleWebPushUnsubscribe(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- Middleware: csrfMiddleware ---

func TestCB102_CsrfMiddleware_GETAllowed(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("GET", "/test", nil)
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("GET should be allowed by CSRF middleware")
	}
}

func TestCB102_CsrfMiddleware_XHRAllowed(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("XHR header should be allowed")
	}
}

func TestCB102_CsrfMiddleware_CSRFTokenAllowed(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", "token123")
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("CSRF token should be allowed")
	}
}

func TestCB102_CsrfMiddleware_OriginAllowed(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "https://example.com"
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("Allowed origin should pass CSRF")
	}
}

func TestCB102_CsrfMiddleware_OriginNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "https://example.com"
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("Disallowed origin should NOT pass CSRF")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCB102_CsrfMiddleware_AuthHeaderAllowed(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer token")
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("Auth header should be allowed")
	}
}

func TestCB102_CsrfMiddleware_AgentSecretAllowed(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-Agent-Secret", "secret")
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("Agent secret header should be allowed")
	}
}

func TestCB102_CsrfMiddleware_NoHeadersRejected(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "https://example.com"
	called := false
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("POST with no headers should be rejected")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// --- isOriginAllowed ---

func TestCB102_IsOriginAllowed_Wildcard(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "*"
	if !isOriginAllowed("https://anything.com") {
		t.Error("wildcard should allow all origins")
	}
}

func TestCB102_IsOriginAllowed_SpecificMatch(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "https://example.com,https://other.com"
	if !isOriginAllowed("https://example.com") {
		t.Error("example.com should be allowed")
	}
}

func TestCB102_IsOriginAllowed_NoMatch(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "https://example.com"
	if isOriginAllowed("https://evil.com") {
		t.Error("evil.com should NOT be allowed")
	}
}

func TestCB102_IsOriginAllowed_WildcardInList(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "https://example.com,*"
	if !isOriginAllowed("https://anything.com") {
		t.Error("wildcard in list should allow all origins")
	}
}

// --- requestIDMiddleware ---

func TestCB102_RequestIDMiddleware_GeneratesID(t *testing.T) {
	resetGlobals_CB102()
	called := false
	var capturedID string
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		capturedID = r.Header.Get("X-Request-ID")
	})
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if !called {
		t.Error("handler was not called")
	}
	if capturedID == "" {
		t.Error("expected non-empty request ID")
	}
	if rr.Header().Get("X-Request-ID") == "" {
		t.Error("expected X-Request-ID in response header")
	}
}

func TestCB102_RequestIDMiddleware_PreservesExisting(t *testing.T) {
	resetGlobals_CB102()
	var capturedID string
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		capturedID = r.Header.Get("X-Request-ID")
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "custom-id-123")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if capturedID != "custom-id-123" {
		t.Errorf("expected custom-id-123, got %s", capturedID)
	}
}

// --- accessLogMiddleware ---

func TestCB102_AccessLogMiddleware_Basic(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if !called {
		t.Error("handler was not called")
	}
}

func TestCB102_AccessLogMiddleware_WithUserID(t *testing.T) {
	resetGlobals_CB102()
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	token, _ := GenerateJWT("user123", "testuser")
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler(rr, req)
	// Should not panic and should call the handler
}

// --- responseWriterWrapper ---

func TestCB102_ResponseWriterWrapper_WriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	wrapped := &responseWriterWrapper{ResponseWriter: rr, statusCode: http.StatusOK}
	wrapped.WriteHeader(http.StatusCreated)
	if wrapped.statusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", wrapped.statusCode)
	}
}

// --- securityHeadersMiddleware ---

func TestCB102_SecurityHeadersMiddleware_HeadersSet(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if !called {
		t.Error("handler was not called")
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options header")
	}
}

// --- corsMiddleware ---

func TestCB102_CorsMiddleware_Wildcard(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "*"
	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://anything.com")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if !called {
		t.Error("handler was not called")
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected *, got %s", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCB102_CorsMiddleware_SpecificOrigin(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "https://example.com"
	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if !called {
		t.Error("handler was not called")
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected https://example.com, got %s", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCB102_CorsMiddleware_Preflight(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "*"
	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT be called for OPTIONS preflight")
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

func TestCB102_CorsMiddleware_NoOrigin(t *testing.T) {
	resetGlobals_CB102()
	corsAllowedOrigins = "*"
	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if !called {
		t.Error("handler was not called")
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("should not set ACAO when no Origin header")
	}
}

// --- ipRateLimitMiddleware ---

func TestCB102_IpRateLimitMiddleware_Allowed(t *testing.T) {
	resetGlobals_CB102()
	ipRateLimiter = NewRateLimiter(100, time.Minute)
	called := false
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called within rate limit")
	}
}

func TestCB102_IpRateLimitMiddleware_RateLimited(t *testing.T) {
	resetGlobals_CB102()
	ipRateLimiter = NewRateLimiter(2, time.Minute)
	called := false
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler(httptest.NewRecorder(), req)
	handler(httptest.NewRecorder(), req)
	called = false
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT be called when rate limited")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
}

// --- authRateLimitMiddleware ---

func TestCB102_AuthRateLimitMiddleware_Allowed(t *testing.T) {
	resetGlobals_CB102()
	authIPLimiter = NewRateLimiter(10, time.Minute)
	called := false
	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called within rate limit")
	}
}

func TestCB102_AuthRateLimitMiddleware_RateLimited(t *testing.T) {
	resetGlobals_CB102()
	authIPLimiter = NewRateLimiter(1, time.Minute)
	called := false
	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler(httptest.NewRecorder(), req)
	called = false
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT be called when rate limited")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
}

// --- adminAuthMiddleware ---

func TestCB102_AdminAuthMiddleware_MissingSecret(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/admin/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT be called without secret")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_AdminAuthMiddleware_FormSecret(t *testing.T) {
	resetGlobals_CB102()
	resetAdminSecret()
	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	form := strings.NewReader("admin_secret=" + getAdminSecret())
	req := httptest.NewRequest("POST", "/admin/test", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called with valid form secret")
	}
}

func TestCB102_AdminAuthMiddleware_QuerySecret(t *testing.T) {
	resetGlobals_CB102()
	resetAdminSecret()
	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("GET", "/admin/test?admin_secret="+getAdminSecret(), nil)
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called with valid query secret")
	}
}

func TestCB102_AdminAuthMiddleware_WrongSecret(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("X-Admin-Secret", "wrongsecret")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT be called with wrong secret")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_AdminAuthMiddleware_HeaderSecret(t *testing.T) {
	resetGlobals_CB102()
	resetAdminSecret()
	called := false
	handler := adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/admin/test", nil)
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called with valid header secret")
	}
}

// --- authMiddleware ---

func TestCB102_AuthMiddleware_ValidJWT(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		uid, _ := getUserID(r)
		if uid != "user123" {
			t.Errorf("expected user123, got %s", uid)
		}
	})
	token, _ := GenerateJWT("user123", "testuser")
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called with valid JWT")
	}
}

func TestCB102_AuthMiddleware_InvalidJWT(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT be called with invalid JWT")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_AuthMiddleware_MissingToken(t *testing.T) {
	resetGlobals_CB102()
	called := false
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if called {
		t.Error("handler should NOT be called without token")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --- extractIP ---

func TestCB102_ExtractIP_XForwardedFor(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
}

func TestCB102_ExtractIP_XRealIP(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.3")
	ip := extractIP(req)
	if ip != "10.0.0.3" {
		t.Errorf("expected 10.0.0.3, got %s", ip)
	}
}

func TestCB102_ExtractIP_RemoteAddr(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:5678"
	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}
}

func TestCB102_ExtractIP_SingleXFF(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	ip := extractIP(req)
	if ip != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", ip)
	}
}

// --- Profile handler: handleAdminProfile ---

func TestCB102_HandleAdminProfile_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("DELETE", "/admin/profile", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleAdminProfile_UnknownAction(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("POST", "/admin/profile?action=badaction", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleAdminProfile_Stats(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("GET", "/admin/profile?action=stats", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["action"] != "stats" {
		t.Errorf("expected action=stats, got %v", resp["action"])
	}
}

func TestCB102_HandleAdminProfile_GC(t *testing.T) {
	resetGlobals_CB102()
	req := httptest.NewRequest("POST", "/admin/profile?action=gc", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["action"] != "gc" {
		t.Errorf("expected action=gc, got %v", resp["action"])
	}
}

func TestCB102_HandleAdminProfile_Heap(t *testing.T) {
	resetGlobals_CB102()
	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")
	req := httptest.NewRequest("POST", "/admin/profile?action=heap", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleAdminProfile_Goroutine(t *testing.T) {
	resetGlobals_CB102()
	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")
	req := httptest.NewRequest("POST", "/admin/profile?action=goroutine", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleAdminProfile_CPUStartStop(t *testing.T) {
	resetGlobals_CB102()
	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")
	// Start CPU profile
	req1 := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr1 := httptest.NewRecorder()
	handleAdminProfile(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("cpu start expected 200, got %d", rr1.Code)
	}
	// Stop CPU profile
	req2 := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr2 := httptest.NewRecorder()
	handleAdminProfile(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("cpu stop expected 200, got %d", rr2.Code)
	}
}

func TestCB102_HandleAdminProfile_CPUStopNotActive(t *testing.T) {
	resetGlobals_CB102()
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.Unlock()
	req := httptest.NewRequest("POST", "/admin/profile?action=cpu_stop", nil)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCB102_HandleAdminProfile_CPUAlreadyActive(t *testing.T) {
	resetGlobals_CB102()
	tmpDir := t.TempDir()
	os.Setenv("PROFILING_DIR", tmpDir)
	defer os.Unsetenv("PROFILING_DIR")
	// Start CPU profile
	req1 := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	handleAdminProfile(httptest.NewRecorder(), req1)
	// Try to start again
	req2 := httptest.NewRequest("POST", "/admin/profile?action=cpu", nil)
	rr2 := httptest.NewRecorder()
	handleAdminProfile(rr2, req2)
	if rr2.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for already active, got %d", rr2.Code)
	}
	// Clean up
	cpuProfileState.Lock()
	if cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
	}
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()
}

func TestCB102_HandleAdminProfile_JSONBodyAction(t *testing.T) {
	resetGlobals_CB102()
	body := strings.NewReader(`{"action":"stats"}`)
	req := httptest.NewRequest("POST", "/admin/profile", body)
	rr := httptest.NewRecorder()
	handleAdminProfile(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- writeProfileError ---

func TestCB102_WriteProfileError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeProfileError(rr, "test context", fmt.Errorf("test error"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["context"] != "test context" {
		t.Errorf("expected 'test context', got %v", resp["context"])
	}
	if resp["detail"] != "test error" {
		t.Errorf("expected 'test error', got %v", resp["detail"])
	}
}

func TestCB102_WriteProfileError_NilErr(t *testing.T) {
	rr := httptest.NewRecorder()
	writeProfileError(rr, "nil test", nil)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --- SetGCPercent / SetMemoryLimit ---

func TestCB102_SetGCPercent(t *testing.T) {
	old := SetGCPercent(200)
	defer SetGCPercent(old)
	// Just verify it doesn't panic
}

func TestCB102_SetMemoryLimit(t *testing.T) {
	old := SetMemoryLimit(1024 * 1024 * 1024)
	defer SetMemoryLimit(old)
	// Just verify it doesn't panic
}

// --- CaptureProfile ---

func TestCB102_CaptureProfile_WithDir(t *testing.T) {
	tmpDir := t.TempDir()
	snapshot := CaptureProfile(tmpDir)
	if snapshot == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snapshot.HeapFile == "" {
		t.Error("expected non-empty heap file")
	}
	if snapshot.GoroutineFile == "" {
		t.Error("expected non-empty goroutine file")
	}
}

func TestCB102_CaptureProfile_WithoutDir(t *testing.T) {
	snapshot := CaptureProfile("")
	if snapshot == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snapshot.HeapFile != "" {
		t.Error("expected empty heap file")
	}
}

// --- ForceGC ---

func TestCB102_ForceGC(t *testing.T) {
	cycles := ForceGC()
	if cycles == 0 {
		t.Error("expected non-zero GC cycles")
	}
}

// --- handleRegisterAgent ---

func TestCB102_HandleRegisterAgent_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/auth/agent", nil)
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleRegisterAgent_NoSecret(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("agent_id=agent1&name=Agent1")
	req := httptest.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleRegisterAgent_MissingFields(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("")
	req := httptest.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleRegisterAgent_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("agent_id=agent1&name=Agent One&model=gpt-4&personality=friendly&specialty=general")
	req := httptest.NewRequest("POST", "/auth/agent", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	rr := httptest.NewRecorder()
	handleRegisterAgent(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- ensureUploadDir ---

func TestCB102_EnsureUploadDir_Success(t *testing.T) {
	resetGlobals_CB102()
	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	err := ensureUploadDir()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Verify dir exists
	uploadDir := filepath.Join(filepath.Dir(serverDBPath), "uploads")
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		t.Error("upload directory was not created")
	}
}

func TestCB102_EnsureUploadDir_AlreadyExists(t *testing.T) {
	resetGlobals_CB102()
	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	uploadDir := filepath.Join(tmpDir, "uploads")
	os.MkdirAll(uploadDir, 0755)
	err := ensureUploadDir()
	if err != nil {
		t.Errorf("unexpected error for existing dir: %v", err)
	}
}

// --- handleGetAttachment ---

func TestCB102_HandleGetAttachment_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/attachments/123", nil)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleGetAttachment_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/attachments/123", nil)
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetAttachment_NotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/attachments/nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleGetAttachment(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// --- handleListAttachments ---

func TestCB102_HandleListAttachments_MethodNotAllowed(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("POST", "/attachments", nil)
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCB102_HandleListAttachments_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/attachments?conversation_id=conv1", nil)
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleListAttachments_MissingConvID(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/attachments", nil, "user1")
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB102_HandleListAttachments_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := makeJWTReq_CB102("GET", "/attachments?conversation_id=nonexistent", nil, "user1")
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestCB102_HandleListAttachments_Empty(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	req := makeJWTReq_CB102("GET", "/attachments?conversation_id="+convID, nil, "user1")
	rr := httptest.NewRecorder()
	handleListAttachments(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- auth.go: Reset, ValidateAdminSecret, resetAdminSecret ---

func TestCB102_ValidateAdminSecret_Empty(t *testing.T) {
	resetGlobals_CB102()
	resetAdminSecret()
	err := ValidateAdminSecret("")
	if err == nil {
		t.Error("expected error for empty admin secret")
	}
}

func TestCB102_ValidateAdminSecret_Wrong(t *testing.T) {
	resetGlobals_CB102()
	resetAdminSecret()
	err := ValidateAdminSecret("wrongsecret")
	if err == nil {
		t.Error("expected error for wrong admin secret")
	}
}

func TestCB102_ValidateAdminSecret_DevDefault(t *testing.T) {
	resetGlobals_CB102()
	resetAdminSecret()
	// In dev mode, admin secret is "admin-dev-secret" and should validate
	err := ValidateAdminSecret("admin-dev-secret")
	if err != nil {
		t.Errorf("expected dev admin secret to validate, got: %v", err)
	}
	// Agent secret should NOT validate as admin secret
	err = ValidateAdminSecret(getAgentSecret())
	if err == nil {
		t.Error("agent secret should not validate as admin secret")
	}
}

func TestCB102_ValidateAdminSecret_EnvSet(t *testing.T) {
	resetGlobals_CB102()
	os.Setenv("ADMIN_SECRET", "myadminsecret")
	resetAdminSecret()
	defer os.Unsetenv("ADMIN_SECRET")
	err := ValidateAdminSecret("myadminsecret")
	if err != nil {
		t.Errorf("expected valid admin secret from env, got %v", err)
	}
}

func TestCB102_ResetAdminSecret(t *testing.T) {
	resetGlobals_CB102()
	os.Setenv("ADMIN_SECRET", "testsecret123")
	resetAdminSecret()
	// ValidateAdminSecret should work with the env-set secret
	if err := ValidateAdminSecret("testsecret123"); err != nil {
		t.Errorf("expected testsecret123 to validate, got: %v", err)
	}
	// Agent secret should still be different
	if getAgentSecret() == "testsecret123" {
		t.Error("getAgentSecret should not return admin secret")
	}
	os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()
}

// --- auth.go: RateLimiter Reset ---

func TestCB102_RateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		rl.Allow("key1")
	}
	if rl.Allow("key1") {
		t.Error("should be rate limited after 5 requests")
	}
	rl.Reset()
	if !rl.Allow("key1") {
		t.Error("should be allowed after reset")
	}
}

// --- dbdriver.go: Placeholders, envIntOrDefault, envDurationOrDefault ---

func TestCB102_Placeholders_SQLite(t *testing.T) {
	resetGlobals_CB102()
	currentDriver = DriverSQLite
	ph := Placeholders(1, 3)
	if ph != "?, ?, ?" {
		t.Errorf("expected '?, ?, ?', got %s", ph)
	}
}

func TestCB102_Placeholders_PostgreSQL(t *testing.T) {
	resetGlobals_CB102()
	currentDriver = DriverPostgreSQL
	ph := Placeholders(1, 3)
	if ph != "$1, $2, $3" {
		t.Errorf("expected '$1, $2, $3', got %s", ph)
	}
}

func TestCB102_Placeholders_Single(t *testing.T) {
	resetGlobals_CB102()
	currentDriver = DriverSQLite
	ph := Placeholders(1, 1)
	if ph != "?" {
		t.Errorf("expected '?', got %s", ph)
	}
}

func TestCB102_EnvIntOrDefault_WithEnv(t *testing.T) {
	os.Setenv("TEST_INT_102", "42")
	defer os.Unsetenv("TEST_INT_102")
	val := envIntOrDefault("TEST_INT_102", 10)
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
}

func TestCB102_EnvIntOrDefault_Default(t *testing.T) {
	val := envIntOrDefault("NONEXISTENT_INT_102", 10)
	if val != 10 {
		t.Errorf("expected 10, got %d", val)
	}
}

func TestCB102_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_INT_BAD_102", "notanumber")
	defer os.Unsetenv("TEST_INT_BAD_102")
	val := envIntOrDefault("TEST_INT_BAD_102", 10)
	if val != 10 {
		t.Errorf("expected 10 for invalid env, got %d", val)
	}
}

func TestCB102_EnvDurationOrDefault_WithEnv(t *testing.T) {
	os.Setenv("TEST_DUR_102", "30s")
	defer os.Unsetenv("TEST_DUR_102")
	val := envDurationOrDefault("TEST_DUR_102", 10*time.Second)
	if val != 30*time.Second {
		t.Errorf("expected 30s, got %v", val)
	}
}

func TestCB102_EnvDurationOrDefault_Default(t *testing.T) {
	val := envDurationOrDefault("NONEXISTENT_DUR_102", 10*time.Second)
	if val != 10*time.Second {
		t.Errorf("expected 10s, got %v", val)
	}
}

func TestCB102_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_DUR_BAD_102", "notaduration")
	defer os.Unsetenv("TEST_DUR_BAD_102")
	val := envDurationOrDefault("TEST_DUR_BAD_102", 10*time.Second)
	if val != 10*time.Second {
		t.Errorf("expected 10s for invalid, got %v", val)
	}
}

// --- routing.go: routeMessage ---

func TestCB102_RouteMessage_UnknownType(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	msg := IncomingMessage{Type: "unknown_type", Data: json.RawMessage(`{}`)}
	msgBytes, _ := json.Marshal(msg)
	routeMessage(conn, msgBytes)
	// Should not panic
}

func TestCB102_RouteMessage_Typing(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	// Register agent
	agentConn := &Connection{
		hub:      h,
		id:       "agent1",
		connType: "agent",
		send:     make(chan []byte, 10),
	}
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	data, _ := json.Marshal(map[string]string{"conversation_id": convID, "status": "typing"})
	msg := IncomingMessage{Type: "typing", Data: data}
	msgBytes, _ := json.Marshal(msg)
	routeMessage(conn, msgBytes)
	// Agent should receive the typing indicator
	select {
	case <-agentConn.send:
		// Good
	case <-time.After(100 * time.Millisecond):
		t.Error("agent did not receive typing indicator")
	}
}

func TestCB102_RouteMessage_Heartbeat(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	msg := IncomingMessage{Type: "heartbeat", Data: json.RawMessage(`{}`)}
	msgBytes, _ := json.Marshal(msg)
	routeMessage(conn, msgBytes)
	// Should not panic, heartbeat just resets deadline
}

// --- queue.go: Purge, QueueDepth ---

func TestCB102_OfflineQueue_Purge(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	if q.TotalDepth() != 2 {
		t.Errorf("expected depth 2, got %d", q.TotalDepth())
	}
	q.Purge("user1")
	if q.TotalDepth() != 0 {
		t.Errorf("expected depth 0 after purge, got %d", q.TotalDepth())
	}
}

func TestCB102_OfflineQueue_QueueDepth(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user2", []byte("msg2"))
	if q.QueueDepth("user1") != 1 {
		t.Errorf("expected depth 1 for user1, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 1 {
		t.Errorf("expected depth 1 for user2, got %d", q.QueueDepth("user2"))
	}
	if q.QueueDepth("nonexistent") != 0 {
		t.Errorf("expected depth 0 for nonexistent, got %d", q.QueueDepth("nonexistent"))
	}
}

// --- queue_persist.go ---

func TestCB102_DeleteQueueMessages_NilDB(t *testing.T) {
	deleteQueueMessages(nil, "user1")
	// Should not panic
}

func TestCB102_DeleteQueueMessages_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	initQueueDB(db)
	persistQueue(db, "user1", []byte("msg1"))
	persistQueue(db, "user1", []byte("msg2"))
	deleteQueueMessages(db, "user1")
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient='user1'").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 messages after delete, got %d", count)
	}
}

func TestCB102_InitQueueDB_NilDB(t *testing.T) {
	initQueueDB(nil)
	// Should not panic
}

func TestCB102_InitQueueDB_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	// initQueueDB should create the table
	initQueueDB(db)
	_, err := db.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES ('test', 'data', '2026-01-01T00:00:00Z')")
	if err != nil {
		t.Errorf("expected table to exist after initQueueDB, got %v", err)
	}
}

func TestCB102_CleanStaleQueueMessages_NilDB(t *testing.T) {
	cleanStaleQueueMessages(nil, time.Hour)
	// Should not panic
}

func TestCB102_CleanStaleQueueMessages_DeletesOld(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	initQueueDB(db)
	// Insert an old message
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES ('user1', 'msg1', '2020-01-01T00:00:00Z')")
	// Insert a recent message (use time.Now to avoid staleness)
	recent := time.Now().UTC().Format(time.RFC3339)
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES ('user1', 'msg2', ?)", recent)
	cleanStaleQueueMessages(db, 24*time.Hour)
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient='user1'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message remaining (recent), got %d", count)
	}
}

func TestCB102_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{Type: "message", Data: map[string]string{"content": "hello"}}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Error("expected non-nil data")
	}
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	if result["type"] != "message" {
		t.Errorf("expected type=message, got %v", result["type"])
	}
}

// --- rate_limit_tiers.go ---

func TestCB102_TieredRateLimiter_Allow(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tl.SetTier("user1", TierPro) // 300/min
	for i := 0; i < 10; i++ {
		allowed, _, _ := tl.Allow("user1")
		if !allowed {
			t.Errorf("expected allowed at request %d", i)
		}
	}
}

func TestCB102_TieredRateLimiter_Deny(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tl.SetTier("user1", TierFree) // 60/min
	for i := 0; i < 60; i++ {
		tl.Allow("user1")
	}
	allowed, _, _ := tl.Allow("user1")
	if allowed {
		t.Error("expected rate limited after 60 requests on free tier")
	}
}

func TestCB102_TieredRateLimiter_SetTier(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tl.SetTier("user1", TierEnterprise)
	tier := tl.GetTier("user1")
	if tier != TierEnterprise {
		t.Errorf("expected enterprise, got %v", tier)
	}
}

func TestCB102_TieredRateLimiter_GetTier(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tier := tl.GetTier("unknown_user")
	if tier != TierFree {
		t.Errorf("expected free tier for unknown user, got %v", tier)
	}
}

func TestCB102_TieredRateLimiter_GetRemaining(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tl.SetTier("user1", TierFree) // 60/min
	remaining := tl.GetRemaining("user1")
	if remaining <= 0 || remaining > 60 {
		t.Errorf("expected remaining between 1 and 60, got %d", remaining)
	}
	tl.Allow("user1")
	remaining2 := tl.GetRemaining("user1")
	if remaining2 != remaining-1 {
		t.Errorf("expected remaining %d after 1 request, got %d", remaining-1, remaining2)
	}
}

func TestCB102_TieredRateLimiter_Reset(t *testing.T) {
	tl := NewTieredRateLimiter()
	defer tl.Stop()
	tl.SetTier("user1", TierFree)
	for i := 0; i < 60; i++ {
		tl.Allow("user1")
	}
	allowed, _, _ := tl.Allow("user1")
	if allowed {
		t.Error("should be rate limited")
	}
	tl.Reset()
	allowed, _, _ = tl.Allow("user1")
	if !allowed {
		t.Error("should be allowed after reset")
	}
}

func TestCB102_TieredRateLimiter_Stop(t *testing.T) {
	tl := NewTieredRateLimiter()
	tl.Stop()
	// Should not panic
}

func TestCB102_PersistTierToDB_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCB102_PersistTierToDB_NilDB(t *testing.T) {
	err := persistTierToDB("user1", TierPro)
	if err != nil {
		t.Errorf("expected nil error for nil DB, got: %v", err)
	}
}

func TestCB102_PersistTierToDB_Replace(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	persistTierToDB("user1", TierFree)
	persistTierToDB("user1", TierEnterprise)
	var tier string
	db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id='user1'").Scan(&tier)
	if tier != "enterprise" {
		t.Errorf("expected enterprise after replace, got %s", tier)
	}
}

// --- tieredRateLimitMiddleware ---

func TestCB102_TieredRateLimitMiddleware_Allowed(t *testing.T) {
	resetGlobals_CB102()
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	globalTieredLimiter.SetTier("user1", TierPro)
	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := makeJWTReq_CB102("GET", "/test", nil, "user1")
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called within rate limit")
	}
}

func TestCB102_TieredRateLimitMiddleware_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	globalTieredLimiter = NewTieredRateLimiter()
	defer globalTieredLimiter.Stop()
	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler should be called for unauthenticated request (IP-based)")
	}
}

// --- handleSetRateLimitTier ---

func TestCB102_HandleSetRateLimitTier_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("user_id=user1&tier=pro")
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetAdminSecret()
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleSetRateLimitTier_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("user_id=user1&tier=pro")
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleSetRateLimitTier_MissingFields(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("user_id=user1")
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetAdminSecret()
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	rr := httptest.NewRecorder()
	handleSetRateLimitTier(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleGetRateLimitTier ---

func TestCB102_HandleGetRateLimitTier_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	persistTierToDB("user1", TierPro)
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user1", nil)
	resetAdminSecret()
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleGetRateLimitTier_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user1", nil)
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCB102_HandleGetRateLimitTier_MissingUserID(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
	resetAdminSecret()
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	rr := httptest.NewRecorder()
	handleGetRateLimitTier(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- itoa ---

func TestCB102_Itoa(t *testing.T) {
	if itoa(0) != "0" {
		t.Errorf("expected '0', got %s", itoa(0))
	}
	if itoa(42) != "42" {
		t.Errorf("expected '42', got %s", itoa(42))
	}
	if itoa(1000000) != "1000000" {
		t.Errorf("expected '1000000', got %s", itoa(1000000))
	}
}

// --- writeJSONResponse ---

func TestCB102_WriteJSONResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONResponse(rr, http.StatusOK, map[string]string{"status": "ok"})
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Error("expected application/json content type")
	}
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %s", resp["status"])
	}
}

// --- handleAdminRateLimitTier ---

func TestCB102_HandleAdminRateLimitTier_Set(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	form := strings.NewReader("user_id=user1&tier=enterprise")
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetAdminSecret()
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	rr := httptest.NewRecorder()
	handleAdminRateLimitTier(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleAdminRateLimitTier_Get(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	persistTierToDB("user1", TierPro)
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user1", nil)
	resetAdminSecret()
	req.Header.Set("X-Admin-Secret", getAdminSecret())
	rr := httptest.NewRecorder()
	handleAdminRateLimitTier(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCB102_HandleAdminRateLimitTier_NoAuth(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user1", nil)
	rr := httptest.NewRecorder()
	handleAdminRateLimitTier(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --- Logger ---

func TestCB102_Logger_SetLevel(t *testing.T) {
	l := NewLogger(LogDebug)
	l.SetLevel(LogWarn)
	// Just verify it doesn't panic
}

func TestCB102_Logger_SetOutput(t *testing.T) {
	l := NewLogger(LogInfo)
	l.SetOutput(io.Discard)
	// Just verify it doesn't panic
}

func TestCB102_Logger_Debug(t *testing.T) {
	l := NewLogger(LogDebug)
	l.SetOutput(io.Discard)
	l.Debug("test_debug", nil)
	// Should not panic
}

func TestCB102_Logger_DebugFiltered(t *testing.T) {
	l := NewLogger(LogWarn) // Debug should be filtered
	l.SetOutput(io.Discard)
	l.Debug("test_debug_filtered", nil)
	// Should not panic, and should not output
}

// --- Hub: GetClient ---

func TestCB102_Hub_GetClient_Found(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)
	found := h.GetClient("user1")
	if found == nil {
		t.Error("expected to find client")
	}
}

func TestCB102_Hub_GetClient_NotFound(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()
	found := h.GetClient("nonexistent")
	if found != nil {
		t.Error("expected nil for nonexistent client")
	}
}

// --- initAuthRateLimit ---

func TestCB102_InitAuthRateLimit_Default(t *testing.T) {
	resetGlobals_CB102()
	os.Unsetenv("AUTH_RATE_LIMIT")
	initAuthRateLimit()
	// authIPLimiter should be set to 30/min
	// Just verify it works
	if !authIPLimiter.Allow("testip") {
		t.Error("expected first request to be allowed")
	}
}

func TestCB102_InitAuthRateLimit_WithEnv(t *testing.T) {
	resetGlobals_CB102()
	os.Setenv("AUTH_RATE_LIMIT", "5")
	defer os.Unsetenv("AUTH_RATE_LIMIT")
	initAuthRateLimit()
	for i := 0; i < 5; i++ {
		authIPLimiter.Allow("testip2")
	}
	if authIPLimiter.Allow("testip2") {
		t.Error("expected rate limit after 5 requests")
	}
}

// --- StartCPUProfile ---

func TestCB102_StartCPUProfile_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cpu.prof")
	stop, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stop == nil {
		t.Fatal("expected non-nil stop function")
	}
	stop()
	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected CPU profile file to be created")
	}
}

func TestCB102_StartCPUProfile_FileError(t *testing.T) {
	// Try to create file in nonexistent directory without permissions
	_, err := StartCPUProfile("/nonexistent/dir/cpu.prof")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

// --- routeTypingIndicator ---

func TestCB102_RouteTypingIndicator_ConvNotFound(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	data, _ := json.Marshal(map[string]string{"conversation_id": "nonexistent"})
	routeTypingIndicator(conn, data)
	// Should not panic
}

func TestCB102_RouteTypingIndicator_Success(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	// Register agent
	agentConn := &Connection{
		hub:      h,
		id:       "agent1",
		connType: "agent",
		send:     make(chan []byte, 10),
	}
	h.register <- agentConn
	time.Sleep(50 * time.Millisecond)
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	data, _ := json.Marshal(map[string]string{"conversation_id": convID})
	routeTypingIndicator(conn, data)
	select {
	case <-agentConn.send:
		// Good
	case <-time.After(100 * time.Millisecond):
		t.Error("agent did not receive typing indicator")
	}
}

func TestCB102_RouteTypingIndicator_AgentOffline(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	conn := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	data, _ := json.Marshal(map[string]string{"conversation_id": convID})
	routeTypingIndicator(conn, data)
	// Should not panic when agent is offline
}

// --- handleUpload with multipart for attachment coverage ---

func TestCB102_HandleUpload_SuccessWithFile(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	convID := generateID("conv")
	db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, 'user1', 'agent1', ?)", convID, time.Now().UTC())
	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	mw.WriteField("conversation_id", convID)
	part, _ := mw.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello world"))
	mw.Close()
	req := makeJWTReq_CB102("POST", "/upload", strings.NewReader(buf.String()), "user1")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- Context-based getUserID test ---

func TestCB102_GetUserID_FromContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "ctxuser123")
	req = req.WithContext(ctx)
	uid, err := getUserID(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if uid != "ctxuser123" {
		t.Errorf("expected ctxuser123, got %s", uid)
	}
}

func TestCB102_GetUserID_NoContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	_, err := getUserID(req)
	if err == nil {
		t.Error("expected error for no context user ID")
	}
}

// --- WebSocket integration: handleClientConnect ---

func TestCB102_HandleClientConnect_WSIntegration(t *testing.T) {
	resetGlobals_CB102()
	setupTestDB_CB102()
	defer teardownTestDB_CB102()
	h := setupHub_CB102()
	defer teardownHub_CB102(h)
	// Create a test HTTP server with WebSocket upgrade
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleClientConnect(w, r)
	}))
	defer srv.Close()
	// Register user in DB
	token, _ := GenerateJWT("wsuser1", "testuser")
	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/client/connect?token=" + token
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WebSocket dial failed: %v", err)
	}
	defer ws.Close()
	defer resp.Body.Close()
	// Should receive a welcome message
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome failed: %v", err)
	}
	var welcome OutgoingMessage
	json.Unmarshal(msg, &welcome)
	if welcome.Type != "connected" {
		t.Errorf("expected welcome, got %s", welcome.Type)
	}
}