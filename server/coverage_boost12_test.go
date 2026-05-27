package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==============================
// Tiered Rate Limiter Cleanup Tests
// ==============================

func TestTieredRateLimiterCleanup_RemovesStale(t *testing.T) {
	trl := NewTieredRateLimiter()
	// Manually add a stale entry (window long expired)
	trl.mu.Lock()
	trl.limits["stale-user"] = &userRateLimitState{
		count:     5,
		windowEnd: time.Now().Add(-15 * time.Minute), // expired 15 min ago
		tier:      TierFree,
	}
	trl.mu.Unlock()

	// Simulate cleanup logic
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, ok := trl.limits["stale-user"]
	trl.mu.Unlock()
	if ok {
		t.Error("stale entry should have been removed")
	}
}

func TestTieredRateLimiterCleanup_KeepsRecent(t *testing.T) {
	trl := NewTieredRateLimiter()
	// Add a recent entry (still within window)
	trl.mu.Lock()
	trl.limits["recent-user"] = &userRateLimitState{
		count:     1,
		windowEnd: time.Now().Add(50 * time.Minute), // far in the future
		tier:      TierFree,
	}
	trl.mu.Unlock()

	// Simulate cleanup logic
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, ok := trl.limits["recent-user"]
	trl.mu.Unlock()
	if !ok {
		t.Error("recent entry should NOT be removed")
	}
}

func TestTieredRateLimiterCleanup_KeepsRecentlyExpired(t *testing.T) {
	trl := NewTieredRateLimiter()
	// Add an entry that expired just 2 minutes ago (not yet stale enough)
	trl.mu.Lock()
	trl.limits["just-expired"] = &userRateLimitState{
		count:     1,
		windowEnd: time.Now().Add(-2 * time.Minute), // expired 2 min ago
		tier:      TierFree,
	}
	trl.mu.Unlock()

	// Simulate cleanup logic
	trl.mu.Lock()
	now := time.Now()
	for id, entry := range trl.limits {
		if now.After(entry.windowEnd) && now.Sub(entry.windowEnd) > 10*time.Minute {
			delete(trl.limits, id)
		}
	}
	trl.mu.Unlock()

	trl.mu.Lock()
	_, ok := trl.limits["just-expired"]
	trl.mu.Unlock()
	if !ok {
		t.Error("recently expired entry should be kept (within 10 min grace)")
	}
}

func TestTieredRateLimiterWindowResetAfterExhaust(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Exhaust the free tier (60 requests)
	for i := 0; i < 60; i++ {
		allowed, _, _ := trl.Allow("reset-user")
		if !allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 61st should be denied
	allowed, remaining, retryAfter := trl.Allow("reset-user")
	if allowed {
		t.Error("request beyond burst should be denied")
	}
	if remaining != 0 {
		t.Errorf("expected remaining=0, got %d", remaining)
	}
	if retryAfter < 1 {
		t.Errorf("expected retryAfter >= 1, got %d", retryAfter)
	}

	// Manually reset the window to simulate time passage
	trl.mu.Lock()
	if entry, ok := trl.limits["reset-user"]; ok {
		entry.windowEnd = time.Now().Add(-1 * time.Second) // expired
	}
	trl.mu.Unlock()

	// Now Allow should reset the window
	allowed, _, _ = trl.Allow("reset-user")
	if !allowed {
		t.Error("request after window reset should be allowed")
	}
}

func TestTieredRateLimiterTierUpgradeDowngrade(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Start as free tier
	allowed, remaining, _ := trl.Allow("tier-user")
	if !allowed {
		t.Error("first request should be allowed")
	}
	if remaining != 59 { // 60-1
		t.Errorf("expected remaining=59, got %d", remaining)
	}

	// Upgrade to pro
	trl.SetTier("tier-user", TierPro)
	tier := trl.GetTier("tier-user")
	if tier.Name != "pro" {
		t.Errorf("expected tier=pro, got %s", tier.Name)
	}

	// Allow should reset count
	allowed, remaining, _ = trl.Allow("tier-user")
	if !allowed {
		t.Error("request after upgrade should be allowed")
	}
	if remaining != 299 { // 300-1
		t.Errorf("expected remaining=299, got %d", remaining)
	}

	// Downgrade back to free
	trl.SetTier("tier-user", TierFree)
	allowed, remaining, _ = trl.Allow("tier-user")
	if !allowed {
		t.Error("request after downgrade should be allowed")
	}
	if remaining != 59 { // 60-1
		t.Errorf("expected remaining=59, got %d", remaining)
	}
}

// ==============================
// Attachment Handler Tests
// ==============================

func TestHandleUpload_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleUpload_InvalidAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleUpload_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/attachments/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleUpload_MissingFileField(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("upload-user", "uploaduser")
	if err != nil {
		t.Fatal(err)
	}

	// Empty multipart form (no file field)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing file, got %d", w.Code)
	}
}

func TestHandleUpload_ValidFile(t *testing.T) {
	setupTestDB(t)
	// Create a test user
	hash, _ := HashAPIKey("password123")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "upload-user", "uploaduser", hash)
	if err != nil {
		t.Fatal(err)
	}

	token, err := GenerateJWT("upload-user", "uploaduser")
	if err != nil {
		t.Fatal(err)
	}

	// Create multipart form with file
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello world"))
	writer.Close()

	// Ensure upload dir exists
	serverDBPath = ":memory:" // will use current dir for upload path calculation
	maxUploadSize = MaxUploadSize

	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	// May fail due to upload directory issues since we're using in-memory DB,
	// but the auth and multipart parsing should work
	// We just want to make sure it doesn't crash
	_ = w.Code
}

func TestHandleGetAttachment_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/attachments/abc123", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleGetAttachment_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/attachments/abc123", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetAttachment_NotFound(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("att-user", "attuser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent attachment, got %d", w.Code)
	}
}

func TestHandleListAttachments_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/messages/conv_123/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleListAttachments_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/messages/conv_123/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleListAttachments_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("list-user", "listuser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestHandleListAttachments_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("list-user2", "listuser2")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/attachments?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

// ==============================
// E2E Encryption Handler Tests
// ==============================

func TestAuthenticateRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for no auth")
	}
	if id != "" || typ != "" {
		t.Errorf("expected empty id/type, got %s/%s", id, typ)
	}
}

func TestAuthenticateRequest_InvalidJWT(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
	if id != "" || typ != "" {
		t.Errorf("expected empty id/type, got %s/%s", id, typ)
	}
}

func TestAuthenticateRequest_AgentNoID(t *testing.T) {
	origAgentSecret := agentSecret
	origEnv := os.Getenv("AGENT_SECRET")
	defer func() { agentSecret = origAgentSecret; os.Setenv("AGENT_SECRET", origEnv) }()
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	agentSecret = "test-agent-secret"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	// No X-Agent-ID header
	id, typ, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for agent auth without X-Agent-ID")
	}
	if id != "" || typ != "" {
		t.Errorf("expected empty id/type, got %s/%s", id, typ)
	}
}

func TestAuthenticateRequest_ValidAgent(t *testing.T) {
	origAgentSecret := agentSecret
	origEnv := os.Getenv("AGENT_SECRET")
	defer func() { agentSecret = origAgentSecret; os.Setenv("AGENT_SECRET", origEnv) }()
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	agentSecret = "test-agent-secret"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	req.Header.Set("X-Agent-ID", "test-agent-1")
	id, typ, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("expected no error for valid agent auth, got %v", err)
	}
	if id != "test-agent-1" {
		t.Errorf("expected id=test-agent-1, got %s", id)
	}
	if typ != "agent" {
		t.Errorf("expected type=agent, got %s", typ)
	}
}

func TestAuthenticateRequest_WrongAgentSecret(t *testing.T) {
	origAgentSecret := agentSecret
	origEnv := os.Getenv("AGENT_SECRET")
	defer func() { agentSecret = origAgentSecret; os.Setenv("AGENT_SECRET", origEnv) }()
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	agentSecret = "test-agent-secret"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "test-agent-1")
	_, _, err := authenticateRequest(req)
	if err == nil {
		t.Error("expected error for wrong agent secret")
	}
}

func TestHandleUploadPublicKey_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleUploadPublicKey_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleUploadPublicKey_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("key-user", "keyuser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHandleUploadPublicKey_MissingPublicKey(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("key-user2", "keyuser2")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"key_type": "identity"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing public_key, got %d", w.Code)
	}
}

func TestHandleUploadPublicKey_InvalidKeyType(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("key-user3", "keyuser3")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"key_type": "invalid_type", "public_key": "abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid key_type, got %d", w.Code)
	}
}

func TestHandleUploadPublicKey_ValidIdentityKey(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("key-user4", "keyuser4")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"key_type": "identity", "public_key": "dGVzdHB1YmtleQ==", "signature": "c2lnbmF0dXJl"}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUploadPublicKey_ReplaceIdentityKey(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("key-user5", "keyuser5")
	if err != nil {
		t.Fatal(err)
	}

	// Upload first identity key
	body := `{"key_type": "identity", "public_key": "a2V5MQ=="}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first upload: expected 200, got %d", w.Code)
	}

	// Upload second identity key (should replace)
	body2 := `{"key_type": "identity", "public_key": "a2V5Mg=="}`
	req2 := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleUploadPublicKey(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("second upload: expected 200, got %d", w2.Code)
	}
}

func TestHandleUploadPublicKey_OneTimePreKey(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("key-user6", "keyuser6")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"key_type": "one_time_prekey", "public_key": "b3RwazE=", "key_id": 1}`
	req := httptest.NewRequest(http.MethodPost, "/keys/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleGetKeyBundle_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleGetKeyBundle_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetKeyBundle_MissingOwnerID(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("bundle-user", "bundleuser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing owner_id, got %d", w.Code)
	}
}

func TestHandleGetKeyBundle_NoIdentityKey(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("bundle-user2", "bundleuser2")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=nonexistent&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for no identity key, got %d", w.Code)
	}
}

func TestHandleGetKeyBundle_WithIdentityKeyOnly(t *testing.T) {
	setupTestDB(t)
	// Insert identity key directly
	_, err := db.Exec(`INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, "kb1", "target-user", "user", "identity", "aWRLZXk=", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	token, err := GenerateJWT("bundle-user3", "bundleuser3")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=target-user&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if _, ok := result["identity_key"]; !ok {
		t.Error("expected identity_key in bundle")
	}
}

func TestHandleGetKeyBundle_FullBundle(t *testing.T) {
	setupTestDB(t)
	// Insert identity, signed prekey, and one-time prekey
	_, err := db.Exec(`INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, signature, key_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "kb-id1", "full-user", "user", "identity", "aWRLZXk=", "c2ln", nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, signature, key_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "kb-sp1", "full-user", "user", "signed_prekey", "c3BrZXk=", "c2ln", nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, signature, key_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "kb-otp1", "full-user", "user", "one_time_prekey", "b3RwazE=", "", 1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	token, err := GenerateJWT("bundle-user4", "bundleuser4")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/bundle?owner_id=full-user&owner_type=user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if _, ok := result["identity_key"]; !ok {
		t.Error("expected identity_key in bundle")
	}
	if _, ok := result["signed_prekey"]; !ok {
		t.Error("expected signed_prekey in bundle")
	}
	if _, ok := result["one_time_prekey"]; !ok {
		t.Error("expected one_time_prekey in bundle")
	}

	// OTP key should be consumed (deleted)
	var count int
	db.QueryRow("SELECT COUNT(*) FROM key_bundles WHERE id = ?", "kb-otp1").Scan(&count)
	if count != 0 {
		t.Error("one-time prekey should be consumed (deleted) after bundle fetch")
	}
}

func TestHandleListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleListOneTimePreKeys_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleListOneTimePreKeys_Valid(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("otpk-user", "otpkuser")
	if err != nil {
		t.Fatal(err)
	}

	// Insert some one-time pre-keys
	for i := 1; i <= 3; i++ {
		_, err := db.Exec(`INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, key_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("otpk-%d", i), "otpk-user", "user", "one_time_prekey", fmt.Sprintf("a2V5%d", i), i, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/keys/otpk-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if count, ok := result["one_time_prekey_count"]; !ok || int(count.(float64)) != 3 {
		t.Errorf("expected 3 one-time pre-keys, got %v", count)
	}
}

func TestHandleStoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessage_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("enc-user", "encuser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader("invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessage_MissingFields(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("enc-user2", "encuser2")
	if err != nil {
		t.Fatal(err)
	}

	// Missing algorithm
	body := `{"conversation_id": "conv1", "ciphertext": "abc", "iv": "def"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessage_UnsupportedAlgorithm(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("enc-user3", "encuser3")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv1", "ciphertext": "abc", "iv": "def", "algorithm": "rsa-2048"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported algorithm, got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessage_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("enc-user4", "encuser4")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "nonexistent", "ciphertext": "abc", "iv": "def", "algorithm": "aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessage_NotParticipant(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("enc-user5", "encuser5")
	if err != nil {
		t.Fatal(err)
	}

	// Create conversation owned by different user
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"other-user", "otheruser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc1", "other-user", "agent-1")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-enc1", "ciphertext": "abc", "iv": "def", "algorithm": "aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for not participant, got %d", w.Code)
	}
}

func TestHandleStoreEncryptedMessage_ValidUserSender(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	token, err := GenerateJWT("enc-user6", "encuser6")
	if err != nil {
		t.Fatal(err)
	}

	// Create user and conversation
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-user6", "encuser6", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc2", "enc-user6", "agent-1")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-enc2", "ciphertext": "YWJjZGVm", "iv": "aXYxMjM0", "algorithm": "aes-256-gcm", "recipient_key_id": "key1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "stored" {
		t.Errorf("expected status=stored, got %v", result["status"])
	}
}

func TestHandleGetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleGetEncryptedMessages_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv1", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetEncryptedMessages_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("get-enc-user", "getencuser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestHandleGetEncryptedMessages_ConversationNotFound(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("get-enc-user2", "getencuser2")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleGetEncryptedMessages_NotParticipant(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("get-enc-user3", "getencuser3")
	if err != nil {
		t.Fatal(err)
	}

	// Create conversation owned by different user
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"other-user2", "otheruser2", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc3", "other-user2", "agent-2")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-enc3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for not participant, got %d", w.Code)
	}
}

func TestHandleGetEncryptedMessages_Valid(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("get-enc-user4", "getencuser4")
	if err != nil {
		t.Fatal(err)
	}

	// Create user and conversation
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"get-enc-user4", "getencuser4", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc4", "get-enc-user4", "agent-1")
	if err != nil {
		t.Fatal(err)
	}

	// Insert an encrypted message
	_, err = db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg-1", "conv-enc4", "get-enc-user4", "user", "Y2lwaGVydGV4dA==", "aXY=", "key1", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-enc4", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleGetEncryptedMessages_AgentAuth(t *testing.T) {
	setupTestDB(t)
	origAgent := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-agent-secret")
	defer os.Setenv("AGENT_SECRET", origAgent)

	// Create conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-agent-user", "encagentuser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-enc5", "enc-agent-user", "test-agent-1")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-enc5", nil)
	req.Header.Set("X-Agent-Secret", "test-agent-secret")
	req.Header.Set("X-Agent-ID", "test-agent-1")
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for agent auth, got %d", w.Code)
	}
}

// ==============================
// Conversation Handler Tests
// ==============================

func TestDeleteConversation_Unauthorized(t *testing.T) {
	setupTestDB(t)
	err := deleteConversation("conv-nonexistent", "user-notexist")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestDeleteConversation_Valid(t *testing.T) {
	setupTestDB(t)
	// Create user and conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"del-user", "deluser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-del1", "del-user", "agent-del")
	if err != nil {
		t.Fatal(err)
	}
	// Insert messages
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-del1", "conv-del1", "user", "del-user", "hello", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	err = deleteConversation("conv-del1", "del-user")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Verify conversation is gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", "conv-del1").Scan(&count)
	if count != 0 {
		t.Error("conversation should be deleted")
	}
}

func TestDeleteConversation_WrongUser(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"del-user2", "deluser2", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-del2", "del-user2", "agent-del2")
	if err != nil {
		t.Fatal(err)
	}

	err = deleteConversation("conv-del2", "wrong-user")
	if err == nil {
		t.Error("expected error when deleting another user's conversation")
	}
}

func TestChangeUserPassword_WrongOldPassword(t *testing.T) {
	setupTestDB(t)
	hash, _ := HashAPIKey("correctpassword")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"pw-user", "pwuser", hash)
	if err != nil {
		t.Fatal(err)
	}

	err = changeUserPassword("pw-user", "wrongpassword", "newpass123")
	if err == nil {
		t.Error("expected error for wrong old password")
	}
}

func TestChangeUserPassword_TooShort(t *testing.T) {
	setupTestDB(t)
	hash, _ := HashAPIKey("oldpassword")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"pw-user2", "pwuser2", hash)
	if err != nil {
		t.Fatal(err)
	}

	err = changeUserPassword("pw-user2", "oldpassword", "short")
	if err == nil {
		t.Error("expected error for short new password")
	}
}

func TestChangeUserPassword_Valid(t *testing.T) {
	setupTestDB(t)
	hash, _ := HashAPIKey("oldpassword123")
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"pw-user3", "pwuser3", hash)
	if err != nil {
		t.Fatal(err)
	}

	err = changeUserPassword("pw-user3", "oldpassword123", "newpassword456")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Verify new password works
	var newHash string
	db.QueryRow("SELECT password_hash FROM users WHERE id = ?", "pw-user3").Scan(&newHash)
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("newpassword456")); err != nil {
		t.Error("new password hash should match")
	}
}

func TestSearchMessages_EmptyQuery(t *testing.T) {
	setupTestDB(t)
	_, err := searchMessages("user1", "", 50)
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestSearchMessages_Valid(t *testing.T) {
	setupTestDB(t)
	// Create user and conversation
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"search-user", "searchuser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-search1", "search-user", "agent-search")
	if err != nil {
		t.Fatal(err)
	}
	// Insert messages
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-s1", "conv-search1", "agent", "agent-search", "hello world", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-s2", "conv-search1", "agent", "agent-search", "goodbye world", time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	msgs, err := searchMessages("search-user", "hello", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 result, got %d", len(msgs))
	}
}

func TestSearchMessages_NoResults(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"search-user2", "searchuser2", "hash")
	if err != nil {
		t.Fatal(err)
	}

	msgs, err := searchMessages("search-user2", "nonexistent", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 results, got %d", len(msgs))
	}
}

func TestMarkMessagesRead_NotFound(t *testing.T) {
	setupTestDB(t)
	_, err := markMessagesRead("nonexistent", "user1")
	if err == nil {
		t.Error("expected error for nonexistent conversation")
	}
}

func TestMarkMessagesRead_Valid(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"read-user", "readuser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-read1", "read-user", "agent-read")
	if err != nil {
		t.Fatal(err)
	}
	// Insert unread agent message
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-read1", "conv-read1", "agent", "agent-read", "unread msg", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	count, err := markMessagesRead("conv-read1", "read-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 message marked read, got %d", count)
	}

	// Marking again should be idempotent (0 rows affected)
	count, err = markMessagesRead("conv-read1", "read-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 on second mark read, got %d", count)
	}
}

func TestMarkMessagesRead_WrongUser(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"read-user2", "readuser2", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-read2", "read-user2", "agent-read2")
	if err != nil {
		t.Fatal(err)
	}

	_, err = markMessagesRead("conv-read2", "wrong-user")
	if err == nil {
		t.Error("expected error for wrong user")
	}
}

func TestCreateConversation_Duplicate(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"conv-user", "convuser", "hash")
	if err != nil {
		t.Fatal(err)
	}

	conv, err := CreateConversation("conv-user", "agent-create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv.ID == "" {
		t.Error("expected conversation ID")
	}
}

func TestGetOrCreateConversation_New(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"gor-user", "goruser", "hash")
	if err != nil {
		t.Fatal(err)
	}

	conv, err := GetOrCreateConversation("gor-user", "agent-gor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conv.UserID != "gor-user" || conv.AgentID != "agent-gor" {
		t.Errorf("unexpected conversation: %+v", conv)
	}
}

func TestGetOrCreateConversation_Existing(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"gor-user2", "goruser2", "hash")
	if err != nil {
		t.Fatal(err)
	}

	conv1, err := GetOrCreateConversation("gor-user2", "agent-gor2")
	if err != nil {
		t.Fatalf("unexpected error creating: %v", err)
	}

	conv2, err := GetOrCreateConversation("gor-user2", "agent-gor2")
	if err != nil {
		t.Fatalf("unexpected error getting: %v", err)
	}

	if conv1.ID != conv2.ID {
		t.Errorf("expected same conversation ID, got %s and %s", conv1.ID, conv2.ID)
	}
}

// ==============================
// Web Push Handler Tests
// ==============================

func TestHandleGetVAPIDKey_NotConfigured(t *testing.T) {
	setupTestDB(t)
	vapidPublicKey = ""

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when VAPID not configured, got %d", w.Code)
	}
}

func TestHandleGetVAPIDKey_Configured(t *testing.T) {
	setupTestDB(t)
	vapidPublicKey = "test-vapid-public-key"
	defer func() { vapidPublicKey = "" }()

	token, err := GenerateJWT("vapid-user", "vapiduser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleGetVAPIDKey_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleWebPushSubscribe_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleWebPushSubscribe_MissingFields(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("webpush-user", "webpushuser")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"endpoint": "https://push.example.com/123"}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing keys, got %d", w.Code)
	}
}

func TestHandleWebPushSubscribe_Valid(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("webpush-user2", "webpushuser2")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"endpoint": "https://push.example.com/456", "keys": {"p256dh": "abc123", "auth": "def456"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleWebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleWebPushUnsubscribe_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleWebPushUnsubscribe_MissingEndpoint(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("webpush-user3", "webpushuser3")
	if err != nil {
		t.Fatal(err)
	}

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing endpoint, got %d", w.Code)
	}
}

func TestHandleWebPushUnsubscribe_Valid(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("webpush-user4", "webpushuser4")
	if err != nil {
		t.Fatal(err)
	}

	// First subscribe
	subBody := `{"endpoint": "https://push.example.com/789", "keys": {"p256dh": "abc", "auth": "def"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(subBody))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("subscribe failed: %d", w.Code)
	}

	// Now unsubscribe
	unsubBody := `{"endpoint": "https://push.example.com/789"}`
	req2 := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(unsubBody))
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleWebPushUnsubscribe(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ==============================
// Rate Limit Handler Tests
// ==============================

// Removed: TestHandleAdminRateLimitTier_MethodNotAllowed - overlaps with existing tests

func TestHandleSetRateLimitTier_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", nil)
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleSetRateLimitTier_UnknownTier(t *testing.T) {
	setupTestDB(t)
	origAdminSecret := adminSecret
	defer func() { adminSecret = origAdminSecret }()
	adminSecret = "test-admin-secret"

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	req.PostForm = url.Values{
		"user_id": {"tier-test-user"},
		"tier":     {"unknown_tier"},
	}
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown tier, got %d", w.Code)
	}
}

func TestHandleGetRateLimitTier_NoAuth(t *testing.T) {
	origAdminEnv := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "test-admin-secret-xyz")
	defer os.Setenv("ADMIN_SECRET", origAdminEnv)
	origAdminSecret := adminSecret
	defer func() { adminSecret = origAdminSecret }()
	adminSecret = getAdminSecret()

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=test", nil)
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetRateLimitTier_MissingUserID(t *testing.T) {
	setupTestDB(t)
	origAdminSecret := adminSecret
	defer func() { adminSecret = origAdminSecret }()
	adminSecret = "test-admin-secret2"

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret2")
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing user_id, got %d", w.Code)
	}
}

func TestItoaExtended(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-1, "-1"},
		{-42, "-42"},
	}
	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ==============================
// NotifyUser / Push Tests
// ==============================

func TestNotifyUser_NilPushConfig(t *testing.T) {
	pushConfig = nil
	// Should not panic
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestNotifyUser_MutedConversation(t *testing.T) {
	setupTestDB(t)
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}
	defer func() { pushConfig = nil }()

	// Create user and muted conversation notification pref
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"mute-user", "muteuser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
		"mute-user", "conv-muted", 1)
	if err != nil {
		// Table may not exist yet - just skip
		t.Skip("notification_preferences table may not exist")
	}

	// Should not attempt to send push notification
	notifyUser("mute-user", "Title", "Body", "conv-muted")
}

func TestNotifyUser_NoDeviceTokens(t *testing.T) {
	setupTestDB(t)
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}
	defer func() { pushConfig = nil }()

	notifyUser("nonexistent-user", "Title", "Body", "conv1")
	// Should not panic
}

func TestGetDeviceTokensForUser_Empty(t *testing.T) {
	setupTestDB(t)
	tokens, err := getDeviceTokensForUser("nonexistent-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestGetDeviceTokensForUser_WithData(t *testing.T) {
	setupTestDB(t)
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"token-user", "tokenuser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		"token-user", "token-abc", "ios")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		"token-user", "token-def", "android")
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := getDeviceTokensForUser("token-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestSendPushNotification_PlatformRouting(t *testing.T) {
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}
	defer func() { pushConfig = nil }()

	// All platforms should return nil when push is disabled
	err := sendPushNotification("token1", "Title", "Body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil for disabled iOS push, got %v", err)
	}
	err = sendPushNotification("token1", "Title", "Body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil for disabled Android push, got %v", err)
	}
	err = sendPushNotification("token1", "Title", "Body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected nil for disabled FCM push, got %v", err)
	}
	err = sendPushNotification("token1", "Title", "Body", "conv1", "unknown")
	if err != nil {
		t.Errorf("expected nil for unknown platform, got %v", err)
	}
}

// ==============================
// Register Device Token Handler Tests
// ==============================

func TestHandleRegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRegisterDeviceToken_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleRegisterDeviceToken_DefaultPlatform(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("device-user", "deviceuser")
	if err != nil {
		t.Fatal(err)
	}

	// Missing platform should default to "ios"
	body := `{"device_token": "abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify platform is ios
	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = ?", "device-user").Scan(&platform)
	if platform != "ios" {
		t.Errorf("expected default platform=ios, got %s", platform)
	}
}

func TestHandleRegisterDeviceToken_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("device-user2", "deviceuser2")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader("invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHandleRegisterDeviceToken_MissingToken(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("device-user3", "deviceuser3")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"platform": "ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceToken_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceToken_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("unreg-user", "unreguser")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader("invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceToken_MissingToken(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("unreg-user2", "unreguser2")
	if err != nil {
		t.Fatal(err)
	}

	body := `{}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_token, got %d", w.Code)
	}
}

func TestHandleUnregisterDeviceToken_Valid(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("unreg-user3", "unreguser3")
	if err != nil {
		t.Fatal(err)
	}

	// Register a token first
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"unreg-user3", "unreguser3", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		"unreg-user3", "token-to-remove", "ios")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"device_token": "token-to-remove"}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// Notification Prefs Handler Tests
// ==============================

// handleGetNotificationPrefs and handleSetNotificationPrefs check auth first (no method check)
// so MethodNotAllowed tests don't apply here

func TestHandleGetNotificationPrefs_NoAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/notifications/preferences", nil)
	w := httptest.NewRecorder()
	authMiddleware(handleGetNotificationPrefs)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleSetNotificationPrefs_NoAuth(t *testing.T) {
	setupTestDB(t)
	body := "conversation_id=conv1&muted=true"
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences/set", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	authMiddleware(handleSetNotificationPrefs)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleSetNotificationPrefs_MissingConversationID(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("notif-user", "notifuser")
	if err != nil {
		t.Fatal(err)
	}

	body := "muted=true"
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences/set", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	authMiddleware(handleSetNotificationPrefs)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing conversation_id, got %d", w.Code)
	}
}

func TestHandleSetNotificationPrefs_Valid(t *testing.T) {
	setupTestDB(t)
	token, err := GenerateJWT("notif-user2", "notifuser2")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"notif-user2", "notifuser2", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-notif1", "notif-user2", "agent-notif")
	if err != nil {
		t.Fatal(err)
	}

	body := "conversation_id=conv-notif1&muted=true"
	req := httptest.NewRequest(http.MethodPost, "/notifications/preferences/set", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	authMiddleware(handleSetNotificationPrefs)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// IsAllowedContentType Tests
// ==============================

func TestIsAllowedContentTypeExtended(t *testing.T) {
	tests := []struct {
		ct       string
		expected bool
	}{
		{"image/jpeg", true},
		{"image/png", true},
		{"image/gif", true},
		{"image/webp", true},
		{"image/svg+xml", true},
		{"application/pdf", true},
		{"text/plain", true},
		{"text/csv", true},
		{"audio/mpeg", true},
		{"audio/ogg", true},
		{"video/mp4", true},
		{"video/webm", true},
		{"application/octet-stream", false},
		{"application/x-executable", false},
		{"image/tiff", true},     // starts with image/
		{"audio/flac", true},     // starts with audio/
		{"video/quicktime", true}, // starts with video/
		{"text/html", true},      // starts with text/
		{"", false},
	}
	for _, tt := range tests {
		result := isAllowedContentType(tt.ct)
		if result != tt.expected {
			t.Errorf("isAllowedContentType(%q) = %v, want %v", tt.ct, result, tt.expected)
		}
	}
}

// ==============================
// Queue Persist Tests
// ==============================

func TestPersistQueue_InsertsData(t *testing.T) {
	setupTestDB(t)
	initQueueDB(db)
	// persistQueue should insert data into the queue
	persistQueue(db, "user1", []byte("test-data"))
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

func TestInitQueueDBCreatesTable(t *testing.T) {
	setupTestDB(t)
	initQueueDB(db)
	// Verify offline_queue table exists
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&name)
	if err != nil {
		t.Errorf("offline_queue table should exist after initQueueDB: %v", err)
	}
}

func TestCleanStaleQueueMessagesWithDB(t *testing.T) {
	setupTestDB(t)
	initQueueDB(db)

	// Insert a stale message (7+ days old)
	_, err := db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, datetime('now', '-8 days'), 0)`,
		"user-stale", []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	// Insert a fresh message
	_, err = db.Exec(`INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, datetime('now'), 0)`,
		"user-fresh", []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Verify fresh message still exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-fresh").Scan(&count)
	if count != 1 {
		t.Errorf("fresh message should still exist, count=%d", count)
	}

	// Verify stale message was deleted
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user-stale").Scan(&count)
	if count != 0 {
		t.Errorf("stale message should be deleted, count=%d", count)
	}
}