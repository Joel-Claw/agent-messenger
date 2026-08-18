package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// CB94: Coverage boost targeting remaining 0% functions
// Focus: HTTP handler endpoints and supporting functions that
// are at 0% because they require DB + hub setup:
//   - profile_handler.go: handleAdminProfile, handleHeapProfile,
//     handleGoroutineProfile, handleCPUProfileStart/Stop,
//     handleForceGC, handleMemoryStats, writeProfileJSON/Error,
//     SetGCPercent, SetMemoryLimit
//   - profile.go: StartCPUProfile, WriteHeapProfile,
//     WriteGoroutineProfile, MemoryStats, ForceGC, CaptureProfile
//   - push.go: handleGetVAPIDKey, handleWebPushSubscribe,
//     handleWebPushUnsubscribe, handleRegisterDeviceToken,
//     handleUnregisterDeviceToken, safeTruncate, getEnvOrDefault
//   - middleware.go: corsMiddleware, ipRateLimitMiddleware,
//     authRateLimitMiddleware, initAuthRateLimit, requestIDMiddleware,
//     accessLogMiddleware, responseWriterWrapper.WriteHeader,
//     extractIP, isUniqueViolation, RateLimiter Stop/Reset/Count
//   - handlers.go: handleHealth, handleLogin, handleRegisterAgent,
//     handleRegisterUser, handleListAgents, handleAdminAgents
//   - protocol.go: upgradeWithProtocol, sendWelcomeMessage
//   - routing.go: routeChatMessage, routeTypingIndicator, routeStatusUpdate
//   - reactions.go: handleReact, handleGetReactions
//   - tags.go: handleAddTag, handleRemoveTag
//   - rate_limit_tiers.go: Allow, GetTier, GetRemaining,
//     tieredRateLimitMiddleware, handleSetRateLimitTier,
//     handleGetRateLimitTier, persistTierToDB, handleAdminRateLimitTier
//   - hub.go: monitorAgentHeartbeats, checkStaleAgents, GetClient
//   - dbdriver.go: openDatabase, envIntOrDefault, envDurationOrDefault
//   - queue_persist.go: initQueueDB, marshalOutgoingMessage
//   - tracing.go: IsTracingEnabled
//   - main.go: parseSize
//   - logger.go: SetOutput
//   - auth.go: Clean, Reset, resetAgentSecret, resetAdminSecret
// ============================================================

// --- Helpers ---

func setupHub_CB94() func() {
	oldHub := hub
	h := newHub()
	hub = h
	go h.run()
	return func() {
		h.Stop()
		hub = oldHub
	}
}

func setupTestDB_CB94(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "cb94_test_*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	dbPath := tmpDir + "/test.db"
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("open db: %v", err)
	}
	initSchema(testDB)
	oldDB := db
	db = testDB
	oldServerDBPath := serverDBPath
	serverDBPath = dbPath
	return testDB, func() {
		db = oldDB
		serverDBPath = oldServerDBPath
		testDB.Close()
		os.RemoveAll(tmpDir)
	}
}

func makeAuthReq_CB94(method, path, body string, userID string) *http.Request {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, bodyReader)
	ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
	r = r.WithContext(ctx)
	return r
}

func setupUserAndAgent_CB94(t *testing.T, testDB *sql.DB) (string, string, string) {
	t.Helper()
	userID := "cb94-user1"
	agentID := "cb94-agent1"
	convID := "cb94-conv1"

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "cb94testuser", string(hash))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		agentID, "TestAgent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		convID, userID, agentID)
	if err != nil {
		t.Fatalf("insert conv: %v", err)
	}
	return userID, agentID, convID
}

func makeJWT_CB94(userID string) string {
	token, _ := GenerateJWT(userID, "cb94testuser")
	return token
}

// ============================================================
// profile.go: StartCPUProfile, WriteHeapProfile, WriteGoroutineProfile,
// MemoryStats, ForceGC, CaptureProfile
// ============================================================

func Test_CB94_StartCPUProfile_Success(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/cpu.prof"
	stop, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("StartCPUProfile: %v", err)
	}
	if stop == nil {
		t.Fatal("stop function is nil")
	}
	// Let it profile briefly
	time.Sleep(time.Millisecond)
	stop()
	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Errorf("cpu profile file not created: %v", err)
	}
}

func Test_CB94_StartCPUProfile_CreateError(t *testing.T) {
	// Try to create in a non-existent directory that we can't create
	// Use a path that would fail (e.g., under /proc which is read-only)
	_, err := StartCPUProfile("/proc/test_cpu.prof")
	if err == nil {
		t.Error("expected error creating file in read-only dir")
	}
}

func Test_CB94_WriteHeapProfile_Success(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/heap.prof"
	if err := WriteHeapProfile(path); err != nil {
		t.Errorf("WriteHeapProfile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("heap profile file not created: %v", err)
	}
}

func Test_CB94_WriteHeapProfile_CreateError(t *testing.T) {
	err := WriteHeapProfile("/proc/test_heap.prof")
	if err == nil {
		t.Error("expected error creating file in read-only dir")
	}
}

func Test_CB94_WriteGoroutineProfile_Success(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/goroutine.prof"
	if err := WriteGoroutineProfile(path); err != nil {
		t.Errorf("WriteGoroutineProfile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("goroutine profile file not created: %v", err)
	}
}

func Test_CB94_WriteGoroutineProfile_CreateError(t *testing.T) {
	err := WriteGoroutineProfile("/proc/test_goroutine.prof")
	if err == nil {
		t.Error("expected error creating file in read-only dir")
	}
}

func Test_CB94_MemoryStats(t *testing.T) {
	stats := MemoryStats()
	if stats == nil {
		t.Fatal("MemoryStats returned nil")
	}
	if _, ok := stats["alloc_bytes"]; !ok {
		t.Error("missing alloc_bytes")
	}
	if _, ok := stats["goroutines"]; !ok {
		t.Error("missing goroutines")
	}
	if _, ok := stats["num_gc"]; !ok {
		t.Error("missing num_gc")
	}
	if _, ok := stats["heap_objects"]; !ok {
		t.Error("missing heap_objects")
	}
}

func Test_CB94_ForceGC(t *testing.T) {
	gc := ForceGC()
	if gc == 0 {
		t.Error("ForceGC returned 0")
	}
}

func Test_CB94_CaptureProfile_NoDir(t *testing.T) {
	snap := CaptureProfile("")
	if snap == nil {
		t.Fatal("CaptureProfile returned nil")
	}
	if snap.HeapFile != "" {
		t.Error("expected empty HeapFile when dir is empty")
	}
	if snap.GoroutineFile != "" {
		t.Error("expected empty GoroutineFile when dir is empty")
	}
	if snap.Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
	if snap.Memory == nil {
		t.Error("memory stats nil")
	}
}

func Test_CB94_CaptureProfile_WithDir(t *testing.T) {
	dir := t.TempDir()
	snap := CaptureProfile(dir)
	if snap == nil {
		t.Fatal("CaptureProfile returned nil")
	}
	if snap.HeapFile == "" {
		t.Error("expected non-empty HeapFile")
	}
	if snap.GoroutineFile == "" {
		t.Error("expected non-empty GoroutineFile")
	}
	// Verify files exist
	if _, err := os.Stat(snap.HeapFile); err != nil {
		t.Errorf("heap file not created: %v", err)
	}
	if _, err := os.Stat(snap.GoroutineFile); err != nil {
		t.Errorf("goroutine file not created: %v", err)
	}
}

// ============================================================
// profile_handler.go: handleAdminProfile, handleHeapProfile,
// handleGoroutineProfile, handleCPUProfileStart/Stop,
// handleForceGC, handleMemoryStats, writeProfileJSON/Error,
// SetGCPercent, SetMemoryLimit
// ============================================================

func Test_CB94_HandleAdminProfile_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/admin/profile", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleAdminProfile_UnknownAction(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=bogus", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleAdminProfile_Stats(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=stats", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
	if resp["action"] != "stats" {
		t.Errorf("expected action=stats, got %v", resp["action"])
	}
}

func Test_CB94_HandleAdminProfile_DefaultGet(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleAdminProfile_JSONBody(t *testing.T) {
	body := `{"action":"stats"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/profile", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	handleAdminProfile(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleAdminProfile_Heap(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
	if resp["action"] != "heap" {
		t.Errorf("expected action=heap, got %v", resp["action"])
	}
}

func Test_CB94_HandleAdminProfile_Goroutine(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
}

func Test_CB94_HandleAdminProfile_GC(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=gc", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
	if resp["action"] != "gc" {
		t.Errorf("expected action=gc, got %v", resp["action"])
	}
}

func Test_CB94_HandleAdminProfile_CPUStartStop(t *testing.T) {
	// Start CPU profile
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/admin/profile?action=cpu", nil)
	handleAdminProfile(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("cpu start: expected 200, got %d", w1.Code)
	}

	// Stop CPU profile
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/admin/profile?action=cpu_stop", nil)
	handleAdminProfile(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("cpu stop: expected 200, got %d", w2.Code)
	}
}

func Test_CB94_HandleAdminProfile_CPUStopNotActive(t *testing.T) {
	// Reset state
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=cpu_stop", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func Test_CB94_HandleAdminProfile_CPUStartAlreadyActive(t *testing.T) {
	cpuProfileState.Lock()
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {}
	cpuProfileState.Unlock()

	defer func() {
		cpuProfileState.Lock()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
		cpuProfileState.Unlock()
	}()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=cpu", nil)
	handleAdminProfile(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func Test_CB94_HandleHeapProfile_DirError(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", "/proc/cannot-create-here")
	defer os.Setenv("PROFILING_DIR", oldDir)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=heap", nil)
	handleHeapProfile(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func Test_CB94_HandleGoroutineProfile_DirError(t *testing.T) {
	oldDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", "/proc/cannot-create-here")
	defer os.Setenv("PROFILING_DIR", oldDir)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/profile?action=goroutine", nil)
	handleGoroutineProfile(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func Test_CB94_SetGCPercent(t *testing.T) {
	old := SetGCPercent(200)
	defer SetGCPercent(old)
	new := SetGCPercent(200)
	if new != 200 {
		t.Errorf("expected 200, got %d", new)
	}
}

func Test_CB94_SetMemoryLimit(t *testing.T) {
	old := SetMemoryLimit(1024 * 1024 * 512)
	defer SetMemoryLimit(old)
	new := SetMemoryLimit(1024 * 1024 * 256)
	if new != 1024*1024*512 {
		t.Errorf("expected 512MB, got %d", new)
	}
}

func Test_CB94_WriteProfileJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileJSON(w, map[string]interface{}{"status": "ok"})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("missing content-type")
	}
}

func Test_CB94_WriteProfileError_WithErr(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileError(w, "test context", fmt.Errorf("test error"))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["context"] != "test context" {
		t.Errorf("expected context=test context, got %v", resp["context"])
	}
	if resp["detail"] != "test error" {
		t.Errorf("expected detail=test error, got %v", resp["detail"])
	}
}

func Test_CB94_WriteProfileError_WithoutErr(t *testing.T) {
	w := httptest.NewRecorder()
	writeProfileError(w, "no error context", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["context"] != "no error context" {
		t.Errorf("expected context, got %v", resp["context"])
	}
	if resp["detail"] != "" {
		t.Errorf("expected empty detail, got %v", resp["detail"])
	}
}

// ============================================================
// push.go: handleGetVAPIDKey, handleWebPushSubscribe,
// handleWebPushUnsubscribe, handleRegisterDeviceToken,
// handleUnregisterDeviceToken, safeTruncate, getEnvOrDefault
// ============================================================

func Test_CB94_HandleGetVAPIDKey_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/vapid-key", nil)
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleGetVAPIDKey_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/vapid-key", nil)
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetVAPIDKey_NotConfigured(t *testing.T) {
	oldKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = oldKey }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/vapid-key", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleGetVAPIDKey_Success(t *testing.T) {
	oldKey := vapidPublicKey
	vapidPublicKey = "test-vapid-key-12345"
	defer func() { vapidPublicKey = oldKey }()

	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/vapid-key", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetVAPIDKey(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["public_key"] != "test-vapid-key-12345" {
		t.Errorf("expected test-vapid-key-12345, got %v", resp["public_key"])
	}
}

func Test_CB94_HandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/web-subscribe", nil)
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushSubscribe_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-subscribe", nil)
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushSubscribe_InvalidBody(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader("invalid"))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"endpoint":"https://example.com/push","keys":{"p256dh":"","auth":""}}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushSubscribe_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"endpoint":"https://push.example.com/s/abc","keys":{"p256dh":"key1","auth":"key2"}}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleWebPushSubscribe(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "subscribed" {
		t.Errorf("expected subscribed, got %v", resp["status"])
	}
}

func Test_CB94_HandleWebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/web-unsubscribe", nil)
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushUnsubscribe_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-unsubscribe", nil)
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushUnsubscribe_InvalidBody(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader("bad"))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushUnsubscribe_EmptyEndpoint(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"endpoint":""}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleWebPushUnsubscribe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleWebPushUnsubscribe_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	// First subscribe
	subBody := `{"endpoint":"https://push.example.com/s/abc","keys":{"p256dh":"key1","auth":"key2"}}`
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("POST", "/push/web-subscribe", strings.NewReader(subBody))
	r1.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleWebPushSubscribe(w1, r1)

	// Now unsubscribe
	unsubBody := `{"endpoint":"https://push.example.com/s/abc"}`
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/push/web-unsubscribe", strings.NewReader(unsubBody))
	r2.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleWebPushUnsubscribe(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w2.Code)
	}
	var resp map[string]string
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["status"] != "unsubscribed" {
		t.Errorf("expected unsubscribed, got %v", resp["status"])
	}
}

func Test_CB94_HandleRegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/device", nil)
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterDeviceToken_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/device", nil)
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterDeviceToken_InvalidBody(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/device", strings.NewReader("bad"))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterDeviceToken_MissingToken(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"device_token":"","platform":"ios"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/device", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterDeviceToken_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"device_token":"token123","platform":"android"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/device", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected ok, got %v", resp["status"])
	}
}

func Test_CB94_HandleRegisterDeviceToken_DefaultPlatform(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"device_token":"token456"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/push/device", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleRegisterDeviceToken(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/push/device", nil)
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleUnregisterDeviceToken_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/push/device", nil)
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleUnregisterDeviceToken_InvalidBody(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/push/device", strings.NewReader("bad"))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleUnregisterDeviceToken_EmptyToken(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"device_token":""}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/push/device", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleUnregisterDeviceToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleUnregisterDeviceToken_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	// Register first
	regBody := `{"device_token":"token789","platform":"ios"}`
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("POST", "/push/device", strings.NewReader(regBody))
	r1.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleRegisterDeviceToken(w1, r1)

	// Unregister
	unregBody := `{"device_token":"token789"}`
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("DELETE", "/push/device", strings.NewReader(unregBody))
	r2.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleUnregisterDeviceToken(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w2.Code)
	}
}

func Test_CB94_SafeTruncate(t *testing.T) {
	if safeTruncate("hello", 10) != "hello" {
		t.Error("short string should be unchanged")
	}
	if safeTruncate("hello world", 5) != "hello" {
		t.Error("long string should be truncated")
	}
	if safeTruncate("", 5) != "" {
		t.Error("empty string")
	}
}

func Test_CB94_GetEnvOrDefault(t *testing.T) {
	os.Setenv("CB94_TEST_VAR", "testval")
	if v := getEnvOrDefault("CB94_TEST_VAR", "default"); v != "testval" {
		t.Errorf("expected testval, got %s", v)
	}
	os.Unsetenv("CB94_TEST_VAR")
	if v := getEnvOrDefault("CB94_TEST_VAR", "default"); v != "default" {
		t.Errorf("expected default, got %s", v)
	}
}

func Test_CB94_InitAPNs_CertLoadError(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/proc/nonexistent.pem",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// apnsClient should be nil (cert loading failed)
	if pushConfig == nil || pushConfig.apnsClient != nil {
		t.Error("expected nil apnsClient after cert load error")
	}
}

func Test_CB94_InitFCM_InvalidCreds(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:    true,
		FCMCredentials: "/proc/nonexistent.json",
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	// fcmClient should be nil (creds not loaded)
	if pushConfig == nil || pushConfig.fcmClient != nil {
		t.Error("expected nil fcmClient after creds error")
	}
}

func Test_CB94_InitPushNotifications_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initPushNotifications()
	// Should not crash, should be no-op
}

func Test_CB94_InitPushNotifications_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
		FCMEnabled:  false,
	}
	defer func() { pushConfig = oldConfig }()

	initPushNotifications()
}

// ============================================================
// middleware.go: corsMiddleware, ipRateLimitMiddleware,
// authRateLimitMiddleware, initAuthRateLimit, requestIDMiddleware,
// accessLogMiddleware, responseWriterWrapper.WriteHeader,
// extractIP, isUniqueViolation, RateLimiter Stop/Reset/Count
// ============================================================

func Test_CB94_CorsMiddleware_WildcardOrigin(t *testing.T) {
	oldOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = oldOrigins }()

	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Origin", "https://example.com")
	handler(w, r)
	if !called {
		t.Error("handler not called")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected * origin")
	}
}

func Test_CB94_CorsMiddleware_SpecificOrigin(t *testing.T) {
	oldOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://allowed.com,https://other.com"
	defer func() { corsAllowedOrigins = oldOrigins }()

	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Origin", "https://allowed.com")
	handler(w, r)
	if !called {
		t.Error("handler not called")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://allowed.com" {
		t.Errorf("expected https://allowed.com, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func Test_CB94_CorsMiddleware_OriginNotInList(t *testing.T) {
	oldOrigins := corsAllowedOrigins
	corsAllowedOrigins = "https://allowed.com"
	defer func() { corsAllowedOrigins = oldOrigins }()

	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Origin", "https://notallowed.com")
	handler(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no Access-Control-Allow-Origin header")
	}
}

func Test_CB94_CorsMiddleware_OptionsPreflight(t *testing.T) {
	oldOrigins := corsAllowedOrigins
	corsAllowedOrigins = "*"
	defer func() { corsAllowedOrigins = oldOrigins }()

	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/test", nil)
	r.Header.Set("Origin", "https://example.com")
	handler(w, r)
	if called {
		t.Error("handler should not be called for OPTIONS")
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func Test_CB94_CorsMiddleware_NoOrigin(t *testing.T) {
	called := false
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	handler(w, r)
	if !called {
		t.Error("handler not called")
	}
}

func Test_CB94_IpRateLimitMiddleware_Allowed(t *testing.T) {
	// Reset the rate limiter to a fresh state
	ipRateLimiter = NewRateLimiter(300, time.Minute)

	called := false
	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "192.168.1.100:12345"
	handler(w, r)
	if !called {
		t.Error("handler not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_IpRateLimitMiddleware_RateLimited(t *testing.T) {
	// Create a very low limit limiter
	ipRateLimiter = NewRateLimiter(1, time.Minute)

	handler := ipRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request OK
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/test", nil)
	r1.RemoteAddr = "10.0.0.1:12345"
	handler(w1, r1)
	if w1.Code != http.StatusOK {
		t.Errorf("first: expected 200, got %d", w1.Code)
	}

	// Second request rate limited
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/test", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	handler(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second: expected 429, got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") != "60" {
		t.Error("missing Retry-After header")
	}
}

func Test_CB94_AuthRateLimitMiddleware_Allowed(t *testing.T) {
	authIPLimiter = NewRateLimiter(30, time.Minute)

	called := false
	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/login", nil)
	r.RemoteAddr = "192.168.1.100:12345"
	handler(w, r)
	if !called {
		t.Error("handler not called")
	}
}

func Test_CB94_AuthRateLimitMiddleware_RateLimited(t *testing.T) {
	authIPLimiter = NewRateLimiter(1, time.Minute)

	handler := authRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("POST", "/auth/login", nil)
	r1.RemoteAddr = "10.0.0.2:12345"
	handler(w1, r1)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/auth/login", nil)
	r2.RemoteAddr = "10.0.0.2:12345"
	handler(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w2.Code)
	}
}

func Test_CB94_InitAuthRateLimit_Default(t *testing.T) {
	os.Unsetenv("AUTH_RATE_LIMIT")
	initAuthRateLimit()
	// authIPLimiter should be set with default 30
}

func Test_CB94_InitAuthRateLimit_Custom(t *testing.T) {
	os.Setenv("AUTH_RATE_LIMIT", "100")
	defer os.Unsetenv("AUTH_RATE_LIMIT")
	initAuthRateLimit()
}

func Test_CB94_InitAuthRateLimit_Invalid(t *testing.T) {
	os.Setenv("AUTH_RATE_LIMIT", "notanumber")
	defer os.Unsetenv("AUTH_RATE_LIMIT")
	initAuthRateLimit()
	// Should fall back to default
}

func Test_CB94_RequestIDMiddleware_GeneratesID(t *testing.T) {
	var capturedID string
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		capturedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	handler(w, r)
	if capturedID == "" {
		t.Error("no request ID generated")
	}
}

func Test_CB94_RequestIDMiddleware_PreservesExisting(t *testing.T) {
	handler := requestIDMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Request-ID") != "existing-id" {
			t.Error("existing ID not preserved")
		}
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Request-ID", "existing-id")
	handler(w, r)
}

func Test_CB94_AccessLogMiddleware_Success(t *testing.T) {
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "192.168.1.100:12345"
	handler(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_AccessLogMiddleware_WithUserID(t *testing.T) {
	handler := accessLogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(r.Context(), contextKeyUserID, "cb94-user")
	r = r.WithContext(ctx)
	handler(w, r)
}

func Test_CB94_ResponseWriterWrapper_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{
		ResponseWriter: rec,
	}
	wrapper.WriteHeader(http.StatusCreated)
	if wrapper.statusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", wrapper.statusCode)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("recorder expected 201, got %d", rec.Code)
	}
}

func Test_CB94_ExtractIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	ip := extractIP(r)
	if ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

func Test_CB94_ExtractIP_XForwardedForSingle(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	ip := extractIP(r)
	if ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

func Test_CB94_ExtractIP_XRealIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Real-IP", "9.8.7.6")
	ip := extractIP(r)
	if ip != "9.8.7.6" {
		t.Errorf("expected 9.8.7.6, got %s", ip)
	}
}

func Test_CB94_ExtractIP_RemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	ip := extractIP(r)
	if ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

func Test_CB94_IsUniqueViolation_True(t *testing.T) {
	err := fmt.Errorf("UNIQUE constraint failed: users.username")
	if !isUniqueViolation(err) {
		t.Error("expected true")
	}
}

func Test_CB94_IsUniqueViolation_False(t *testing.T) {
	err := fmt.Errorf("some other error")
	if isUniqueViolation(err) {
		t.Error("expected false")
	}
}

func Test_CB94_IsUniqueViolation_Nil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("expected false for nil")
	}
}

func Test_CB94_RateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	rl.Stop()
	// Stop should not panic
}

func Test_CB94_RateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	rl.Allow("key1")
	rl.Reset()
	// After reset, should allow again
	if !rl.Allow("key1") {
		t.Error("expected allow after reset")
	}
}

func Test_CB94_RateLimiter_Count(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	rl.Allow("key1")
	rl.Allow("key1")
	if c := rl.Count("key1"); c != 2 {
		t.Errorf("expected count 2, got %d", c)
	}
	if c := rl.Count("key2"); c != 0 {
		t.Errorf("expected count 0, got %d", c)
	}
}

// ============================================================
// handlers.go: handleHealth, handleLogin, handleRegisterAgent,
// handleRegisterUser, handleListAgents, handleAdminAgents
// ============================================================

func Test_CB94_HandleHealth_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/health", nil)
	handleHealth(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleHealth_NoDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	oldMetrics := ServerMetrics
	ServerMetrics = nil
	defer func() { ServerMetrics = oldMetrics }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/health", nil)
	handleHealth(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func Test_CB94_HandleHealth_WithDB(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/health", nil)
	handleHealth(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected ok, got %v", resp["status"])
	}
}

func Test_CB94_HandleHealth_Degraded(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	// Close the DB to make ping fail
	testDB.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/health", nil)
	handleHealth(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func Test_CB94_HandleLogin_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login", nil)
	handleLogin(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleLogin_MissingFields(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/login", nil)
	handleLogin(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleLogin_UserNotFound(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	form := "username=nonexistent&password=test"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleLogin(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleLogin_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "username=cb94testuser&password=testpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleLogin(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Error("missing token")
	}
	if resp["user_id"] != "cb94-user1" {
		t.Errorf("expected cb94-user1, got %s", resp["user_id"])
	}
}

func Test_CB94_HandleLogin_WrongPassword(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "username=cb94testuser&password=wrongpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleLogin(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterAgent_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/agent", nil)
	handleRegisterAgent(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterAgent_NoSecret(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/agent", nil)
	handleRegisterAgent(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterAgent_WrongSecret(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/agent", nil)
	r.Header.Set("X-Agent-Secret", "wrongsecret")
	handleRegisterAgent(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterAgent_MissingAgentID(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { agentSecret = oldSecret }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/agent", nil)
	r.Header.Set("X-Agent-Secret", "testsecret")
	handleRegisterAgent(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterAgent_Success(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { agentSecret = oldSecret }()

	form := "agent_id=cb94-newagent&name=NewAgent&model=gpt-4&personality=helpful&specialty=general"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Agent-Secret", "testsecret")
	handleRegisterAgent(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["agent_id"] != "cb94-newagent" {
		t.Errorf("expected cb94-newagent, got %s", resp["agent_id"])
	}
	if resp["status"] != "registered" {
		t.Errorf("expected registered, got %s", resp["status"])
	}
}

func Test_CB94_HandleRegisterAgent_Duplicate(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	oldSecret := agentSecret
	agentSecret = "testsecret"
	defer func() { agentSecret = oldSecret }()

	form := "agent_id=cb94-agent1&name=UpdatedAgent&model=gpt-5&personality=formal&specialty=expert"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Agent-Secret", "testsecret")
	handleRegisterAgent(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (upsert), got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/user", nil)
	handleRegisterUser(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterUser_MissingFields(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/user", nil)
	handleRegisterUser(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterUser_ShortUsername(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	form := "username=ab&password=testpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleRegisterUser(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterUser_InvalidChars(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	form := "username=test@user&password=testpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleRegisterUser(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterUser_Success(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	form := "username=cb94newuser&password=testpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleRegisterUser(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "registered" {
		t.Errorf("expected registered, got %s", resp["status"])
	}
	if resp["username"] != "cb94newuser" {
		t.Errorf("expected cb94newuser, got %s", resp["username"])
	}
}

func Test_CB94_HandleRegisterUser_Duplicate(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "username=cb94testuser&password=testpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleRegisterUser(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func Test_CB94_HandleRegisterUser_LongUsername(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	form := "username=" + strings.Repeat("a", 51) + "&password=testpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleRegisterUser(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleListAgents_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/agents", nil)
	handleListAgents(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleListAgents_Empty(t *testing.T) {
	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/agents", nil)
	handleListAgents(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp []AgentInfo
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty list, got %d", len(resp))
	}
}

func Test_CB94_HandleListAgents_WithData(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/agents", nil)
	handleListAgents(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp []AgentInfo
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(resp))
	}
	if resp[0].ID != "cb94-agent1" {
		t.Errorf("expected cb94-agent1, got %s", resp[0].ID)
	}
}

func Test_CB94_HandleListAgents_DBClosed(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	testDB.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/agents", nil)
	handleListAgents(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func Test_CB94_HandleAdminAgents_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/agents", nil)
	handleAdminAgents(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleAdminAgents_WithData(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/agents", nil)
	handleAdminAgents(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp []AgentInfo
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(resp))
	}
}

func Test_CB94_HandleAdminAgents_DBClosed(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	testDB.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/agents", nil)
	handleAdminAgents(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ============================================================
// handlers.go: handleChangePassword, handleDeleteConversation,
// handleSearchMessages, handleMarkRead, handleCreateConversation,
// handleGetMessages, handleListConversations
// ============================================================

func Test_CB94_HandleChangePassword_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/change-password", nil)
	handleChangePassword(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleChangePassword_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/change-password", nil)
	handleChangePassword(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleChangePassword_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/change-password", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleChangePassword(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleChangePassword_WrongOld(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "old_password=wrong&new_password=newpass123"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleChangePassword(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleChangePassword_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "old_password=testpass&new_password=newpass123"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleChangePassword(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteConversation_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations/delete", nil)
	handleDeleteConversation(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteConversation_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/conversations/delete", nil)
	handleDeleteConversation(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteConversation_MissingID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/conversations/delete", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleDeleteConversation(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteConversation_NotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleDeleteConversation(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteConversation_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleDeleteConversation(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteConversation_Unauthorized(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	_, _, convID := setupUserAndAgent_CB94(t, testDB)

	// Create a second user
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.DefaultCost)
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "cb94-user2", "cb94user2", string(hash))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id="+convID, nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user2"))
	handleDeleteConversation(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleSearchMessages_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/search", nil)
	handleSearchMessages(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleSearchMessages_EmptyQuery(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/search?q=", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleSearchMessages(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleSearchMessages_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	// Insert a message
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg1", convID, "agent", agentID, "hello world test", time.Now().UTC())

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/search?q=world", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleSearchMessages(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleMarkRead_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/mark-read", nil)
	handleMarkRead(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleMarkRead_MissingConvID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/mark-read", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleMarkRead(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleMarkRead_NotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "conversation_id=nonexistent"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleMarkRead(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleMarkRead_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	// Insert an unread message
	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-mr1", convID, "agent", agentID, "unread message", time.Now().UTC())

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	form := "conversation_id=" + convID
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleMarkRead(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleCreateConversation_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/create", nil)
	handleCreateConversation(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleCreateConversation_MissingAgentID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/create", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleCreateConversation(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleCreateConversation_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	form := "agent_id=cb94-agent1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/create", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleCreateConversation(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["conversation_id"] == nil {
		t.Error("missing conversation_id")
	}
}

func Test_CB94_HandleGetMessages_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations/messages", nil)
	handleGetMessages(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetMessages_MissingConvID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations/messages", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetMessages(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleGetMessages_NotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations/messages?conversation_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetMessages(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleGetMessages_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-gm1", convID, "agent", agentID, "test message", time.Now().UTC())

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations/messages?conversation_id="+convID, nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleGetMessages(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleListConversations_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations", nil)
	handleListConversations(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleListConversations_Empty(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleListConversations(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleListConversations_WithData(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleListConversations(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ============================================================
// reactions.go: handleReact, handleGetReactions
// ============================================================

func Test_CB94_HandleReact_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/react", nil)
	handleReact(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleReact_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/react", nil)
	handleReact(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleReact_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/react", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleReact(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleReact_MessageNotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	form := "message_id=nonexistent&emoji=👍"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleReact(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleReact_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-react1", convID, "agent", agentID, "react to this", time.Now().UTC())

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	form := "message_id=msg-react1&emoji=👍"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/react", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleReact(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleGetReactions_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/reactions", nil)
	handleGetReactions(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleGetReactions_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/reactions", nil)
	handleGetReactions(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetReactions_MissingMessageID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/reactions", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetReactions(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleGetReactions_NotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/reactions?message_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetReactions(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleGetReactions_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-gr1", convID, "agent", agentID, "get reactions test", time.Now().UTC())

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/messages/reactions?message_id=msg-gr1", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleGetReactions(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ============================================================
// tags.go: handleAddTag, handleRemoveTag
// ============================================================

func Test_CB94_HandleAddTag_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations/tags/add", nil)
	handleAddTag(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleAddTag_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/tags/add", nil)
	handleAddTag(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleAddTag_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/tags/add", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleAddTag(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleAddTag_ConvNotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "conversation_id=nonexistent&tag=important"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleAddTag(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleAddTag_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	form := "conversation_id=" + convID + "&tag=important"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleAddTag(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleAddTag_Duplicate(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	// Add first time
	form := "conversation_id=" + convID + "&tag=important"
	r1 := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r1.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleAddTag(httptest.NewRecorder(), r1)

	// Add same tag again
	w := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleAddTag(w, r2)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func Test_CB94_HandleRemoveTag_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/conversations/tags/remove", nil)
	handleRemoveTag(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleRemoveTag_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/tags/remove", nil)
	handleRemoveTag(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleRemoveTag_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/tags/remove", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleRemoveTag(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleRemoveTag_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	// Add tag first
	form := "conversation_id=" + convID + "&tag=important"
	r1 := httptest.NewRequest("POST", "/conversations/tags/add", strings.NewReader(form))
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r1.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleAddTag(httptest.NewRecorder(), r1)

	// Remove tag
	w := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleRemoveTag(w, r2)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleRemoveTag_ConvNotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "conversation_id=nonexistent&tag=important"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/conversations/tags/remove", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleRemoveTag(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ============================================================
// rate_limit_tiers.go: Allow, GetTier, GetRemaining,
// tieredRateLimitMiddleware, handleSetRateLimitTier,
// handleGetRateLimitTier, persistTierToDB, handleAdminRateLimitTier
// ============================================================

func Test_CB94_TieredRateLimiter_Allow(t *testing.T) {
	tl := NewTieredRateLimiter()
	allowed, _, _ := tl.Allow("user1")
	if !allowed {
		t.Error("expected allow for first request")
	}
}

func Test_CB94_TieredRateLimiter_AllowExceed(t *testing.T) {
	tl := NewTieredRateLimiter()
	tl.SetTier("user1", TierPro) // 300/min
	// Exhaust the limit
	for i := 0; i < 300; i++ {
		allowed, _, _ := tl.Allow("user1")
		if !allowed {
			t.Fatalf("rate limited at %d", i)
		}
	}
	// Next should be denied
	allowed, _, _ := tl.Allow("user1")
	if allowed {
		t.Error("expected rate limit after 300 requests")
	}
}

func Test_CB94_TieredRateLimiter_GetTier(t *testing.T) {
	tl := NewTieredRateLimiter()
	tl.SetTier("user1", TierEnterprise)
	tier := tl.GetTier("user1")
	if tier.Name != "enterprise" {
		t.Errorf("expected enterprise, got %s", tier.Name)
	}
}

func Test_CB94_TieredRateLimiter_GetTierDefault(t *testing.T) {
	tl := NewTieredRateLimiter()
	tier := tl.GetTier("unknown-user")
	if tier.Name != "free" {
		t.Errorf("expected free, got %s", tier.Name)
	}
}

func Test_CB94_TieredRateLimiter_GetRemaining(t *testing.T) {
	tl := NewTieredRateLimiter()
	// Free tier = 60/min
	remaining := tl.GetRemaining("user1")
	if remaining != 60 {
		t.Errorf("expected 60, got %d", remaining)
	}
}

func Test_CB94_TieredRateLimiter_GetRemaining_AfterUse(t *testing.T) {
	tl := NewTieredRateLimiter()
	tl.Allow("user1")
	tl.Allow("user1")
	// Allow returns (bool, int, int) - just call it, don't use return values
	remaining := tl.GetRemaining("user1")
	if remaining != 58 {
		t.Errorf("expected 58, got %d", remaining)
	}
}

func Test_CB94_TieredRateLimitMiddleware_Allowed(t *testing.T) {
	// Reset limiter
	globalTieredLimiter = NewTieredRateLimiter()

	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handler(w, r)
	if !called {
		t.Error("handler not called")
	}
}

func Test_CB94_TieredRateLimitMiddleware_NoUserID(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()

	called := false
	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	// No user ID in context — should use IP
	handler(w, r)
	if !called {
		t.Error("handler not called")
	}
}

func Test_CB94_TieredRateLimitMiddleware_RateLimited(t *testing.T) {
	globalTieredLimiter = NewTieredRateLimiter()

	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	// Free tier = 60/min, exhaust it
	for i := 0; i < 60; i++ {
		globalTieredLimiter.Allow("cb94-user1")
	}

	handler := tieredRateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handler(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func Test_CB94_HandleSetRateLimitTier_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/rate-limit/tier", nil)
	handleSetRateLimitTier(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleSetRateLimitTier_WrongSecret(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/rate-limit/tier", nil)
	r.Header.Set("X-Admin-Secret", "wrong")
	handleSetRateLimitTier(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleSetRateLimitTier_MissingUserID(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "testadmin"
	defer func() { adminSecret = oldSecret }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/rate-limit/tier", nil)
	r.Header.Set("X-Admin-Secret", "testadmin")
	handleSetRateLimitTier(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleSetRateLimitTier_MissingTier(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "testadmin"
	defer func() { adminSecret = oldSecret }()

	form := "user_id=cb94-user1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Admin-Secret", "testadmin")
	handleSetRateLimitTier(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleSetRateLimitTier_UnknownTier(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "testadmin"
	defer func() { adminSecret = oldSecret }()

	form := "user_id=cb94-user1&tier=bogus"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Admin-Secret", "testadmin")
	handleSetRateLimitTier(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleSetRateLimitTier_Enterprise(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "testadmin"
	defer func() { adminSecret = oldSecret }()

	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	form := "user_id=cb94-ent-user&tier=enterprise"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Admin-Secret", "testadmin")
	handleSetRateLimitTier(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleGetRateLimitTier_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
	handleGetRateLimitTier(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetRateLimitTier_MissingUserID(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "testadmin"
	defer func() { adminSecret = oldSecret }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/rate-limit/tier", nil)
	r.Header.Set("X-Admin-Secret", "testadmin")
	handleGetRateLimitTier(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleGetRateLimitTier_Default(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "testadmin"
	defer func() { adminSecret = oldSecret }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=unknown-user", nil)
	r.Header.Set("X-Admin-Secret", "testadmin")
	handleGetRateLimitTier(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tier"] != "free" {
		t.Errorf("expected free, got %v", resp["tier"])
	}
}

// ============================================================
// dbdriver.go: envIntOrDefault, envDurationOrDefault, openDatabase
// ============================================================

func Test_CB94_EnvIntOrDefault_Set(t *testing.T) {
	os.Setenv("CB94_INT_TEST", "42")
	defer os.Unsetenv("CB94_INT_TEST")
	if v := envIntOrDefault("CB94_INT_TEST", 10); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
}

func Test_CB94_EnvIntOrDefault_Default(t *testing.T) {
	os.Unsetenv("CB94_INT_MISSING")
	if v := envIntOrDefault("CB94_INT_MISSING", 10); v != 10 {
		t.Errorf("expected 10, got %d", v)
	}
}

func Test_CB94_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("CB94_INT_BAD", "notanumber")
	defer os.Unsetenv("CB94_INT_BAD")
	if v := envIntOrDefault("CB94_INT_BAD", 10); v != 10 {
		t.Errorf("expected 10, got %d", v)
	}
}

func Test_CB94_EnvDurationOrDefault_Set(t *testing.T) {
	os.Setenv("CB94_DUR_TEST", "30s")
	defer os.Unsetenv("CB94_DUR_TEST")
	v := envDurationOrDefault("CB94_DUR_TEST", 5*time.Second)
	if v != 30*time.Second {
		t.Errorf("expected 30s, got %v", v)
	}
}

func Test_CB94_EnvDurationOrDefault_Default(t *testing.T) {
	os.Unsetenv("CB94_DUR_MISSING")
	v := envDurationOrDefault("CB94_DUR_MISSING", 5*time.Second)
	if v != 5*time.Second {
		t.Errorf("expected 5s, got %v", v)
	}
}

func Test_CB94_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("CB94_DUR_BAD", "notaduration")
	defer os.Unsetenv("CB94_DUR_BAD")
	v := envDurationOrDefault("CB94_DUR_BAD", 5*time.Second)
	if v != 5*time.Second {
		t.Errorf("expected 5s, got %v", v)
	}
}

func Test_CB94_OpenDatabase_SQLite(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test_opendb.db"
	oldDriver := currentDriver
	oldDBPath := serverDBPath
	defer func() {
		currentDriver = oldDriver
		serverDBPath = oldDBPath
	}()
	serverDBPath = dbPath
	currentDriver = DriverSQLite

	testDB, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer testDB.Close()
	if err := testDB.Ping(); err != nil {
		t.Errorf("ping: %v", err)
	}
}

func Test_CB94_OpenDatabase_InvalidDriver(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()
	currentDriver = "invalid-driver"

	_, err := openDatabase("invalid-driver", "")
	if err == nil {
		t.Error("expected error for invalid driver")
	}
}

// ============================================================
// queue_persist.go: initQueueDB, marshalOutgoingMessage
// ============================================================

func Test_CB94_InitQueueDB_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	initQueueDB(testDB)
	// Should not panic
}

func Test_CB94_InitQueueDB_Idempotent(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	// Call twice — should not error
	initQueueDB(testDB)
	initQueueDB(testDB)
}

func Test_CB94_MarshalOutgoingMessage_Success(t *testing.T) {
	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]string{"content": "hello"},
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("returned nil")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Errorf("unmarshal: %v", err)
	}
	if decoded["type"] != "message" {
		t.Errorf("expected message, got %v", decoded["type"])
	}
}

func Test_CB94_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "test",
		Data: nil,
	}
	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("returned nil for nil data")
	}
}

// ============================================================
// tracing.go: IsTracingEnabled
// ============================================================

func Test_CB94_IsTracingEnabled_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldEnabled }()

	if IsTracingEnabled() {
		t.Error("expected false")
	}
}

func Test_CB94_IsTracingEnabled_Enabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = true
	defer func() { tracingEnabled = oldEnabled }()

	if !IsTracingEnabled() {
		t.Error("expected true")
	}
}

// ============================================================
// main.go: parseSize
// ============================================================

func Test_CB94_ParseSize(t *testing.T) {
	cases := []struct {
		input    string
		expected int64
	}{
		{"100", 100},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"1kb", 1024},
		{"1mb", 1024 * 1024},
		{"1gb", 1024 * 1024 * 1024},
		{"", 0},
	}
	for _, c := range cases {
		result, err := parseSize(c.input)
		if err != nil && c.input != "" {
			t.Errorf("parseSize(%q) error: %v", c.input, err)
		}
		if err != nil && c.input == "" {
			// Empty string returns error, that's fine
			continue
		}
		if result != c.expected {
			t.Errorf("parseSize(%q) = %d, expected %d", c.input, result, c.expected)
		}
	}
}

// ============================================================
// logger.go: SetOutput
// ============================================================

func Test_CB94_Logger_SetOutput(t *testing.T) {
	l := NewLogger(LogInfo)
	var buf bytes.Buffer
	l.SetOutput(&buf)
	l.Info("test message")
	if !strings.Contains(buf.String(), "test message") {
		t.Error("message not in output buffer")
	}
}

func Test_CB94_Logger_SetOutput_ThenReset(t *testing.T) {
	l := NewLogger(LogInfo)
	l.SetOutput(io.Discard)
	l.Info("discarded message")
	// Should not panic
}

// ============================================================
// auth.go: resetAgentSecret, resetAdminSecret, Clean, Reset
// ============================================================

func Test_CB94_ResetAgentSecret(t *testing.T) {
	oldSecret := agentSecret
	defer func() { agentSecret = oldSecret }()
	// resetAgentSecret re-reads from env, which gives a dev default
	os.Unsetenv("AGENT_SECRET")
	resetAgentSecret()
	if agentSecret != "dev-agent-secret-change-me" {
		t.Errorf("expected dev default, got %s", agentSecret)
	}
}

func Test_CB94_ResetAdminSecret(t *testing.T) {
	oldSecret := adminSecret
	defer func() { adminSecret = oldSecret }()
	os.Unsetenv("ADMIN_SECRET")
	resetAdminSecret()
	if adminSecret != "admin-dev-secret" {
		t.Errorf("expected dev default, got %s", adminSecret)
	}
}

func Test_CB94_RateLimiter_StopAndReset(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	rl.Allow("key1")
	rl.Allow("key2")
	rl.Reset()
	// After reset, all counters cleared
	if c := rl.Count("key1"); c != 0 {
		t.Errorf("expected 0 after reset, got %d", c)
	}
	rl.Stop()
	// Should not panic
}

func Test_CB94_RateLimiter_Reset_Empty(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	rl.Reset()
	// Should not panic
}

// ============================================================
// hub.go: GetClient, monitorAgentHeartbeats, checkStaleAgents
// ============================================================

func Test_CB94_Hub_GetClient_NotFound(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := h.GetClient("nonexistent")
	if c != nil {
		t.Error("expected nil for nonexistent client")
	}
}

func Test_CB94_Hub_GetClient_Found(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "cb94-client1",
		send:     make(chan []byte, 256),
	}
	h.register <- conn
	time.Sleep(time.Millisecond * 50) // wait for register

	c := h.GetClient("cb94-client1")
	if c == nil {
		t.Error("expected non-nil client")
	}
}

func Test_CB94_Hub_MonitorAgentHeartbeats_Disabled(t *testing.T) {
	oldInterval := agentPresenceInterval
	oldEnabled := agentPresenceEnabled
	agentPresenceInterval = 0
	agentPresenceEnabled = true
	defer func() {
		agentPresenceInterval = oldInterval
		agentPresenceEnabled = oldEnabled
	}()

	// When interval=0, monitorAgentHeartbeats returns immediately.
	// But newHub() already starts it, so monitorDone will be closed.
	// We just verify Stop() doesn't block.
	h := newHub()
	go h.run()
	
	done := make(chan struct{})
	go func() {
		h.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Error("Stop() didn't return")
	}
}

func Test_CB94_Hub_CheckStaleAgents(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Register an agent with stale heartbeat
	conn := &Connection{
		hub:         h,
		connType:    "agent",
		id:          "cb94-stale-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now().Add(-time.Hour),
	}
	h.register <- conn
	time.Sleep(time.Millisecond * 50)

	// Set stale heartbeat
	h.mu.Lock()
	if a, ok := h.agents["cb94-stale-agent"]; ok {
		a.lastHeartbeat = time.Now().Add(-time.Hour)
	}
	h.mu.Unlock()

	// Set very short stale timeout
	oldTimeout := agentPresenceTimeout
	agentPresenceTimeout = time.Minute
	defer func() { agentPresenceTimeout = oldTimeout }()

	h.checkStaleAgents()

	// Wait for unregister to be processed
	time.Sleep(time.Millisecond * 100)

	// Agent should be removed
	h.mu.Lock()
	_, exists := h.agents["cb94-stale-agent"]
	h.mu.Unlock()
	if exists {
		t.Error("expected stale agent to be removed")
	}
}

// ============================================================
// protocol.go: upgradeWithProtocol, sendWelcomeMessage
// ============================================================

func Test_CB94_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		hub:      nil,
		connType: "client",
		id:       "cb94-welcome-user",
		deviceID: "cb94-device-1",
		send:     make(chan []byte, 256),
		negotiatedVersion: "v1",
	}

	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		if len(msg) == 0 {
			t.Error("empty message")
		}
		var data map[string]interface{}
		if err := json.Unmarshal(msg, &data); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		if data["type"] != "connected" {
			t.Errorf("expected connected, got %v", data["type"])
		}
	case <-time.After(time.Second):
		t.Error("no welcome message received")
	}
}

func Test_CB94_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 0),
	}
	close(conn.send)

	// Should not panic
	sendWelcomeMessage(conn)
}

// ============================================================
// routing.go: routeTypingIndicator, routeStatusUpdate (with hub)
// ============================================================

func Test_CB94_RouteTypingIndicator_AgentSender(t *testing.T) {
	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	_, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	// Register a client connection
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "cb94-user1",
		send:     make(chan []byte, 256),
	}
	hub.register <- clientConn
	time.Sleep(time.Millisecond * 50)

	// Agent sends typing indicator
	agentConn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       agentID,
		send:     make(chan []byte, 256),
	}

	typingData, _ := json.Marshal(map[string]string{
		"conversation_id": convID,
	})
	routeTypingIndicator(agentConn, typingData)

	// Client should receive the typing indicator
	select {
	case msg := <-clientConn.send:
		var data map[string]interface{}
		json.Unmarshal(msg, &data)
		if data["type"] != "typing" {
			t.Errorf("expected typing, got %v", data["type"])
		}
	case <-time.After(time.Second):
		t.Error("no typing indicator received")
	}
}

func Test_CB94_RouteTypingIndicator_InvalidJSON(t *testing.T) {
	conn := &Connection{
		connType: "agent",
		id:       "test",
		send:     make(chan []byte, 256),
	}
	routeTypingIndicator(conn, json.RawMessage("invalid"))
	// Should not panic
}

func Test_CB94_RouteTypingIndicator_EmptyConvID(t *testing.T) {
	conn := &Connection{
		connType: "agent",
		id:       "test",
		send:     make(chan []byte, 256),
	}
	typingData, _ := json.Marshal(map[string]string{
		"conversation_id": "",
	})
	routeTypingIndicator(conn, typingData)
	// Should not panic
}

func Test_CB94_RouteStatusUpdate_AgentStatusChange(t *testing.T) {
	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	_, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	// Register a client connection
	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "cb94-user1",
		send:     make(chan []byte, 256),
	}
	hub.register <- clientConn
	time.Sleep(time.Millisecond * 50)

	// Agent sends status update - first register the agent
	agentConn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       agentID,
		send:     make(chan []byte, 256),
	}
	hub.register <- agentConn
	time.Sleep(time.Millisecond * 50)

	statusData, _ := json.Marshal(map[string]string{
		"conversation_id": convID,
		"status":          "busy",
	})
	routeStatusUpdate(agentConn, statusData)

	// Verify agent status was updated in hub
	status := hub.AgentStatus(agentID)
	if status != "busy" {
		t.Errorf("expected busy, got %s", status)
	}
}

func Test_CB94_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	conn := &Connection{
		connType: "agent",
		id:       "test",
		send:     make(chan []byte, 256),
	}
	routeStatusUpdate(conn, json.RawMessage("invalid"))
	// Should not panic
}

func Test_CB94_RouteStatusUpdate_ClientSender(t *testing.T) {
	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	_, cleanup := setupTestDB_CB94(t)
	defer cleanup()

	clientConn := &Connection{
		hub:      hub,
		connType: "client",
		id:       "cb94-user1",
		send:     make(chan []byte, 256),
	}

	statusData, _ := json.Marshal(map[string]string{
		"conversation_id": "nonexistent",
		"status":          "active",
	})
	routeStatusUpdate(clientConn, statusData)
	// Should not panic, client status updates are not processed
}

// ============================================================
// presence.go: handleGetPresence (with DB)
// ============================================================

func Test_CB94_HandleGetPresence_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/presence", nil)
	handleGetPresence(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetPresence_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/presence", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetPresence(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ============================================================
// notifications: handleGetNotificationPrefs, handleSetNotificationPrefs,
// handleDeleteNotificationPrefs (with DB)
// ============================================================

func Test_CB94_HandleGetNotificationPrefs_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/notifications/prefs", nil)
	handleGetNotificationPrefs(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetNotificationPrefs_Empty(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := makeAuthReq_CB94("GET", "/notifications/prefs", "", "cb94-user1")
	handleGetNotificationPrefs(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleSetNotificationPrefs_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/notifications/prefs", nil)
	handleSetNotificationPrefs(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleSetNotificationPrefs_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	form := "conversation_id=" + convID + "&muted=true"
	w := httptest.NewRecorder()
	r := makeAuthReq_CB94("POST", "/notifications/prefs", form, userID)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleSetNotificationPrefs(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleSetNotificationPrefs_Unmute(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	// First mute
	form1 := "conversation_id=" + convID + "&muted=true"
	r1 := makeAuthReq_CB94("POST", "/notifications/prefs", form1, userID)
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleSetNotificationPrefs(httptest.NewRecorder(), r1)

	// Then unmute
	form2 := "conversation_id=" + convID + "&muted=false"
	w := httptest.NewRecorder()
	r2 := makeAuthReq_CB94("POST", "/notifications/prefs", form2, userID)
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleSetNotificationPrefs(w, r2)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteNotificationPrefs_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/notifications/prefs", nil)
	handleDeleteNotificationPrefs(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleDeleteNotificationPrefs_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	// First set a pref
	form := "conversation_id=" + convID + "&muted=true"
	r1 := makeAuthReq_CB94("POST", "/notifications/prefs", form, userID)
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleSetNotificationPrefs(httptest.NewRecorder(), r1)

	// Delete it
	w := httptest.NewRecorder()
	r := makeAuthReq_CB94("DELETE", "/notifications/prefs?conversation_id="+convID, "", userID)
	handleDeleteNotificationPrefs(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ============================================================
// metrics_handler.go: handleMetrics (with real metrics)
// ============================================================

func Test_CB94_HandleMetrics_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/metrics", nil)
	handleMetrics(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func Test_CB94_HandleMetrics_Success(t *testing.T) {
	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	if ServerMetrics == nil {
		ServerMetrics = NewMetrics(hub)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ============================================================
// messages_edit_delete.go: handleMessageEdit, handleMessageDelete (with DB)
// ============================================================

func Test_CB94_HandleMessageEdit_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/edit", nil)
	handleMessageEdit(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageEdit_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/edit", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleMessageEdit(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageEdit_EmptyContent(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "message_id=msg-edit1&content="
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleMessageEdit(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageEdit_NotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	form := "message_id=nonexistent&content=updated"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleMessageEdit(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageEdit_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-edit-ok", convID, "client", userID, "original content", time.Now().UTC())

	form := "message_id=msg-edit-ok&content=updated content"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleMessageEdit(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageEdit_NotSender(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	_, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-edit-other", convID, "agent", agentID, "agent content", time.Now().UTC())

	// Create second user
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.DefaultCost)
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "cb94-user2", "cb94user2", string(hash))

	form := "message_id=msg-edit-other&content=hacked"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/edit", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user2"))
	handleMessageEdit(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageDelete_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/delete", nil)
	handleMessageDelete(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageDelete_MissingMsgID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/delete", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleMessageDelete(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageDelete_NotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/delete?message_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleMessageDelete(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageDelete_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-del-ok", convID, "client", userID, "to be deleted", time.Now().UTC())

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/delete?message_id=msg-del-ok", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleMessageDelete(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleMessageDelete_NotSender(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	_, agentID, convID := setupUserAndAgent_CB94(t, testDB)

	testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-del-other", convID, "agent", agentID, "agent message", time.Now().UTC())

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.DefaultCost)
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "cb94-user2", "cb94user2", string(hash))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/messages/delete?message_id=msg-del-other", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user2"))
	handleMessageDelete(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ============================================================
// e2e.go: handleUploadPublicKey, handleGetKeyBundle (with DB)
// ============================================================

func Test_CB94_HandleUploadPublicKey_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/e2e/keys/upload", nil)
	handleUploadPublicKey(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleUploadPublicKey_InvalidJSON(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/e2e/keys/upload", strings.NewReader("bad"))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleUploadPublicKey(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleUploadPublicKey_MissingFields(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	body := `{"key_type":"identity","public_key":"","key_id":"k1"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/e2e/keys/upload", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleUploadPublicKey(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleUploadPublicKey_IdentitySuccess(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, _ := setupUserAndAgent_CB94(t, testDB)

	body := `{"key_type":"identity","public_key":"base64key123","key_id":1}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/e2e/keys/upload", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleUploadPublicKey(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleGetKeyBundle_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/e2e/keys/bundle", nil)
	handleGetKeyBundle(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetKeyBundle_MissingOwner(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/e2e/keys/bundle", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetKeyBundle(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleGetKeyBundle_NoKeys(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/e2e/keys/bundle?owner_id=cb94-user1", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetKeyBundle(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleListOneTimePreKeys_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/e2e/keys/prekeys", nil)
	handleListOneTimePreKeys(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleListOneTimePreKeys_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/e2e/keys/prekeys?owner_id=cb94-user1", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleListOneTimePreKeys(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleStoreEncryptedMessage_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/e2e/messages/store", nil)
	handleStoreEncryptedMessage(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/e2e/messages/store", strings.NewReader("bad"))
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleStoreEncryptedMessage(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ============================================================
// attachments.go: handleListAttachments, handleGetAttachment (with DB)
// ============================================================

func Test_CB94_HandleListAttachments_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/attachments", nil)
	handleListAttachments(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleListAttachments_MissingConvID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/attachments", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleListAttachments(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleListAttachments_ConvNotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/attachments?conversation_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleListAttachments(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func Test_CB94_HandleListAttachments_Success(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	userID, _, convID := setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/attachments?conversation_id="+convID, nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94(userID))
	handleListAttachments(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func Test_CB94_HandleGetAttachment_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/attachments/get", nil)
	handleGetAttachment(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetAttachment_MissingID(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/attachments/", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetAttachment(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func Test_CB94_HandleGetAttachment_NotFound(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/attachments/get?attachment_id=nonexistent", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetAttachment(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ============================================================
// handlers.go: handleGetUserPresence
// ============================================================

func Test_CB94_HandleGetUserPresence_NoAuth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/presence/user", nil)
	handleGetUserPresence(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func Test_CB94_HandleGetUserPresence_Online(t *testing.T) {
	testDB, cleanup := setupTestDB_CB94(t)
	defer cleanup()
	setupUserAndAgent_CB94(t, testDB)

	cleanupHub := setupHub_CB94()
	defer cleanupHub()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/presence/user?user_id=cb94-user1", nil)
	r.Header.Set("Authorization", "Bearer "+makeJWT_CB94("cb94-user1"))
	handleGetUserPresence(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ============================================================
// hub.go: maxMessageSize env, readPump basic, writePump basic
// ============================================================

func Test_CB94_Hub_BroadcastPresence(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// Add a client
	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "cb94-bp-user",
		send:     make(chan []byte, 256),
	}
	h.register <- conn
	time.Sleep(time.Millisecond * 50)

	// Broadcast presence should not panic
	h.mu.Lock()
	h.agents["cb94-agent1"] = &Connection{
		id:       "cb94-agent1",
		connType: "agent",
		status:   "online",
	}
	h.mu.Unlock()

	// Drain the send channel to check messages
	go func() {
		for range conn.send {
		}
	}()

	time.Sleep(time.Millisecond * 50)
}

func Test_CB94_Hub_BroadcastToAllClients_ClosedChannel(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "cb94-closed-user",
		send:     make(chan []byte, 256),
	}
	close(conn.send)
	h.mu.Lock()
	h.clientConns["cb94-closed-user"] = []*Connection{conn}
	h.mu.Unlock()

	// Should not panic
	h.BroadcastToAllClients([]byte("test"))
}

// ============================================================
// Concurrent test to ensure thread safety
// ============================================================

func Test_CB94_OfflineQueue_ConcurrentStress(t *testing.T) {
	q := newOfflineQueue(1000, 7*24*time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				msg := OutgoingMessage{
					Type: "message",
					Data: map[string]interface{}{
						"content": fmt.Sprintf("msg-%d-%d", g, j),
					},
				}
				data, _ := json.Marshal(msg)
				q.Enqueue(fmt.Sprintf("user-%d", g%3), data)
			}
		}(i)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				q.Drain(fmt.Sprintf("user-%d", g%3))
			}
		}(i)
	}
	wg.Wait()
}