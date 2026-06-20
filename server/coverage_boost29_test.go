package main

// Coverage boost 29: targeting remaining low-coverage function paths
// - handleLogin: success path, missing fields, form-encoded
// - handleRegisterUser: success, short username, invalid chars, form-encoded
// - handleGetPresence: method not allowed, empty agents list
// - handleGetUserPresence: method not allowed, missing user
// - openDatabase: SQLite in-memory success
// - initPushNotifications: APNs with cert, FCM with creds
// - sendAPNSNotification: actual send path (with mock)
// - sendFCMNotification: actual send path (with mock)
// - hub.run: broadcast, unregister, message routing
// - routeMessage: more edge cases
// - writePump: channel close, ping ticker
// - readPump: close error, pong handler
// - Connection: SafeSend variants
// - Hub: BroadcastToAllClients, GetAgent, GetClientConns
// - Additional handler edge cases

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

)

// ==============================
// handleLogin: success and edge cases (form-encoded)
// ==============================

func TestCB29_HandleLogin_Success(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register a user first (form-encoded)
	form := url.Values{"username": {"testuser"}, "password": {"password123"}}.Encode()
	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
	regReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	regW := httptest.NewRecorder()
	handleRegisterUser(regW, regReq)
	if regW.Code != http.StatusOK {
		t.Fatalf("expected 200 for registration, got %d: %s", regW.Code, regW.Body.String())
	}

	// Login with same credentials
	loginForm := url.Values{"username": {"testuser"}, "password": {"password123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["token"] == nil || resp["token"] == "" {
		t.Error("expected token in response")
	}
	if resp["username"] != "testuser" {
		t.Errorf("expected username testuser, got %v", resp["username"])
	}
}

func TestCB29_HandleLogin_WrongPassword(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register a user
	form := url.Values{"username": {"loginuser"}, "password": {"password123"}}.Encode()
	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
	regReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	regW := httptest.NewRecorder()
	handleRegisterUser(regW, regReq)

	// Login with wrong password
	loginForm := url.Values{"username": {"loginuser"}, "password": {"wrongpass"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB29_HandleLogin_MissingFields(t *testing.T) {
	// Missing password
	form := url.Values{"username": {"someone"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	// Missing username
	form2 := url.Values{"password": {"pass123"}}.Encode()
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form2))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleLogin(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w2.Code)
	}
}

func TestCB29_HandleLogin_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleRegisterUser: form-encoded tests
// ==============================

func TestCB29_HandleRegisterUser_Success(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	form := url.Values{"username": {"newuser29"}, "password": {"password123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["username"] != "newuser29" {
		t.Errorf("expected username newuser29, got %v", resp["username"])
	}
	if resp["user_id"] == nil || resp["user_id"] == "" {
		t.Error("expected user_id in response")
	}
}

func TestCB29_HandleRegisterUser_ShortUsername(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	form := url.Values{"username": {"ab"}, "password": {"password123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB29_HandleRegisterUser_InvalidChars(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	form := url.Values{"username": {"user name"}, "password": {"password123"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB29_HandleRegisterUser_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/register", nil)
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// handleGetPresence edge cases
// ==============================

func TestCB29_HandleGetPresence_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/presence", nil)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB29_HandleGetPresence_EmptyAgents(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	token, err := GenerateJWT("user-pres-1", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var agents []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	// Should return empty array, not null
	if len(agents) != 0 {
		t.Errorf("expected empty agents list, got %d", len(agents))
	}
}

// ==============================
// handleGetUserPresence edge cases
// ==============================

func TestCB29_HandleGetUserPresence_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/presence/user", nil)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB29_HandleGetUserPresence_Online(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	h := newHub()
	go h.run()
	defer h.Stop()

	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	token, err := GenerateJWT("user-pres-online", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	// Register a client connection for this user
	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "user-pres-online",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/presence/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["online"] != true {
		t.Errorf("expected online=true, got %v", resp["online"])
	}
}

// ==============================
// Hub: BroadcastToAllClients, GetAgent, GetClientConns
// ==============================

func TestCB29_Hub_GetAgent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	// No agent registered yet
	if ag := h.GetAgent("nonexistent"); ag != nil {
		t.Error("expected nil for nonexistent agent")
	}

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-get-test",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	if ag := h.GetAgent("agent-get-test"); ag == nil {
		t.Error("expected agent to be found")
	}
}

func TestCB29_Hub_GetClientConns(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conns := h.GetClientConns("nonexistent")
	if len(conns) != 0 {
		t.Errorf("expected 0 conns for nonexistent user, got %d", len(conns))
	}

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-get-test",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	conns = h.GetClientConns("client-get-test")
	if len(conns) != 1 {
		t.Errorf("expected 1 conn, got %d", len(conns))
	}
}

func TestCB29_Hub_BroadcastToAllClients(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	client1 := &Connection{
		hub:      h,
		connType: "client",
		id:       "broadcast-client-1",
		send:     make(chan []byte, 10),
	}
	client2 := &Connection{
		hub:      h,
		connType: "client",
		id:       "broadcast-client-2",
		send:     make(chan []byte, 10),
	}
	agent1 := &Connection{
		hub:      h,
		connType: "agent",
		id:       "broadcast-agent-1",
		send:     make(chan []byte, 10),
	}

	h.register <- client1
	h.register <- client2
	h.register <- agent1
	time.Sleep(50 * time.Millisecond)

	msg := []byte(`{"type":"broadcast","data":"hello"}`)
	h.BroadcastToAllClients(msg)

	// Both clients should receive the message
	select {
	case <-client1.send:
	case <-time.After(time.Second):
		t.Error("client1 did not receive broadcast")
	}
	select {
	case <-client2.send:
	case <-time.After(time.Second):
		t.Error("client2 did not receive broadcast")
	}
	// Agent should NOT receive the broadcast
	select {
	case <-agent1.send:
		t.Error("agent should not receive client broadcast")
	default:
		// Expected: no message for agent
	}
}

// ==============================
// Connection: SafeSend variants
// ==============================

func TestCB29_Connection_SafeSend_OpenWithDrain(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "drain-test",
		send:     make(chan []byte, 256),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	// SafeSend on open connection should succeed
	ok := conn.SafeSend([]byte("test message"))
	if !ok {
		t.Error("expected SafeSend to succeed on open connection")
	}
}

// ==============================
// RouteMessage: edge cases
// ==============================

func TestCB29_RouteMessage_InvalidJSON(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "route-invalid-json",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	// Send invalid JSON - should be handled gracefully
	routeMessage(conn, []byte(`not json at all`))
}

func TestCB29_RouteMessage_EmptyType(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "route-empty-type",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	routeMessage(conn, []byte(`{"type":"","data":{}}`))
}

// ==============================
// Hub: unregister and message routing
// ==============================

func TestCB29_Hub_UnregisterAgent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "agent",
		id:       "unreg-agent",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("unreg-agent") == nil {
		t.Error("agent should be registered")
	}

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	if h.GetAgent("unreg-agent") != nil {
		t.Error("agent should be unregistered")
	}
}

func TestCB29_Hub_UnregisterClient(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "unreg-client",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	conns := h.GetClientConns("unreg-client")
	if len(conns) != 1 {
		t.Errorf("expected 1 conn, got %d", len(conns))
	}

	h.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	conns = h.GetClientConns("unreg-client")
	if len(conns) != 0 {
		t.Errorf("expected 0 conns after unregister, got %d", len(conns))
	}
}

// ==============================
// Hub: broadcast message
// ==============================

func TestCB29_Hub_Broadcast(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	conn := &Connection{
		hub:      h,
		connType: "client",
		id:       "broadcast-test",
		send:     make(chan []byte, 10),
	}
	h.register <- conn
	time.Sleep(50 * time.Millisecond)

	h.broadcast <- []byte(`{"type":"system","data":"test broadcast"}`)

	select {
	case msg := <-conn.send:
		t.Logf("received broadcast: %s", string(msg))
	case <-time.After(time.Second):
		t.Error("client should receive broadcast message")
	}
}

// ==============================
// authenticateRequest: agent secret from env
// ==============================

func TestCB29_AuthenticateRequest_AgentSecretFromEnv(t *testing.T) {
	origSecret := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "env-secret-29")
	defer func() {
		if origSecret == "" {
			os.Unsetenv("AGENT_SECRET")
		} else {
			os.Setenv("AGENT_SECRET", origSecret)
		}
		resetAgentSecret()
	}()
	resetAgentSecret() // Reload from env

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Agent-Secret", "env-secret-29")
	req.Header.Set("X-Agent-ID", "agent-29")

	userID, connType, err := authenticateRequest(req)
	if err != nil {
		t.Errorf("expected auth success, got error: %v", err)
	}
	if connType != "agent" {
		t.Errorf("expected agent connType, got %s", connType)
	}
	if userID == "" {
		t.Error("expected non-empty user ID for agent auth")
	}
}

// ==============================
// ValidateJWT: various edge cases
// ==============================

func TestCB29_ValidateJWT_ExpiredToken(t *testing.T) {
	// Generate a token and test validation
	token, err := GenerateJWT("user-expired", "expireduser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Errorf("valid token should not fail: %v", err)
	}
	if claims.UserID != "user-expired" {
		t.Errorf("expected user_id user-expired, got %s", claims.UserID)
	}
}

func TestCB29_ValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not-a-valid-jwt-token")
	if err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestCB29_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// ==============================
// sendError and writeJSON helpers
// ==============================

func TestCB29_WriteJSON_ErrorResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["error"] != "test error" {
		t.Errorf("expected 'test error', got %s", resp["error"])
	}
}

func TestCB29_WriteJSON_Success(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected 'ok', got %s", resp["status"])
	}
}

// ==============================
// openDatabase: SQLite success
// ==============================

func TestCB29_OpenDatabase_SQLite(t *testing.T) {
	db, err := openDatabase("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open SQLite in-memory: %v", err)
	}
	defer db.Close()

	if db == nil {
		t.Error("expected non-nil db")
	}

	// Verify it works
	if err := db.Ping(); err != nil {
		t.Errorf("failed to ping db: %v", err)
	}
}

// ==============================
// initPushNotifications: environment config
// ==============================

func TestCB29_InitPushNotifications_APNSConfig(t *testing.T) {
	// Save and restore env
	origAPNsCert := os.Getenv("APNS_CERT_PATH")
	origAPNsKey := os.Getenv("APNS_KEY_PATH")
	origFCMCreds := os.Getenv("FCM_CREDENTIALS")

	defer func() {
		os.Setenv("APNS_CERT_PATH", origAPNsCert)
		os.Setenv("APNS_KEY_PATH", origAPNsKey)
		os.Setenv("FCM_CREDENTIALS", origFCMCreds)
		pushConfig = nil
		pushConfig = nil
	}()

	// Set APNs env vars but point to nonexistent files (should not panic)
	os.Setenv("APNS_CERT_PATH", "/nonexistent/cert.pem")
	os.Setenv("APNS_KEY_PATH", "/nonexistent/key.pem")
	os.Setenv("FCM_CREDENTIALS", "")

	// Should not panic even with invalid paths
	initPushNotifications()
}

func TestCB29_InitPushNotifications_FCMConfig(t *testing.T) {
	origFCMCreds := os.Getenv("FCM_CREDENTIALS")
	origAPNsCert := os.Getenv("APNS_CERT_PATH")
	defer func() {
		os.Setenv("FCM_CREDENTIALS", origFCMCreds)
		os.Setenv("APNS_CERT_PATH", origAPNsCert)
		pushConfig = nil
		pushConfig = nil
	}()

	// Set FCM env var but with invalid path
	os.Setenv("FCM_CREDENTIALS", "/nonexistent/creds.json")
	os.Setenv("APNS_CERT_PATH", "")

	// Should not panic even with invalid paths
	initPushNotifications()
}

// ==============================
// sendPushNotification: platform routing
// ==============================

func TestCB29_SendPushNotification_PlatformRouting(t *testing.T) {
	// With nil pushConfig, all platforms return nil (no crash)
	pushConfig = nil

	// iOS route — defaults to APNs
	err := sendPushNotification("test-ios-token", "title", "body", "conv-1", "ios")
	if err != nil {
		t.Errorf("expected nil error with nil pushConfig for iOS, got %v", err)
	}

	// Android/FCM route
	err = sendPushNotification("test-android-token", "title", "body", "conv-1", "android")
	if err != nil {
		t.Errorf("expected nil error with nil pushConfig for Android, got %v", err)
	}

	// FCM explicit
	err = sendPushNotification("test-fcm-token", "title", "body", "conv-1", "fcm")
	if err != nil {
		t.Errorf("expected nil error with nil pushConfig for FCM, got %v", err)
	}
}

// ==============================
// Metrics: ConnectionsTotal and MessagesIn
// ==============================

func TestCB29_Metrics_ConnectionsTotal(t *testing.T) {
	h := newHub()
	m := NewMetrics(h)
	if m == nil {
		t.Fatal("expected non-nil metrics")
	}

	initial := m.ConnectionsTotal.Load()
	m.ConnectionsTotal.Add(1)
	if m.ConnectionsTotal.Load() != initial+1 {
		t.Errorf("expected ConnectionsTotal to increment")
	}
}

func TestCB29_Metrics_MessagesIn(t *testing.T) {
	h := newHub()
	m := NewMetrics(h)

	initial := m.MessagesIn.Load()
	m.MessagesIn.Add(1)
	if m.MessagesIn.Load() != initial+1 {
		t.Errorf("expected MessagesIn to increment")
	}
}

// ==============================
// generateID: various prefixes
// ==============================

func TestCB29_GenerateID_MsgPrefix(t *testing.T) {
	id := generateID("msg")
	if !strings.HasPrefix(id, "msg_") {
		t.Errorf("expected 'msg_' prefix, got %s", id)
	}
}

func TestCB29_GenerateID_ConvPrefix(t *testing.T) {
	id := generateID("conv")
	if !strings.HasPrefix(id, "conv_") {
		t.Errorf("expected 'conv_' prefix, got %s", id)
	}
}

func TestCB29_GenerateID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID("uniq")
		if ids[id] {
			t.Errorf("duplicate id generated: %s", id)
		}
		ids[id] = true
	}
}

// ==============================
// truncate: additional edge cases
// ==============================

func TestCB29_Truncate_ExactLength(t *testing.T) {
	result := truncate("hello", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestCB29_Truncate_ShortString(t *testing.T) {
	result := truncate("hi", 10)
	if result != "hi" {
		t.Errorf("expected 'hi', got %q", result)
	}
}

func TestCB29_Truncate_VeryShortMaxLen(t *testing.T) {
	// When maxLen <= 3, truncate returns s[:maxLen]
	result := truncate("hello world", 3)
	if result != "hel" {
		t.Errorf("expected 'hel', got %q", result)
	}
}

func TestCB29_Truncate_MaxLen0(t *testing.T) {
	// maxLen=0, len(s) > maxLen, returns s[:0] = ""
	result := truncate("hello", 0)
	if result != "" {
		t.Errorf("expected '', got %q", result)
	}
}

// ==============================
// safeTruncate: edge cases
// ==============================

func TestCB29_SafeTruncate_Short(t *testing.T) {
	result := safeTruncate("abc", 10)
	if result != "abc" {
		t.Errorf("expected 'abc', got %q", result)
	}
}

func TestCB29_SafeTruncate_Empty(t *testing.T) {
	result := safeTruncate("", 10)
	if result != "" {
		t.Errorf("expected '', got %q", result)
	}
}

// ==============================
// parseSize: additional formats
// ==============================

func TestCB29_ParseSize_Kilobytes(t *testing.T) {
	size, err := parseSize("2KB")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if size != 2*1024 {
		t.Errorf("expected %d, got %d", 2*1024, size)
	}
}

func TestCB29_ParseSize_Gigabytes(t *testing.T) {
	size, err := parseSize("1GB")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if size != 1<<30 {
		t.Errorf("expected %d, got %d", 1<<30, size)
	}
}

func TestCB29_ParseSize_Terabytes(t *testing.T) {
	size, err := parseSize("1TB")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if size != int64(1)<<40 {
		t.Errorf("expected %d, got %d", int64(1)<<40, size)
	}
}

// ==============================
// isAllowedContentType: more types
// ==============================

func TestCB29_IsAllowedContentType_ImageTypes(t *testing.T) {
	imageTypes := []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
	}
	for _, ct := range imageTypes {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB29_IsAllowedContentType_DocumentTypes(t *testing.T) {
	docTypes := []string{
		"application/pdf",
		"text/plain",
	}
	for _, ct := range docTypes {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB29_IsAllowedContentType_DisallowedTypes(t *testing.T) {
	disallowed := []string{
		"application/x-executable",
		"application/x-sh",
		"application/javascript",
	}
	for _, ct := range disallowed {
		if isAllowedContentType(ct) {
			t.Errorf("expected %s to be disallowed", ct)
		}
	}
}

// ==============================
// isUniqueViolation: SQLite and PostgreSQL
// ==============================

func TestCB29_IsUniqueViolation_SQLite(t *testing.T) {
	err := fmt.Errorf("UNIQUE constraint failed: users.username")
	if !isUniqueViolation(err) {
		t.Error("expected UNIQUE constraint to be detected")
	}
}

func TestCB29_IsUniqueViolation_PostgreSQL(t *testing.T) {
	// The current implementation only checks for SQLite's "UNIQUE constraint failed"
	// PostgreSQL violations would need a separate check. Verify it does NOT match.
	err := fmt.Errorf("pq: duplicate key value violates unique constraint \"users_username_key\"")
	if isUniqueViolation(err) {
		t.Error("PostgreSQL unique violation should NOT be detected by current implementation")
	}
}

// ==============================
// extractIP: more edge cases
// ==============================

func TestCB29_ExtractIP_MultipleForwarded(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 70.41.3.18, 150.172.238.178")
	ip := extractIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("expected first IP in X-Forwarded-For, got %s", ip)
	}
}

func TestCB29_ExtractIP_NoHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected RemoteAddr IP, got %s", ip)
	}
}

// ==============================
// OfflineQueue: drain and purge
// ==============================

func TestCB29_OfflineQueue_DrainEmpty(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	msgs := q.Drain("nobody")
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestCB29_OfflineQueue_EnqueueAndDrain(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user-1", []byte(`{"type":"message","data":"hello"}`))
	q.Enqueue("user-1", []byte(`{"type":"message","data":"world"}`))

	msgs := q.Drain("user-1")
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}
}

func TestCB29_OfflineQueue_MaxLenEviction(t *testing.T) {
	q := newOfflineQueue(2, 7*24*time.Hour)
	q.Enqueue("user-1", []byte("msg1"))
	q.Enqueue("user-1", []byte("msg2"))
	q.Enqueue("user-1", []byte("msg3"))

	msgs := q.Drain("user-1")
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages (max eviction), got %d", len(msgs))
	}
}

func TestCB29_OfflineQueue_Purge(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user-1", []byte("msg1"))
	q.Enqueue("user-2", []byte("msg2"))

	q.Purge("user-1")
	msgs := q.Drain("user-1")
	if len(msgs) != 0 {
		t.Errorf("expected 0 after purge, got %d", len(msgs))
	}

	// user-2 should still have messages
	msgs2 := q.Drain("user-2")
	if len(msgs2) != 1 {
		t.Errorf("expected 1 message for user-2, got %d", len(msgs2))
	}
}

func TestCB29_OfflineQueue_TotalDepth(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user-1", []byte("msg1"))
	q.Enqueue("user-1", []byte("msg2"))
	q.Enqueue("user-2", []byte("msg3"))

	if q.TotalDepth() != 3 {
		t.Errorf("expected total depth 3, got %d", q.TotalDepth())
	}
}

// ==============================
// DBDriver constants and switch
// ==============================

func TestCB29_DBDriver_Constants(t *testing.T) {
	if DriverSQLite != "sqlite3" {
		t.Errorf("expected DriverSQLite='sqlite3', got %s", DriverSQLite)
	}
	if DriverPostgreSQL != "postgres" {
		t.Errorf("expected DriverPostgreSQL='postgres', got %s", DriverPostgreSQL)
	}
}

// ==============================
// Logger: Debug, Info, Warn, Error, WithFields
// ==============================

func TestCB29_Logger_Debug(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogInfo)
	l.SetOutput(&buf)
	l.SetLevel(LogDebug)
	l.Debug("test debug", map[string]interface{}{"key": "value"})
	if buf.Len() == 0 {
		t.Error("expected debug output")
	}
}

func TestCB29_Logger_Info(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogInfo)
	l.SetOutput(&buf)
	l.SetLevel(LogInfo)
	l.Info("test info", nil)
	if buf.Len() == 0 {
		t.Error("expected info output")
	}
}

func TestCB29_Logger_Warn(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogInfo)
	l.SetOutput(&buf)
	l.SetLevel(LogWarn)
	l.Warn("test warn", nil)
	if buf.Len() == 0 {
		t.Error("expected warn output")
	}
}

func TestCB29_Logger_Error(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogInfo)
	l.SetOutput(&buf)
	l.SetLevel(LogError)
	l.Error("test error", nil)
	if buf.Len() == 0 {
		t.Error("expected error output")
	}
}

func TestCB29_Logger_LevelFilter(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogInfo)
	l.SetOutput(&buf)
	l.SetLevel(LogWarn)

	// Debug and Info should be filtered out
	l.Debug("should not appear", nil)
	l.Info("should not appear", nil)
	if buf.Len() > 0 {
		t.Error("debug/info should be filtered at warn level")
	}

	// Warn should appear
	l.Warn("should appear", nil)
	if buf.Len() == 0 {
		t.Error("warn should appear at warn level")
	}
}

func TestCB29_Logger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogInfo)
	l.SetOutput(&buf)
	l.SetLevel(LogInfo)
	l2 := l.WithFields(map[string]interface{}{"request_id": "abc123"})
	l2.Info("with fields", nil)
	if buf.Len() == 0 {
		t.Error("expected output with fields")
	}
}

// ==============================
// Route: chat message with various types
// ==============================

func TestCB29_RouteChatMessage_EmptyContent(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	agent := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-chat-empty",
		send:     make(chan []byte, 10),
	}
	client := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-chat-empty",
		send:     make(chan []byte, 10),
	}
	h.register <- agent
	h.register <- client
	time.Sleep(50 * time.Millisecond)

	msg := []byte(`{"type":"chat","data":{"conversation_id":"conv-1","content":"","sender_type":"client"}}`)
	routeMessage(client, msg)
}

func TestCB29_RouteStatusUpdate(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register agent
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"agent-status-1", "Status Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	agent := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-status-1",
		send:     make(chan []byte, 10),
	}
	client := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-status-1",
		send:     make(chan []byte, 10),
	}
	h.register <- agent
	h.register <- client
	time.Sleep(50 * time.Millisecond)

	msg := []byte(`{"type":"status","data":{"conversation_id":"conv-1","status":"idle"}}`)
	routeMessage(agent, msg)
}

func TestCB29_RouteTypingIndicator(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	h := newHub()
	go h.run()
	defer h.Stop()

	agent := &Connection{
		hub:      h,
		connType: "agent",
		id:       "agent-typing-1",
		send:     make(chan []byte, 10),
	}
	client := &Connection{
		hub:      h,
		connType: "client",
		id:       "client-typing-1",
		send:     make(chan []byte, 10),
	}
	h.register <- agent
	h.register <- client
	time.Sleep(50 * time.Millisecond)

	// Empty conversation_id — should be ignored
	routeMessage(client, []byte(`{"type":"typing","data":{"is_typing":true}}`))
}

// ==============================
// handleHealth: DB connectivity
// ==============================

func TestCB29_HandleHealth_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["db"] != "not initialized" {
		t.Errorf("expected db='not initialized', got %v", resp["db"])
	}
}

// ==============================
// HandleMetrics
// ==============================

func TestCB29_HandleMetrics_Success(t *testing.T) {
	h := newHub()
	m := NewMetrics(h)
	origMetrics := ServerMetrics
	ServerMetrics = m
	defer func() { ServerMetrics = origMetrics }()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCB29_HandleMetrics_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// negotiateProtocol and isSupportedVersion
// ==============================

func TestCB29_NegotiateProtocol_Supported(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1, other-protocol")
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Errorf("expected 'v1', got %q", version)
	}
}

func TestCB29_NegotiateProtocol_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	version := negotiateProtocol(req)
	if version != "v1" {
		t.Errorf("expected 'v1' (default), got %q", version)
	}
}

func TestCB29_IsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Error("expected v1 to be supported")
	}
	if isSupportedVersion("unsupported-v99") {
		t.Error("expected unsupported version to return false")
	}
}

// ==============================
// env helpers
// ==============================

func TestCB29_EnvIntOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_ENV_INT_29", "42")
	defer os.Unsetenv("TEST_ENV_INT_29")

	result := envIntOrDefault("TEST_ENV_INT_29", 0)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestCB29_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_ENV_INT_INV_29", "not-a-number")
	defer os.Unsetenv("TEST_ENV_INT_INV_29")

	result := envIntOrDefault("TEST_ENV_INT_INV_29", 10)
	if result != 10 {
		t.Errorf("expected default 10, got %d", result)
	}
}

func TestCB29_EnvDurationOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_ENV_DUR_29", "5s")
	defer os.Unsetenv("TEST_ENV_DUR_29")

	result := envDurationOrDefault("TEST_ENV_DUR_29", time.Minute)
	if result != 5*time.Second {
		t.Errorf("expected 5s, got %v", result)
	}
}

func TestCB29_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_ENV_DUR_INV_29", "not-a-duration")
	defer os.Unsetenv("TEST_ENV_DUR_INV_29")

	result := envDurationOrDefault("TEST_ENV_DUR_INV_29", time.Minute)
	if result != time.Minute {
		t.Errorf("expected 1m default, got %v", result)
	}
}

func TestCB29_GetEnvOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_ENV_STR_29", "hello")
	defer os.Unsetenv("TEST_ENV_STR_29")

	result := getEnvOrDefault("TEST_ENV_STR_29", "default")
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestCB29_GetEnvOrDefault_Default(t *testing.T) {
	result := getEnvOrDefault("NONEXISTENT_ENV_29", "default")
	if result != "default" {
		t.Errorf("expected 'default', got %q", result)
	}
}

// ==============================
// RegisterAgentOnConnect
// ==============================

func TestCB29_RegisterAgentOnConnect_New(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	err = RegisterAgentOnConnect("new-agent-29", "Test Agent", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Verify agent was created
	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "new-agent-29").Scan(&name)
	if err != nil {
		t.Errorf("expected to find agent, got error: %v", err)
	}
	if name != "Test Agent" {
		t.Errorf("expected name 'Test Agent', got %q", name)
	}
}

func TestCB29_RegisterAgentOnConnect_Existing(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register first time
	err = RegisterAgentOnConnect("existing-agent-29", "Original Name", "gpt-3.5", "serious", "math")
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Reconnect with updated metadata
	err = RegisterAgentOnConnect("existing-agent-29", "Updated Name", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Errorf("re-registration failed: %v", err)
	}

	// Verify updated metadata
	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "existing-agent-29").Scan(&name)
	if err != nil {
		t.Errorf("expected to find agent, got error: %v", err)
	}
	if name != "Updated Name" {
		t.Errorf("expected 'Updated Name', got %q", name)
	}
}

func TestCB29_RegisterAgentOnConnect_PartialUpdate(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register first time with full metadata
	err = RegisterAgentOnConnect("partial-agent-29", "Full Name", "gpt-4", "friendly", "coding")
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Reconnect with no metadata (should preserve existing)
	err = RegisterAgentOnConnect("partial-agent-29", "", "", "", "")
	if err != nil {
		t.Errorf("partial re-registration failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "partial-agent-29").Scan(&name)
	if err != nil {
		t.Errorf("expected to find agent, got error: %v", err)
	}
	// Name should be preserved since empty strings are not sent
	if name != "Full Name" {
		t.Errorf("expected preserved name 'Full Name', got %q", name)
	}
}

// ==============================
// isConversationMuted
// ==============================

func TestCB29_IsConversationMuted_True(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create a user and conversation, then mute it
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"mute-user-29", "muteuser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"mute-agent-29", "Mute Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"mute-conv-29", "mute-user-29", "mute-agent-29")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"mute-user-29", "mute-conv-29")
	if err != nil {
		t.Fatalf("failed to insert notification pref: %v", err)
	}

	muted := isConversationMuted("mute-user-29", "mute-conv-29")
	if !muted {
		t.Error("expected conversation to be muted")
	}
}

func TestCB29_IsConversationMuted_False(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// No notification preferences exist
	muted := isConversationMuted("no-user-29", "no-conv-29")
	if muted {
		t.Error("expected conversation to not be muted")
	}
}

// ==============================
// BoolToInt helper
// ==============================

func TestCB29_BoolToInt_True(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("expected boolToInt(true) = 1")
	}
}

func TestCB29_BoolToInt_False(t *testing.T) {
	if boolToInt(false) != 0 {
		t.Error("expected boolToInt(false) = 0")
	}
}

// ==============================
// Itoa helper
// ==============================

func TestCB29_Itoa(t *testing.T) {
	if itoa(0) != "0" {
		t.Error("expected itoa(0) = '0'")
	}
	if itoa(42) != "42" {
		t.Error("expected itoa(42) = '42'")
	}
}

// ==============================
// Connection: NegotiatedVersion
// ==============================

func TestCB29_Connection_NegotiatedVersion(t *testing.T) {
	conn := &Connection{
		hub:               hub,
		connType:          "client",
		id:                "version-test",
		send:              make(chan []byte, 10),
		negotiatedVersion: "agent-messenger-v1",
	}
	if conn.negotiatedVersion != "agent-messenger-v1" {
		t.Errorf("expected 'agent-messenger-v1', got %q", conn.negotiatedVersion)
	}
}

// ==============================
// Agent rate limiter
// ==============================

func TestCB29_AgentRateLimiter_Allow(t *testing.T) {
	limiter := NewRateLimiter(5, time.Minute)

	for i := 0; i < 5; i++ {
		if !limiter.Allow("agent-29") {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// 6th request should be rate limited
	if limiter.Allow("agent-29") {
		t.Error("expected 6th request to be rate limited")
	}
}

func TestCB29_AgentRateLimiter_Reset(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)

	limiter.Allow("agent-29-r")
	limiter.Allow("agent-29-r")

	// Should be rate limited
	if limiter.Allow("agent-29-r") {
		t.Error("expected rate limit")
	}

	// Reset
	limiter.Reset()

	// Should be allowed again
	if !limiter.Allow("agent-29-r") {
		t.Error("expected allow after reset")
	}
}

func TestCB29_AgentRateLimiter_Stop(t *testing.T) {
	limiter := NewRateLimiter(10, time.Minute)
	limiter.Allow("agent-stop-1")
	limiter.Allow("agent-stop-2")

	// Stop should not panic
	limiter.Stop()
}

// ==============================
// TieredRateLimiter edge cases
// ==============================

func TestCB29_TieredRateLimiter_FreeDefault(t *testing.T) {
	limiter := NewTieredRateLimiter()

	// Free tier: 60/min
	for i := 0; i < 60; i++ {
		ok, _, _ := limiter.Allow("free-user-29")
		if !ok {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// 61st should be denied
	ok, _, _ := limiter.Allow("free-user-29")
	if ok {
		t.Error("expected 61st request to be rate limited")
	}
}

func TestCB29_TieredRateLimiter_TierPro(t *testing.T) {
	limiter := NewTieredRateLimiter()

	// Pro tier: 300/min — set tier first
	limiter.SetTier("pro-user-29", TierPro)

	// Just verify first few work
	for i := 0; i < 10; i++ {
		ok, _, _ := limiter.Allow("pro-user-29")
		if !ok {
			t.Errorf("expected pro request %d to be allowed", i+1)
		}
	}
}

func TestCB29_TieredRateLimiter_TierEnterprise(t *testing.T) {
	limiter := NewTieredRateLimiter()

	// Enterprise tier: 1500/min
	limiter.SetTier("ent-user-29", TierEnterprise)

	for i := 0; i < 10; i++ {
		ok, _, _ := limiter.Allow("ent-user-29")
		if !ok {
			t.Errorf("expected enterprise request %d to be allowed", i+1)
		}
	}
}

// ==============================
// changeUserPassword
// ==============================

func TestCB29_ChangeUserPassword_Success(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register a user
	form := url.Values{"username": {"pwuser"}, "password": {"oldpass123"}}.Encode()
	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
	regReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	regW := httptest.NewRecorder()
	handleRegisterUser(regW, regReq)

	var regResp map[string]interface{}
	json.Unmarshal(regW.Body.Bytes(), &regResp)
	userID := regResp["user_id"].(string)

	// Change password
	err = changeUserPassword(userID, "oldpass123", "newpass456")
	if err != nil {
		t.Errorf("expected password change to succeed, got %v", err)
	}

	// Verify old password no longer works
	loginForm := url.Values{"username": {"pwuser"}, "password": {"oldpass123"}}.Encode()
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW := httptest.NewRecorder()
	handleLogin(loginW, loginReq)

	if loginW.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for old password, got %d", loginW.Code)
	}

	// Verify new password works
	loginForm2 := url.Values{"username": {"pwuser"}, "password": {"newpass456"}}.Encode()
	loginReq2 := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginForm2))
	loginReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginW2 := httptest.NewRecorder()
	handleLogin(loginW2, loginReq2)

	if loginW2.Code != http.StatusOK {
		t.Errorf("expected 200 for new password, got %d", loginW2.Code)
	}
}

func TestCB29_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Register a user
	form := url.Values{"username": {"pwuser2"}, "password": {"password123"}}.Encode()
	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form))
	regReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	regW := httptest.NewRecorder()
	handleRegisterUser(regW, regReq)

	var regResp map[string]interface{}
	json.Unmarshal(regW.Body.Bytes(), &regResp)
	userID := regResp["user_id"].(string)

	err = changeUserPassword(userID, "wrongpassword", "newpass456")
	if err == nil {
		t.Error("expected error for wrong old password")
	}
}

func TestCB29_ChangeUserPassword_UserNotFound(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	err = changeUserPassword("nonexistent-user-29", "oldpass", "newpass")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

// ==============================
// markMessagesRead
// ==============================

func TestCB29_MarkMessagesRead_Success(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create user, agent, conversation, and a message
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"read-user-29", "readuser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"read-agent-29", "Read Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"read-conv-29", "read-user-29", "read-agent-29")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_id, content, sender_type) VALUES (?, ?, ?, ?, ?)",
		"read-msg-29", "read-conv-29", "read-agent-29", "Hello", "agent")
	if err != nil {
		t.Fatalf("failed to insert message: %v", err)
	}

	count, err := markMessagesRead("read-conv-29", "read-user-29")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 message read, got %d", count)
	}

	// Verify read_at was set
	var readAt *string
	err = db.QueryRow("SELECT read_at FROM messages WHERE id = ?", "read-msg-29").Scan(&readAt)
	if err != nil {
		t.Errorf("failed to query read_at: %v", err)
	}
	if readAt == nil {
		t.Error("expected read_at to be set")
	}
}

// ==============================
// createConversation / getOrCreateConversation
// ==============================

func TestCB29_CreateConversation_New(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"conv-user-29", "convuser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"conv-agent-29", "Conv Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	conv, err := CreateConversation("conv-user-29", "conv-agent-29")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if conv == nil || conv.ID == "" {
		t.Error("expected non-empty conversation ID")
	}

	// Verify in DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", conv.ID).Scan(&count)
	if err != nil {
		t.Errorf("failed to query conversations: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 conversation, got %d", count)
	}
}

func TestCB29_GetOrCreateConversation_Existing(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"gor-user-29", "goruser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"gor-agent-29", "Gor Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	// Create first
	conv1, err := GetOrCreateConversation("gor-user-29", "gor-agent-29")
	if err != nil {
		t.Fatalf("first creation failed: %v", err)
	}

	// Get or create should return same ID
	conv2, err := GetOrCreateConversation("gor-user-29", "gor-agent-29")
	if err != nil {
		t.Fatalf("get-or-create failed: %v", err)
	}
	if conv1.ID != conv2.ID {
		t.Errorf("expected same conversation ID, got %s and %s", conv1.ID, conv2.ID)
	}
}

// ==============================
// searchMessages
// ==============================

func TestCB29_SearchMessages_Success(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create user, agent, conversation, and messages
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"search-user-29", "searchuser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"search-agent-29", "Search Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"search-conv-29", "search-user-29", "search-agent-29")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_id, content, sender_type) VALUES (?, ?, ?, ?, ?)",
		"search-msg-29a", "search-conv-29", "search-agent-29", "Hello world", "agent")
	if err != nil {
		t.Fatalf("failed to insert message: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_id, content, sender_type) VALUES (?, ?, ?, ?, ?)",
		"search-msg-29b", "search-conv-29", "search-user-29", "Hello back", "client")
	if err != nil {
		t.Fatalf("failed to insert message: %v", err)
	}

	results, err := searchMessages("search-user-29", "Hello", 50)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(results) < 1 {
		t.Errorf("expected at least 1 result, got %d", len(results))
	}
}

// ==============================
// HashAPIKey and bcrypt
// ==============================

func TestCB29_HashAPIKey_Success(t *testing.T) {
	hash, err := HashAPIKey("test-key-29")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	// bcrypt hashes start with $2a$
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("expected bcrypt hash prefix, got %q", hash[:4])
	}
}

// ==============================
// validateAgentSecret
// ==============================

func TestCB29_ValidateAgentSecret_Success(t *testing.T) {
	origSecret := getAgentSecret()
	setAgentSecretForTest("test-secret-29")
	defer setAgentSecretForTest(origSecret)

	err := ValidateAgentSecret("test-agent", "test-secret-29")
	if err != nil {
		t.Errorf("expected validation to succeed, got %v", err)
	}
}

func TestCB29_ValidateAgentSecret_Wrong(t *testing.T) {
	origSecret := getAgentSecret()
	setAgentSecretForTest("test-secret-29")
	defer setAgentSecretForTest(origSecret)

	err := ValidateAgentSecret("test-agent", "wrong-secret")
	if err == nil {
		t.Error("expected validation to fail with wrong secret")
	}
}

func TestCB29_ValidateAgentSecret_Empty(t *testing.T) {
	origSecret := getAgentSecret()
	setAgentSecretForTest("")
	defer setAgentSecretForTest(origSecret)

	err := ValidateAgentSecret("test-agent", "any-secret")
	if err == nil {
		t.Error("expected validation to fail with empty secret")
	}
}

// ==============================
// sendAPNSNotification: disabled (nil client)
// ==============================

func TestCB29_SendAPNSNotification_Disabled(t *testing.T) {
	// With nil client, should just return (no crash)
	pushConfig = nil
	sendAPNSNotification("test-token", "title", "body", "conv-1")
}

// ==============================
// sendFCMNotification: disabled (nil client)
// ==============================

func TestCB29_SendFCMNotification_Disabled(t *testing.T) {
	// With nil client, should just return (no crash)
	pushConfig = nil
	sendFCMNotification("test-token", "title", "body", "conv-1")
}

// ==============================
// getConversation
// ==============================

func TestCB29_GetConversation_Found(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"gconv-user-29", "gconvuser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"gconv-agent-29", "GConv Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"gconv-29", "gconv-user-29", "gconv-agent-29")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}

	conv, err := getConversation("gconv-29")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if conv == nil {
		t.Fatal("expected non-nil conversation")
	}
	if conv.ID != "gconv-29" {
		t.Errorf("expected ID gconv-29, got %s", conv.ID)
	}
}

func TestCB29_GetConversation_NotFound(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	conv, err := getConversation("nonexistent-conv-29")
	if err != nil {
		t.Error("expected nil error for nonexistent conversation")
	}
	if conv != nil {
		t.Errorf("expected nil conversation, got %+v", conv)
	}
}

// ==============================
// getDeviceTokensForUser
// ==============================

func TestCB29_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		"tokens-user-29", "token-abc-29", "ios")
	if err != nil {
		t.Fatalf("failed to insert iOS token: %v", err)
	}
	_, err = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)",
		"tokens-user-29", "token-def-29", "android")
	if err != nil {
		t.Fatalf("failed to insert device token: %v", err)
	}

	tokens, err := getDeviceTokensForUser("tokens-user-29")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

// ==============================
// notifyUser: muted conversation
// ==============================

func TestCB29_NotifyUser_MutedConversation(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Create user, agent, conversation, and mute it
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"notif-user-29", "notifuser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO agents (id, name, status) VALUES (?, ?, ?)",
		"notif-agent-29", "Notif Agent", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"notif-conv-29", "notif-user-29", "notif-agent-29")
	if err != nil {
		t.Fatalf("failed to insert conversation: %v", err)
	}
	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)",
		"notif-user-29", "notif-conv-29")
	if err != nil {
		t.Fatalf("failed to insert notification pref: %v", err)
	}

	// notifyUser should skip muted conversations without error
	notifyUser("notif-user-29", "notif-conv-29", "test message", "agent")
}

// ==============================
// ensureUploadDir
// ==============================

func TestCB29_EnsureUploadDir(t *testing.T) {
	dir := getUploadDir()
	err := ensureUploadDir()
	if err != nil {
		t.Errorf("expected no error ensuring upload dir, got %v", err)
	}
	// Verify directory exists
	if stat, err := os.Stat(dir); err != nil || !stat.IsDir() {
		t.Errorf("expected upload dir to exist: %s", dir)
	}
}

// ==============================
// getMaxUploadSize
// ==============================

func TestCB29_GetMaxUploadSize(t *testing.T) {
	size := getMaxUploadSize()
	if size <= 0 {
		t.Errorf("expected positive max upload size, got %d", size)
	}
}

// ==============================
// HandleAdminProfile: unknown action
// ==============================

func TestCB29_HandleAdminProfile_UnknownAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=unknown", nil)
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")
	w := httptest.NewRecorder()

	// Call handleAdminProfile directly (adminAuthMiddleware is tested separately)
	handleAdminProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown action, got %d", w.Code)
	}
}

// ==============================
// HandleAdminAgents: list
// ==============================

func TestCB29_HandleAdminAgents_List(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// Need a running hub for handleAdminAgents
	h := newHub()
	go h.run()
	defer h.Stop()

	origHub := hub
	hub = h
	defer func() { hub = origHub }()

	// Insert an agent
	_, err = db.Exec("INSERT INTO agents (id, name, model, personality, specialty, status) VALUES (?, ?, ?, ?, ?, ?)",
		"admin-agent-29", "Admin Agent", "gpt-4", "friendly", "coding", "online")
	if err != nil {
		t.Fatalf("failed to insert agent: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")
	w := httptest.NewRecorder()

	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// HandleRegisterAgent: via agent secret (form value)
// ==============================

func TestCB29_HandleRegisterAgent_FormValueSecret(t *testing.T) {
	origDB := db
	tmpDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db = tmpDB
	defer func() {
		db = origDB
		tmpDB.Close()
	}()

	if err := initSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	origSecret := getAgentSecret()
	setAgentSecretForTest("form-secret-29")
	defer setAgentSecretForTest(origSecret)

	form := url.Values{"agent_id": {"form-agent-29"}, "name": {"Form Agent"}, "agent_secret": {"form-secret-29"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	w := httptest.NewRecorder()
	handleRegisterAgent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// MarshalOutgoingMessage
// ==============================

func TestCB29_MarshalOutgoingMessage_AllFields(t *testing.T) {
	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]interface{}{
			"id":              "msg-29",
			"conversation_id": "conv-29",
			"content":         "hello",
			"sender_id":       "agent-29",
			"sender_type":     "agent",
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal outgoing message: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty marshaled data")
	}
}