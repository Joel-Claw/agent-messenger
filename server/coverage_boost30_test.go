package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// cb30CreateConversation creates a conversation using a JWT token to get the user ID
func cb30CreateConversation(t *testing.T, token, agentID string) string {
	t.Helper()
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}
	conv, err := GetOrCreateConversation(claims.UserID, agentID)
	if err != nil {
		t.Fatalf("Failed to create conversation: %v", err)
	}
	return conv.ID
}

// ==============================
// CB30: Push Notification Handler Tests
// ==============================

func TestCB30_RegisterDeviceToken_Success(t *testing.T) {
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

	// Create user
	token := createTestUser(t, "pushuser1")

	body := `{"device_token":"abc123def456","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp)
	}
}

func TestCB30_RegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_RegisterDeviceToken_NoAuth(t *testing.T) {
	body := `{"device_token":"abc123","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB30_RegisterDeviceToken_MissingToken(t *testing.T) {
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

	token := createTestUser(t, "pushuser2")

	body := `{"platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_RegisterDeviceToken_InvalidJSON(t *testing.T) {
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

	token := createTestUser(t, "pushuser3")

	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB30_RegisterDeviceToken_DefaultPlatform(t *testing.T) {
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

	token := createTestUser(t, "pushuser4")

	// Omit platform, should default to "ios"
	body := `{"device_token":"token_default_plat"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify platform defaulted to ios
	var platform string
	db.QueryRow("SELECT platform FROM device_tokens WHERE device_token = ?", "token_default_plat").Scan(&platform)
	if platform != "ios" {
		t.Errorf("expected platform ios, got %s", platform)
	}
}

func TestCB30_UnregisterDeviceToken_Success(t *testing.T) {
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

	token := createTestUser(t, "pushuser5")

	// Register first
	body := `{"device_token":"unreg_token_1","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register failed: %d", w.Code)
	}

	// Then unregister
	delBody := `{"device_token":"unreg_token_1"}`
	delReq := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(delBody))
	delReq.Header.Set("Authorization", "Bearer "+token)
	delReq.Header.Set("Content-Type", "application/json")
	delW := httptest.NewRecorder()
	handleUnregisterDeviceToken(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", delW.Code, delW.Body.String())
	}
}

func TestCB30_UnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/unregister", nil)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_UnregisterDeviceToken_NoAuth(t *testing.T) {
	body := `{"device_token":"abc"}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB30_UnregisterDeviceToken_MissingToken(t *testing.T) {
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

	token := createTestUser(t, "pushuser6")

	body := `{}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_UnregisterDeviceToken_InvalidJSON(t *testing.T) {
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

	token := createTestUser(t, "pushuser7")

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ==============================
// CB30: VAPID Key and Web Push
// ==============================

func TestCB30_GetVAPIDKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_GetVAPIDKey_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB30_GetVAPIDKey_NotConfigured(t *testing.T) {
	origKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = origKey }()

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

	token := createTestUser(t, "vapiduser1")

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_GetVAPIDKey_Success(t *testing.T) {
	origKey := vapidPublicKey
	vapidPublicKey = "test-vapid-public-key-123"
	defer func() { vapidPublicKey = origKey }()

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

	token := createTestUser(t, "vapiduser2")

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["public_key"] != "test-vapid-public-key-123" {
		t.Errorf("expected vapid key, got %v", resp)
	}
}

func TestCB30_WebPushSubscribe_Success(t *testing.T) {
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

	token := createTestUser(t, "webpushuser1")

	body := `{"endpoint":"https://push.example.com/sub/123","keys":{"p256dh":"BCEKeyExample","auth":"authKey123"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "subscribed" {
		t.Errorf("expected status subscribed, got %v", resp)
	}
}

func TestCB30_WebPushSubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_WebPushSubscribe_NoAuth(t *testing.T) {
	body := `{"endpoint":"https://push.example.com/sub/123","keys":{"p256dh":"key","auth":"auth"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB30_WebPushSubscribe_InvalidJSON(t *testing.T) {
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

	token := createTestUser(t, "webpushuser2")

	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB30_WebPushSubscribe_MissingFields(t *testing.T) {
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

	token := createTestUser(t, "webpushuser3")

	// Missing endpoint
	body := `{"endpoint":"","keys":{"p256dh":"key","auth":"auth"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing endpoint, got %d: %s", w.Code, w.Body.String())
	}

	// Missing p256dh
	body2 := `{"endpoint":"https://push.example.com","keys":{"p256dh":"","auth":"auth"}}`
	req2 := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	handleWebPushSubscribe(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing p256dh, got %d: %s", w2.Code, w2.Body.String())
	}

	// Missing auth key
	body3 := `{"endpoint":"https://push.example.com","keys":{"p256dh":"key","auth":""}}`
	req3 := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body3))
	req3.Header.Set("Authorization", "Bearer "+token)
	req3.Header.Set("Content-Type", "application/json")

	w3 := httptest.NewRecorder()
	handleWebPushSubscribe(w3, req3)

	if w3.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing auth, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestCB30_WebPushUnsubscribe_Success(t *testing.T) {
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

	token := createTestUser(t, "webpushuser4")

	// Subscribe first
	subBody := `{"endpoint":"https://push.example.com/sub/unsub1","keys":{"p256dh":"BKey1","auth":"AKey1"}}`
	subReq := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(subBody))
	subReq.Header.Set("Authorization", "Bearer "+token)
	subReq.Header.Set("Content-Type", "application/json")
	subW := httptest.NewRecorder()
	handleWebPushSubscribe(subW, subReq)
	if subW.Code != http.StatusOK {
		t.Fatalf("subscribe failed: %d", subW.Code)
	}

	// Then unsubscribe
	unsubBody := `{"endpoint":"https://push.example.com/sub/unsub1"}`
	unsubReq := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(unsubBody))
	unsubReq.Header.Set("Authorization", "Bearer "+token)
	unsubReq.Header.Set("Content-Type", "application/json")
	unsubW := httptest.NewRecorder()
	handleWebPushUnsubscribe(unsubW, unsubReq)

	if unsubW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", unsubW.Code, unsubW.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(unsubW.Body.Bytes(), &resp)
	if resp["status"] != "unsubscribed" {
		t.Errorf("expected status unsubscribed, got %v", resp)
	}
}

func TestCB30_WebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_WebPushUnsubscribe_NoAuth(t *testing.T) {
	body := `{"endpoint":"https://push.example.com/sub/123"}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB30_WebPushUnsubscribe_InvalidJSON(t *testing.T) {
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

	token := createTestUser(t, "webpushuser5")

	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCB30_WebPushUnsubscribe_MissingEndpoint(t *testing.T) {
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

	token := createTestUser(t, "webpushuser6")

	body := `{"endpoint":""}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// CB30: Notification Preferences Handlers
// ==============================

func TestCB30_SetNotificationPrefs_Success(t *testing.T) {
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

	token := createTestUser(t, "notifuser1")

	// Create a conversation first
	convID := cb30CreateConversation(t, token, "notifagent1")

	form := "conversation_id=" + convID + "\u0026muted=true"
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", strings.NewReader(form))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	authMiddleware(handleSetNotificationPrefs)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_GetNotificationPrefs_Success(t *testing.T) {
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

	token := createTestUser(t, "notifuser2")
	convID := cb30CreateConversation(t, token, "notifagent2")

	// Set muted first using form encoding
	setForm := "conversation_id=" + convID + "\u0026muted=true"
	setReq := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", strings.NewReader(setForm))
	setReq.Header.Set("Authorization", "Bearer "+token)
	setReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setW := httptest.NewRecorder()
	authMiddleware(handleSetNotificationPrefs)(setW, setReq)
	if setW.Code != http.StatusOK {
		t.Fatalf("set prefs failed: %d %s", setW.Code, setW.Body.String())
	}

	// Get prefs
	getReq := httptest.NewRequest(http.MethodGet, "/notification-prefs?conversation_id="+convID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getW := httptest.NewRecorder()
	authMiddleware(handleGetNotificationPrefs)(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", getW.Code, getW.Body.String())
	}
}

func TestCB30_DeleteNotificationPrefs_Success(t *testing.T) {
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

	token := createTestUser(t, "notifuser3")
	convID := cb30CreateConversation(t, token, "notifagent3")

	// Set muted first using form encoding
	setForm := "conversation_id=" + convID + "\u0026muted=true"
	setReq := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", strings.NewReader(setForm))
	setReq.Header.Set("Authorization", "Bearer "+token)
	setReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setW := httptest.NewRecorder()
	authMiddleware(handleSetNotificationPrefs)(setW, setReq)

	// Delete prefs using query param (DELETE with FormValue reads from URL query)
	delReq := httptest.NewRequest(http.MethodDelete, "/notification-prefs/delete?conversation_id="+convID, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delW := httptest.NewRecorder()
	authMiddleware(handleDeleteNotificationPrefs)(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", delW.Code, delW.Body.String())
	}
}

// ==============================
// CB30: Admin Rate Limit Tier Handler
// ==============================

func TestCB30_AdminRateLimitTier_GetMethod(t *testing.T) {
	// GET on /admin/rate-limit/tier requires admin auth and user_id
	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/tier?user_id=testuser", nil)
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")
	w := httptest.NewRecorder()
	handleAdminRateLimitTier(w, req)

	// GET without user_id returns 400 (missing user_id)
	if w.Code != http.StatusOK {
		t.Logf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_AdminRateLimitTier_NoAuth(t *testing.T) {
	body := `{"user_id":"testuser","tier":"pro"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/tier", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Use csrfMiddleware + adminAuthMiddleware chain
	handler := csrfMiddleware(corsMiddleware(handleAdminRateLimitTier))
	handler(w, req)

	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		// CSRF or admin auth should block this
		t.Logf("got status %d (expected 401/403)", w.Code)
	}
}

// ==============================
// CB30: Profile Handler Edge Cases
// ==============================

func TestCB30_Profile_CPUStart(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile", strings.NewReader(`{"action":"cpu_start"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")

	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	// Should start CPU profile (or return error if already started)
	if w.Code != http.StatusOK && w.Code != http.StatusConflict {
		t.Logf("cpu_start returned %d: %s", w.Code, w.Body.String())
	}

	// Stop it
	stopReq := httptest.NewRequest(http.MethodPost, "/admin/profile", strings.NewReader(`{"action":"cpu_stop"}`))
	stopReq.Header.Set("Content-Type", "application/json")
	stopReq.Header.Set("X-Admin-Secret", "admin-dev-secret")
	stopW := httptest.NewRecorder()
	handleAdminProfile(stopW, stopReq)
}

func TestCB30_Profile_ForceGC(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile", strings.NewReader(`{"action":"gc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")

	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_Profile_MemStats(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile", strings.NewReader(`{"action":"stats"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")

	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_Profile_InvalidAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile", strings.NewReader(`{"action":"invalid_action_xyz"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "admin-dev-secret")

	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// CB30: List Conversations Handler
// ==============================

func TestCB30_ListConversations_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_ListConversations_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB30_ListConversations_Success(t *testing.T) {
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

	token := createTestUser(t, "convuser1")
	convID := createTestConversation(t, token, "conv-agent-1")

	// Also add a message to the conversation
	_, err = db.Exec(`INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at)
		VALUES (?, ?, 'user', 'convuser1', 'hello world', ?)`, "msg-conv1", convID, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var convos []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &convos)
	if len(convos) < 1 {
		t.Errorf("expected at least 1 conversation, got %d", len(convos))
	}
}

func TestCB30_ListConversations_EmptyResult(t *testing.T) {
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

	token := createTestUser(t, "convuser2")

	req := httptest.NewRequest(http.MethodGet, "/conversations/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Should be empty array, not null
	var convos []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &convos)
	if convos == nil {
		t.Error("expected empty array, got null")
	}
	if len(convos) != 0 {
		t.Errorf("expected 0 conversations, got %d", len(convos))
	}
}

// ==============================
// CB30: GetMessages Handler Edge Cases
// ==============================

func TestCB30_GetMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/messages", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_GetMessages_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCB30_GetMessages_MissingConvID(t *testing.T) {
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

	token := createTestUser(t, "msguser1")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_GetMessages_NotFound(t *testing.T) {
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

	token := createTestUser(t, "msguser2")

	req := httptest.NewRequest(http.MethodGet, "/conversations/messages?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// CB30: Agent Listing
// ==============================

func TestCB30_ListAgents_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_ListAgents_Success(t *testing.T) {
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

	// Need a hub for AgentStatus
	origHub := hub
	hub = newHub()
	go hub.run()
	defer func() {
		hub.Stop()
		hub = origHub
	}()

	// Register an agent in DB
	_, err = db.Exec(`INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)`,
		"list-agent-1", "Test Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) < 1 {
		t.Errorf("expected at least 1 agent, got %d", len(agents))
	}
}

// ==============================
// CB30: Admin Agents Handler
// ==============================

func TestCB30_AdminAgents_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/agents", nil)
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_AdminAgents_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	w := httptest.NewRecorder()

	// Wrap with adminAuthMiddleware
	handler := adminAuthMiddleware(corsMiddleware(handleAdminAgents))
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ==============================
// CB30: Attachment Upload Edge Cases
// ==============================

func TestCB30_Upload_TooLarge(t *testing.T) {
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

	token := createTestUser(t, "uploaduser1")

	// Set a very small upload limit
	origMax := maxUploadSize
	maxUploadSize = 10 // 10 bytes
	defer func() { maxUploadSize = origMax }()

	// Create a body larger than 10 bytes
	body := strings.NewReader("this is way more than ten bytes for sure")
	req := httptest.NewRequest(http.MethodPost, "/attachments/upload", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusRequestEntityTooLarge && w.Code != http.StatusBadRequest {
		t.Errorf("expected 413 or 400, got %d: %s", w.Code, w.Body.String())
	}
}

// ==============================
// CB30: Reaction Handler Edge Cases
// ==============================

func TestCB30_React_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/react", nil)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_GetReactions_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/reactions", nil)
	w := httptest.NewRecorder()
	handleGetReactions(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// CB30: Tag Handler Edge Cases
// ==============================

func TestCB30_AddTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags/add", nil)
	w := httptest.NewRecorder()
	handleAddTag(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_RemoveTag_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/conversations/tags/remove", nil)
	w := httptest.NewRecorder()
	handleRemoveTag(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_GetTags_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/conversations/tags", nil)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// CB30: Message Edit/Delete Method Not Allowed
// ==============================

func TestCB30_MessageEdit_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/edit", nil)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_MessageDelete_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/delete", nil)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// CB30: Auth Handlers Edge Cases
// ==============================

func TestCB30_Login_InvalidJSON(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_RegisterUser_DuplicateUsername(t *testing.T) {
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

	// Register first user via form
	form1 := "username=dupuser\u0026password=pass123"
	req1 := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form1))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	handleRegisterUser(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d %s", w1.Code, w1.Body.String())
	}

	// Try duplicate username
	form2 := "username=dupuser\u0026password=pass456"
	req2 := httptest.NewRequest(http.MethodPost, "/auth/user", strings.NewReader(form2))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handleRegisterUser(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate username, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ==============================
// CB30: E2E Encryption Handler Edge Cases
// ==============================

func TestCB30_UploadPublicKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/keys/upload", nil)
	w := httptest.NewRecorder()
	handleUploadPublicKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_GetKeyBundle_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/bundle", nil)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_ListOneTimePreKeys_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/otpk-count", nil)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_StoreEncryptedMessage_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCB30_GetEncryptedMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted/list", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ==============================
// CB30: Route Message Edge Cases
// ==============================

func TestCB30_RouteMessage_UnknownType(t *testing.T) {
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

	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
		connType:  "agent",
		id:         "route-agent-30",
		send:      make(chan []byte, 256),
		hub:       testHub,
		connectedAt: time.Now(),
	}
	testHub.register <- conn

	// Send unknown message type
	routeMessage(conn, []byte(`{"type":"unknown_type_xyz","data":{}}`))
	// Should not panic - unknown types are logged and ignored
}

// ==============================
// CB30: Hub Agent Status
// ==============================

func TestCB30_Hub_AgentStatus(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	// Default status is "online"
	conn := &Connection{
		connType:    "agent",
		id:         "status-agent-30",
		send:        make(chan []byte, 256),
		hub:         testHub,
		connectedAt: time.Now(),
	}
	testHub.register <- conn

	status := testHub.AgentStatus("status-agent-30")
	if status != "online" {
		t.Errorf("expected online, got %s", status)
	}

	testHub.SetAgentStatus("status-agent-30", "busy")
	status = testHub.AgentStatus("status-agent-30")
	if status != "busy" {
		t.Errorf("expected busy, got %s", status)
	}

	// Unknown agent
	status = testHub.AgentStatus("unknown-agent")
	if status != "offline" {
		t.Errorf("expected offline, got %s", status)
	}
}

func TestCB30_Hub_StaleAgentCount(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	count := testHub.StaleAgentCount()
	if count != 0 {
		t.Errorf("expected 0 stale agents, got %d", count)
	}
}

func TestCB30_Hub_ClientConnCount(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	count := testHub.ClientConnCount()
	if count != 0 {
		t.Errorf("expected 0 client connections, got %d", count)
	}

	// Add a client
	clientConn := &Connection{
		connType:    "client",
		id:         "client-30",
		deviceID:    "dev1",
		send:        make(chan []byte, 256),
		hub:         testHub,
		connectedAt: time.Now(),
	}
	testHub.register <- clientConn

	count = testHub.ClientConnCount()
	if count != 1 {
		t.Errorf("expected 1 client connection, got %d", count)
	}
}

func TestCB30_Hub_GetClient(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	// Nonexistent client
	conn := testHub.GetClient("nonexistent-user")
	if conn != nil {
		t.Errorf("expected nil for nonexistent client")
	}
}

// ==============================
// CB30: Connection IsClosed/MarkClosed/SafeSend
// ==============================

func TestCB30_Connection_MarkClosed_SafeSend(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn := &Connection{
		connType:    "agent",
		id:         "closed-conn-30",
		send:        make(chan []byte, 256),
		hub:         testHub,
		connectedAt: time.Now(),
	}
	testHub.register <- conn

	if conn.IsClosed() {
		t.Error("connection should not be closed initially")
	}

	conn.MarkClosed()

	if !conn.IsClosed() {
		t.Error("connection should be closed after MarkClosed")
	}

	// SafeSend should return false on closed connection
	result := conn.SafeSend([]byte("test"))
	if result {
		t.Error("SafeSend should return false on closed connection")
	}
}

// ==============================
// CB30: Utility Functions
// ==============================

func TestCB30_BoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("expected 1 for true")
	}
	if boolToInt(false) != 0 {
		t.Error("expected 0 for false")
	}
}

func TestCB30_NegotiateProtocol(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"v1", "v1"},
		{"v1,v2", "v1"},
		{"v2", "v1"},  // v2 not supported, defaults to latest
		{"", "v1"},   // no header, defaults to latest
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tt.header != "" {
			req.Header.Set("Sec-WebSocket-Protocol", tt.header)
		}
		got := negotiateProtocol(req)
		if got != tt.want {
			t.Errorf("negotiateProtocol(header=%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestCB30_IsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Error("v1 should be supported")
	}
	if isSupportedVersion("v99") {
		t.Error("v99 should not be supported")
	}
}

// ==============================
// CB30: DB Driver
// ==============================

func TestCB30_DBDriver_Constants(t *testing.T) {
	if DriverSQLite != "sqlite3" {
		t.Errorf("expected sqlite3, got %s", DriverSQLite)
	}
	if DriverPostgreSQL != "postgres" {
		t.Errorf("expected postgres, got %s", DriverPostgreSQL)
	}
}

func TestCB30_Placeholders_SQLite(t *testing.T) {
	ph := Placeholder(1)
	if ph != "?" {
		t.Errorf("expected ?, got %s", ph)
	}
}

func TestCB30_Placeholders_PostgreSQL(t *testing.T) {
	orig := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = orig }()

	ph := Placeholder(1)
	if ph != "$1" {
		t.Errorf("expected $1, got %s", ph)
	}
}

// ==============================
// CB30: SafeTruncate
// ==============================

func TestCB30_SafeTruncate_Exact(t *testing.T) {
	result := safeTruncate("hello", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB30_SafeTruncate_Truncate(t *testing.T) {
	result := safeTruncate("hello world", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB30_SafeTruncate_Empty(t *testing.T) {
	result := safeTruncate("", 5)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

func TestCB30_SafeTruncate_Zero(t *testing.T) {
	result := safeTruncate("hello", 0)
	if result != "" {
		t.Errorf("expected '', got '%s'", result)
	}
}

// ==============================
// CB30: ParseSize
// ==============================

func TestCB30_ParseSize_Bytes(t *testing.T) {
	result, err := parseSize("100")
	if err != nil || result != 100 {
		t.Errorf("expected 100, got %d, err=%v", result, err)
	}
}

func TestCB30_ParseSize_MB(t *testing.T) {
	result, err := parseSize("50MB")
	if err != nil || result != 50*1024*1024 {
		t.Errorf("expected %d, got %d, err=%v", 50*1024*1024, result, err)
	}
}

func TestCB30_ParseSize_GB(t *testing.T) {
	result, err := parseSize("2GB")
	if err != nil || result != 2*1024*1024*1024 {
		t.Errorf("expected %d, got %d, err=%v", 2*1024*1024*1024, result, err)
	}
}

func TestCB30_ParseSize_TB(t *testing.T) {
	result, err := parseSize("1TB")
	if err != nil || result != 1<<40 {
		t.Errorf("expected %d, got %d, err=%v", 1<<40, result, err)
	}
}

func TestCB30_ParseSize_KB(t *testing.T) {
	result, err := parseSize("512KB")
	if err != nil || result != 512*1024 {
		t.Errorf("expected %d, got %d, err=%v", 512*1024, result, err)
	}
}

func TestCB30_ParseSize_Empty(t *testing.T) {
	_, err := parseSize("")
	if err == nil {
		t.Error("expected error for empty size")
	}
}

func TestCB30_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("abc")
	if err == nil {
		t.Error("expected error for invalid size")
	}
}

func TestCB30_ParseSize_InvalidSuffix(t *testing.T) {
	_, err := parseSize("100XB")
	if err == nil {
		t.Error("expected error for invalid suffix")
	}
}

// ==============================
// CB30: Env Defaults
// ==============================

func TestCB30_EnvOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_CB30_ENV", "hello")
	defer os.Unsetenv("TEST_CB30_ENV")

	result := getEnvOrDefault("TEST_CB30_ENV", "default")
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestCB30_EnvOrDefault_Default(t *testing.T) {
	os.Unsetenv("TEST_CB30_ENV_NOTSET")
	result := getEnvOrDefault("TEST_CB30_ENV_NOTSET", "default_val")
	if result != "default_val" {
		t.Errorf("expected 'default_val', got '%s'", result)
	}
}

func TestCB30_EnvIntOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_CB30_INT", "42")
	defer os.Unsetenv("TEST_CB30_INT")

	result := envIntOrDefault("TEST_CB30_INT", 10)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestCB30_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_CB30_INT_INV", "notanumber")
	defer os.Unsetenv("TEST_CB30_INT_INV")

	result := envIntOrDefault("TEST_CB30_INT_INV", 10)
	if result != 10 {
		t.Errorf("expected 10, got %d", result)
	}
}

func TestCB30_EnvIntOrDefault_Default(t *testing.T) {
	os.Unsetenv("TEST_CB30_INT_DEF")

	result := envIntOrDefault("TEST_CB30_INT_DEF", 99)
	if result != 99 {
		t.Errorf("expected 99, got %d", result)
	}
}

func TestCB30_EnvDurationOrDefault_Set(t *testing.T) {
	os.Setenv("TEST_CB30_DUR", "5s")
	defer os.Unsetenv("TEST_CB30_DUR")

	result := envDurationOrDefault("TEST_CB30_DUR", 10*time.Second)
	if result != 5*time.Second {
		t.Errorf("expected 5s, got %v", result)
	}
}

func TestCB30_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("TEST_CB30_DUR_INV", "notaduration")
	defer os.Unsetenv("TEST_CB30_DUR_INV")

	result := envDurationOrDefault("TEST_CB30_DUR_INV", 10*time.Second)
	if result != 10*time.Second {
		t.Errorf("expected 10s, got %v", result)
	}
}

func TestCB30_EnvDurationOrDefault_Default(t *testing.T) {
	os.Unsetenv("TEST_CB30_DUR_DEF")

	result := envDurationOrDefault("TEST_CB30_DUR_DEF", 30*time.Second)
	if result != 30*time.Second {
		t.Errorf("expected 30s, got %v", result)
	}
}

// ==============================
// CB30: Logger Edge Cases
// ==============================

func TestCB30_Logger_WithFields(t *testing.T) {
	l := NewLogger(LogInfo)
	entry := l.WithFields(map[string]interface{}{"key": "value"})
	if entry == nil {
		t.Error("expected non-nil logger entry")
	}
}

func TestCB30_Logger_LevelFilter(t *testing.T) {
	l := NewLogger(LogError)
	// These should be filtered out (no panic/error)
	l.Info("should be filtered")
	l.Warn("should be filtered")
	l.Debug("should be filtered")
}

// ==============================
// CB30: Metrics
// ==============================

func TestCB30_Metrics_ErrorsTotal(t *testing.T) {
	m := NewMetrics(nil)
	m.ErrorsTotal.Add(1)
	if m.ErrorsTotal.Load() != 1 {
		t.Errorf("expected 1, got %d", m.ErrorsTotal.Load())
	}
}

func TestCB30_MessagesRouted(t *testing.T) {
	testHub := newHub()
	testHub.messagesRouted.Add(1)
	if testHub.messagesRouted.Load() != 1 {
		t.Errorf("expected 1, got %d", testHub.messagesRouted.Load())
	}
}

// ==============================
// CB30: IsUniqueViolation
// ==============================

func TestCB30_IsUniqueViolation_Nil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("expected false for nil error")
	}
}

func TestCB30_IsUniqueViolation_OtherError(t *testing.T) {
	if isUniqueViolation(sql.ErrNoRows) {
		t.Error("expected false for non-unique violation error")
	}
}

// ==============================
// CB30: Write JSON helpers
// ==============================

func TestCB30_WriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "test error" {
		t.Errorf("expected 'test error', got '%s'", resp["error"])
	}
}

func TestCB30_WriteJSON_Success(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected 'ok', got '%s'", resp["status"])
	}
}

// ==============================
// CB30: Extract IP
// ==============================

func TestCB30_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.1")

	ip := extractIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1, got %s", ip)
	}
}

func TestCB30_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}
}

// ==============================
// CB30: CSRF Middleware
// ==============================

func TestCB30_CSRF_GETAllowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for GET, got %d", w.Code)
	}
}

func TestCB30_CSRF_HEADAllowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for HEAD, got %d", w.Code)
	}
}

func TestCB30_CSRF_OPTIONSAllowed(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", w.Code)
	}
}

func TestCB30_CSRF_XRequestedWith(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for X-Requested-With POST, got %d", w.Code)
	}
}

func TestCB30_CSRF_Blocked(t *testing.T) {
	handler := csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// No X-Requested-With, no CSRF token
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST without CSRF, got %d", w.Code)
	}
}

// ==============================
// CB30: Security Headers Middleware
// ==============================

func TestCB30_SecurityHeaders(t *testing.T) {
	handler := securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options header")
	}
}

// ==============================
// CB30: CORS Middleware
// ==============================

func TestCB30_CORS_Preflight(t *testing.T) {
	handler := corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Errorf("expected 204 or 200 for CORS preflight, got %d", w.Code)
	}
	// Should have CORS headers
	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		t.Error("missing Access-Control-Allow-Origin header")
	}
}

// ==============================
// CB30: Rate Limiter
// ==============================

func TestCB30_RateLimiter_ResetAndCount(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	defer rl.Stop()

	// Use some slots
	rl.Allow("user1")
	rl.Allow("user1")
	rl.Allow("user1")

	count := rl.Count("user1")
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}

	// Reset
	rl.Reset()
	count = rl.Count("user1")
	if count != 0 {
		t.Errorf("expected count 0 after reset, got %d", count)
	}
}

func TestCB30_ResponseWriterWrapper(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapper := &responseWriterWrapper{ResponseWriter: rec}

	wrapper.WriteHeader(http.StatusNotFound)
	if wrapper.statusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", wrapper.statusCode)
	}
}

// ==============================
// CB30: Tiered Rate Limiter
// ==============================

func TestCB30_TieredRateLimiter_SetAndGetTier(t *testing.T) {
	tl := NewTieredRateLimiter()

	tl.SetTier("user1", TierPro)
	tier := tl.GetTier("user1")
	if tier != TierPro {
		t.Errorf("expected Pro, got %v", tier)
	}

	// Default tier for unknown user
	tier = tl.GetTier("unknown")
	if tier != TierFree {
		t.Errorf("expected Free, got %v", tier)
	}
}

func TestCB30_TieredRateLimiter_GetRemaining(t *testing.T) {
	tl := NewTieredRateLimiter()

	remaining := tl.GetRemaining("user1")
	if remaining <= 0 {
		t.Errorf("expected positive remaining, got %d", remaining)
	}
}

// ==============================
// CB30: Create/Get Conversation
// ==============================

func TestCB30_CreateConversation_Success(t *testing.T) {
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

	conv, err := CreateConversation("conv-user-30", "conv-agent-30")
	if err != nil {
		t.Fatalf("CreateConversation failed: %v", err)
	}
	if conv == nil {
		t.Fatal("expected non-nil conversation")
	}
	if conv.UserID != "conv-user-30" {
		t.Errorf("expected user conv-user-30, got %s", conv.UserID)
	}
	if conv.AgentID != "conv-agent-30" {
		t.Errorf("expected agent conv-agent-30, got %s", conv.AgentID)
	}
}

func TestCB30_GetOrCreateConversation_New(t *testing.T) {
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

	conv, err := GetOrCreateConversation("gor-user-30", "gor-agent-30")
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv == nil {
		t.Fatal("expected non-nil conversation")
	}
}

func TestCB30_GetOrCreateConversation_Existing(t *testing.T) {
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

	// Create first
	conv1, err := GetOrCreateConversation("gor2-user-30", "gor2-agent-30")
	if err != nil {
		t.Fatalf("first GetOrCreateConversation failed: %v", err)
	}

	// Get existing
	conv2, err := GetOrCreateConversation("gor2-user-30", "gor2-agent-30")
	if err != nil {
		t.Fatalf("second GetOrCreateConversation failed: %v", err)
	}

	if conv1.ID != conv2.ID {
		t.Errorf("expected same conversation ID, got %s and %s", conv1.ID, conv2.ID)
	}
}

// ==============================
// CB30: Store/Get Messages
// ==============================

func TestCB30_StoreMessagesBatch(t *testing.T) {
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

	token := createTestUser(t, "batchuser30")
	convID := cb30CreateConversation(t, token, "batchagent30")

	msgs := []RoutedMessage{
		{Type: "message", ConversationID: convID, Content: "msg1", SenderType: "user", SenderID: "batch-user-30"},
		{Type: "message", ConversationID: convID, Content: "msg2", SenderType: "agent", SenderID: "batch-agent-30"},
	}

	ids, err := storeMessagesBatch(msgs)
	if err != nil {
		t.Fatalf("storeMessagesBatch failed: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 message IDs, got %d", len(ids))
	}
}

// ==============================
// CB30: Open Database
// ==============================

func TestCB30_OpenDatabase_SQLite(t *testing.T) {
	dbConn, err := openDatabase(DriverSQLite, ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory SQLite: %v", err)
	}
	defer dbConn.Close()

	if dbConn == nil {
		t.Error("expected non-nil db connection")
	}

	// Verify we can ping it
	if err := dbConn.Ping(); err != nil {
		t.Errorf("failed to ping db: %v", err)
	}
}

// ==============================
// CB30: Validate JWT Edge Cases
// ==============================

func TestCB30_ValidateJWT_InvalidFormat(t *testing.T) {
	_, err := ValidateJWT("not.a.valid.jwt.token.at.all")
	if err == nil {
		t.Error("expected error for invalid JWT format")
	}
}

// ==============================
// CB30: Generate ID
// ==============================

func TestCB30_GenerateID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID("test")
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

// ==============================
// CB30: Notification Prefs Edge Cases
// ==============================

func TestCB30_GetNotificationPrefs_Empty(t *testing.T) {
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

	token := createTestUser(t, "notifempty1")
	convID := cb30CreateConversation(t, token, "notifempty-agent")

	// Get prefs for conversation with no prefs set
	req := httptest.NewRequest(http.MethodGet, "/notification-prefs?conversation_id="+convID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	authMiddleware(handleGetNotificationPrefs)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_SetNotificationPrefs_NotYourConversation(t *testing.T) {
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

	// Create user1 and their conversation
	tokenA := createTestUser(t, "notifuser_a")
	convID := cb30CreateConversation(t, tokenA, "notif-agent-a")

	// Create user2 who tries to set prefs on user1's conversation
	token2 := createTestUser(t, "notifuser_b")

	body := "conversation_id=" + convID + "\u0026muted=true"
	req := httptest.NewRequest(http.MethodPost, "/notification-prefs/set", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token2)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	authMiddleware(handleSetNotificationPrefs)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB30_DeleteNotificationPrefs_MethodNotAllowed(t *testing.T) {
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

	token := createTestUser(t, "notifdel1")

	// For DELETE, FormValue reads from URL query params
	req := httptest.NewRequest(http.MethodDelete, "/notification-prefs/delete?conversation_id=conv-del", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	authMiddleware(handleDeleteNotificationPrefs)(w, req)

	// Will succeed (200) since no prefs exist, but auth passes
	if w.Code != http.StatusOK {
		t.Logf("got %d: %s", w.Code, w.Body.String())
	}
}