package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// --- CB63 Helpers ---

func setupTestDB_CB63(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return testDB
}

func authReqCB63(method, target, body, userID string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
	return r.WithContext(ctx)
}

func generateTestToken_CB63(userID string) string {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)
	return tokenString
}

// --- InitTracing tests ---

func resetTracing_CB63() {
	tracingMu = sync.Once{}
	tracingEnabled = false
	if tp != nil {
		tp.Shutdown(context.Background())
		tp = nil
	}
	tracer = nil
}

func restoreEnv_CB63(keys ...string) func() {
	vals := make(map[string]string)
	for _, k := range keys {
		vals[k] = os.Getenv(k)
	}
	return func() {
		for _, k := range keys {
			if v, ok := vals[k]; ok && v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}
}

func TestCB63_InitTracing_HTTPProtocol(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_SERVICE_NAME", "OTEL_SAMPLING_RATE")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	os.Setenv("OTEL_SERVICE_NAME", "test-service")
	os.Setenv("OTEL_SAMPLING_RATE", "0.5")
	resetTracing_CB63()
	_ = InitTracing()
}

func TestCB63_InitTracing_HTTPInsecureEndpoint(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	resetTracing_CB63()
	_ = InitTracing()
}

func TestCB63_InitTracing_GRPCInsecure(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	resetTracing_CB63()
	_ = InitTracing()
}

func TestCB63_InitTracing_GRPCSecure443(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel.example.com:443")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	resetTracing_CB63()
	_ = InitTracing()
}

func TestCB63_InitTracing_HTTPFallbackEndpoint(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Setenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	resetTracing_CB63()
	_ = InitTracing()
}

func TestCB63_InitTracing_CustomSamplingRate(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_SAMPLING_RATE")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	os.Setenv("OTEL_SAMPLING_RATE", "0.25")
	resetTracing_CB63()
	_ = InitTracing()
}

func TestCB63_InitTracing_InvalidSamplingRate(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_SAMPLING_RATE")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	os.Setenv("OTEL_SAMPLING_RATE", "not-a-number")
	resetTracing_CB63()
	_ = InitTracing()
}

func TestCB63_ShutdownTracing_WithTracingEnabled(t *testing.T) {
	restore := restoreEnv_CB63("OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL")
	t.Cleanup(func() {
		restore()
		resetTracing_CB63()
	})

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	resetTracing_CB63()

	if err := InitTracing(); err == nil && tp != nil {
		ShutdownTracing()
	} else {
		tp = nil
		ShutdownTracing()
	}
}

// --- sendWelcomeMessage tests ---

func TestCB63_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	hub := newTestHub()
	

	conn := &Connection{
		id:                "conn-test-dev",
		connType:          "client",
		deviceID:          "dev-abc-123",
		hub:               hub,
		send:              make(chan []byte, 10),
		negotiatedVersion: "1.0",
	}

	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var parsed map[string]interface{}
		if err := json.Unmarshal(msg, &parsed); err != nil {
			t.Fatalf("Failed to parse welcome: %v", err)
		}
		data := parsed["data"].(map[string]interface{})
		if data["device_id"] != "dev-abc-123" {
			t.Errorf("Expected device_id=dev-abc-123, got %v", data["device_id"])
		}
	default:
		t.Fatal("No welcome message received")
	}
}

func TestCB63_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	hub := newTestHub()
	

	conn := &Connection{
		id:                "conn-closed",
		connType:          "client",
		hub:               hub,
		send:              make(chan []byte, 1),
		negotiatedVersion: "1.0",
	}
	close(conn.send)
	sendWelcomeMessage(conn)
}

func TestCB63_SendWelcomeMessage_SupportedVersions(t *testing.T) {
	hub := newTestHub()
	

	conn := &Connection{
		id:                "conn-ver",
		connType:          "agent",
		hub:               hub,
		send:              make(chan []byte, 10),
		negotiatedVersion: "1.0",
	}

	sendWelcomeMessage(conn)

	select {
	case msg := <-conn.send:
		var parsed map[string]interface{}
		if err := json.Unmarshal(msg, &parsed); err != nil {
			t.Fatalf("Failed to parse welcome: %v", err)
		}
		data := parsed["data"].(map[string]interface{})
		versions := data["supported_versions"].([]interface{})
		if len(versions) == 0 {
			t.Error("Expected at least one supported version")
		}
		if data["id"] != "conn-ver" {
			t.Errorf("Expected id=conn-ver, got %v", data["id"])
		}
	default:
		t.Fatal("No welcome message received")
	}
}

// --- initSchema tests ---

func TestCB63_InitSchema_ClosedDB(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	db.Close()

	err = initSchema(db)
	if err == nil {
		t.Error("Expected error from initSchema on closed DB")
	}
}

func TestCB63_InitSchema_MigrationCountNonZero(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatalf("First initSchema failed: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count == 0 {
		t.Error("Expected migrations to be recorded")
	}

	if err := initSchema(db); err != nil {
		t.Fatalf("Second initSchema failed: %v", err)
	}

	var count2 int
	db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count2)
	if count2 != count {
		t.Errorf("Expected migration count to stay %d, got %d", count, count2)
	}
}

func TestCB63_InitSchema_NotificationPrefsTable(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	_, err = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)", "u1", "c1", 0)
	if err != nil {
		t.Errorf("Failed to insert into notification_preferences: %v", err)
	}
}

func TestCB63_InitSchema_RateLimitTiersTable(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	_, err = db.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "user-tier-test", "pro")
	if err != nil {
		t.Errorf("Failed to insert into user_rate_limit_tiers: %v", err)
	}

	var tierName string
	err = db.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id=?", "user-tier-test").Scan(&tierName)
	if err != nil || tierName != "pro" {
		t.Errorf("Expected tier_name=pro, got %s, err=%v", tierName, err)
	}
}

// --- rate_limit_tiers cleanup tests ---

func TestCB63_TieredRateLimiter_CleanupStopChannel(t *testing.T) {
	trl := NewTieredRateLimiter()
	go trl.cleanup()
	close(trl.stopCh)
	time.Sleep(50 * time.Millisecond)
}

func TestCB63_TieredRateLimiter_CleanupWithStaleEntries(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer close(trl.stopCh)

	trl.mu.Lock()
	trl.limits["stale-user"] = &userRateLimitState{
		count:     5,
		windowEnd: time.Now().Add(-15 * time.Minute),
		tier:      TierFree,
	}
	trl.limits["fresh-user"] = &userRateLimitState{
		count:     3,
		windowEnd: time.Now().Add(30 * time.Second),
		tier:      TierPro,
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["stale-user"]; exists {
		t.Error("Expected stale-user entry to be removed")
	}
	if _, exists := trl.limits["fresh-user"]; !exists {
		t.Error("Expected fresh-user entry to still exist")
	}
}

// --- initAPNs tests ---

func TestCB63_InitAPNs_ProductionEnvironment(t *testing.T) {
	origPushConfig := pushConfig
	t.Cleanup(func() { pushConfig = origPushConfig })

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.p12")
	os.WriteFile(certPath, []byte("fake-p12-data"), 0644)

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Password:    "test-pass",
		Environment: "production",
		BundleID:    "com.test.app",
	}

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled after invalid cert")
	}
}

func TestCB63_InitAPNs_DirCreation(t *testing.T) {
	origPushConfig := pushConfig
	t.Cleanup(func() { pushConfig = origPushConfig })

	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "certs")
	certPath := filepath.Join(nestedDir, "cert.p12")

	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Environment: "development",
		BundleID:    "com.test.app",
	}

	initAPNs()
	if _, err := os.Stat(nestedDir); err != nil {
		t.Errorf("Expected nested cert dir to be created: %v", err)
	}
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs disabled when cert not found")
	}
}

// --- handleUpload tests ---

func TestCB63_HandleUpload_SuccessWithMessageID(t *testing.T) {
	origDB := db
	origUploadDir := os.Getenv("UPLOAD_DIR")
	t.Cleanup(func() {
		db = origDB
		if origUploadDir != "" {
			os.Setenv("UPLOAD_DIR", origUploadDir)
		} else {
			os.Unsetenv("UPLOAD_DIR")
		}
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	tmpDir := t.TempDir()
	os.Setenv("UPLOAD_DIR", tmpDir)

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-up-1", "uploader@test.com", string(hashedPass))

	token := generateTestToken_CB63("user-up-1")

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("message_id", "msg-123")
	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0x3F, 0x00, 0x05, 0xFE, 0x02, 0xFE, 0xDC, 0xCC, 0x59, 0xE7, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}
	part, _ := writer.CreateFormFile("file", "test.png")
	part.Write(pngData)
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["id"] == "" || resp["id"] == nil {
		t.Error("Expected attachment ID in response")
	}

	var messageID sql.NullString
	testDB.QueryRow("SELECT message_id FROM attachments WHERE user_id=?", "user-up-1").Scan(&messageID)
	if !messageID.Valid || messageID.String != "msg-123" {
		t.Errorf("Expected message_id=msg-123, got %v", messageID)
	}
}

func TestCB63_HandleUpload_DBError(t *testing.T) {
	origDB := db
	origUploadDir := os.Getenv("UPLOAD_DIR")
	t.Cleanup(func() {
		db = origDB
		if origUploadDir != "" {
			os.Setenv("UPLOAD_DIR", origUploadDir)
		} else {
			os.Unsetenv("UPLOAD_DIR")
		}
	})

	testDB := setupTestDB_CB63(t)
	testDB.Exec("DROP TABLE attachments")
	db = testDB
	tmpDir := t.TempDir()
	os.Setenv("UPLOAD_DIR", tmpDir)

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-up-2", "uploader2@test.com", string(hashedPass))

	token := generateTestToken_CB63("user-up-2")

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.png")
	part.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB63_HandleUpload_NoContentTypeDetection(t *testing.T) {
	origDB := db
	origUploadDir := os.Getenv("UPLOAD_DIR")
	t.Cleanup(func() {
		db = origDB
		if origUploadDir != "" {
			os.Setenv("UPLOAD_DIR", origUploadDir)
		} else {
			os.Unsetenv("UPLOAD_DIR")
		}
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	tmpDir := t.TempDir()
	os.Setenv("UPLOAD_DIR", tmpDir)

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-up-3", "uploader3@test.com", string(hashedPass))

	token := generateTestToken_CB63("user-up-3")

	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="test.png"`}
	h["Content-Type"] = []string{"application/octet-stream"}
	part, _ := writer.CreatePart(h)
	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0x3F, 0x00, 0x05, 0xFE, 0x02, 0xFE, 0xDC, 0xCC, 0x59, 0xE7, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}
	part.Write(pngData)
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- initFCM tests ---

func TestCB63_InitFCM_EmptyCredsPath(t *testing.T) {
	origPushConfig := pushConfig
	t.Cleanup(func() { pushConfig = origPushConfig })

	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	initFCM()
}

func TestCB63_InitFCM_NilConfig(t *testing.T) {
	origPushConfig := pushConfig
	t.Cleanup(func() { pushConfig = origPushConfig })

	pushConfig = nil
	initFCM()
}

// --- readPump tests ---

func TestCB63_ReadPump_NormalClosure(t *testing.T) {
	hub := newTestHub()
	

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			id:       "conn-readpump-1",
			connType: "client",
			hub:      hub,
			conn:     conn,
			send:     make(chan []byte, 10),
		}
		go c.readPump()
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer wsConn.Close()
	wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
	time.Sleep(100 * time.Millisecond)
}

func TestCB63_ReadPump_UnexpectedCloseError(t *testing.T) {
	hub := newTestHub()
	

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		c := &Connection{
			id:       "conn-readpump-2",
			connType: "agent",
			hub:      hub,
			conn:     conn,
			send:     make(chan []byte, 10),
		}
		go c.readPump()
		time.Sleep(50 * time.Millisecond)
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	wsConn.Close()
	time.Sleep(150 * time.Millisecond)
}

// --- loadQueueFromDB tests ---

func TestCB63_LoadQueueFromDB_WithData(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()
	initQueueDB(testDB)

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)", "recipient-1", []byte("message-data-1"), now)
	if err != nil {
		t.Fatalf("Failed to insert: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)", "recipient-2", []byte("message-data-2"), now)
	if err != nil {
		t.Fatalf("Failed to insert: %v", err)
	}

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 2 {
		t.Errorf("Expected queue depth=2, got %d", q.TotalDepth())
	}
}

func TestCB63_LoadQueueFromDB_QueryError(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)
	if q.TotalDepth() != 0 {
		t.Errorf("Expected 0 on error, got %d", q.TotalDepth())
	}
}

// --- handleListAgents tests ---

func TestCB63_HandleListAgents_WithAgents(t *testing.T) {
	origDB := db
	origHub := hub
	t.Cleanup(func() {
		db = origDB
		hub = origHub
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	h := newTestHub()
	
	hub = h

	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-list-1", "Agent One", "gpt-4", "helpful", "general")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-list-2", "Agent Two", "claude-3", "creative", "writing")

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) != 2 {
		t.Errorf("Expected 2 agents, got %d", len(agents))
	}
	if agents[0]["name"] != "Agent One" {
		t.Errorf("Expected first=Agent One, got %v", agents[0]["name"])
	}
}

func TestCB63_HandleListAgents_ScanError(t *testing.T) {
	origDB := db
	origHub := hub
	t.Cleanup(func() {
		db = origDB
		hub = origHub
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	h := newTestHub()
	
	hub = h

	testDB.Exec("DROP TABLE agents")
	testDB.Exec(`CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT)`)
	_, _ = testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-bad", "Bad Agent")

	req := httptest.NewRequest("GET", "/agents", nil)
	w := httptest.NewRecorder()
	handleListAgents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 on scan error, got %d", w.Code)
	}
}

// --- handleAdminAgents tests ---

func TestCB63_HandleAdminAgents_ScanError(t *testing.T) {
	origDB := db
	origHub := hub
	t.Cleanup(func() {
		db = origDB
		hub = origHub
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	h := newTestHub()
	
	hub = h

	testDB.Exec("DROP TABLE agents")
	testDB.Exec(`CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT)`)
	_, _ = testDB.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "agent-admin", "Admin Agent")

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", string(adminSecret))
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 on scan error, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB63_HandleAdminAgents_Success(t *testing.T) {
	origDB := db
	origHub := hub
	t.Cleanup(func() {
		db = origDB
		hub = origHub
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	h := newTestHub()
	
	hub = h

	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-admin-1", "Admin Test Agent", "gpt-4", "pro", "general")

	req := httptest.NewRequest("GET", "/admin/agents", nil)
	req.Header.Set("X-Admin-Secret", string(adminSecret))
	w := httptest.NewRecorder()
	handleAdminAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) != 1 {
		t.Errorf("Expected 1 agent, got %d", len(agents))
	}
	if agents[0]["status"] != "offline" {
		t.Errorf("Expected status=offline, got %v", agents[0]["status"])
	}
}

// --- getDeviceTokensForUser tests ---

func TestCB63_GetDeviceTokensForUser_MultipleTokens(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", "user-multi-dev", "token-ios-1", "ios")
	_, _ = testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", "user-multi-dev", "token-android-1", "android")

	tokens, err := getDeviceTokensForUser("user-multi-dev")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("Expected 2 tokens, got %d", len(tokens))
	}
}

func TestCB63_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	tokens, err := getDeviceTokensForUser("user-no-devices")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens, got %d", len(tokens))
	}
}

// --- notifyUser tests ---

func TestCB63_NotifyUser_NilPushConfig(t *testing.T) {
	origPushConfig := pushConfig
	t.Cleanup(func() { pushConfig = origPushConfig })

	pushConfig = nil
	notifyUser("user-1", "Title", "Body", "conv-1")
}

func TestCB63_NotifyUser_NoTokens(t *testing.T) {
	origDB := db
	origPushConfig := pushConfig
	t.Cleanup(func() {
		db = origDB
		pushConfig = origPushConfig
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	pushConfig = &PushNotificationConfig{APNSEnabled: false, FCMEnabled: false}

	notifyUser("user-no-tokens", "Title", "Body", "conv-1")
}

func TestCB63_NotifyUser_MutedConversation(t *testing.T) {
	origDB := db
	origPushConfig := pushConfig
	t.Cleanup(func() {
		db = origDB
		pushConfig = origPushConfig
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-muted", "muted@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)", "user-muted", "conv-muted", 1)

	notifyUser("user-muted", "Title", "Body", "conv-muted")
}

// --- handleListConversations tests ---

func TestCB63_HandleListConversations_DBError(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	testDB.Close()
	db = testDB

	token := generateTestToken_CB63("user-conv-err")
	req := httptest.NewRequest("GET", "/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListConversations(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleListAttachments tests ---

func TestCB63_HandleListAttachments_Empty(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-no-att", "noatt@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-no-att", "NoAtt Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-no-att", "user-no-att", "agent-no-att")

	token := generateTestToken_CB63("user-no-att")
	req := httptest.NewRequest("GET", "/attachments?conversation_id=conv-no-att", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachments []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &attachments)
	if len(attachments) != 0 {
		t.Errorf("Expected 0 attachments, got %d", len(attachments))
	}
}

// --- handleGetMessages tests ---

func TestCB63_HandleGetMessages_Success(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-msg-1", "msg@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-msg-1", "Msg Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-msg-1", "user-msg-1", "agent-msg-1")
	_, _ = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content) VALUES (?, ?, ?, ?, ?)", "msg-1", "conv-msg-1", "user-msg-1", "user", "Hello")
	_, _ = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content) VALUES (?, ?, ?, ?, ?)", "msg-2", "conv-msg-1", "agent-msg-1", "agent", "Hi there")

	token := generateTestToken_CB63("user-msg-1")
	req := httptest.NewRequest("GET", "/conversations/messages?conversation_id=conv-msg-1&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var raw interface{}
	json.Unmarshal(w.Body.Bytes(), &raw)
	var count int
	switch v := raw.(type) {
	case []interface{}:
		count = len(v)
	case map[string]interface{}:
		if msgs, ok := v["messages"].([]interface{}); ok {
			count = len(msgs)
		}
	}
	if count != 2 {
		t.Errorf("Expected 2 messages, got %d", count)
	}
}

// --- ValidateJWT tests ---

func TestCB63_ValidateJWT_ExpiredToken(t *testing.T) {
	claims := &Claims{
		UserID: "user-expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestCB63_ValidateJWT_WrongSigningMethod(t *testing.T) {
	claims := &Claims{
		UserID: "user-wrong",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, _ := token.SignedString([]byte(""))

	_, err := ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for wrong signing method")
	}
}

func TestCB63_ValidateJWT_ValidToken(t *testing.T) {
	token := generateTestToken_CB63("user-valid-jwt")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Expected valid token, got error: %v", err)
	}
	if claims.UserID != "user-valid-jwt" {
		t.Errorf("Expected UserID=user-valid-jwt, got %s", claims.UserID)
	}
}

// --- handleLogin tests ---

func TestCB63_HandleLogin_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB63_HandleLogin_EmptyPassword(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	body := `{"username":"user@test.com","password":""}`
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- handleRegisterUser tests ---

func TestCB63_HandleRegisterUser_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	req := httptest.NewRequest("POST", "/auth/register", strings.NewReader("bad json"))
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- handleMessageDelete tests ---

func TestCB63_HandleMessageDelete_NotFound(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-del-1")
	req := httptest.NewRequest("POST", "/messages/delete?message_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleMessageEdit tests ---

func TestCB63_HandleMessageEdit_NotFound(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-edit-1")
	req := httptest.NewRequest("POST", "/messages/edit?message_id=nonexistent&content=edited", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMessageEdit(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetNotificationPrefs tests ---

func TestCB63_HandleGetNotificationPrefs_NoPrefs(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	req := authReqCB63("GET", "/notifications/preferences", "", "user-nopref")
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var prefs []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &prefs)
	if len(prefs) != 0 {
		t.Errorf("Expected 0 preferences, got %d", len(prefs))
	}
}

// --- handleGetPresence tests ---

func TestCB63_HandleGetPresence_NoAgents(t *testing.T) {
	origDB := db
	origHub := hub
	t.Cleanup(func() {
		db = origDB
		hub = origHub
	})

	testDB := setupTestDB_CB63(t)
	db = testDB
	h := newTestHub()
	
	hub = h

	token := generateTestToken_CB63("user-pres-1")
	req := httptest.NewRequest("GET", "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
}

// --- handleSearchMessages tests ---

func TestCB63_HandleSearchMessages_NumericLimit(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-search-1", "search@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-search-1", "Search Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-search-1", "user-search-1", "agent-search-1")
	_, _ = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content) VALUES (?, ?, ?, ?, ?)", "smsg-1", "conv-search-1", "user-search-1", "user", "hello world test")
	_, _ = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content) VALUES (?, ?, ?, ?, ?)", "smsg-2", "conv-search-1", "agent-search-1", "agent", "hello again test")

	token := generateTestToken_CB63("user-search-1")
	req := httptest.NewRequest("GET", "/messages/search?q=hello&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleSearchMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var results []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 1 {
		t.Errorf("Expected 1 result (limit=1), got %d", len(results))
	}
}

// --- getConversationMessages tests ---

func TestCB63_GetConversationMessages_Empty(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-empty-conv", "empty@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-empty", "Empty Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-empty", "user-empty-conv", "agent-empty")

	msgs, err := getConversationMessages("conv-empty", 50, "")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("Expected 0 messages, got %d", len(msgs))
	}
}

// --- addReaction tests ---

func TestCB63_AddReaction_DifferentEmoji(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-react-multi", "react@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-react-multi", "React Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-react-multi", "user-react-multi", "agent-react-multi")
	_, _ = testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content) VALUES (?, ?, ?, ?, ?)", "msg-react-multi", "conv-react-multi", "user-react-multi", "user", "react test")

	_, _, err := addReaction("msg-react-multi", "user-react-multi", "😀")
	if err != nil {
		t.Fatalf("addReaction failed: %v", err)
	}

	_, _, err = addReaction("msg-react-multi", "user-react-multi", "😍")
	if err != nil {
		t.Fatalf("addReaction second failed: %v", err)
	}

	reactions, _ := getMessageReactions("msg-react-multi")
	if len(reactions) != 2 {
		t.Errorf("Expected 2 reactions, got %d", len(reactions))
	}
}

// --- handleReact tests ---

func TestCB63_HandleReact_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-react-bad")
	req := httptest.NewRequest("POST", "/messages/react", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleReact(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- addConversationTag tests ---

func TestCB63_AddConversationTag_Duplicate(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-tag-dup", "tagdup@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-tag-dup", "Tag Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-tag-dup", "user-tag-dup", "agent-tag-dup")

	_, err := addConversationTag("conv-tag-dup", "user-tag-dup", "important")
	if err != nil {
		t.Fatalf("First addConversationTag failed: %v", err)
	}

	_, err = addConversationTag("conv-tag-dup", "user-tag-dup", "important")
	_ = err
}

// --- getConversationTags tests ---

func TestCB63_GetConversationTags_WithTags(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-tags-get", "tagsget@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-tags-get", "Tags Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-tags-get", "user-tags-get", "agent-tags-get")

	addConversationTag("conv-tags-get", "user-tags-get", "work")
	addConversationTag("conv-tags-get", "user-tags-get", "urgent")

	tags, err := getConversationTags("conv-tags-get")
	if err != nil {
		t.Fatalf("getConversationTags failed: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tags))
	}
}

// --- handleGetTags tests ---

func TestCB63_HandleGetTags_SuccessWithTags(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-tags-list", "tagslist@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-tags-list", "Tags List Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-tags-list", "user-tags-list", "agent-tags-list")

	addConversationTag("conv-tags-list", "user-tags-list", "priority")
	addConversationTag("conv-tags-list", "user-tags-list", "followup")

	token := generateTestToken_CB63("user-tags-list")
	req := httptest.NewRequest("GET", "/conversations/tags?conversation_id=conv-tags-list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetTags(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var tagsList []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &tagsList)
	if len(tagsList) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tagsList))
	}
}

// --- Drain tests ---

func TestCB63_Drain_MixedData(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Enqueue("user-a", []byte("msg-a-1"))
	q.Enqueue("user-b", []byte("msg-b-1"))
	q.Enqueue("user-a", []byte("msg-a-2"))

	msgs := q.Drain("user-a")
	if len(msgs) != 2 {
		t.Errorf("Expected 2 messages for user-a, got %d", len(msgs))
	}

	msgsB := q.Drain("user-b")
	if len(msgsB) != 1 {
		t.Errorf("Expected 1 message for user-b, got %d", len(msgsB))
	}

	if q.TotalDepth() != 0 {
		t.Errorf("Expected depth=0 after drain, got %d", q.TotalDepth())
	}
}

// --- TieredRateLimiter tests ---

func TestCB63_TieredAllow_EnterpriseTier(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer close(trl.stopCh)
	trl.SetTier("user-ent", TierEnterprise)

	allowed := 0
	for i := 0; i < 100; i++ {
		ok, _, _ := trl.Allow("user-ent")
		if ok {
			allowed++
		}
	}
	if allowed != 100 {
		t.Errorf("Expected 100 allowed for enterprise, got %d", allowed)
	}
}

func TestCB63_TieredAllow_FreeTierLimit(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer close(trl.stopCh)
	trl.SetTier("user-free", TierFree)

	allowed := 0
	for i := 0; i < 70; i++ {
		ok, _, _ := trl.Allow("user-free")
		if ok {
			allowed++
		}
	}
	if allowed != 60 {
		t.Errorf("Expected 60 allowed for free tier, got %d", allowed)
	}
}

func TestCB63_TieredRateLimiter_GetTier_Default(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer close(trl.stopCh)

	tier := trl.GetTier("user-no-tier")
	if tier.Name != TierFree.Name {
		t.Errorf("Expected default tier=free, got %s", tier.Name)
	}
}

func TestCB63_TieredRateLimiter_GetTier_Pro(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer close(trl.stopCh)

	trl.SetTier("user-pro-tier", TierPro)
	tier := trl.GetTier("user-pro-tier")
	if tier.Name != TierPro.Name {
		t.Errorf("Expected tier=pro, got %s", tier.Name)
	}
}

func TestCB63_LoadTiersFromDB_WithTiers(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO user_rate_limit_tiers (user_id, tier_name) VALUES (?, ?)", "user-load-tier", "enterprise")

	trl := NewTieredRateLimiter()
	defer close(trl.stopCh)
	loadTiersFromDB(trl)

	tier := trl.GetTier("user-load-tier")
	if tier.Name != TierEnterprise.Name {
		t.Errorf("Expected tier=enterprise after load, got %s", tier.Name)
	}
}

// --- handleSetNotificationPrefs tests ---

func TestCB63_HandleSetNotificationPrefs_Success(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-notif-set", "notifset@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-notif-set", "Notif Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-notif-set", "user-notif-set", "agent-notif-set")

	form := "conversation_id=conv-notif-set&muted=true"
	req := authReqCB63("POST", "/notifications/preferences", form, "user-notif-set")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var muted bool
	testDB.QueryRow("SELECT muted FROM notification_preferences WHERE user_id=? AND conversation_id=?", "user-notif-set", "conv-notif-set").Scan(&muted)
	if !muted {
		t.Error("Expected muted=true in DB")
	}
}

// --- handleCreateConversation tests ---

func TestCB63_HandleCreateConversation_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-conv-bad")
	req := httptest.NewRequest("POST", "/conversations/create", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB63_HandleCreateConversation_Success(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-cc-1", "cc@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-cc-1", "CC Agent", "gpt-4", "test", "test")

	token := generateTestToken_CB63("user-cc-1")
	form := "agent_id=agent-cc-1"
	req := httptest.NewRequest("POST", "/conversations/create", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreateConversation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["conversation_id"] == "" {
		t.Error("Expected conversation_id in response")
	}
}

// --- handleChangePassword tests ---

func TestCB63_HandleChangePassword_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-pw-bad")
	req := httptest.NewRequest("POST", "/auth/change-password", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- handleMarkRead tests ---

func TestCB63_HandleMarkRead_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-mr-bad")
	req := httptest.NewRequest("POST", "/conversations/mark-read", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleMarkRead(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- handleDeleteConversation tests ---

func TestCB63_HandleDeleteConversation_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-dc-bad")
	req := httptest.NewRequest("DELETE", "/conversations/delete?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleDeleteConversation(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- routeChatMessage tests ---

func TestCB63_RouteChatMessage_EmptyData(t *testing.T) {
	hub := newTestHub()
	

	conn := &Connection{
		id:       "conn-route-1",
		connType: "client",
		hub:      hub,
		send:     make(chan []byte, 10),
	}

	msg := []byte(`{"type":"chat_message","data":{}}`)
	routeMessage(conn, msg)
}

// --- isConversationMuted tests ---

func TestCB63_IsConversationMuted_NotMuted(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-mute-check", "mutecheck@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-mute-check", "Mute Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-mute-check", "user-mute-check", "agent-mute-check")

	if isConversationMuted("user-mute-check", "conv-mute-check") {
		t.Error("Expected not muted")
	}
}

func TestCB63_IsConversationMuted_Muted(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-muted-2", "muted2@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-muted-2", "Muted Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-muted-2", "user-muted-2", "agent-muted-2")
	_, _ = testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)", "user-muted-2", "conv-muted-2", 1)

	if !isConversationMuted("user-muted-2", "conv-muted-2") {
		t.Error("Expected muted")
	}
}

// --- cleanStaleQueueMessages tests ---

func TestCB63_CleanStaleQueueMessages_RemovesOld(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	defer testDB.Close()
	initQueueDB(testDB)

	oldTime := time.Now().UTC().Add(-8 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)", "user-stale", []byte("old-msg"), oldTime)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	freshTime := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)", "user-fresh", []byte("fresh-msg"), freshTime)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	cleanStaleQueueMessages(testDB, 7*24*time.Hour)

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 remaining (fresh), got %d", count)
	}
}

// --- persistQueue tests ---

func TestCB63_PersistQueue_Success(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	defer testDB.Close()
	initQueueDB(testDB)

	persistQueue(testDB, "user-persist-1", []byte("persist-msg-1"))
	persistQueue(testDB, "user-persist-2", []byte("persist-msg-2"))

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue").Scan(&count)
	if count != 2 {
		t.Errorf("Expected 2 persisted, got %d", count)
	}
}

// --- deleteQueueMessages tests ---

func TestCB63_DeleteQueueMessages_Success(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	defer testDB.Close()
	initQueueDB(testDB)

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, _ = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)", "user-del-q", []byte("msg-to-delete"), now)
	_, _ = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)", "user-keep-q", []byte("msg-to-keep"), now)

	deleteQueueMessages(testDB, "user-del-q")

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient=?", "user-del-q").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 for user-del-q, got %d", count)
	}

	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient=?", "user-keep-q").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 for user-keep-q, got %d", count)
	}
}

// --- GetOrCreateConversation tests ---

func TestCB63_GetOrCreateConversation_New(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-goc-1", "goc@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-goc-1", "GOC Agent", "gpt-4", "test", "test")

	conv, err := GetOrCreateConversation("user-goc-1", "agent-goc-1")
	if err != nil {
		t.Fatalf("GetOrCreateConversation failed: %v", err)
	}
	if conv == nil {
		t.Fatal("Expected non-nil conversation")
	}

	conv2, _ := GetOrCreateConversation("user-goc-1", "agent-goc-1")
	if conv2.ID != conv.ID {
		t.Errorf("Expected same conversation ID, got %s vs %s", conv2.ID, conv.ID)
	}
}

// --- SafeSend tests ---

func TestCB63_SafeSend_Success(t *testing.T) {
	conn := &Connection{
		id:   "conn-safe-1",
		send: make(chan []byte, 5),
	}
	if !conn.SafeSend([]byte("test-message")) {
		t.Error("Expected SafeSend to return true")
	}
}

func TestCB63_SafeSend_ClosedChannel(t *testing.T) {
	conn := &Connection{
		id:   "conn-safe-2",
		send: make(chan []byte, 1),
	}
	close(conn.send)
	if conn.SafeSend([]byte("test-message")) {
		t.Error("Expected SafeSend to return false on closed channel")
	}
}

// --- Utility function tests ---

func TestCB63_Itoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"}, {1, "1"}, {100, "100"}, {-1, "-1"}, {999999, "999999"},
	}
	for _, tt := range tests {
		if result := itoa(tt.input); result != tt.expected {
			t.Errorf("itoa(%d) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestCB63_SafeTruncate(t *testing.T) {
	if result := safeTruncate("abcdefghij", 5); result != "abcde" {
		t.Errorf("Expected 'abcde', got '%s'", result)
	}
	if result := safeTruncate("abc", 10); result != "abc" {
		t.Errorf("Expected 'abc', got '%s'", result)
	}
	if result := safeTruncate("", 5); result != "" {
		t.Errorf("Expected '', got '%s'", result)
	}
}

func TestCB63_GetEnvOrDefault(t *testing.T) {
	origVal := os.Getenv("TEST_ENV_VAR_CB63")
	t.Cleanup(func() {
		if origVal != "" {
			os.Setenv("TEST_ENV_VAR_CB63", origVal)
		} else {
			os.Unsetenv("TEST_ENV_VAR_CB63")
		}
	})

	if result := getEnvOrDefault("TEST_ENV_VAR_CB63", "default-val"); result != "default-val" {
		t.Errorf("Expected 'default-val', got '%s'", result)
	}

	os.Setenv("TEST_ENV_VAR_CB63", "custom-val")
	if result := getEnvOrDefault("TEST_ENV_VAR_CB63", "default-val"); result != "custom-val" {
		t.Errorf("Expected 'custom-val', got '%s'", result)
	}
}

func TestCB63_ExtractIP_Direct(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	if ip := extractIP(req); ip != "192.168.1.100" {
		t.Errorf("Expected '192.168.1.100', got '%s'", ip)
	}
}

func TestCB63_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	req.RemoteAddr = "192.168.1.1:12345"
	if ip := extractIP(req); ip != "10.0.0.1" {
		t.Errorf("Expected '10.0.0.1', got '%s'", ip)
	}
}

func TestCB63_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "172.16.0.1")
	req.RemoteAddr = "192.168.1.1:12345"
	if ip := extractIP(req); ip != "172.16.0.1" {
		t.Errorf("Expected '172.16.0.1', got '%s'", ip)
	}
}

func TestCB63_GenerateID(t *testing.T) {
	id := generateID("msg")
	if !strings.HasPrefix(id, "msg") {
		t.Errorf("Expected ID to start with 'msg', got '%s'", id)
	}
	id2 := generateID("msg")
	if id == id2 {
		t.Error("Expected two generated IDs to be different")
	}
}

func TestCB63_GetMaxUploadSize_Default(t *testing.T) {
	origVal := os.Getenv("MAX_UPLOAD_SIZE")
	t.Cleanup(func() {
		if origVal != "" {
			os.Setenv("MAX_UPLOAD_SIZE", origVal)
		} else {
			os.Unsetenv("MAX_UPLOAD_SIZE")
		}
	})

	os.Unsetenv("MAX_UPLOAD_SIZE")
	if size := getMaxUploadSize(); size <= 0 {
		t.Errorf("Expected positive default, got %d", size)
	}
}

func TestCB63_GetMaxUploadSize_Custom(t *testing.T) {
	origVal := maxUploadSize
	t.Cleanup(func() { maxUploadSize = origVal })

	maxUploadSize = 10485760
	if size := getMaxUploadSize(); size != 10485760 {
		t.Errorf("Expected 10485760, got %d", size)
	}
}

func TestCB63_GetUploadDir_Default(t *testing.T) {
	result := getUploadDir()
	if result == "" {
		t.Error("Expected non-empty upload dir")
	}
}

func TestCB63_EnsureUploadDir_CreatesDir(t *testing.T) {
	origDBPath := serverDBPath
	t.Cleanup(func() { serverDBPath = origDBPath })

	tmpDir := t.TempDir()
	serverDBPath = filepath.Join(tmpDir, "test.db")
	err := ensureUploadDir()
	if err != nil {
		t.Errorf("Expected no error: %v", err)
	}
	expectedDir := filepath.Join(tmpDir, UploadSubdir)
	if _, err := os.Stat(expectedDir); err != nil {
		t.Errorf("Expected dir created: %v", err)
	}
}

func TestCB63_IsAllowedContentType_Allowed(t *testing.T) {
	allowed := []string{"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain"}
	for _, ct := range allowed {
		if !isAllowedContentType(ct) {
			t.Errorf("Expected %s to be allowed", ct)
		}
	}
}

func TestCB63_IsAllowedContentType_Disallowed(t *testing.T) {
	disallowed := []string{"application/x-executable", "application/x-msdownload", "application/x-sh"}
	for _, ct := range disallowed {
		if isAllowedContentType(ct) {
			t.Errorf("Expected %s to be disallowed", ct)
		}
	}
}

// --- writeJSON / writeJSONError tests ---

func TestCB63_WriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "test error message")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "test error message" {
		t.Errorf("Expected error message, got %v", resp["error"])
	}
}

func TestCB63_WriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	writeJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["key"] != "value" {
		t.Errorf("Expected key=value, got %v", resp["key"])
	}
}

// --- handleGetAttachment tests ---

func TestCB63_HandleGetAttachment_NotFound(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-att-nf")
	req := httptest.NewRequest("GET", "/attachments/nonexistent-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

// --- handleAgentConnect tests ---

func TestCB63_HandleAgentConnect_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", string(agentSecret))
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB63_HandleAgentConnect_WrongSecret(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	req := httptest.NewRequest("POST", "/auth/agent?agent_id=agent-ws-1&agent_secret=wrong-secret", nil)
	w := httptest.NewRecorder()
	handleAgentConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- handleSetRateLimitTier tests ---

func TestCB63_HandleSetRateLimitTier_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", string(adminSecret))
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB63_HandleSetRateLimitTier_UnknownTier(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	body := `{"user_id":"user-unk-tier","tier":"platinum"}`
	req := httptest.NewRequest("POST", "/admin/rate-limit/tier", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", string(adminSecret))
	w := httptest.NewRecorder()
	handleSetRateLimitTier(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for unknown tier, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetRateLimitTier tests ---

func TestCB63_HandleGetRateLimitTier_Success(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	globalTieredLimiter.SetTier("user-get-tier", TierPro)

	req := httptest.NewRequest("GET", "/admin/rate-limit/tier?user_id=user-get-tier", nil)
	req.Header.Set("X-Admin-Secret", string(adminSecret))
	w := httptest.NewRecorder()
	handleGetRateLimitTier(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["tier"] != "pro" {
		t.Errorf("Expected tier=pro, got %v", resp["tier"])
	}
}

// --- E2E handler tests ---

func TestCB63_HandleStoreEncryptedMessage_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-e2e-bad")
	req := httptest.NewRequest("POST", "/e2e/store", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB63_HandleGetEncryptedMessages_Empty(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	_, _ = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "user-e2e-empty", "e2eempty@test.com", "hash")
	_, _ = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "agent-e2e-empty", "E2E Agent", "gpt-4", "test", "test")
	_, _ = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", "conv-e2e-empty", "user-e2e-empty", "agent-e2e-empty")

	token := generateTestToken_CB63("user-e2e-empty")
	req := httptest.NewRequest("GET", "/e2e/messages?conversation_id=conv-e2e-empty", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB63_HandleGetKeyBundle_AgentNotFound(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-kb-1")
	req := httptest.NewRequest("GET", "/e2e/key-bundle?owner_id=nonexistent-user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetKeyBundle(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCB63_HandleListOneTimePreKeys_AgentNotFound(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-otpk-1")
	req := httptest.NewRequest("GET", "/e2e/one-time-prekeys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListOneTimePreKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]int
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["one_time_prekey_count"] != 0 {
		t.Errorf("Expected 0 prekeys, got %d", resp["one_time_prekey_count"])
	}
}

// --- Push handler tests ---

func TestCB63_HandleWebPushSubscribe_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-wps-bad")
	req := httptest.NewRequest("POST", "/push/subscribe", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB63_HandleRegisterDeviceToken_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-rt-bad")
	req := httptest.NewRequest("POST", "/push/register-token", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCB63_HandleUnregisterDeviceToken_InvalidJSON(t *testing.T) {
	origDB := db
	t.Cleanup(func() { db = origDB })

	testDB := setupTestDB_CB63(t)
	db = testDB

	token := generateTestToken_CB63("user-urt-bad")
	req := httptest.NewRequest("DELETE", "/push/unregister-token", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

// --- NewOfflineQueue capacity test ---

func TestCB63_NewOfflineQueue_Capacity(t *testing.T) {
	q := newOfflineQueue(3, 7*24*time.Hour)
	q.Enqueue("user-cap-1", []byte("msg-1"))
	q.Enqueue("user-cap-1", []byte("msg-2"))
	q.Enqueue("user-cap-1", []byte("msg-3"))
	q.Enqueue("user-cap-1", []byte("msg-4"))

	if q.TotalDepth() != 3 {
		t.Errorf("Expected depth=3 (max capacity), got %d", q.TotalDepth())
	}
}

// --- HashAPIKey test ---

func TestCB63_HashAPIKey(t *testing.T) {
	hash1, err1 := HashAPIKey("test-key-123")
	if err1 != nil {
		t.Fatalf("HashAPIKey failed: %v", err1)
	}
	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}

	hash2, err2 := HashAPIKey("test-key-123")
	if err2 != nil {
		t.Fatalf("HashAPIKey second failed: %v", err2)
	}
	if hash2 == "" {
		t.Error("Expected non-empty hash")
	}

	// bcrypt uses random salt, so hashes differ but both should be valid
	if hash1 == hash2 {
		t.Error("Expected different bcrypt hashes for same input (random salt)")
	}

	// Both should validate against the same input
	if bcrypt.CompareHashAndPassword([]byte(hash1), []byte("test-key-123")) != nil {
		t.Error("hash1 should validate against test-key-123")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash2), []byte("test-key-123")) != nil {
		t.Error("hash2 should validate against test-key-123")
	}
}

// --- Secret validation tests ---

func TestCB63_ValidateAgentSecret_Correct(t *testing.T) {
	if err := ValidateAgentSecret("test-agent", string(agentSecret)); err != nil {
		t.Errorf("Expected nil error for correct secret: %v", err)
	}
}

func TestCB63_ValidateAgentSecret_Incorrect(t *testing.T) {
	if err := ValidateAgentSecret("test-agent", "wrong-secret"); err == nil {
		t.Error("Expected error for wrong secret")
	}
}

func TestCB63_ValidateAdminSecret_Correct(t *testing.T) {
	if err := ValidateAdminSecret(string(adminSecret)); err != nil {
		t.Errorf("Expected nil error for correct admin secret: %v", err)
	}
}

func TestCB63_ValidateAdminSecret_Incorrect(t *testing.T) {
	if err := ValidateAdminSecret("wrong-admin-secret"); err == nil {
		t.Error("Expected error for wrong admin secret")
	}
}

// --- fmt import guard (prevents unused import) ---
var _ = fmt.Sprintf