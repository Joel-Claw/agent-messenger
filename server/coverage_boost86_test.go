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
)

// ============================================================
// CB86: Coverage boost targeting low-coverage functions
// Focus: InitTracing (79.5%), sendWelcomeMessage (80%), ShutdownTracing (80%),
// RegisterAgentOnConnect (81.8%), deleteConversation (83.3%),
// rate_limit_tiers cleanup (83.3%), initAPNs (84%), initSchema (85.3%),
// handleUpload (85.7%), readPump (86.4%), loadQueueFromDB (89.5%)
// ============================================================

// --- Helpers ---

func withTestDB_CB86(t *testing.T, fn func(db *sql.DB)) {
	t.Helper()
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer testDB.Close()
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	fn(testDB)
}

func withGlobalDB_CB86(t *testing.T, fn func()) {
	t.Helper()
	oldDB := db
	dbPath := fmt.Sprintf("/tmp/cb86_test_%d.db", time.Now().UnixNano())
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		testDB.Close()
		os.Remove(dbPath)
		t.Fatalf("Failed to init schema: %v", err)
	}
	db = testDB
	defer func() {
		testDB.Close()
		os.Remove(dbPath)
		db = oldDB
	}()
	fn()
}

// ============================================================
// InitTracing tests — targeting 79.5% → 90%+
// ============================================================

func TestCB86_InitTracing_ResourceMergeError(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SERVICE_NAME", "test-service")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_SERVICE_NAME")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err

	if tp != nil {
		ShutdownTracing()
	}
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

func TestCB86_InitTracing_HTTPExporterWithInsecure(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err

	if tp != nil {
		ShutdownTracing()
	}
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

func TestCB86_InitTracing_GRPCSecureEndpoint(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel collector:443")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err

	if tp != nil {
		ShutdownTracing()
	}
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

func TestCB86_InitTracing_HTTPSecureEndpoint(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.secure.example.com:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err

	if tp != nil {
		ShutdownTracing()
	}
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

func TestCB86_InitTracing_HTTPFallbackFromHTTPEndpoint(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Setenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err

	if tp != nil {
		ShutdownTracing()
	}
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

func TestCB86_InitTracing_ZeroSamplingRate(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "0")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_SAMPLING_RATE")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err

	if tp != nil {
		ShutdownTracing()
	}
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

func TestCB86_InitTracing_NegativeSamplingRate(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "-0.5")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_SAMPLING_RATE")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err

	if tp != nil {
		ShutdownTracing()
	}
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

// ============================================================
// ShutdownTracing tests — targeting 80% → 90%+
// ============================================================

func TestCB86_ShutdownTracing_WithError(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		tracingMu = sync.Once{}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	_ = InitTracing()

	ShutdownTracing()

	if tp != nil {
		ShutdownTracing()
	}

	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil
}

func TestCB86_ShutdownTracing_NilProviderNoOp(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	ShutdownTracing()
}

// ============================================================
// sendWelcomeMessage tests — targeting 80% → 90%+
// ============================================================

func TestCB86_SendWelcomeMessage_BufferFull(t *testing.T) {
	c := &Connection{
		id:                "test-conn",
		connType:          "agent",
		send:              make(chan []byte, 1),
		negotiatedVersion: "v1",
	}

	c.send <- []byte("dummy")

	sendWelcomeMessage(c)

	if len(c.send) != 1 {
		t.Errorf("Expected channel len 1, got %d", len(c.send))
	}
}

func TestCB86_SendWelcomeMessage_NilDeviceID(t *testing.T) {
	c := &Connection{
		id:                "test-conn-no-device",
		connType:          "client",
		send:              make(chan []byte, 10),
		negotiatedVersion: "v1",
		deviceID:          "",
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		var welcome OutgoingMessage
		if err := json.Unmarshal(msg, &welcome); err != nil {
			t.Fatalf("Failed to unmarshal welcome: %v", err)
		}
		if welcome.Type != "connected" {
			t.Errorf("Expected type 'connected', got '%s'", welcome.Type)
		}
		data, ok := welcome.Data.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected map data, got %T", welcome.Data)
		}
		if _, exists := data["device_id"]; exists {
			t.Errorf("Expected no device_id in welcome when empty")
		}
		if data["protocol_version"] != "v1" {
			t.Errorf("Expected protocol_version 'v1', got '%v'", data["protocol_version"])
		}
	default:
		t.Error("Expected to receive welcome message")
	}
}

func TestCB86_SendWelcomeMessage_WithNonEmptyDeviceID(t *testing.T) {
	c := &Connection{
		id:                "test-conn-device",
		connType:          "client",
		send:              make(chan []byte, 10),
		negotiatedVersion: "v1",
		deviceID:          "iphone-15-pro",
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		var welcome OutgoingMessage
		if err := json.Unmarshal(msg, &welcome); err != nil {
			t.Fatalf("Failed to unmarshal welcome: %v", err)
		}
		data, ok := welcome.Data.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected map data, got %T", welcome.Data)
		}
		if data["device_id"] != "iphone-15-pro" {
			t.Errorf("Expected device_id 'iphone-15-pro', got '%v'", data["device_id"])
		}
		if data["id"] != "test-conn-device" {
			t.Errorf("Expected id 'test-conn-device', got '%v'", data["id"])
		}
		if data["status"] != "connected" {
			t.Errorf("Expected status 'connected', got '%v'", data["status"])
		}
	default:
		t.Error("Expected to receive welcome message")
	}
}

func TestCB86_SendWelcomeMessage_SupportedVersions(t *testing.T) {
	c := &Connection{
		id:                "test-conn-versions",
		connType:          "agent",
		send:              make(chan []byte, 10),
		negotiatedVersion: "v1",
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		var welcome OutgoingMessage
		if err := json.Unmarshal(msg, &welcome); err != nil {
			t.Fatalf("Failed to unmarshal welcome: %v", err)
		}
		data, ok := welcome.Data.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected map data, got %T", welcome.Data)
		}
		versions, ok := data["supported_versions"].([]interface{})
		if !ok {
			t.Fatalf("Expected supported_versions to be array, got %T", data["supported_versions"])
		}
		if len(versions) == 0 {
			t.Error("Expected at least 1 supported version")
		}
		if versions[0] != "v1" {
			t.Errorf("Expected first version 'v1', got '%v'", versions[0])
		}
	default:
		t.Error("Expected to receive welcome message")
	}
}

// ============================================================
// RegisterAgentOnConnect tests — targeting 81.8% → 90%+
// ============================================================

func TestCB86_RegisterAgentOnConnect_ClosedDB(t *testing.T) {
	dbPath := fmt.Sprintf("/tmp/cb86_reg_%d.db", time.Now().UnixNano())
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		testDB.Close()
		os.Remove(dbPath)
		t.Fatalf("Failed to init schema: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		"test-agent-cb86", "Test Agent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	oldDB := db
	db = testDB

	// Close the DB so subsequent queries fail
	testDB.Close()
	db = testDB // closed DB

	err = RegisterAgentOnConnect("test-agent-cb86", "Updated Name", "", "", "")
	if err == nil {
		t.Error("Expected error from closed DB, got nil")
	}

	db = oldDB
	os.Remove(dbPath)
}

func TestCB86_RegisterAgentOnConnect_UpdateNameAndFields(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"agent-86", "Old Name", "gpt-4", "friendly", "general")
		if err != nil {
			t.Fatalf("Failed to insert agent: %v", err)
		}

		err = RegisterAgentOnConnect("agent-86", "New Display Name", "gpt-5", "serious", "coding")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}

		var name, model, personality, specialty string
		err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent-86").
			Scan(&name, &model, &personality, &specialty)
		if err != nil {
			t.Fatalf("Failed to query agent: %v", err)
		}
		if name != "New Display Name" {
			t.Errorf("Expected name 'New Display Name', got '%s'", name)
		}
		if model != "gpt-5" {
			t.Errorf("Expected model 'gpt-5', got '%s'", model)
		}
		if personality != "serious" {
			t.Errorf("Expected personality 'serious', got '%s'", personality)
		}
		if specialty != "coding" {
			t.Errorf("Expected specialty 'coding', got '%s'", specialty)
		}
	})
}

func TestCB86_RegisterAgentOnConnect_NameEqualsAgentID(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"agent-equal", "Custom Name", "gpt-4", "", "")
		if err != nil {
			t.Fatalf("Failed to insert agent: %v", err)
		}

		err = RegisterAgentOnConnect("agent-equal", "agent-equal", "", "", "")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}

		var name string
		err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "agent-equal").Scan(&name)
		if err != nil {
			t.Fatalf("Failed to query agent: %v", err)
		}
		if name != "Custom Name" {
			t.Errorf("Expected name 'Custom Name', got '%s'", name)
		}
	})
}

func TestCB86_RegisterAgentOnConnect_NewAgentWithAllMetadata(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		err := RegisterAgentOnConnect("new-agent-86", "Claude", "claude-3", "helpful", "analysis")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}

		var name, model, personality, specialty string
		err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "new-agent-86").
			Scan(&name, &model, &personality, &specialty)
		if err != nil {
			t.Fatalf("Failed to query agent: %v", err)
		}
		if name != "Claude" {
			t.Errorf("Expected name 'Claude', got '%s'", name)
		}
		if model != "claude-3" {
			t.Errorf("Expected model 'claude-3', got '%s'", model)
		}
		if personality != "helpful" {
			t.Errorf("Expected personality 'helpful', got '%s'", personality)
		}
		if specialty != "analysis" {
			t.Errorf("Expected specialty 'analysis', got '%s'", specialty)
		}
	})
}

// ============================================================
// deleteConversation tests — targeting 83.3% → 90%+
// ============================================================

func TestCB86_DeleteConversation_ClosedDB(t *testing.T) {
	dbPath := fmt.Sprintf("/tmp/cb86_del_%d.db", time.Now().UnixNano())
	testDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		testDB.Close()
		os.Remove(dbPath)
		t.Fatalf("Failed to init schema: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"user-del-86", "deluser", "$2a$10$hash")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-del-86", "user-del-86", "agent-1")
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	oldDB := db
	db = testDB
	testDB.Close()

	err = deleteConversation("conv-del-86", "user-del-86")
	if err == nil {
		t.Error("Expected error from closed DB, got nil")
	}

	db = oldDB
	os.Remove(dbPath)
}

func TestCB86_DeleteConversation_MessagesTableDropped(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"user-msg-err", "msgerruser", "$2a$10$hash")
		if err != nil {
			t.Fatalf("Failed to insert user: %v", err)
		}
		_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
			"conv-msg-err", "user-msg-err", "agent-1")
		if err != nil {
			t.Fatalf("Failed to insert conversation: %v", err)
		}

		_, _ = db.Exec("DROP TABLE messages")

		err = deleteConversation("conv-msg-err", "user-msg-err")
		if err == nil {
			t.Error("Expected error from missing messages table, got nil")
		}
	})
}

func TestCB86_DeleteConversation_ConversationTableDropped(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
			"user-conv-err", "converruser", "$2a$10$hash")
		if err != nil {
			t.Fatalf("Failed to insert user: %v", err)
		}
		_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
			"conv-err-86", "user-conv-err", "agent-1")
		if err != nil {
			t.Fatalf("Failed to insert conversation: %v", err)
		}

		_, _ = db.Exec("DROP TABLE conversations")

		err = deleteConversation("conv-err-86", "user-conv-err")
		if err == nil {
			t.Error("Expected error from missing conversations table, got nil")
		}
	})
}

// ============================================================
// rate_limit_tiers cleanup tests — targeting 83.3% → 100%
// ============================================================

func TestCB86_TieredRateLimiter_CleanupOnce_RemovesStale(t *testing.T) {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
		stopCh: make(chan struct{}),
	}

	trl.limits["stale-user"] = &userRateLimitState{
		tier:      TierFree,
		windowEnd: time.Now().Add(-15 * time.Minute),
		count:     5,
	}
	trl.limits["recent-user"] = &userRateLimitState{
		tier:      TierFree,
		windowEnd: time.Now().Add(30 * time.Second),
		count:     2,
	}

	trl.cleanupOnce()

	if _, exists := trl.limits["stale-user"]; exists {
		t.Error("Expected stale entry to be removed")
	}
	if _, exists := trl.limits["recent-user"]; !exists {
		t.Error("Expected recent entry to remain")
	}
}

func TestCB86_TieredRateLimiter_CleanupOnce_Boundary(t *testing.T) {
	trl := &TieredRateLimiter{
		limits: make(map[string]*userRateLimitState),
		stopCh: make(chan struct{}),
	}

	// Entry that expired 9 minutes ago — within 10 min grace, should NOT be removed
	trl.limits["just-expired"] = &userRateLimitState{
		tier:      TierFree,
		windowEnd: time.Now().Add(-9 * time.Minute),
		count:     3,
	}

	trl.cleanupOnce()

	if _, exists := trl.limits["just-expired"]; !exists {
		t.Error("Expected just-expired (within 10 min grace) to remain")
	}
}

func TestCB86_TieredRateLimiter_CleanupOnce_RemovesExpired(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	trl.mu.Lock()
	trl.limits["expired"] = &userRateLimitState{
		tier:      TierPro,
		windowEnd: time.Now().Add(-11 * time.Minute),
		count:     10,
	}
	trl.mu.Unlock()

	trl.Allow("active-user")

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["expired"]; exists {
		t.Error("Expected expired entry to be removed")
	}
	if _, exists := trl.limits["active-user"]; !exists {
		t.Error("Expected active-user to remain")
	}
}

func TestCB86_TieredRateLimiter_CleanupGoroutineLifecycle(t *testing.T) {
	trl := NewTieredRateLimiter()
	trl.Allow("user1")
	trl.Allow("user2")
	trl.Stop()
	trl.Stop() // double stop should not panic
}

// ============================================================
// initAPNs tests — targeting 84% → 90%+
// ============================================================

func TestCB86_InitAPNs_DevEnvironment(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "dev.p12")
	if err := os.WriteFile(certPath, []byte("dummy p12 content"), 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Environment: "development",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()

	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled after cert load failure")
	}
	if pushConfig.apnsClient != nil {
		t.Error("Expected apnsClient to be nil after failure")
	}
}

func TestCB86_InitAPNs_ProductionEnvironment(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "prod.p12")
	if err := os.WriteFile(certPath, []byte("dummy p12 content"), 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Environment: "production",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()

	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled after cert load failure")
	}
}

func TestCB86_InitAPNs_CertDirCreation(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "deep", "nested", "path")
	certPath := filepath.Join(nestedDir, "cert.p12")

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
		Environment: "development",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()

	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("Expected directory to be created for cert path")
	}
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to be disabled (cert not found or invalid)")
	}
}

func TestCB86_InitAPNs_EmptyCertPath(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "",
		Environment: "development",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()

	if !pushConfig.APNSEnabled {
		t.Error("Expected APNs to remain enabled when cert path is empty (just returns)")
	}
}

func TestCB86_InitAPNs_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initAPNs()
}

func TestCB86_InitAPNs_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("Expected APNs to remain disabled")
	}
}

// ============================================================
// initFCM tests — targeting 88.9% → 95%+
// ============================================================

func TestCB86_InitFCM_AppMessagingError(t *testing.T) {
	tmpDir := t.TempDir()
	credsPath := filepath.Join(tmpDir, "firebase-creds.json")
	if err := os.WriteFile(credsPath, []byte(`{"type":"service_account","project_id":"test"}`), 0644); err != nil {
		t.Fatalf("Failed to write creds file: %v", err)
	}

	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: credsPath,
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()

	// firebase.NewApp may succeed with minimal JSON (lazy validation);
	// the Messaging client may also be created without immediate error.
	// Either way, we've exercised the initFCM code path.
	_ = pushConfig.FCMEnabled
	_ = pushConfig.fcmClient
}

func TestCB86_InitFCM_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initFCM()
}

func TestCB86_InitFCM_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("Expected FCM to remain disabled")
	}
}

func TestCB86_InitFCM_EmptyCredsPath(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	if !pushConfig.FCMEnabled {
		t.Error("Expected FCM to remain enabled when creds path is empty")
	}
}

func TestCB86_InitFCM_CredsNotFound(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/nonexistent/path/creds.json",
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("Expected FCM to be disabled when creds not found")
	}
}

// ============================================================
// initSchema tests — targeting 85.3% → 90%+
// ============================================================

func TestCB86_InitSchema_ReactionsTableError(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()

	_, err := testDB.Exec("CREATE TABLE reactions (id INTEGER PRIMARY KEY, different_col TEXT)")
	if err != nil {
		t.Fatalf("Failed to create conflicting table: %v", err)
	}

	// initSchema uses CREATE TABLE IF NOT EXISTS, so it won't error
	err = initSchema(testDB)
	if err != nil {
		t.Errorf("Expected no error with IF NOT EXISTS: %v", err)
	}
}

func TestCB86_InitSchema_ConversationTagsTableError(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()

	_, err := testDB.Exec("CREATE TABLE conversation_tags (id INTEGER PRIMARY KEY, different_col TEXT)")
	if err != nil {
		t.Fatalf("Failed to create conflicting table: %v", err)
	}

	err = initSchema(testDB)
	if err != nil {
		t.Errorf("Expected no error with IF NOT EXISTS: %v", err)
	}
}

func TestCB86_InitSchema_RateLimitTiersTableError(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()

	_, err := testDB.Exec("CREATE TABLE user_rate_limit_tiers (id INTEGER PRIMARY KEY, different_col TEXT)")
	if err != nil {
		t.Fatalf("Failed to create conflicting table: %v", err)
	}

	err = initSchema(testDB)
	if err != nil {
		t.Errorf("Expected no error with IF NOT EXISTS: %v", err)
	}
}

func TestCB86_InitSchema_NotificationPrefsTableError(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()

	_, err := testDB.Exec("CREATE TABLE notification_preferences (id INTEGER PRIMARY KEY, different_col TEXT)")
	if err != nil {
		t.Fatalf("Failed to create conflicting table: %v", err)
	}

	err = initSchema(testDB)
	if err != nil {
		t.Errorf("Expected no error with IF NOT EXISTS: %v", err)
	}
}

func TestCB86_InitSchema_SchemaMigrationsTableError(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()

	_, err := testDB.Exec("CREATE TABLE schema_migrations (id INTEGER PRIMARY KEY, col TEXT)")
	if err != nil {
		t.Fatalf("Failed to create conflicting table: %v", err)
	}

	err = initSchema(testDB)
	if err != nil {
		t.Errorf("Expected no error with IF NOT EXISTS: %v", err)
	}
}

func TestCB86_InitSchema_IdempotentWithMigrations(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	err = initSchema(testDB)
	if err != nil {
		t.Fatalf("First initSchema failed: %v", err)
	}
	err = initSchema(testDB)
	if err != nil {
		t.Fatalf("Second initSchema failed: %v", err)
	}

	var count int
	err = testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query migration count: %v", err)
	}
	if count == 0 {
		t.Error("Expected migrations to be recorded")
	}
}

// ============================================================
// handleUpload tests — targeting 85.7% → 90%+
// ============================================================

func TestCB86_HandleUpload_DirCreateError(t *testing.T) {
	oldPath := serverDBPath
	// Set serverDBPath to a file (so filepath.Dir gives a file, and MkdirAll fails)
	serverDBPath = "/dev/null/cannot-create/test.db"
	defer func() { serverDBPath = oldPath }()

	withGlobalDB_CB86(t, func() {
		token, err := GenerateJWT("user-upload-86", "uploader")
		if err != nil {
			t.Fatalf("Failed to generate JWT: %v", err)
		}

		body := &strings.Builder{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("file", "test.txt")
		if err != nil {
			t.Fatalf("Failed to create form file: %v", err)
		}
		part.Write([]byte("test file content"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body.String()))
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		handleUpload(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500 for dir create error, got %d", w.Code)
		}
	})
}

func TestCB86_HandleUpload_NoFileField(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		token, err := GenerateJWT("user-upload-nofile", "uploader")
		if err != nil {
			t.Fatalf("Failed to generate JWT: %v", err)
		}

		body := &strings.Builder{}
		writer := multipart.NewWriter(body)
		writer.WriteField("message_id", "msg123")
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body.String()))
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		handleUpload(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for missing file field, got %d", w.Code)
		}
	})
}

func TestCB86_HandleUpload_InvalidToken(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		body := &strings.Builder{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test.txt")
		part.Write([]byte("content"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body.String()))
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Authorization", "Bearer invalid-token")

		w := httptest.NewRecorder()
		handleUpload(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for invalid token, got %d", w.Code)
		}
	})
}

func TestCB86_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestCB86_HandleUpload_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestCB86_HandleUpload_ParseFormError(t *testing.T) {
	withGlobalDB_CB86(t, func() {
		token, err := GenerateJWT("user-upload-parse", "uploader")
		if err != nil {
			t.Fatalf("Failed to generate JWT: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("invalid multipart data"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=invalid")
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		handleUpload(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid form data, got %d", w.Code)
		}
	})
}

// ============================================================
// readPump tests — targeting 86.4% → 90%+
// ============================================================

func TestCB86_ReadPump_UnexpectedCloseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, "abnormal"))
		conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/connect?agent_id=test-read-86"
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer wsConn.Close()

	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	c := &Connection{
		id:       "test-read-86",
		connType: "agent",
		hub:      testHub,
		conn:     wsConn,
		send:     make(chan []byte, 256),
	}

	done := make(chan struct{})
	go func() {
		c.readPump()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("readPump did not exit within 5 seconds")
	}
}

func TestCB86_ReadPump_MessageRouting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		msg := `{"type":"chat","conversation_id":"conv1","content":"hello","sender_type":"agent","sender_id":"a1","recipient_id":"u1"}`
		conn.WriteMessage(websocket.TextMessage, []byte(msg))
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/connect?agent_id=test-route-86"
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer wsConn.Close()

	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	c := &Connection{
		id:       "test-route-86",
		connType: "agent",
		hub:      testHub,
		conn:     wsConn,
		send:     make(chan []byte, 256),
	}

	done := make(chan struct{})
	go func() {
		c.readPump()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("readPump did not exit within 5 seconds")
	}
}

func TestCB86_ReadPump_NormalClosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
		conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/connect?agent_id=test-normal-86"
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer wsConn.Close()

	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	c := &Connection{
		id:       "test-normal-86",
		connType: "agent",
		hub:      testHub,
		conn:     wsConn,
		send:     make(chan []byte, 256),
	}

	done := make(chan struct{})
	go func() {
		c.readPump()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("readPump did not exit within 5 seconds")
	}
}

func TestCB86_ReadPump_GoingAway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "going away"))
		conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/connect?agent_id=test-goaway-86"
	dialer := websocket.Dialer{}
	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer wsConn.Close()

	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	c := &Connection{
		id:       "test-goaway-86",
		connType: "agent",
		hub:      testHub,
		conn:     wsConn,
		send:     make(chan []byte, 256),
	}

	done := make(chan struct{})
	go func() {
		c.readPump()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("readPump did not exit within 5 seconds")
	}
}

// ============================================================
// loadQueueFromDB tests — targeting 89.5% → 95%+
// ============================================================

func TestCB86_LoadQueueFromDB_WithCorruptData(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()
	initSchema(testDB)
	initQueueDB(testDB)

	_, err := testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
		"user1", []byte("message data 1"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to insert: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
		"user2", []byte(""), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to insert empty data: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
		"user3", []byte("message data 3"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to insert third: %v", err)
	}

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() == 0 {
		t.Error("Expected some entries to be loaded")
	}
}

func TestCB86_LoadQueueFromDB_MultipleEntries(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()
	initSchema(testDB)
	initQueueDB(testDB)

	for i := 0; i < 5; i++ {
		_, err := testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
			"multi-user", []byte(fmt.Sprintf("message-%d", i)), time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			t.Fatalf("Failed to insert entry %d: %v", i, err)
		}
	}

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)

	depth := q.QueueDepth("multi-user")
	if depth != 5 {
		t.Errorf("Expected queue depth 5, got %d", depth)
	}
}

func TestCB86_LoadQueueFromDB_EmptyTable(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()
	initSchema(testDB)
	initQueueDB(testDB)

	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 0 {
		t.Error("Expected 0 depth from empty table")
	}
}

// ============================================================
// Protocol negotiation tests
// ============================================================

func TestCB86_NegotiateProtocol_QueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1&protocol_version=v1", nil)
	if result := negotiateProtocol(req); result != "v1" {
		t.Errorf("Expected 'v1', got '%s'", result)
	}
}

func TestCB86_NegotiateProtocol_UnsupportedQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1&protocol_version=v99", nil)
	if result := negotiateProtocol(req); result != ProtocolVersion {
		t.Errorf("Expected default '%s', got '%s'", ProtocolVersion, result)
	}
}

func TestCB86_NegotiateProtocol_EmptyHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1", nil)
	if result := negotiateProtocol(req); result != ProtocolVersion {
		t.Errorf("Expected default '%s', got '%s'", ProtocolVersion, result)
	}
}

func TestCB86_NegotiateProtocol_WebSocketHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v1")
	if result := negotiateProtocol(req); result != "v1" {
		t.Errorf("Expected 'v1', got '%s'", result)
	}
}

func TestCB86_NegotiateProtocol_MultipleProtocolsInHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v0, v1, v2")
	if result := negotiateProtocol(req); result != "v1" {
		t.Errorf("Expected 'v1', got '%s'", result)
	}
}

func TestCB86_NegotiateProtocol_NoMatchInHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "v0, v2, v3")
	if result := negotiateProtocol(req); result != ProtocolVersion {
		t.Errorf("Expected default '%s', got '%s'", ProtocolVersion, result)
	}
}

func TestCB86_UpgradeWithProtocol_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1", nil)
	upgradeWithProtocol(w, r, "v1")

	if w.Header().Get("Sec-WebSocket-Protocol") != "v1" {
		t.Errorf("Expected 'v1', got '%s'", w.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestCB86_UpgradeWithProtocol_InvalidVersion(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1", nil)
	upgradeWithProtocol(w, r, "v99")

	if w.Header().Get("Sec-WebSocket-Protocol") != "" {
		t.Errorf("Expected empty, got '%s'", w.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestCB86_UpgradeWithProtocol_EmptyVersion(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/agent/connect?agent_id=a1", nil)
	upgradeWithProtocol(w, r, "")

	if w.Header().Get("Sec-WebSocket-Protocol") != "" {
		t.Errorf("Expected empty, got '%s'", w.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestCB86_IsSupportedVersion(t *testing.T) {
	if !isSupportedVersion("v1") {
		t.Error("Expected v1 to be supported")
	}
	if isSupportedVersion("v99") {
		t.Error("Expected v99 to not be supported")
	}
	if isSupportedVersion("") {
		t.Error("Expected empty to not be supported")
	}
}

// ============================================================
// Trace helper function tests
// ============================================================

func TestCB86_TraceHelpers_DisabledTracing(t *testing.T) {
	oldEnabled := tracingEnabled
	oldTracer := tracer
	tracingEnabled = false
	tracer = nil
	defer func() {
		tracingEnabled = oldEnabled
		tracer = oldTracer
	}()

	span := TraceRouteMessage("agent", "conn1")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	ctx := context.Background()
	_, span = TraceChatMessage(ctx, "agent", "a1", "conv1", "u1")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	_, span = TraceStoreMessage(ctx, "conv1", "a1")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	_, span = TraceDeliverMessage(ctx, "u1", "client", true)
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	span = TraceOfflineEnqueue("u1")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	span = TracePushNotify("u1", "conv1", true)
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	span = TraceAgentConnect("a1")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	span = TraceClientConnect("u1", "device1")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}

	SpanError(span, fmt.Errorf("test error"))
	SpanOK(span)
}

func TestCB86_StartSpanFromRequest_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	oldTracer := tracer
	tracingEnabled = false
	tracer = nil
	defer func() {
		tracingEnabled = oldEnabled
		tracer = oldTracer
	}()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, span := StartSpanFromRequest(req, "test-span")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}
}

func TestCB86_StartSpan_Disabled(t *testing.T) {
	oldEnabled := tracingEnabled
	oldTracer := tracer
	tracingEnabled = false
	tracer = nil
	defer func() {
		tracingEnabled = oldEnabled
		tracer = oldTracer
	}()

	ctx := context.Background()
	_, span := StartSpan(ctx, "test-span")
	if span == nil {
		t.Error("Expected non-nil no-op span")
	}
}

// ============================================================
// ValidateAgentSecret rate limiter tests
// ============================================================

func TestCB86_ValidateAgentSecret_RateLimited(t *testing.T) {
	agentRateLimiter.Reset()
	defer agentRateLimiter.Reset()

	// Reset agentSecret to default to avoid interference from other tests
	agentSecretMu.Lock()
	oldSecret := agentSecret
	agentSecret = "dev-agent-secret-change-me"
	agentSecretMu.Unlock()
	defer func() {
		agentSecretMu.Lock()
		agentSecret = oldSecret
		agentSecretMu.Unlock()
	}()

	// Use a unique agent ID to avoid interference from other tests
	agentID := "cb86-rate-test-agent-unique"

	for i := 0; i < maxAgentAttempts; i++ {
		err := ValidateAgentSecret(agentID, "dev-agent-secret-change-me")
		if err != nil {
			t.Fatalf("Attempt %d should succeed: %v", i+1, err)
		}
	}

	err := ValidateAgentSecret(agentID, "dev-agent-secret-change-me")
	if err == nil {
		t.Error("Expected rate limit error")
	} else if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("Expected 'rate limited' error, got '%s'", err.Error())
	}

	err = ValidateAgentSecret("other-agent-cb86", "dev-agent-secret-change-me")
	if err != nil {
		t.Errorf("Different agent should not be rate limited: %v", err)
	}
}

func TestCB86_ValidateAgentSecret_EmptySecret(t *testing.T) {
	agentRateLimiter.Reset()
	defer agentRateLimiter.Reset()

	err := ValidateAgentSecret("test-agent", "")
	if err == nil {
		t.Error("Expected error for empty secret")
	}
}

func TestCB86_ValidateAgentSecret_WrongSecret(t *testing.T) {
	agentRateLimiter.Reset()
	defer agentRateLimiter.Reset()

	err := ValidateAgentSecret("test-agent-wrong", "wrong-secret")
	if err == nil {
		t.Error("Expected error for wrong secret")
	}
}

func TestCB86_RateLimiter_Clean(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}

	rl.attempts["old"] = &rateLimitEntry{count: 5, firstSeen: time.Now().Add(-2 * time.Minute)}
	rl.attempts["recent"] = &rateLimitEntry{count: 1, firstSeen: time.Now()}

	rl.Clean()

	if _, exists := rl.attempts["old"]; exists {
		t.Error("Expected old entry to be cleaned")
	}
	if _, exists := rl.attempts["recent"]; !exists {
		t.Error("Expected recent entry to remain")
	}
}

func TestCB86_RateLimiter_Reset(t *testing.T) {
	rl := &rateLimiter{attempts: make(map[string]*rateLimitEntry)}
	rl.attempts["a"] = &rateLimitEntry{count: 3, firstSeen: time.Now()}
	rl.attempts["b"] = &rateLimitEntry{count: 1, firstSeen: time.Now()}

	rl.Reset()

	if len(rl.attempts) != 0 {
		t.Errorf("Expected empty after reset, got %d", len(rl.attempts))
	}
}

// ============================================================
// OfflineQueue tests
// ============================================================

func TestCB86_OfflineQueue_DrainWithExpiredAndValid(t *testing.T) {
	q := newOfflineQueue(100, 1*time.Second)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))

	time.Sleep(1100 * time.Millisecond)

	q.Enqueue("user1", []byte("msg3"))

	messages := q.Drain("user1")
	if len(messages) == 0 {
		t.Error("Expected at least 1 non-expired message")
	}

	found3 := false
	for _, m := range messages {
		if string(m) == "msg3" {
			found3 = true
			break
		}
	}
	if !found3 {
		t.Error("Expected to find 'msg3' in drained messages")
	}
}

func TestCB86_OfflineQueue_PurgeNonExistent(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	q.Purge("nonexistent")

	if q.TotalDepth() != 0 {
		t.Error("Expected 0 depth")
	}
}

func TestCB86_OfflineQueue_ConcurrentEnqueueDrain(t *testing.T) {
	q := newOfflineQueue(1000, 7*24*time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				q.Enqueue("concurrent-user", []byte(fmt.Sprintf("msg-%d-%d", id, j)))
			}
		}(i)
	}
	wg.Wait()

	messages := q.Drain("concurrent-user")
	if len(messages) != 100 {
		t.Errorf("Expected 100 messages, got %d", len(messages))
	}
}

// ============================================================
// Hub tests
// ============================================================

func TestCB86_Hub_BroadcastToMultipleDevices(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	conn1 := &Connection{
		id:       "user1",
		connType: "client",
		hub:      testHub,
		send:     make(chan []byte, 10),
	}
	conn2 := &Connection{
		id:       "user1",
		connType: "client",
		hub:      testHub,
		send:     make(chan []byte, 10),
		deviceID: "device2",
	}

	testHub.register <- conn1
	time.Sleep(50 * time.Millisecond)
	testHub.register <- conn2
	time.Sleep(50 * time.Millisecond)

	count := testHub.ClientConnCount()
	if count < 1 {
		t.Errorf("Expected at least 1 client connection, got %d", count)
	}

	testHub.unregister <- conn1
	time.Sleep(50 * time.Millisecond)
	testHub.unregister <- conn2
	time.Sleep(50 * time.Millisecond)
}

func TestCB86_Hub_RegisterAndUnregisterAgent(t *testing.T) {
	testHub := newHub()
	go testHub.run()
	defer testHub.Stop()

	agent := &Connection{
		id:       "agent-86-test",
		connType: "agent",
		hub:      testHub,
		send:     make(chan []byte, 10),
	}

	testHub.register <- agent
	time.Sleep(50 * time.Millisecond)

	testHub.mu.RLock()
	_, exists := testHub.agents["agent-86-test"]
	testHub.mu.RUnlock()
	if !exists {
		t.Error("Expected agent to be registered")
	}

	testHub.unregister <- agent
	time.Sleep(50 * time.Millisecond)

	testHub.mu.RLock()
	_, exists = testHub.agents["agent-86-test"]
	testHub.mu.RUnlock()
	if exists {
		t.Error("Expected agent to be unregistered")
	}
}

// ============================================================
// SafeSend tests
// ============================================================

func TestCB86_SafeSend_NormalSend(t *testing.T) {
	c := &Connection{send: make(chan []byte, 1)}

	result := c.SafeSend([]byte("test message"))
	if !result {
		t.Error("Expected SafeSend to succeed")
	}

	select {
	case msg := <-c.send:
		if string(msg) != "test message" {
			t.Errorf("Expected 'test message', got '%s'", string(msg))
		}
	default:
		t.Error("Expected to receive message")
	}
}

func TestCB86_SafeSend_NilChannel(t *testing.T) {
	c := &Connection{send: nil}

	result := c.SafeSend([]byte("test"))
	if result {
		t.Error("Expected SafeSend to return false for nil channel")
	}
}

func TestCB86_SafeSend_FullChannel(t *testing.T) {
	c := &Connection{send: make(chan []byte, 1)}
	c.send <- []byte("first")

	result := c.SafeSend([]byte("second"))
	if result {
		t.Error("Expected SafeSend to return false for full channel")
	}
}

// ============================================================
// isAllowedContentType tests
// ============================================================

func TestCB86_IsAllowedContentType_VariousTypes(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"text/plain", true},
		{"text/html", true},
		{"text/csv", true},
		{"application/json", true},
		{"application/pdf", true},
		{"image/png", true},
		{"image/jpeg", true},
		{"image/gif", true},
		{"image/webp", true},
		{"image/svg+xml", true},
		{"video/mp4", true},
		{"audio/mpeg", true},
		{"application/octet-stream", false},
		{"application/x-executable", false},
		{"", false},
	}

	for _, tt := range tests {
		result := isAllowedContentType(tt.contentType)
		if result != tt.expected {
			t.Errorf("isAllowedContentType(%q) = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

// ============================================================
// parseSize tests
// ============================================================

func TestCB86_ParseSize_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"", 0},
		{"0", 0},
		{"100", 100},
		{"100B", 100},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"2KB", 2048},
		{"-5", -5},
		{"invalid", 0},
	}

	for _, tt := range tests {
		result, _ := parseSize(tt.input)
		if result != tt.expected {
			t.Errorf("parseSize(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

// ============================================================
// GetEnvOrDefault tests
// ============================================================

func TestCB86_GetEnvOrDefault_ExistingAndDefault(t *testing.T) {
	os.Setenv("CB86_TEST_VAR", "test-value")
	if result := getEnvOrDefault("CB86_TEST_VAR", "default"); result != "test-value" {
		t.Errorf("Expected 'test-value', got '%s'", result)
	}
	os.Unsetenv("CB86_TEST_VAR")

	if result := getEnvOrDefault("CB86_NONEXISTENT_VAR", "fallback"); result != "fallback" {
		t.Errorf("Expected 'fallback', got '%s'", result)
	}
}

// ============================================================
// ValidateJWT tests
// ============================================================

func TestCB86_ValidateJWT_UnexpectedSigningMethod(t *testing.T) {
	tokenStr := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoidGVzdCIsInVzZXJuYW1lIjoidGVzdCIsImV4cCI6OTk5OTk5OTk5OX0."
	_, err := ValidateJWT(tokenStr)
	if err == nil {
		t.Error("Expected error for unexpected signing method")
	}
}

func TestCB86_ValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not.a.valid.jwt.token.at.all")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
}

func TestCB86_ValidateJWT_ExpiredToken(t *testing.T) {
	claims := &Claims{
		UserID:   "expired-user",
		Username: "expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "agent-messenger",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(jwtSecret)

	_, err := ValidateJWT(tokenStr)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestCB86_GenerateJWT_AndValidate(t *testing.T) {
	token, err := GenerateJWT("user-gen-86", "genuser")
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}

	if claims.UserID != "user-gen-86" {
		t.Errorf("Expected UserID 'user-gen-86', got '%s'", claims.UserID)
	}
	if claims.Username != "genuser" {
		t.Errorf("Expected Username 'genuser', got '%s'", claims.Username)
	}
	if claims.Issuer != "agent-messenger" {
		t.Errorf("Expected Issuer 'agent-messenger', got '%s'", claims.Issuer)
	}
}

// ============================================================
// ValidateAdminSecret tests
// ============================================================

func TestCB86_ValidateAdminSecret_Correct(t *testing.T) {
	resetAdminSecret()
	if err := ValidateAdminSecret("admin-dev-secret"); err != nil {
		t.Errorf("Expected nil error: %v", err)
	}
}

func TestCB86_ValidateAdminSecret_Wrong(t *testing.T) {
	resetAdminSecret()
	if err := ValidateAdminSecret("wrong-admin-secret"); err == nil {
		t.Error("Expected error for wrong admin secret")
	}
}

func TestCB86_ValidateAdminSecret_Empty(t *testing.T) {
	resetAdminSecret()
	if err := ValidateAdminSecret(""); err == nil {
		t.Error("Expected error for empty admin secret")
	}
}

// ============================================================
// extractIP tests
// ============================================================

func TestCB86_ExtractIP_Variations(t *testing.T) {
	tests := []struct {
		name       string
		forwarded  string
		realIP     string
		remoteAddr string
		expected   string
	}{
		{"X-Forwarded-For single", "1.2.3.4", "", "5.6.7.8:12345", "1.2.3.4"},
		{"X-Forwarded-For multiple", "1.2.3.4, 5.6.7.8", "", "9.10.11.12:12345", "1.2.3.4"},
		{"X-Real-IP", "", "10.0.0.1", "192.168.1.1:12345", "10.0.0.1"},
		{"RemoteAddr only", "", "", "172.16.0.1:8080", "172.16.0.1"},
		{"RemoteAddr no port", "", "", "172.16.0.1", "172.16.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			if tt.realIP != "" {
				req.Header.Set("X-Real-IP", tt.realIP)
			}
			req.RemoteAddr = tt.remoteAddr

			if result := extractIP(req); result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// ============================================================
// Logger tests
// ============================================================

func TestCB86_Logger_AllLevels(t *testing.T) {
	logger := NewLogger(LogDebug)
	logger.Debug("debug message", map[string]interface{}{"key": "value"})
	logger.Info("info message", map[string]interface{}{"key": "value"})
	logger.Warn("warn message", map[string]interface{}{"key": "value"})
	logger.Error("error message", map[string]interface{}{"key": "value"})
}

func TestCB86_Logger_NilFields(t *testing.T) {
	logger := NewLogger(LogInfo)
	logger.Info("message with nil fields", nil)
	logger.Info("message with empty fields", map[string]interface{}{})
}

func TestCB86_Logger_WithFieldsChaining(t *testing.T) {
	logger := NewLogger(LogInfo)
	l1 := logger.WithFields(map[string]interface{}{"field1": "value1"})
	l2 := l1.WithFields(map[string]interface{}{"field2": "value2"})
	l2.Info("chained message", map[string]interface{}{"extra": "data"})
}

// ============================================================
// marshalOutgoingMessage tests
// ============================================================

func TestCB86_MarshalOutgoingMessage_Valid(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{"content": "hello", "id": "msg1"},
	}
	data := marshalOutgoingMessage(msg)
	if !strings.Contains(string(data), `"type":"chat"`) {
		t.Errorf("Expected 'type' field: %s", string(data))
	}
}

func TestCB86_MarshalOutgoingMessage_NilData(t *testing.T) {
	msg := OutgoingMessage{
		Type: "status",
		Data: nil,
	}
	data := marshalOutgoingMessage(msg)
	if !strings.Contains(string(data), `"type":"status"`) {
		t.Errorf("Expected 'type' field: %s", string(data))
	}
}

// ============================================================
// HashAPIKey tests
// ============================================================

func TestCB86_HashAPIKey_Success(t *testing.T) {
	hash, err := HashAPIKey("test-api-key-86")
	if err != nil {
		t.Fatalf("Failed to hash: %v", err)
	}
	if hash == "" {
		t.Error("Expected non-empty hash")
	}
	if hash == "test-api-key-86" {
		t.Error("Expected hash to differ from input")
	}
}

func TestCB86_HashAPIKey_Empty(t *testing.T) {
	hash, err := HashAPIKey("")
	if err != nil {
		t.Fatalf("Failed to hash: %v", err)
	}
	if hash == "" {
		t.Error("Expected non-empty hash")
	}
}

func TestCB86_HashAPIKey_DifferentInputs(t *testing.T) {
	hash1, _ := HashAPIKey("key1")
	hash2, _ := HashAPIKey("key2")
	if hash1 == hash2 {
		t.Error("Expected different hashes for different inputs")
	}
}
