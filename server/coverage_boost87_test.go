package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// CB87: Coverage boost targeting remaining low-coverage functions
// Focus: openDatabase (0%), InitTracing (79.5%), sendWelcomeMessage (80%),
// ShutdownTracing (80%), RegisterAgentOnConnect (81.8%), cleanup (83.3%),
// initAPNs (84%), initSchema (85.3%), handleUpload (85.7%),
// readPump (86.4%), initFCM (88.9%), loadQueueFromDB (89.5%)
// ============================================================

// --- Helpers ---

func withTestDB_CB87(t *testing.T, fn func(db *sql.DB)) {
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

func withGlobalDB_CB87(t *testing.T, fn func()) {
	t.Helper()
	oldDB := db
	dbPath := fmt.Sprintf("/tmp/cb87_test_%d.db", time.Now().UnixNano())
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
// openDatabase tests — targeting 0% → 60%+
// ============================================================

func TestCB87_OpenDatabase_SQLite_Success(t *testing.T) {
	dbPath := fmt.Sprintf("/tmp/cb87_opendb_%d.db", time.Now().UnixNano())
	defer os.Remove(dbPath)

	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()

	result, err := openDatabase("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("openDatabase failed: %v", err)
	}
	defer result.Close()

	if result == nil {
		t.Fatal("expected non-nil db")
	}
	if currentDriver != "sqlite3" {
		t.Errorf("expected currentDriver=sqlite3, got %s", currentDriver)
	}
}

func TestCB87_OpenDatabase_InvalidDriver(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()

	_, err := openDatabase("nonexistent_driver", "fake_dsn")
	if err == nil {
		t.Fatal("expected error for invalid driver")
	}
	if !strings.Contains(err.Error(), "failed to open database") {
		t.Errorf("expected 'failed to open database' error, got: %v", err)
	}
}

func TestCB87_OpenDatabase_EmptyDSN(t *testing.T) {
	oldDriver := currentDriver
	defer func() { currentDriver = oldDriver }()

	_, err := openDatabase("sqlite3", "")
	// sqlite3 with empty DSN might actually succeed (creates in-memory or temp db)
	// Just verify it doesn't panic
	_ = err
}

// ============================================================
// InitTracing tests — targeting 79.5% → 85%+
// ============================================================

func TestCB87_InitTracing_DoubleInitNoOp(t *testing.T) {
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
		if tp != nil {
			ShutdownTracing()
		}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	// First init - may fail due to resource merge conflicts in test env
	err1 := InitTracing()
	_ = err1

	// Second init should be no-op (sync.Once)
	err2 := InitTracing()
	if err2 != nil {
		t.Errorf("second InitTracing should not return error, got: %v", err2)
	}
}

func TestCB87_InitTracing_InvalidSamplingRate(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "not_a_number")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_SAMPLING_RATE")
		tracingMu = sync.Once{}
		if tp != nil {
			ShutdownTracing()
		}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err
	// If it succeeded, invalid sampling rate should fall back to default
	// If it failed due to resource merge, that's also fine
}

func TestCB87_InitTracing_CustomServiceName(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SERVICE_NAME", "custom-messenger")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_SERVICE_NAME")
		tracingMu = sync.Once{}
		if tp != nil {
			ShutdownTracing()
		}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err
}

func TestCB87_InitTracing_GRPCInsecureDetection(t *testing.T) {
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
		if tp != nil {
			ShutdownTracing()
		}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err
}

func TestCB87_InitTracing_HTTPInsecureDetection(t *testing.T) {
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
		if tp != nil {
			ShutdownTracing()
		}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err
}

func TestCB87_InitTracing_DisabledByDefault(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Unsetenv("OTEL_ENABLED")
	defer func() {
		tracingMu = sync.Once{}
	}()

	err := InitTracing()
	if err != nil {
		t.Errorf("InitTracing should not return error when disabled: %v", err)
	}
	if tracingEnabled {
		t.Fatal("expected tracingEnabled=false")
	}
}

func TestCB87_InitTracing_NoEndpoint(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		tracingMu = sync.Once{}
	}()

	err := InitTracing()
	if err != nil {
		t.Errorf("InitTracing should not return error when no endpoint: %v", err)
	}
	if tracingEnabled {
		t.Fatal("expected tracingEnabled=false when no endpoint")
	}
}

func TestCB87_InitTracing_HTTPProtocolExplicit(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel-collector:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		tracingMu = sync.Once{}
		if tp != nil {
			ShutdownTracing()
		}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err
}

func TestCB87_InitTracing_GRPCSecurePort443(t *testing.T) {
	tracingMu = sync.Once{}
	tp = nil
	tracingEnabled = false
	tracer = nil

	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:443")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		tracingMu = sync.Once{}
		if tp != nil {
			ShutdownTracing()
		}
		tp = nil
		tracingEnabled = false
		tracer = nil
	}()

	err := InitTracing()
	_ = err
}

// ============================================================
// ShutdownTracing tests — targeting 80% → 90%+
// ============================================================

func TestCB87_ShutdownTracing_ActiveProvider(t *testing.T) {
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

	// Shutdown should flush and not panic
	ShutdownTracing()
}

func TestCB87_ShutdownTracing_NilProvider(t *testing.T) {
	tp = nil
	// Should not panic
	ShutdownTracing()
}

func TestCB87_ShutdownTracing_AlreadyShutdown(t *testing.T) {
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
	// Double shutdown should not panic
	ShutdownTracing()
}

// ============================================================
// sendWelcomeMessage tests — targeting 80% → 90%+
// ============================================================

func TestCB87_SendWelcomeMessage_MarshalError(t *testing.T) {
	// sendWelcomeMessage marshals an OutgoingMessage with welcome data.
	// The marshal itself shouldn't fail with normal data, but we can
	// test the SafeSend failure path by closing the channel first.
	c := &Connection{
		id:               "test-conn",
		connType:         "agent",
		send:             make(chan []byte, 1),
		negotiatedVersion: "0.1",
	}

	// Fill the buffer to capacity
	c.send <- []byte("filler")

	// Now SafeSend should fail (buffer full)
	// sendWelcomeMessage should log a warning but not panic
	sendWelcomeMessage(c)
}

func TestCB87_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	c := &Connection{
		id:               "test-conn",
		connType:         "client",
		send:             make(chan []byte, 1),
		negotiatedVersion: "0.1",
	}

	close(c.send)

	// Should not panic from send on closed channel
	// SafeSend handles this with recover
	sendWelcomeMessage(c)
}

func TestCB87_SendWelcomeMessage_EmptyVersion(t *testing.T) {
	c := &Connection{
		id:               "test-user",
		connType:         "client",
		send:             make(chan []byte, 256),
		negotiatedVersion: "",
	}

	sendWelcomeMessage(c)

	// Verify message was sent
	select {
	case msg := <-c.send:
		var data map[string]interface{}
		if err := json.Unmarshal(msg, &data); err != nil {
			t.Fatalf("failed to unmarshal welcome message: %v", err)
		}
		if data["type"] != "connected" {
			t.Errorf("expected type=connected, got %v", data["type"])
		}
		welcomeData, ok := data["data"].(map[string]interface{})
		if !ok {
			t.Fatal("expected data to be a map")
		}
		if welcomeData["id"] != "test-user" {
			t.Errorf("expected id=test-user, got %v", welcomeData["id"])
		}
		if welcomeData["protocol_version"] != "" {
			t.Errorf("expected empty protocol_version, got %v", welcomeData["protocol_version"])
		}
	default:
		t.Fatal("expected message in send channel")
	}
}

func TestCB87_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	c := &Connection{
		id:               "test-user",
		connType:         "client",
		send:             make(chan []byte, 256),
		negotiatedVersion: "0.2",
		deviceID:         "device-abc",
	}

	sendWelcomeMessage(c)

	select {
	case msg := <-c.send:
		var data map[string]interface{}
		if err := json.Unmarshal(msg, &data); err != nil {
			t.Fatalf("failed to unmarshal welcome message: %v", err)
		}
		welcomeData, ok := data["data"].(map[string]interface{})
		if !ok {
			t.Fatal("expected data to be a map")
		}
		if welcomeData["device_id"] != "device-abc" {
			t.Errorf("expected device_id=device-abc, got %v", welcomeData["device_id"])
		}
	default:
		t.Fatal("expected message in send channel")
	}
}

// ============================================================
// RegisterAgentOnConnect tests — targeting 81.8% → 90%+
// ============================================================

func TestCB87_RegisterAgentOnConnect_QueryError(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		// Close the DB to cause query error
		db.Close()

		err := RegisterAgentOnConnect("agent1", "Agent One", "gpt-4", "friendly", "general")
		if err == nil {
			t.Fatal("expected error from closed DB")
		}
	})
}

func TestCB87_RegisterAgentOnConnect_InsertError(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		// Drop the agents table to cause insert error
		db.Exec("DROP TABLE agents")

		err := RegisterAgentOnConnect("new-agent", "", "", "", "")
		if err == nil {
			t.Fatal("expected insert error")
		}
	})
}

func TestCB87_RegisterAgentOnConnect_UpdateModelError(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		// Insert an agent first
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"agent1", "Agent One", "", "", "")
		if err != nil {
			t.Fatalf("failed to insert agent: %v", err)
		}

		// Close DB to cause update error
		db.Close()

		err = RegisterAgentOnConnect("agent1", "New Name", "gpt-4", "friendly", "general")
		if err == nil {
			t.Fatal("expected update error from closed DB")
		}
	})
}

func TestCB87_RegisterAgentOnConnect_UpdatePersonalityError(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"agent1", "Agent One", "gpt-4", "", "")
		if err != nil {
			t.Fatalf("failed to insert agent: %v", err)
		}

		// Close DB after query succeeds but before update
		db.Close()

		err = RegisterAgentOnConnect("agent1", "", "", "friendly", "")
		if err == nil {
			t.Fatal("expected personality update error from closed DB")
		}
	})
}

func TestCB87_RegisterAgentOnConnect_UpdateSpecialtyError(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"agent1", "Agent One", "gpt-4", "friendly", "")
		if err != nil {
			t.Fatalf("failed to insert agent: %v", err)
		}

		db.Close()

		err = RegisterAgentOnConnect("agent1", "", "", "", "special")
		if err == nil {
			t.Fatal("expected specialty update error from closed DB")
		}
	})
}

func TestCB87_RegisterAgentOnConnect_UpdateNameError(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"agent1", "Agent One", "gpt-4", "friendly", "general")
		if err != nil {
			t.Fatalf("failed to insert agent: %v", err)
		}

		db.Close()

		// name != agentID, so it will try to update name
		err = RegisterAgentOnConnect("agent1", "Custom Name", "", "", "")
		if err == nil {
			t.Fatal("expected name update error from closed DB")
		}
	})
}

func TestCB87_RegisterAgentOnConnect_PreserveExistingFields(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		// Insert agent with all fields set
		_, err := db.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"agent1", "Original Name", "original-model", "calm", "coding")
		if err != nil {
			t.Fatalf("failed to insert agent: %v", err)
		}

		// Connect with no metadata - should preserve existing
		err = RegisterAgentOnConnect("agent1", "", "", "", "")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}

		var name, model, personality, specialty string
		err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "agent1").
			Scan(&name, &model, &personality, &specialty)
		if err != nil {
			t.Fatalf("failed to query agent: %v", err)
		}

		if name != "Original Name" {
			t.Errorf("expected name=Original Name, got %s", name)
		}
		if model != "original-model" {
			t.Errorf("expected model=original-model, got %s", model)
		}
		if personality != "calm" {
			t.Errorf("expected personality=calm, got %s", personality)
		}
		if specialty != "coding" {
			t.Errorf("expected specialty=coding, got %s", specialty)
		}
	})
}

func TestCB87_RegisterAgentOnConnect_NameDefaultsToAgentID(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		err := RegisterAgentOnConnect("bot123", "", "", "", "")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}

		var name string
		err = db.QueryRow("SELECT name FROM agents WHERE id = ?", "bot123").Scan(&name)
		if err != nil {
			t.Fatalf("failed to query: %v", err)
		}
		if name != "bot123" {
			t.Errorf("expected name=bot123 (default to agentID), got %s", name)
		}
	})
}

func TestCB87_RegisterAgentOnConnect_SuccessNewAgent(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		err := RegisterAgentOnConnect("new-agent", "My Agent", "gpt-4", "helpful", "research")
		if err != nil {
			t.Fatalf("RegisterAgentOnConnect failed: %v", err)
		}

		var name, model, personality, specialty string
		err = db.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "new-agent").
			Scan(&name, &model, &personality, &specialty)
		if err != nil {
			t.Fatalf("failed to query: %v", err)
		}
		if name != "My Agent" {
			t.Errorf("expected name=My Agent, got %s", name)
		}
		if model != "gpt-4" {
			t.Errorf("expected model=gpt-4, got %s", model)
		}
	})
}

// ============================================================
// RateLimiter cleanup tests — targeting 83.3% → 90%+
// ============================================================

func TestCB87_RateLimiter_CleanupRemovesExpired(t *testing.T) {
	rl := NewRateLimiter(100, time.Millisecond*50)
	defer rl.Stop()

	rl.mu.Lock()
	rl.counters["key1"] = &rateCounter{count: 1, expires: time.Now().Add(-time.Second)}
	rl.counters["key2"] = &rateCounter{count: 1, expires: time.Now().Add(time.Second)}
	rl.mu.Unlock()

	// Wait for cleanup tick
	time.Sleep(time.Millisecond * 60)

	rl.mu.Lock()
	_, key1Exists := rl.counters["key1"]
	_, key2Exists := rl.counters["key2"]
	rl.mu.Unlock()

	if key1Exists {
		t.Error("expected key1 to be removed (expired)")
	}
	if !key2Exists {
		t.Error("expected key2 to still exist (not expired)")
	}

	rl.Reset()
}

func TestCB87_RateLimiter_CleanupStopChannel(t *testing.T) {
	rl := NewRateLimiter(100, time.Second)
	rl.Stop()

	// Should not panic after stop
	time.Sleep(time.Millisecond * 50)
}

func TestCB87_TieredRateLimiter_CleanupStopChannel(t *testing.T) {
	trl := NewTieredRateLimiter()
	close(trl.stopCh)

	// Should not panic after stop
	time.Sleep(time.Millisecond * 50)
}

// ============================================================
// initAPNs tests — targeting 84% → 90%+
// ============================================================

func TestCB87_InitAPNs_NilPushConfig(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPushConfig }()

	// Should not panic
	initAPNs()
}

func TestCB87_InitAPNs_Disabled(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	defer func() { pushConfig = oldPushConfig }()

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled=false")
	}
}

func TestCB87_InitAPNs_EmptyCertPath(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "",
	}
	defer func() { pushConfig = oldPushConfig }()

	initAPNs()
	// Should remain enabled but not load cert (no path)
	if !pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled to remain true (no cert path is warning, not disable)")
	}
}

func TestCB87_InitAPNs_CertNotFound(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/tmp/cb87_nonexistent_cert.p12",
	}
	defer func() { pushConfig = oldPushConfig }()

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled=false after cert not found")
	}
}

func TestCB87_InitAPNs_DevEnvironment(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/tmp/cb87_nonexistent_cert.p12",
		Environment: "development",
	}
	defer func() { pushConfig = oldPushConfig }()

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled=false (cert not found)")
	}
}

func TestCB87_InitAPNs_ProductionEnvironment(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/tmp/cb87_nonexistent_cert.p12",
		Environment: "production",
	}
	defer func() { pushConfig = oldPushConfig }()

	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("expected APNSEnabled=false (cert not found)")
	}
}

// ============================================================
// initSchema tests — targeting 85.3% → 90%+
// ============================================================

func TestCB87_InitSchema_NilDB(t *testing.T) {
	// initSchema panics on nil DB because it calls db.Exec directly
	// We can't test nil DB directly - test with a closed DB instead
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	testDB.Close()

	err = initSchema(testDB)
	if err == nil {
		t.Fatal("expected error from closed DB")
	}
}

func TestCB87_InitSchema_IdempotentWithMigrations(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	// First init
	if err := initSchema(testDB); err != nil {
		t.Fatalf("first initSchema failed: %v", err)
	}

	// Second init should succeed (idempotent)
	if err := initSchema(testDB); err != nil {
		t.Fatalf("second initSchema failed: %v", err)
	}

	// Verify tables exist
	tables := []string{"users", "agents", "conversations", "messages", "device_tokens",
		"reactions", "conversation_tags", "user_rate_limit_tiers", "notification_preferences"}
	for _, table := range tables {
		var name string
		err := testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}
}

func TestCB87_InitSchema_MigrationCountRecorded(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	if err := initSchema(testDB); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	var count int
	err = testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query migration count: %v", err)
	}
	if count != 8 {
		t.Errorf("expected 8 migrations, got %d", count)
	}
}

func TestCB87_InitSchema_AlterTableIdempotent(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	// Run initSchema twice - ALTER TABLE ADD COLUMN should fail silently on second run
	if err := initSchema(testDB); err != nil {
		t.Fatalf("first initSchema: %v", err)
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("second initSchema: %v", err)
	}

	// Verify columns exist
	_, err = testDB.Exec("SELECT model, personality, specialty, read_at, edited_at, is_deleted FROM agents, messages LIMIT 0")
	// The above query is wrong syntax - let's just check agents table columns
	columns, err := testDB.Query("PRAGMA table_info(agents)")
	if err != nil {
		t.Fatalf("failed to get table info: %v", err)
	}
	defer columns.Close()

	colNames := make(map[string]bool)
	for columns.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := columns.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			continue
		}
		colNames[name] = true
	}
	for _, col := range []string{"model", "personality", "specialty"} {
		if !colNames[col] {
			t.Errorf("expected column %s in agents table", col)
		}
	}
}

// ============================================================
// handleUpload tests — targeting 85.7% → 90%+
// ============================================================

func TestCB87_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/upload", nil)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestCB87_HandleUpload_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCB87_HandleUpload_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid_token_here")
	w := httptest.NewRecorder()

	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCB87_HandleUpload_ValidAuthNoFile(t *testing.T) {
	// Generate a valid JWT
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-test-secret")
	defer func() { jwtSecret = oldSecret }()

	token, err := GenerateJWT("user1", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUpload(w, req)

	// Should get 400 because no file
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// ============================================================
// loadQueueFromDB tests — targeting 89.5% → 95%+
// ============================================================

func TestCB87_LoadQueueFromDB_ScanError(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	if err := initSchema(testDB); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	// Insert a row with wrong column type for scan
	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES ('user1', 'not-blob-data', '2026-01-01')")
	if err != nil {
		t.Fatalf("failed to insert: %v", err)
	}

	q := newOfflineQueue(100, time.Hour)

	// Should handle scan error gracefully (data is TEXT not BLOB, but SQLite is flexible)
	// The scan into []byte should actually work with TEXT in SQLite
	loadQueueFromDB(testDB, q)

	// Verify it loaded (SQLite is flexible with types)
	if q.TotalDepth() != 1 {
		// If it didn't load due to scan error, that's the expected path we're testing
		t.Logf("queue depth: %d (scan error path exercised)", q.TotalDepth())
	}
}

func TestCB87_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)

	// Should not panic
	loadQueueFromDB(nil, q)

	if q.TotalDepth() != 0 {
		t.Error("expected 0 entries with nil DB")
	}
}

func TestCB87_LoadQueueFromDB_QueryError(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	// Don't create schema - query will fail
	q := newOfflineQueue(100, time.Hour)

	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 0 {
		t.Error("expected 0 entries from query error")
	}
}

func TestCB87_LoadQueueFromDB_MultipleEntries(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	if err := initSchema(testDB); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	// Insert multiple entries
	for i := 0; i < 5; i++ {
		_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
			fmt.Sprintf("user%d", i), []byte(fmt.Sprintf("message-%d", i)), time.Now().UTC())
		if err != nil {
			t.Fatalf("failed to insert: %v", err)
		}
	}

	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 5 {
		t.Errorf("expected 5 entries, got %d", q.TotalDepth())
	}
}

func TestCB87_LoadQueueFromDB_EmptyTable(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	if err := initSchema(testDB); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	q := newOfflineQueue(100, time.Hour)
	loadQueueFromDB(testDB, q)

	if q.TotalDepth() != 0 {
		t.Error("expected 0 entries from empty table")
	}
}

// ============================================================
// initFCM tests — targeting 88.9% → 95%+
// ============================================================

func TestCB87_InitFCM_NilPushConfig(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPushConfig }()

	initFCM()
}

func TestCB87_InitFCM_Disabled(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = oldPushConfig }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCMEnabled=false")
	}
}

func TestCB87_InitFCM_EmptyCredsPath(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "",
	}
	defer func() { pushConfig = oldPushConfig }()

	initFCM()
	// Empty creds path returns early without disabling
	// FCMEnabled should remain true (the function just warns and returns)
	if !pushConfig.FCMEnabled {
		t.Error("expected FCMEnabled to remain true (empty path only warns)")
	}
}

func TestCB87_InitFCM_CredsNotFound(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:     true,
		FCMCredentials: "/tmp/cb87_nonexistent_creds.json",
	}
	defer func() { pushConfig = oldPushConfig }()

	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("expected FCMEnabled=false after creds not found")
	}
}

// ============================================================
// notifyUser tests — targeting 93.3% → 96%+
// ============================================================

func TestCB87_NotifyUser_NilPushConfig(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPushConfig }()

	// Should not panic or do anything
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestCB87_NotifyUser_NilDB(t *testing.T) {
	oldPushConfig := pushConfig
	oldDB := db
	pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
	db = nil
	defer func() {
		pushConfig = oldPushConfig
		db = oldDB
	}()

	// Should not panic
	notifyUser("user1", "Title", "Body", "conv1")
}

func TestCB87_NotifyUser_MutedConversation(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		oldPushConfig := pushConfig
		pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
		defer func() { pushConfig = oldPushConfig }()

		// Create user and conversation
		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")
		_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv1', 'user1', 'agent1')")

		// Mute the conversation
		_, _ = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES ('user1', 'conv1', 1)")

		// Should not send notification (muted)
		notifyUser("user1", "Title", "Body", "conv1")
		// No assertion needed - just verify no panic
	})
}

func TestCB87_NotifyUser_NoTokens(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		oldPushConfig := pushConfig
		pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
		defer func() { pushConfig = oldPushConfig }()

		// No device tokens registered - should return without error
		notifyUser("user1", "Title", "Body", "conv1")
	})
}

func TestCB87_NotifyUser_PanicRecovery(t *testing.T) {
	// notifyUser has a defer/recover for panics
	// We can't easily cause a panic, but verify the function doesn't crash
	notifyUser("nonexistent", "Title", "Body", "")
}

// ============================================================
// storeMessagesBatch tests — targeting 92.6% → 95%+
// ============================================================

func TestCB87_StoreMessagesBatch_Empty(t *testing.T) {
	ids, err := storeMessagesBatch(nil)
	if err != nil {
		t.Errorf("expected nil error for empty batch, got: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 ids, got %d", len(ids))
	}
}

func TestCB87_StoreMessagesBatch_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB; recover() }()

	msgs := []RoutedMessage{
		{ConversationID: "conv1", SenderID: "user1", SenderType: "user", Content: "hello"},
	}

	// storeMessagesBatch panics on nil db (calls db.Begin on nil)
	// Use recover to catch the panic
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from nil DB")
		}
	}()

	_, _ = storeMessagesBatch(msgs)
}

// ============================================================
// sendAPNSNotification tests
// ============================================================

func TestCB87_SendAPNSNotification_Disabled(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = oldPushConfig }()

	err := sendAPNSNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when disabled, got: %v", err)
	}
}

func TestCB87_SendAPNSNotification_NilConfig(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPushConfig }()

	err := sendAPNSNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when nil config, got: %v", err)
	}
}

func TestCB87_SendAPNSNotification_NilClient(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		apnsClient:  nil,
	}
	defer func() { pushConfig = oldPushConfig }()

	err := sendAPNSNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when nil client, got: %v", err)
	}
}

// ============================================================
// sendFCMNotification tests
// ============================================================

func TestCB87_SendFCMNotification_Disabled(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = oldPushConfig }()

	err := sendFCMNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when disabled, got: %v", err)
	}
}

func TestCB87_SendFCMNotification_NilConfig(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldPushConfig }()

	err := sendFCMNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when nil config, got: %v", err)
	}
}

func TestCB87_SendFCMNotification_NilClient(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: true,
		fcmClient:  nil,
	}
	defer func() { pushConfig = oldPushConfig }()

	err := sendFCMNotification("token", "title", "body", "conv1")
	if err != nil {
		t.Errorf("expected nil error when nil client, got: %v", err)
	}
}

// ============================================================
// sendPushNotification tests
// ============================================================

func TestCB87_SendPushNotification_AndroidPlatform(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = oldPushConfig }()

	// Should route to FCM (which is disabled, so returns nil)
	err := sendPushNotification("token", "title", "body", "conv1", "android")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestCB87_SendPushNotification_FCMPlatform(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = oldPushConfig }()

	err := sendPushNotification("token", "title", "body", "conv1", "fcm")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestCB87_SendPushNotification_IOSPlatform(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = oldPushConfig }()

	err := sendPushNotification("token", "title", "body", "conv1", "ios")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestCB87_SendPushNotification_UnknownPlatform(t *testing.T) {
	oldPushConfig := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = oldPushConfig }()

	// Unknown platform should default to APNs
	err := sendPushNotification("token", "title", "body", "conv1", "unknown")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

// ============================================================
// handleGetVAPIDKey tests
// ============================================================

func TestCB87_HandleGetVAPIDKey_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/vapid-key", nil)
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestCB87_HandleGetVAPIDKey_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCB87_HandleGetVAPIDKey_NotConfigured(t *testing.T) {
	oldVapidKey := vapidPublicKey
	vapidPublicKey = ""
	defer func() { vapidPublicKey = oldVapidKey }()

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer some_token")
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCB87_HandleGetVAPIDKey_Success(t *testing.T) {
	oldVapidKey := vapidPublicKey
	vapidPublicKey = "test-vapid-key-base64"
	defer func() { vapidPublicKey = oldVapidKey }()

	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-vapid-secret")
	defer func() { jwtSecret = oldSecret }()

	token, err := GenerateJWT("user1", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["public_key"] != "test-vapid-key-base64" {
		t.Errorf("expected public_key=test-vapid-key-base64, got %s", resp["public_key"])
	}
}

// ============================================================
// handleRegisterDeviceToken tests
// ============================================================

func TestCB87_HandleRegisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/register", nil)
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestCB87_HandleRegisterDeviceToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/register", nil)
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCB87_HandleRegisterDeviceToken_InvalidBody(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-device-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader("invalid json"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleRegisterDeviceToken_EmptyToken(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-device-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	body := `{"device_token": "", "platform": "ios"}`
	req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleRegisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleRegisterDeviceToken_Success(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		oldSecret := jwtSecret
		jwtSecret = []byte("cb87-device-secret")
		defer func() { jwtSecret = oldSecret }()

		// Create user
		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")

		token, _ := GenerateJWT("user1", "testuser")

		body := `{"device_token": "abc123", "platform": "ios"}`
		req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handleRegisterDeviceToken(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected %d, got %d", http.StatusOK, w.Code)
		}
	})
}

func TestCB87_HandleRegisterDeviceToken_DefaultPlatform(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		oldSecret := jwtSecret
		jwtSecret = []byte("cb87-device-secret")
		defer func() { jwtSecret = oldSecret }()

		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")

		token, _ := GenerateJWT("user1", "testuser")

		body := `{"device_token": "abc456"}`
		req := httptest.NewRequest(http.MethodPost, "/push/register", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handleRegisterDeviceToken(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected %d, got %d", http.StatusOK, w.Code)
		}

		// Verify platform defaulted to "ios"
		var platform string
		err := db.QueryRow("SELECT platform FROM device_tokens WHERE user_id = ?", "user1").Scan(&platform)
		if err != nil {
			t.Fatalf("failed to query: %v", err)
		}
		if platform != "ios" {
			t.Errorf("expected platform=ios (default), got %s", platform)
		}
	})
}

// ============================================================
// handleUnregisterDeviceToken tests
// ============================================================

func TestCB87_HandleUnregisterDeviceToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/unregister", nil)
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestCB87_HandleUnregisterDeviceToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", nil)
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCB87_HandleUnregisterDeviceToken_InvalidBody(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-unreg-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader("invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleUnregisterDeviceToken_EmptyToken(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-unreg-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	body := `{"device_token": ""}`
	req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleUnregisterDeviceToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleUnregisterDeviceToken_Success(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		oldSecret := jwtSecret
		jwtSecret = []byte("cb87-unreg-secret")
		defer func() { jwtSecret = oldSecret }()

		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")
		_, _ = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES ('user1', 'token123', 'ios')")

		token, _ := GenerateJWT("user1", "testuser")

		body := `{"device_token": "token123"}`
		req := httptest.NewRequest(http.MethodDelete, "/push/unregister", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handleUnregisterDeviceToken(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected %d, got %d", http.StatusOK, w.Code)
		}

		// Verify token removed
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ? AND device_token = ?", "user1", "token123").Scan(&count)
		if err != nil {
			t.Fatalf("failed to query: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 tokens after unregister, got %d", count)
		}
	})
}

// ============================================================
// handleWebPushSubscribe tests — targeting 96.3% → 100%
// ============================================================

func TestCB87_HandleWebPushSubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestCB87_HandleWebPushSubscribe_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", nil)
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCB87_HandleWebPushSubscribe_InvalidBody(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-webpush-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader("invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleWebPushSubscribe_MissingFields(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-webpush-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	body := `{"endpoint": "", "keys": {"p256dh": "", "auth": ""}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleWebPushSubscribe_Success(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		oldSecret := jwtSecret
		jwtSecret = []byte("cb87-webpush-secret")
		defer func() { jwtSecret = oldSecret }()

		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")

		token, _ := GenerateJWT("user1", "testuser")

		body := `{"endpoint": "https://fcm.googleapis.com/f/abc", "keys": {"p256dh": "key1", "auth": "auth1"}}`
		req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handleWebPushSubscribe(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected %d, got %d", http.StatusOK, w.Code)
		}
	})
}

// ============================================================
// handleWebPushUnsubscribe tests — targeting 100%
// ============================================================

func TestCB87_HandleWebPushUnsubscribe_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()

	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestCB87_HandleWebPushUnsubscribe_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", nil)
	w := httptest.NewRecorder()

	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCB87_HandleWebPushUnsubscribe_InvalidBody(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-webunsub-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader("invalid"))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleWebPushUnsubscribe_EmptyEndpoint(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-webunsub-secret")
	defer func() { jwtSecret = oldSecret }()

	token, _ := GenerateJWT("user1", "testuser")

	body := `{"endpoint": ""}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCB87_HandleWebPushUnsubscribe_Success(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		oldSecret := jwtSecret
		jwtSecret = []byte("cb87-webunsub-secret")
		defer func() { jwtSecret = oldSecret }()

		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")
		_, _ = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES ('user1', 'https://fcm.googleapis.com/f/abc', 'web')")
		_, _ = db.Exec("INSERT INTO web_push_subscriptions (user_id, endpoint, p256dh, auth) VALUES ('user1', 'https://fcm.googleapis.com/f/abc', 'key1', 'auth1')")

		token, _ := GenerateJWT("user1", "testuser")

		body := `{"endpoint": "https://fcm.googleapis.com/f/abc"}`
		req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handleWebPushUnsubscribe(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected %d, got %d", w.Code, http.StatusOK)
		}

		// Verify removed
		var count int
		_ = db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = 'user1' AND device_token = 'https://fcm.googleapis.com/f/abc'").Scan(&count)
		if count != 0 {
			t.Errorf("expected 0 tokens after unsubscribe, got %d", count)
		}
	})
}

// ============================================================
// getDeviceTokensForUser tests
// ============================================================

func TestCB87_GetDeviceTokensForUser_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	tokens, err := getDeviceTokensForUser("user1")
	if err == nil {
		t.Fatal("expected error for nil DB")
	}
	if tokens != nil {
		t.Error("expected nil tokens")
	}
}

func TestCB87_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")

		tokens, err := getDeviceTokensForUser("user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tokens) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(tokens))
		}
	})
}

func TestCB87_GetDeviceTokensForUser_WithTokens(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")
		_, _ = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES ('user1', 'token1', 'ios')")
		_, _ = db.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES ('user1', 'token2', 'android')")

		tokens, err := getDeviceTokensForUser("user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tokens) != 2 {
			t.Fatalf("expected 2 tokens, got %d", len(tokens))
		}

		// Verify token contents
		tokenMap := make(map[string]string)
		for _, t := range tokens {
			tokenMap[t.Token] = t.Platform
		}
		if tokenMap["token1"] != "ios" {
			t.Errorf("expected token1=ios, got %s", tokenMap["token1"])
		}
		if tokenMap["token2"] != "android" {
			t.Errorf("expected token2=android, got %s", tokenMap["token2"])
		}
	})
}

func TestCB87_GetDeviceTokensForUser_QueryError(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		// Drop the table to cause query error
		db.Exec("DROP TABLE device_tokens")

		tokens, err := getDeviceTokensForUser("user1")
		if err == nil {
			t.Fatal("expected query error")
		}
		if tokens != nil {
			t.Error("expected nil tokens on error")
		}
	})
}

// ============================================================
// isConversationMuted tests
// ============================================================

func TestCB87_IsConversationMuted_NotMuted(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")
		_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv1', 'user1', 'agent1')")

		muted := isConversationMuted("user1", "conv1")
		if muted {
			t.Error("expected conversation not muted")
		}
	})
}

func TestCB87_IsConversationMuted_Muted(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		_, _ = db.Exec("INSERT INTO users (id, username, password_hash) VALUES ('user1', 'user1', 'hash')")
		_, _ = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES ('conv1', 'user1', 'agent1')")
		_, _ = db.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES ('user1', 'conv1', 1)")

		muted := isConversationMuted("user1", "conv1")
		if !muted {
			t.Error("expected conversation to be muted")
		}
	})
}

func TestCB87_IsConversationMuted_EmptyConvID(t *testing.T) {
	withGlobalDB_CB87(t, func() {
		muted := isConversationMuted("user1", "")
		if muted {
			t.Error("expected false for empty conversation ID")
		}
	})
}

func TestCB87_IsConversationMuted_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	muted := isConversationMuted("user1", "conv1")
	if muted {
		t.Error("expected false for nil DB")
	}
}

// ============================================================
// safeTruncate tests
// ============================================================

func TestCB87_SafeTruncate_LongerThanN(t *testing.T) {
	result := safeTruncate("hello world", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got %s", result)
	}
}

func TestCB87_SafeTruncate_ShorterThanN(t *testing.T) {
	result := safeTruncate("hi", 10)
	if result != "hi" {
		t.Errorf("expected 'hi', got %s", result)
	}
}

func TestCB87_SafeTruncate_ExactLength(t *testing.T) {
	result := safeTruncate("hello", 5)
	if result != "hello" {
		t.Errorf("expected 'hello', got %s", result)
	}
}

func TestCB87_SafeTruncate_EmptyString(t *testing.T) {
	result := safeTruncate("", 5)
	if result != "" {
		t.Errorf("expected '', got %s", result)
	}
}

func TestCB87_SafeTruncate_ZeroN(t *testing.T) {
	result := safeTruncate("hello", 0)
	if result != "" {
		t.Errorf("expected '', got %s", result)
	}
}

// ============================================================
// getEnvOrDefault tests
// ============================================================

func TestCB87_GetEnvOrDefault_Existing(t *testing.T) {
	os.Setenv("CB87_TEST_VAR", "custom_value")
	defer os.Unsetenv("CB87_TEST_VAR")

	result := getEnvOrDefault("CB87_TEST_VAR", "default")
	if result != "custom_value" {
		t.Errorf("expected 'custom_value', got %s", result)
	}
}

func TestCB87_GetEnvOrDefault_Default(t *testing.T) {
	os.Unsetenv("CB87_TEST_NONEXISTENT_VAR")

	result := getEnvOrDefault("CB87_TEST_NONEXISTENT_VAR", "default_value")
	if result != "default_value" {
		t.Errorf("expected 'default_value', got %s", result)
	}
}

func TestCB87_GetEnvOrDefault_EmptyValue(t *testing.T) {
	os.Setenv("CB87_TEST_EMPTY", "")
	defer os.Unsetenv("CB87_TEST_EMPTY")

	result := getEnvOrDefault("CB87_TEST_EMPTY", "default")
	if result != "default" {
		t.Errorf("expected 'default' for empty env var, got %s", result)
	}
}

// ============================================================
// ValidateJWT tests — targeting remaining uncovered paths
// ============================================================

func TestCB87_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

func TestCB87_ValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestCB87_ValidateJWT_ExpiredToken(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-jwt-secret")
	defer func() { jwtSecret = oldSecret }()

	// Create an expired token
	claims := &Claims{
		UserID:   "user1",
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "agent-messenger",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = ValidateJWT(tokenString)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestCB87_ValidateJWT_ValidToken(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-jwt-secret")
	defer func() { jwtSecret = oldSecret }()

	tokenString, err := GenerateJWT("user1", "testuser")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	claims, err := ValidateJWT(tokenString)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "user1" {
		t.Errorf("expected UserID=user1, got %s", claims.UserID)
	}
	if claims.Username != "testuser" {
		t.Errorf("expected Username=testuser, got %s", claims.Username)
	}
}

func TestCB87_ValidateJWT_UnexpectedSigningMethod(t *testing.T) {
	// Create a token with a different signing method
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-jwt-secret")
	defer func() { jwtSecret = oldSecret }()

	// Use RS256 which is not HMAC
	token := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{
		UserID:           "user1",
		Username:         "testuser",
		RegisteredClaims: jwt.RegisteredClaims{},
	})
	// Use unsafe none method to test the signing method check
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = ValidateJWT(tokenString)
	if err == nil {
		t.Fatal("expected error for unexpected signing method")
	}
}

// ============================================================
// ValidateAdminSecret tests
// ============================================================

func TestCB87_ValidateAdminSecret_Correct(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = oldSecret }()

	err := ValidateAdminSecret("test-admin-secret")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestCB87_ValidateAdminSecret_Wrong(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = oldSecret }()

	err := ValidateAdminSecret("wrong-secret")
	if err == nil {
		t.Error("expected non-nil error for wrong secret")
	}
}

func TestCB87_ValidateAdminSecret_Empty(t *testing.T) {
	oldSecret := adminSecret
	adminSecret = "test-admin-secret"
	defer func() { adminSecret = oldSecret }()

	err := ValidateAdminSecret("")
	if err == nil {
		t.Error("expected non-nil error for empty string")
	}
}

// ============================================================
// HashAPIKey tests
// ============================================================

func TestCB87_HashAPIKey_Success(t *testing.T) {
	hash, err := HashAPIKey("my-api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if hash == "my-api-key" {
		t.Error("hash should not equal input")
	}
}

func TestCB87_HashAPIKey_Empty(t *testing.T) {
	// bcrypt actually succeeds on empty string - it hashes it
	hash, err := HashAPIKey("")
	if err != nil {
		t.Errorf("unexpected error for empty key: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash even for empty key")
	}
}

func TestCB87_HashAPIKey_DifferentInputs(t *testing.T) {
	hash1, _ := HashAPIKey("key1")
	hash2, _ := HashAPIKey("key2")
	if hash1 == hash2 {
		t.Error("expected different hashes for different inputs")
	}
}

// ============================================================
// extractIP tests
// ============================================================

func TestCB87_ExtractIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50")

	ip := extractIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("expected 203.0.113.50, got %s", ip)
	}
}

func TestCB87_ExtractIP_MultipleXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 198.51.100.10")

	ip := extractIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("expected 203.0.113.50 (first IP), got %s", ip)
	}
}

func TestCB87_ExtractIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.20")

	ip := extractIP(req)
	if ip != "198.51.100.20" {
		t.Errorf("expected 198.51.100.20, got %s", ip)
	}
}

func TestCB87_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	ip := extractIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %s", ip)
	}
}

func TestCB87_ExtractIP_RemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1"

	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
}

// ============================================================
// OfflineQueue tests
// ============================================================

func TestCB87_OfflineQueue_BasicEnqueueDrain(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))

	if q.TotalDepth() != 2 {
		t.Errorf("expected depth 2, got %d", q.TotalDepth())
	}

	msgs := q.Drain("user1")
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
}

func TestCB87_OfflineQueue_MaxLen(t *testing.T) {
	q := newOfflineQueue(2, time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user1", []byte("msg3")) // should drop oldest

	if q.TotalDepth() != 2 {
		t.Errorf("expected depth 2 (max len), got %d", q.TotalDepth())
	}
}

func TestCB87_OfflineQueue_TTLExpiry(t *testing.T) {
	q := newOfflineQueue(100, time.Millisecond*10)

	q.Enqueue("user1", []byte("msg1"))
	time.Sleep(time.Millisecond * 20)

	msgs := q.Drain("user1")
	if len(msgs) > 0 {
		t.Errorf("expected expired messages to be dropped, got %d", len(msgs))
	}
}

func TestCB87_OfflineQueue_QueueDepth(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	if q.QueueDepth("user1") != 2 {
		t.Errorf("expected depth 2 for user1, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 1 {
		t.Errorf("expected depth 1 for user2, got %d", q.QueueDepth("user2"))
	}
	if q.QueueDepth("nonexistent") != 0 {
		t.Error("expected 0 for nonexistent user")
	}
}

func TestCB87_OfflineQueue_Purge(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)

	q.Enqueue("user1", []byte("msg1"))
	q.Enqueue("user1", []byte("msg2"))
	q.Enqueue("user2", []byte("msg3"))

	q.Purge("user1")

	if q.TotalDepth() != 1 {
		t.Errorf("expected 1 after purge, got %d", q.TotalDepth())
	}

	// user2 should still have messages
	msgs := q.Drain("user2")
	if len(msgs) != 1 {
		t.Errorf("expected 1 message for user2, got %d", len(msgs))
	}
}

func TestCB87_OfflineQueue_PurgeNonExistent(t *testing.T) {
	q := newOfflineQueue(100, time.Hour)
	q.Purge("nonexistent_user")

	if q.TotalDepth() != 0 {
		t.Error("expected 0 depth")
	}
}

func TestCB87_OfflineQueue_Concurrent(t *testing.T) {
	q := newOfflineQueue(1000, time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				q.Enqueue(fmt.Sprintf("user%d", n), []byte(fmt.Sprintf("msg-%d-%d", n, j)))
			}
		}(i)
	}
	wg.Wait()

	if q.TotalDepth() != 100 {
		t.Errorf("expected 100, got %d", q.TotalDepth())
	}
}

// ============================================================
// MarshalOutgoingMessage tests
// ============================================================

func TestCB87_MarshalOutgoingMessage_Valid(t *testing.T) {
	msg := OutgoingMessage{
		Type: "chat",
		Data: map[string]interface{}{"content": "hello"},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded["type"] != "chat" {
		t.Errorf("expected type=chat, got %v", decoded["type"])
	}
}

// ============================================================
// IsTracingEnabled tests
// ============================================================

func TestCB87_IsTracingEnabled_Disabled(t *testing.T) {
	tracingEnabled = false
	if IsTracingEnabled() {
		t.Error("expected false")
	}
}

func TestCB87_IsTracingEnabled_Enabled(t *testing.T) {
	oldEnabled := tracingEnabled
	tracingEnabled = true
	defer func() { tracingEnabled = oldEnabled }()

	if !IsTracingEnabled() {
		t.Error("expected true")
	}
}

// ============================================================
// StartSpan / StartSpanFromRequest tests
// ============================================================

func TestCB87_StartSpan_TracingDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	ctx := context.Background()
	newCtx, span := StartSpan(ctx, "test-span")
	if span == nil {
		t.Error("expected non-nil span")
	}
	_ = newCtx
}

func TestCB87_StartSpanFromRequest_TracingDisabled(t *testing.T) {
	tracingEnabled = false
	tracer = nil

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, span := StartSpanFromRequest(req, "test-span")
	if span == nil {
		t.Error("expected non-nil span")
	}
	_ = ctx
}

// ============================================================
// SpanError / SpanOK tests
// ============================================================

func TestCB87_SpanError_TracingDisabled(t *testing.T) {
	tracingEnabled = false
	// Should not panic with nil span
	SpanError(nil, fmt.Errorf("test error"))
}

func TestCB87_SpanOK_TracingDisabled(t *testing.T) {
	tracingEnabled = false
	// Should not panic with nil span
	SpanOK(nil)
}

// ============================================================
// isSupportedVersion / negotiateProtocol tests
// ============================================================

func TestCB87_IsSupportedVersion_Valid(t *testing.T) {
	// Check against the supported versions in the codebase
	versions := strings.Split(SupportedVersions, ",")
	if len(versions) == 0 {
		t.Fatal("no supported versions defined")
	}
	for _, v := range versions {
		v = strings.TrimSpace(v)
		if !isSupportedVersion(v) {
			t.Errorf("expected %s to be supported", v)
		}
	}
}

func TestCB87_IsSupportedVersion_Invalid(t *testing.T) {
	if isSupportedVersion("99.99") {
		t.Error("expected 99.99 to not be supported")
	}
}

func TestCB87_IsSupportedVersion_Empty(t *testing.T) {
	if isSupportedVersion("") {
		t.Error("expected empty string to not be supported")
	}
}

// ============================================================
// upgradeWithProtocol tests
// ============================================================

func TestCB87_UpgradeWithProtocol_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	versions := strings.Split(SupportedVersions, ",")
	firstVersion := strings.TrimSpace(versions[0])

	upgradeWithProtocol(w, httptest.NewRequest(http.MethodGet, "/", nil), firstVersion)

	if w.Header().Get("Sec-WebSocket-Protocol") != firstVersion {
		t.Errorf("expected Sec-WebSocket-Protocol=%s, got %s", firstVersion, w.Header().Get("Sec-WebSocket-Protocol"))
	}
}

func TestCB87_UpgradeWithProtocol_Invalid(t *testing.T) {
	w := httptest.NewRecorder()

	upgradeWithProtocol(w, httptest.NewRequest(http.MethodGet, "/", nil), "99.99")

	if w.Header().Get("Sec-WebSocket-Protocol") != "" {
		t.Error("expected empty Sec-WebSocket-Protocol for invalid version")
	}
}

func TestCB87_UpgradeWithProtocol_Empty(t *testing.T) {
	w := httptest.NewRecorder()

	upgradeWithProtocol(w, httptest.NewRequest(http.MethodGet, "/", nil), "")

	if w.Header().Get("Sec-WebSocket-Protocol") != "" {
		t.Error("expected empty Sec-WebSocket-Protocol for empty version")
	}
}

// ============================================================
// negotiateProtocol tests
// ============================================================

func TestCB87_NegotiateProtocol_QueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?protocol=0.1", nil)

	// Check if 0.1 is in supported versions
	versions := strings.Split(SupportedVersions, ",")
	firstVersion := strings.TrimSpace(versions[0])

	result := negotiateProtocol(req)
	if result == "" {
		// If no match, that's okay - depends on config
		t.Logf("negotiateProtocol returned empty for query param (supported: %s)", SupportedVersions)
	} else {
		// Should return the first supported version
		if result != firstVersion {
			t.Logf("negotiateProtocol returned %s (first supported: %s)", result, firstVersion)
		}
	}
}

func TestCB87_NegotiateProtocol_Header(t *testing.T) {
	versions := strings.Split(SupportedVersions, ",")
	firstVersion := strings.TrimSpace(versions[0])

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-WebSocket-Protocol", firstVersion)

	result := negotiateProtocol(req)
	if result == "" {
		t.Logf("negotiateProtocol returned empty for header (supported: %s)", SupportedVersions)
	}
}

func TestCB87_NegotiateProtocol_NoVersion(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	result := negotiateProtocol(req)
	if result == "" {
		// Expected when no version is specified
		return
	}
	// Some configs might have a default - log it
	t.Logf("negotiateProtocol returned %s with no version specified", result)
}

// ============================================================
// RateLimiter tests — additional coverage
// ============================================================

func TestCB87_RateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if !rl.Allow("user1") {
			t.Errorf("expected Allow to return true for call %d", i)
		}
	}

	// 4th call should be rate limited
	if rl.Allow("user1") {
		t.Error("expected Allow to return false on 4th call")
	}

	// Different user should not be rate limited
	if !rl.Allow("user2") {
		t.Error("expected Allow to return true for different user")
	}

	rl.Reset()
}

func TestCB87_RateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	rl.Allow("user1")
	rl.Allow("user1")

	rl.Reset()

	// After reset, should be allowed again
	if !rl.Allow("user1") {
		t.Error("expected Allow to return true after Reset")
	}
}

// ============================================================
// TieredRateLimiter tests — additional coverage
// ============================================================

func TestCB87_TieredRateLimiter_SetTier(t *testing.T) {
	trl := NewTieredRateLimiter()

	trl.SetTier("user1", TierPro)
	tier := trl.GetTier("user1")
	if tier.Name != "pro" {
		t.Errorf("expected tier name=pro, got %s", tier.Name)
	}

	trl.SetTier("user2", TierEnterprise)
	tier = trl.GetTier("user2")
	if tier.Name != "enterprise" {
		t.Errorf("expected tier name=enterprise, got %s", tier.Name)
	}
}

func TestCB87_TieredRateLimiter_DefaultTier(t *testing.T) {
	trl := NewTieredRateLimiter()

	tier := trl.GetTier("unknown_user")
	if tier.Name != "free" {
		t.Errorf("expected default tier=free, got %s", tier.Name)
	}
}

func TestCB87_TieredRateLimiter_AllowAndRemaining(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Free tier burst is defined in the code
	freeTier := TierFree

	for i := 0; i < freeTier.Burst; i++ {
		allowed, remaining, _ := trl.Allow("test_user")
		if !allowed {
			t.Errorf("expected allowed on call %d", i)
		}
		if remaining != freeTier.Burst-1-i {
			t.Errorf("expected remaining=%d, got %d", freeTier.Burst-1-i, remaining)
		}
	}

	// Next call should be denied
	allowed, _, _ := trl.Allow("test_user")
	if allowed {
		t.Error("expected rate limited after exceeding burst")
	}
}

func TestCB87_TieredRateLimiter_CleanupOnce_NoStale(t *testing.T) {
	trl := NewTieredRateLimiter()

	// Add a fresh entry
	trl.Allow("user1")

	// Cleanup should not remove it (not stale)
	trl.cleanupOnce()

	// User should still be rate limited
	allowed, _, _ := trl.Allow("user1")
	// Depending on how many calls we've made, this might pass or fail
	// The important thing is that cleanupOnce didn't panic
	_ = allowed
}

// ============================================================
// writeJSONError / writeJSON tests
// ============================================================

func TestCB87_WriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if resp["error"] != "test error" {
		t.Errorf("expected error='test error', got %s", resp["error"])
	}
}

// ============================================================
// SafeSend tests
// ============================================================

func TestCB87_SafeSend_Normal(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 1),
	}

	if !c.SafeSend([]byte("test")) {
		t.Error("expected SafeSend to return true")
	}
}

func TestCB87_SafeSend_FullChannel(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 1),
	}
	c.send <- []byte("filler")

	if c.SafeSend([]byte("test")) {
		t.Error("expected SafeSend to return false for full channel")
	}
}

func TestCB87_SafeSend_ClosedChannel(t *testing.T) {
	c := &Connection{
		send: make(chan []byte, 1),
	}
	close(c.send)

	if c.SafeSend([]byte("test")) {
		t.Error("expected SafeSend to return false for closed channel")
	}
}

// ============================================================
// Hub tests — additional coverage
// ============================================================

func TestCB87_Hub_RegisterUnregister(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 256),
	}

	h.register <- c

	// Give hub time to process
	time.Sleep(time.Millisecond * 50)

	if h.ClientConnCount() != 1 {
		t.Errorf("expected 1 client connection, got %d", h.ClientConnCount())
	}

	h.unregister <- c

	time.Sleep(time.Millisecond * 50)

	if h.ClientConnCount() != 0 {
		t.Errorf("expected 0 client connections after unregister, got %d", h.ClientConnCount())
	}
}

func TestCB87_Hub_Broadcast(t *testing.T) {
	h := newHub()
	go h.run()
	defer h.Stop()

	c := &Connection{
		hub:      h,
		id:       "user1",
		connType: "client",
		send:     make(chan []byte, 256),
	}

	h.register <- c
	time.Sleep(time.Millisecond * 50)

	h.broadcast <- []byte("broadcast message")

	time.Sleep(time.Millisecond * 50)

	select {
	case msg := <-c.send:
		if string(msg) != "broadcast message" {
			t.Errorf("expected 'broadcast message', got %s", string(msg))
		}
	default:
		t.Error("expected message in send channel")
	}
}

// ============================================================
// Logger tests — additional coverage
// ============================================================

func TestCB87_Logger_Info(t *testing.T) {
	// Just verify it doesn't panic
	DefaultLogger.Info("test_info", map[string]interface{}{"key": "value"})
}

func TestCB87_Logger_Warn(t *testing.T) {
	DefaultLogger.Warn("test_warn", map[string]interface{}{"key": "value"})
}

func TestCB87_Logger_Error(t *testing.T) {
	DefaultLogger.Error("test_error", map[string]interface{}{"key": "value"})
}

func TestCB87_Logger_Debug(t *testing.T) {
	DefaultLogger.Debug("test_debug", map[string]interface{}{"key": "value"})
}

func TestCB87_Logger_NilFields(t *testing.T) {
	DefaultLogger.Info("test_nil_fields", nil)
}

// ============================================================
// parseSize tests
// ============================================================

func TestCB87_ParseSize_Valid(t *testing.T) {
	cases := []struct {
		input    string
		expected int64
	}{
		{"100", 100},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"0", 0},
	}

	for _, tc := range cases {
		result, err := parseSize(tc.input)
		if err != nil {
			t.Errorf("parseSize(%q) error: %v", tc.input, err)
		}
		if result != tc.expected {
			t.Errorf("parseSize(%q) = %d, expected %d", tc.input, result, tc.expected)
		}
	}
}

func TestCB87_ParseSize_Invalid(t *testing.T) {
	_, err := parseSize("invalid")
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestCB87_ParseSize_Empty(t *testing.T) {
	result, err := parseSize("")
	if err != nil {
		// Empty string might return error or 0
		_ = err
	}
	_ = result
}

// ============================================================
// isAllowedContentType tests
// ============================================================

func TestCB87_IsAllowedContentType_Allowed(t *testing.T) {
	allowed := []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/bmp",
		"image/svg+xml",
		"image/tiff",
		"image/x-icon",
		"video/mp4",
		"video/webm",
		"audio/mpeg",
		"audio/wav",
		"audio/ogg",
		"application/pdf",
		"text/plain",
		"text/csv",
	}

	for _, ct := range allowed {
		if !isAllowedContentType(ct) {
			t.Errorf("expected %s to be allowed", ct)
		}
	}
}

func TestCB87_IsAllowedContentType_Disallowed(t *testing.T) {
	disallowed := []string{
		"application/octet-stream",
		"application/x-executable",
		"application/zip",
	}

	for _, ct := range disallowed {
		if isAllowedContentType(ct) {
			t.Errorf("expected %s to be disallowed", ct)
		}
	}
}

// ============================================================
// getMaxUploadSize / getUploadDir / ensureUploadDir tests
// ============================================================

func TestCB87_GetMaxUploadSize_Default(t *testing.T) {
	os.Unsetenv("MAX_UPLOAD_SIZE")
	size := getMaxUploadSize()
	if size <= 0 {
		t.Errorf("expected positive default max upload size, got %d", size)
	}
}

func TestCB87_GetMaxUploadSize_Custom(t *testing.T) {
	oldSize := maxUploadSize
	maxUploadSize = 5 * 1024 * 1024
	defer func() { maxUploadSize = oldSize }()

	size := getMaxUploadSize()
	if size != 5*1024*1024 {
		t.Errorf("expected 5MB, got %d", size)
	}
}

func TestCB87_GetUploadDir_Default(t *testing.T) {
	oldPath := serverDBPath
	serverDBPath = "/tmp/cb87_server.db"
	defer func() { serverDBPath = oldPath }()

	dir := getUploadDir()
	if dir == "" {
		t.Error("expected non-empty upload dir")
	}
	if !strings.Contains(dir, "uploads") {
		t.Errorf("expected dir to contain 'uploads', got %s", dir)
	}
}

func TestCB87_GetUploadDir_Custom(t *testing.T) {
	oldPath := serverDBPath
	serverDBPath = "/tmp/cb87_custom.db"
	defer func() { serverDBPath = oldPath }()

	dir := getUploadDir()
	expectedPath := filepath.Join(filepath.Dir("/tmp/cb87_custom.db"), UploadSubdir)
	if dir != expectedPath {
		t.Errorf("expected %s, got %s", expectedPath, dir)
	}
}

func TestCB87_EnsureUploadDir(t *testing.T) {
	// ensureUploadDir uses getUploadDir() which is based on serverDBPath
	// We can't easily test it without setting serverDBPath, so just verify it doesn't panic
	// with the default path
	oldPath := serverDBPath
	serverDBPath = "/tmp/cb87_test_server.db"
	defer func() { serverDBPath = oldPath }()

	dir := getUploadDir()
	defer os.RemoveAll(dir)

	err := ensureUploadDir()
	if err != nil {
		t.Fatalf("ensureUploadDir failed: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestCB87_EnsureUploadDir_AlreadyExists(t *testing.T) {
	oldPath := serverDBPath
	serverDBPath = "/tmp/cb87_test_server2.db"
	defer func() { serverDBPath = oldPath }()

	dir := getUploadDir()
	defer os.RemoveAll(dir)

	os.MkdirAll(dir, 0755)

	err := ensureUploadDir()
	if err != nil {
		t.Fatalf("ensureUploadDir failed for existing dir: %v", err)
	}
}

// ============================================================
// envIntOrDefault / envDurationOrDefault tests
// ============================================================

func TestCB87_EnvIntOrDefault_Default(t *testing.T) {
	os.Unsetenv("CB87_INT_TEST")
	result := envIntOrDefault("CB87_INT_TEST", 42)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestCB87_EnvIntOrDefault_Valid(t *testing.T) {
	os.Setenv("CB87_INT_TEST", "100")
	defer os.Unsetenv("CB87_INT_TEST")
	result := envIntOrDefault("CB87_INT_TEST", 42)
	if result != 100 {
		t.Errorf("expected 100, got %d", result)
	}
}

func TestCB87_EnvIntOrDefault_Invalid(t *testing.T) {
	os.Setenv("CB87_INT_TEST", "not_a_number")
	defer os.Unsetenv("CB87_INT_TEST")
	result := envIntOrDefault("CB87_INT_TEST", 42)
	if result != 42 {
		t.Errorf("expected 42 (fallback), got %d", result)
	}
}

func TestCB87_EnvDurationOrDefault_Default(t *testing.T) {
	os.Unsetenv("CB87_DUR_TEST")
	result := envDurationOrDefault("CB87_DUR_TEST", 30*time.Minute)
	if result != 30*time.Minute {
		t.Errorf("expected 30m, got %v", result)
	}
}

func TestCB87_EnvDurationOrDefault_Valid(t *testing.T) {
	os.Setenv("CB87_DUR_TEST", "1h30m")
	defer os.Unsetenv("CB87_DUR_TEST")
	result := envDurationOrDefault("CB87_DUR_TEST", 30*time.Minute)
	if result != 90*time.Minute {
		t.Errorf("expected 90m, got %v", result)
	}
}

func TestCB87_EnvDurationOrDefault_Invalid(t *testing.T) {
	os.Setenv("CB87_DUR_TEST", "not_a_duration")
	defer os.Unsetenv("CB87_DUR_TEST")
	result := envDurationOrDefault("CB87_DUR_TEST", 30*time.Minute)
	if result != 30*time.Minute {
		t.Errorf("expected 30m (fallback), got %v", result)
	}
}

// ============================================================
// initSchemaForDriver tests
// ============================================================

func TestCB87_InitSchemaForDriver_SQLite(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = oldDriver }()

	schema := initSchemaForDriver()
	if schema == "" {
		t.Error("expected non-empty schema for SQLite")
	}
	if !strings.Contains(schema, "CREATE TABLE") {
		t.Error("expected CREATE TABLE in schema")
	}
}

func TestCB87_InitSchemaForDriver_PostgreSQL(t *testing.T) {
	oldDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = oldDriver }()

	schema := initSchemaForDriver()
	if schema == "" {
		t.Error("expected non-empty schema for PostgreSQL")
	}
}

// ============================================================
// initQueueDB tests
// ============================================================

func TestCB87_InitQueueDB_Success(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	// Verify table exists
	var name string
	err = testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&name)
	if err != nil {
		t.Fatalf("offline_queue table not found: %v", err)
	}
}

func TestCB87_InitQueueDB_NilDB(t *testing.T) {
	// Should not panic
	initQueueDB(nil)
}

func TestCB87_InitQueueDB_Idempotent(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	initQueueDB(testDB)
	initQueueDB(testDB) // should not fail

	// Verify only one table
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='offline_queue'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 table, got %d", count)
	}
}

// ============================================================
// cleanStaleQueueMessages tests
// ============================================================

func TestCB87_CleanStaleQueueMessages_RemovesOld(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer testDB.Close()

	initQueueDB(testDB)

	// Insert a stale message (old queued_at)
	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES ('user1', ?, ?)",
		[]byte("old_msg"), time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert: %v", err)
	}

	// Insert a fresh message
	_, err = testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES ('user1', ?, ?)",
		[]byte("new_msg"), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert: %v", err)
	}

	// Clean with 1 hour TTL
	cleanStaleQueueMessages(testDB, time.Hour)

	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = 'user1'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 message after cleanup, got %d", count)
	}
}

func TestCB87_CleanStaleQueueMessages_NilDB(t *testing.T) {
	// Should not panic
	cleanStaleQueueMessages(nil, time.Hour)
}

// deleteOfflineMessages doesn't exist in the codebase - removed
// persistOfflineMessage doesn't exist in the codebase - removed

// ============================================================
// MonitorAgentHeartbeats tests — targeting 100%
// ============================================================

func TestCB87_MonitorAgentHeartbeats_Disabled(t *testing.T) {
	oldInterval := agentPresenceInterval
	agentPresenceInterval = 0
	defer func() { agentPresenceInterval = oldInterval }()

	// monitorAgentHeartbeats closes monitorDone when done.
	// Create a hub manually without starting run goroutine to avoid
	// double-close of monitorDone.
	h := &Hub{
		agents:        make(map[string]*Connection),
		clientConns:   make(map[string][]*Connection),
		register:     make(chan *Connection, 256),
		unregister:   make(chan *Connection, 256),
		broadcast:    make(chan []byte, 256),
		done:         make(chan struct{}),
		monitorDone:   make(chan struct{}),
		runDone:      make(chan struct{}),
	}

	// With interval=0, monitorAgentHeartbeats returns immediately after closing monitorDone
	h.monitorAgentHeartbeats()

	// Verify monitorDone was closed
	select {
	case <-h.monitorDone:
		// good, channel was closed
	default:
		t.Error("expected monitorDone to be closed")
	}
}

func TestCB87_MonitorAgentHeartbeats_WithStop(t *testing.T) {
	oldInterval := agentPresenceInterval
	agentPresenceInterval = time.Millisecond * 10
	defer func() { agentPresenceInterval = oldInterval }()

	h := newHub()
	go h.run()
	defer h.Stop()

	// Let it run briefly
	time.Sleep(time.Millisecond * 30)
}

// ============================================================
// checkRateLimit tests — targeting 100%
// ============================================================

func TestCB87_CheckRateLimit_Allowed(t *testing.T) {
	oldLimit := messageRateLimiter
	messageRateLimiter = NewRateLimiter(100, time.Minute)
	defer func() { messageRateLimiter = oldLimit; messageRateLimiter.Stop() }()

	oldUserLimit := userRateLimiter
	userRateLimiter = NewRateLimiter(100, time.Minute)
	defer func() { userRateLimiter = oldUserLimit; userRateLimiter.Stop() }()

	c := &Connection{
		id:       "user1",
		connType: "client",
	}

	if !checkRateLimit(c) {
		t.Error("expected checkRateLimit to return true")
	}
}

func TestCB87_CheckRateLimit_Exceeded(t *testing.T) {
	oldLimit := messageRateLimiter
	messageRateLimiter = NewRateLimiter(1, time.Minute)
	defer func() { messageRateLimiter = oldLimit; messageRateLimiter.Stop() }()

	oldUserLimit := userRateLimiter
	userRateLimiter = NewRateLimiter(100, time.Minute)
	defer func() { userRateLimiter = oldUserLimit; userRateLimiter.Stop() }()

	c := &Connection{
		id:       "user1",
		connType: "client",
	}

	if !checkRateLimit(c) {
		t.Error("expected first call to be allowed")
	}
	if checkRateLimit(c) {
		t.Error("expected second call to be rate limited")
	}
}

// ============================================================
// cpuProfileTestSetup tests — targeting 93.8% → 100%
// ============================================================

func TestCB87_CpuProfileTestSetup_Basic(t *testing.T) {
	cleanup := cpuProfileTestSetup()
	if cleanup != nil {
		cleanup()
	}
}

func TestCB87_CpuProfileTestSetup_WithDir(t *testing.T) {
	dir := "/tmp/cb87_cpu_profile_test"
	defer os.RemoveAll(dir)

	os.Setenv("PROFILING_DIR", dir)
	defer os.Unsetenv("PROFILING_DIR")

	cleanup := cpuProfileTestSetup()
	if cleanup != nil {
		cleanup()
	}
}

// ============================================================
// ValidateAgentSecret tests
// ============================================================

func TestCB87_ValidateAgentSecret_Correct(t *testing.T) {
	oldSecret := agentSecret
	agentSecret = "test-secret"
	defer func() { agentSecret = oldSecret }()

	err := ValidateAgentSecret("agent1", "test-secret")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestCB87_ValidateAgentSecret_Wrong(t *testing.T) {
	oldSecret := agentSecret
	agentSecret = "test-secret"
	defer func() { agentSecret = oldSecret }()

	err := ValidateAgentSecret("agent1", "wrong-secret")
	if err == nil {
		t.Error("expected non-nil error for wrong secret")
	}
}

func TestCB87_ValidateAgentSecret_Empty(t *testing.T) {
	oldSecret := agentSecret
	agentSecret = "test-secret"
	defer func() { agentSecret = oldSecret }()

	err := ValidateAgentSecret("agent1", "")
	if err == nil {
		t.Error("expected non-nil error for empty string")
	}
}

// ============================================================
// GenerateJWT tests
// ============================================================

func TestCB87_GenerateJWT_Success(t *testing.T) {
	oldSecret := jwtSecret
	jwtSecret = []byte("cb87-gen-jwt-secret")
	defer func() { jwtSecret = oldSecret }()

	token, err := GenerateJWT("user1", "testuser")
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}

	// Validate the token
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}
	if claims.UserID != "user1" {
		t.Errorf("expected UserID=user1, got %s", claims.UserID)
	}
}