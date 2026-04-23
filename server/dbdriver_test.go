package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLiteDriverPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := openDatabase(DriverSQLite, dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	if currentDriver != DriverSQLite {
		t.Errorf("Expected currentDriver to be %s, got %s", DriverSQLite, currentDriver)
	}

	if err := initSchema(db); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}

	// Verify tables were created
	tables := []string{"users", "agents", "conversations", "messages", "attachments", "key_bundles", "encrypted_messages", "schema_migrations"}
	for _, table := range tables {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		if err != nil {
			t.Errorf("Error checking table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("Table %s not found in SQLite database", table)
		}
	}
}

func TestPostgreSQLSchemaGeneration(t *testing.T) {
	// Save and restore driver
	origDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = origDriver }()

	schema := initSchemaForDriver()
	if schema != pgSchema {
		t.Error("PostgreSQL schema should match pgSchema constant")
	}

	// Verify key PostgreSQL-specific features in the schema
	if !containsString(schema, "BIGINT") {
		t.Error("PostgreSQL schema should use BIGINT for attachment sizes")
	}
	if !containsString(schema, "schema_migrations") {
		t.Error("PostgreSQL schema should include schema_migrations table")
	}
}

func TestSQLiteSchemaGeneration(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = origDriver }()

	schema := initSchemaForDriver()
	if schema != sqliteSchema {
		t.Error("SQLite schema should match sqliteSchema constant")
	}
}

func TestPlaceholderSQLite(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { currentDriver = origDriver }()

	if Placeholder(1) != "?" {
		t.Errorf("Expected ?, got %s", Placeholder(1))
	}
	if Placeholders(1, 3) != "?, ?, ?" {
		t.Errorf("Expected '?, ?, ?', got %s", Placeholders(1, 3))
	}
}

func TestPlaceholderPostgreSQL(t *testing.T) {
	origDriver := currentDriver
	currentDriver = DriverPostgreSQL
	defer func() { currentDriver = origDriver }()

	if Placeholder(1) != "$1" {
		t.Errorf("Expected $1, got %s", Placeholder(1))
	}
	if Placeholder(3) != "$3" {
		t.Errorf("Expected $3, got %s", Placeholder(3))
	}
	if Placeholders(1, 3) != "$1, $2, $3" {
		t.Errorf("Expected '$1, $2, $3', got %s", Placeholders(1, 3))
	}
}

func TestOpenDatabaseSQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := openDatabase(DriverSQLite, dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Errorf("Failed to ping SQLite: %v", err)
	}
}

func TestOpenDatabaseInvalidDriver(t *testing.T) {
	_, err := openDatabase("nonexistent", "whatever")
	if err == nil {
		t.Error("Expected error for invalid driver")
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSQLiteDriverWithFullInit(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Use the same path as the openDatabase function
	serverDBPath = dbPath

	db, err := openDatabase(DriverSQLite, dbPath)
	if err != nil {
		t.Fatalf("Failed to open SQLite: %v", err)
	}
	defer func() {
		db.Close()
		// Reset global for other tests
		currentDriver = ""
	}()

	// Initialize the global db variable for initSchema
	origDB := db
	_ = origDB

	if err := initSchema(db); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}

	// Verify schema_migrations populated
	var count int
	db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count == 0 {
		t.Error("Expected schema_migrations to be populated")
	}
}

// Re-declare sql.DB type usage for the test
var _ *sql.DB