package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates a temporary database with the agent_messenger schema
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		api_key_hash TEXT NOT NULL,
		name TEXT NOT NULL,
		model TEXT NOT NULL DEFAULT '',
		personality TEXT NOT NULL DEFAULT '',
		specialty TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestGenerateAPIKey(t *testing.T) {
	key1 := generateAPIKey()
	key2 := generateAPIKey()

	if !strings.HasPrefix(key1, "am_") {
		t.Errorf("API key should start with 'am_', got %s", key1)
	}
	if key1 == key2 {
		t.Error("Two generated API keys should not be equal")
	}
	if len(key1) < 20 {
		t.Errorf("API key too short: %s", key1)
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID("user")
	id2 := generateID("agent")

	if !strings.HasPrefix(id1, "user_") {
		t.Errorf("ID should start with 'user_', got %s", id1)
	}
	if !strings.HasPrefix(id2, "agent_") {
		t.Errorf("ID should start with 'agent_', got %s", id2)
	}
	if id1 == generateID("user") {
		t.Error("Two generated IDs should not be equal")
	}
}

func TestOpenDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db := openDB(dbPath)
	// SQLite creates the file on first write
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS test (id TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file should exist after creating a table")
	}
}

func TestOpenDBNonexistentDir(t *testing.T) {
	// openDB calls sql.Open which doesn't actually access the file
	// This tests that openDB doesn't panic on a bad path
	dbPath := "/tmp/nonexistent_dir_am_test_" + generateID("x") + "/test.db"
	db := openDB(dbPath)
	// The file won't actually be created until a write, but openDB shouldn't panic
	db.Close()
}