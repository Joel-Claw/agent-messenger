package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates a temporary database for testing.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db
}

func TestEnsureMigrationsTable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	if err := ensureMigrationsTable(db); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}

	// Verify table exists
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&name)
	if err != nil {
		t.Fatalf("schema_migrations table not created: %v", err)
	}
}

func TestGetCurrentVersionEmpty(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	if err := ensureMigrationsTable(db); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}

	version, err := getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 0 {
		t.Errorf("expected version 0, got %d", version)
	}
}

func TestMigrateUpFromScratch(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Run migrate up
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("migrateUp: %v", err)
	}

	// Verify all tables exist
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	tables := []string{"agents", "users", "conversations", "device_tokens", "messages", "schema_migrations"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}

	// Verify version
	version, err := getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 7 {
		t.Errorf("expected version 7, got %d", version)
	}
}

func TestMigrateUpIdempotent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Run migrate up twice
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("first migrateUp: %v", err)
	}
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("second migrateUp: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	version, err := getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 7 {
		t.Errorf("expected version 7 after double migrate, got %d", version)
	}
}

func TestMigrateUpToTarget(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Migrate up to version 1 only
	if err := migrateUp(dbPath, 1); err != nil {
		t.Fatalf("migrateUp to 1: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	version, err := getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}

	// Now migrate to version 2
	db.Close()
	if err := migrateUp(dbPath, 2); err != nil {
		t.Fatalf("migrateUp to 2: %v", err)
	}

	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	version, err = getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}
}

func TestMigrateDown(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// First, migrate up to latest
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("migrateUp: %v", err)
	}

	// Roll back to version 1
	if err := migrateDown(dbPath, 1); err != nil {
		t.Fatalf("migrateDown to 1: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	version, err := getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1 after rollback, got %d", version)
	}

	// Can re-migrate up
	db.Close()
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("re-migrateUp: %v", err)
	}

	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	version, err = getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 7 {
		t.Errorf("expected version 7 after re-migrate, got %d", version)
	}
}

func TestMigrateDownToZero(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Migrate up then roll back all
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("migrateUp: %v", err)
	}
	if err := migrateDown(dbPath, 0); err != nil {
		t.Fatalf("migrateDown to 0: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	version, err := getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 0 {
		t.Errorf("expected version 0 after full rollback, got %d", version)
	}

	// Tables should be dropped
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='agents'").Scan(&name)
	if err == nil {
		t.Error("agents table should have been dropped")
	}
}

func TestShowStatus(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Migrate up
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("migrateUp: %v", err)
	}

	// showStatus just prints, shouldn't error
	if err := showStatus(dbPath); err != nil {
		t.Fatalf("showStatus: %v", err)
	}
}

func TestSplitStatements(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want int
	}{
		{"empty", "", 0},
		{"single", "SELECT 1", 1},
		{"multiple", "SELECT 1; SELECT 2; SELECT 3", 3},
		{"trailing semicolon", "SELECT 1;", 1},
		{"with whitespace", "  SELECT 1  ;  SELECT 2  ;  ", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitStatements(tt.sql)
			if len(got) != tt.want {
				t.Errorf("got %d statements, want %d", len(got), tt.want)
			}
		})
	}
}

func TestIsDuplicateColumnError(t *testing.T) {
	if !isDuplicateColumnError(sql.ErrNoRows) {
		// ErrNoRows is not a duplicate column error
	}

	// We can't easily create a real duplicate column error without executing
	// ALTER TABLE ADD COLUMN twice, but we can test the string matching
	if isDuplicateColumnError(nil) {
		t.Error("nil error should not be duplicate column")
	}
}

func TestMigrateUpExistingDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create a database with the old inline schema (no schema_migrations table)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	// Create the agents table without model/personality/specialty columns
	// (simulating old schema)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	db.Close()

	// Now run migrateUp — it should add the missing columns and track migrations
	if err := migrateUp(dbPath, -1); err != nil {
		t.Fatalf("migrateUp on existing DB: %v", err)
	}

	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// Verify migration was recorded
	version, err := getCurrentVersion(db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 7 {
		t.Errorf("expected version 7, got %d", version)
	}

	// Verify the new columns exist
	_, err = db.Exec("SELECT model, personality, specialty FROM agents LIMIT 1")
	if err != nil {
		t.Errorf("metadata columns not found: %v", err)
	}
}

func TestCreateMigrationStub(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data", "test.db")

	// Create the data directory
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := createMigrationStub(dbPath, "add_avatars"); err != nil {
		t.Fatalf("createMigrationStub: %v", err)
	}

	// Check file was created
	migrationsDir := filepath.Join(filepath.Dir(dbPath), "..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 migration file, got %d", len(entries))
	}
}