package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Migration represents a numbered SQL migration.
type Migration struct {
	Version  int
	Name     string
	UpSQL    string
	DownSQL  string
}

// migrations is the ordered list of all migrations.
// Each migration should be idempotent where possible (SQLite ALTER TABLE ADD COLUMN
// will fail if column exists, which we handle gracefully).
var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_schema",
		UpSQL: `
CREATE TABLE IF NOT EXISTS agents (
	id TEXT PRIMARY KEY,
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
);

CREATE TABLE IF NOT EXISTS conversations (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id),
	FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS device_tokens (
	user_id TEXT NOT NULL,
	device_token TEXT NOT NULL,
	platform TEXT NOT NULL DEFAULT 'ios',
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (user_id, device_token),
	FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS messages (
	id TEXT PRIMARY KEY,
	conversation_id TEXT NOT NULL,
	sender_type TEXT NOT NULL,
	sender_id TEXT NOT NULL,
	content TEXT NOT NULL,
	metadata TEXT,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id)
);
`,
		DownSQL: `
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS device_tokens;
DROP TABLE IF EXISTS conversations;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS agents;
`,
	},
	{
		Version: 2,
		Name:    "agent_metadata_columns",
		UpSQL: `
ALTER TABLE agents ADD COLUMN model TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN personality TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN specialty TEXT NOT NULL DEFAULT '';
`,
		DownSQL: `
-- SQLite does not support DROP COLUMN before 3.35.0
-- These columns are harmless if left in place.
`,
	},
	{
		Version: 3,
		Name:    "message_read_at",
		UpSQL: `
ALTER TABLE messages ADD COLUMN read_at TIMESTAMP DEFAULT NULL;
`,
		DownSQL: `
-- SQLite does not support DROP COLUMN before 3.35.0
`,
	},
	{
		Version: 4,
		Name:    "attachments_table",
		UpSQL: `
CREATE TABLE IF NOT EXISTS attachments (
	id TEXT PRIMARY KEY,
	message_id TEXT,
	user_id TEXT NOT NULL,
	filename TEXT NOT NULL,
	content_type TEXT NOT NULL,
	size INTEGER NOT NULL,
	sha256 TEXT NOT NULL,
	storage_path TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (message_id) REFERENCES messages(id),
	FOREIGN KEY (user_id) REFERENCES users(id)
);
`,
		DownSQL: `
DROP TABLE IF EXISTS attachments;
`,
	},
	{
		Version: 5,
		Name:    "e2e_encryption_tables",
		UpSQL: `
CREATE TABLE IF NOT EXISTS key_bundles (
	id TEXT PRIMARY KEY,
	owner_id TEXT NOT NULL,
	owner_type TEXT NOT NULL,
	key_type TEXT NOT NULL,
	public_key TEXT NOT NULL,
	signature TEXT,
	key_id INTEGER,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS encrypted_messages (
	id TEXT PRIMARY KEY,
	conversation_id TEXT NOT NULL,
	sender_id TEXT NOT NULL,
	sender_type TEXT NOT NULL,
	ciphertext TEXT NOT NULL,
	iv TEXT NOT NULL,
	recipient_key_id TEXT NOT NULL,
	sender_key_id TEXT,
	algorithm TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id)
);
`,
		DownSQL: `
DROP TABLE IF EXISTS encrypted_messages;
DROP TABLE IF EXISTS key_bundles;
`,
	},
	{
		Version: 6,
		Name:    "reactions_and_tags_tables",
		UpSQL: `
CREATE TABLE IF NOT EXISTS reactions (
	id TEXT PRIMARY KEY,
	message_id TEXT NOT NULL,
	user_id TEXT NOT NULL,
	emoji TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (message_id) REFERENCES messages(id),
	FOREIGN KEY (user_id) REFERENCES users(id),
	UNIQUE(message_id, user_id, emoji)
);

CREATE TABLE IF NOT EXISTS conversation_tags (
	id TEXT PRIMARY KEY,
	conversation_id TEXT NOT NULL,
	tag TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id),
	UNIQUE(conversation_id, tag)
);
`,
		DownSQL: `
DROP TABLE IF EXISTS conversation_tags;
DROP TABLE IF EXISTS reactions;
`,
	},
	{
		Version: 7,
		Name:    "message_edit_delete_columns",
		UpSQL: `
ALTER TABLE messages ADD COLUMN edited_at TIMESTAMP DEFAULT NULL;
ALTER TABLE messages ADD COLUMN is_deleted BOOLEAN DEFAULT 0;
`,
		DownSQL: `
-- SQLite doesn't support DROP COLUMN easily; no-op for safety
`,
	},
}

func main() {
	dbPath := flag.String("db", "./data/agent-messenger.db", "path to SQLite database")
	action := flag.String("action", "", "migration action: up, down, status, create")
	targetVersion := flag.Int("target", -1, "target version for up/down (default: latest)")
	migrationName := flag.String("name", "", "name for new migration (used with 'create' action)")
	flag.Parse()

	if *action == "" {
		fmt.Fprintln(os.Stderr, "Usage: am-migrate -db <path> -action <up|down|status|create> [-target N] [-name name]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Actions:")
		fmt.Fprintln(os.Stderr, "  up      Run pending migrations (to latest or -target version)")
		fmt.Fprintln(os.Stderr, "  down    Rollback migrations (to version 0 or -target version)")
		fmt.Fprintln(os.Stderr, "  status  Show current migration version and pending migrations")
		fmt.Fprintln(os.Stderr, "  create  Generate a new migration file stub with -name")
		os.Exit(1)
	}

	switch *action {
	case "up":
		if err := migrateUp(*dbPath, *targetVersion); err != nil {
			log.Fatalf("Migration up failed: %v", err)
		}
	case "down":
		if err := migrateDown(*dbPath, *targetVersion); err != nil {
			log.Fatalf("Migration down failed: %v", err)
		}
	case "status":
		if err := showStatus(*dbPath); err != nil {
			log.Fatalf("Status check failed: %v", err)
		}
	case "create":
		if *migrationName == "" {
			log.Fatal("-name is required for 'create' action")
		}
		if err := createMigrationStub(*dbPath, *migrationName); err != nil {
			log.Fatalf("Create migration failed: %v", err)
		}
	default:
		log.Fatalf("Unknown action: %s (use up, down, status, or create)", *action)
	}
}

// ensureMigrationsTable creates the schema_migrations table if it doesn't exist.
func ensureMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER NOT NULL,
			name TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (version)
		);
	`)
	return err
}

// getCurrentVersion returns the highest applied migration version.
func getCurrentVersion(db *sql.DB) (int, error) {
	var version int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	return version, err
}

// getAppliedMigrations returns all applied migration versions.
func getAppliedMigrations(db *sql.DB) (map[int]string, error) {
	rows, err := db.Query("SELECT version, name FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]string)
	for rows.Next() {
		var v int
		var n string
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		applied[v] = n
	}
	return applied, rows.Err()
}

// migrateUp applies pending migrations up to the target version (or latest).
func migrateUp(dbPath string, targetVersion int) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := ensureMigrationsTable(db); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	current, err := getCurrentVersion(db)
	if err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	// Sort migrations by version
	sorted := make([]Migration, len(migrations))
	copy(sorted, migrations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Version < sorted[j].Version
	})

	// Determine target
	maxVersion := sorted[len(sorted)-1].Version
	if targetVersion < 0 {
		targetVersion = maxVersion
	}
	if targetVersion > maxVersion {
		return fmt.Errorf("target version %d exceeds available migrations (%d)", targetVersion, maxVersion)
	}

	applied := 0
	for _, m := range sorted {
		if m.Version <= current {
			continue
		}
		if m.Version > targetVersion {
			break
		}

		log.Printf("Applying migration %d: %s", m.Version, m.Name)

		// For ALTER TABLE ADD COLUMN, ignore "duplicate column" errors
		for _, stmt := range splitStatements(m.UpSQL) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			_, err := db.Exec(stmt)
			if err != nil {
				// Allow idempotent ALTER TABLE ADD COLUMN to fail silently
				if isDuplicateColumnError(err) {
					log.Printf("  (column already exists, skipping)")
					continue
				}
				return fmt.Errorf("migration %d (%s) statement failed: %w\n  SQL: %s", m.Version, m.Name, err, stmt)
			}
		}

		// Record the migration
		_, err = db.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", m.Version, m.Name)
		if err != nil {
			return fmt.Errorf("record migration %d: %w", m.Version, err)
		}

		applied++
		log.Printf("  ✓ Applied migration %d: %s", m.Version, m.Name)
	}

	if applied == 0 {
		log.Printf("Database is already at version %d, no migrations to apply", current)
	} else {
		newVersion, _ := getCurrentVersion(db)
		log.Printf("Migrated from version %d to %d (%d migration(s) applied)", current, newVersion, applied)
	}

	return nil
}

// migrateDown rolls back migrations to the target version (or 0).
func migrateDown(dbPath string, targetVersion int) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := ensureMigrationsTable(db); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	current, err := getCurrentVersion(db)
	if err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	if targetVersion < 0 {
		targetVersion = 0
	}

	if targetVersion >= current {
		log.Printf("Database is already at version %d, nothing to roll back", current)
		return nil
	}

	// Sort migrations descending for rollback
	sorted := make([]Migration, len(migrations))
	copy(sorted, migrations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Version > sorted[j].Version
	})

	rolledBack := 0
	for _, m := range sorted {
		if m.Version <= targetVersion || m.Version > current {
			continue
		}

		log.Printf("Rolling back migration %d: %s", m.Version, m.Name)

		for _, stmt := range splitStatements(m.DownSQL) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" || strings.HasPrefix(stmt, "--") {
				continue
			}
			_, err := db.Exec(stmt)
			if err != nil {
				log.Printf("  Warning: rollback statement failed (non-fatal): %v", err)
			}
		}

		// Remove the migration record
		_, err = db.Exec("DELETE FROM schema_migrations WHERE version = ?", m.Version)
		if err != nil {
			return fmt.Errorf("remove migration record %d: %w", m.Version, err)
		}

		rolledBack++
		log.Printf("  ✓ Rolled back migration %d: %s", m.Version, m.Name)
	}

	if rolledBack == 0 {
		log.Printf("No migrations to roll back")
	} else {
		newVersion, _ := getCurrentVersion(db)
		log.Printf("Rolled back from version %d to %d (%d migration(s) removed)", current, newVersion, rolledBack)
	}

	return nil
}

// showStatus displays the current migration version and pending migrations.
func showStatus(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := ensureMigrationsTable(db); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	current, err := getCurrentVersion(db)
	if err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	applied, err := getAppliedMigrations(db)
	if err != nil {
		return fmt.Errorf("get applied migrations: %w", err)
	}

	sorted := make([]Migration, len(migrations))
	copy(sorted, migrations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Version < sorted[j].Version
	})

	maxVersion := 0
	if len(sorted) > 0 {
		maxVersion = sorted[len(sorted)-1].Version
	}

	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Current version: %d\n", current)
	fmt.Printf("Latest available: %d\n", maxVersion)
	fmt.Println()

	if len(applied) > 0 {
		fmt.Println("Applied migrations:")
		for _, m := range sorted {
			if _, ok := applied[m.Version]; ok {
				fmt.Printf("  ✓ %d: %s\n", m.Version, m.Name)
			}
		}
	}

	pending := 0
	for _, m := range sorted {
		if _, ok := applied[m.Version]; !ok {
			if pending == 0 {
				fmt.Println("Pending migrations:")
			}
			fmt.Printf("  ○ %d: %s\n", m.Version, m.Name)
			pending++
		}
	}

	if pending == 0 && current == maxVersion {
		fmt.Println("Database is up to date.")
	}

	return nil
}

// createMigrationStub generates a new migration file in the migrations/ directory.
func createMigrationStub(dbPath string, name string) error {
	// Determine next version number
	nextVersion := len(migrations) + 1

	// Look for existing migration files to determine the next number
	migrationsDir := filepath.Join(filepath.Dir(dbPath), "..", "migrations")
	if err := os.MkdirAll(migrationsDir, 0755); err != nil {
		return fmt.Errorf("create migrations directory: %w", err)
	}

	// Check existing files
	entries, _ := os.ReadDir(migrationsDir)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		if v, err := strconv.Atoi(parts[0]); err == nil && v >= nextVersion {
			nextVersion = v + 1
		}
	}

	filename := fmt.Sprintf("%03d_%s.sql", nextVersion, name)
	filePath := filepath.Join(migrationsDir, filename)

	content := fmt.Sprintf("-- Migration %d: %s\n-- Created: %s\n\n-- Up\n\n-- Down\n", nextVersion, name, "auto-generated")

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write migration file: %w", err)
	}

	log.Printf("Created migration stub: %s", filePath)
	log.Printf("Add the migration to the migrations slice in main.go and update the list.")
	return nil
}

// splitStatements splits SQL text into individual statements on semicolons.
func splitStatements(sql string) []string {
	statements := strings.Split(sql, ";")
	// Remove empty trailing element from final semicolon
	result := make([]string, 0, len(statements))
	for _, s := range statements {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// isDuplicateColumnError checks if the error is SQLite's "duplicate column name" error.
func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column name")
}