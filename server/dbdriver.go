package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Supported database drivers
const (
	DriverSQLite     = "sqlite3"
	DriverPostgreSQL = "postgres"
)

// currentDriver holds the active database driver name
var currentDriver string

// Placeholder returns the appropriate placeholder for the current driver
// SQLite uses ?, PostgreSQL uses $1, $2, etc.
func Placeholder(n int) string {
	if currentDriver == DriverPostgreSQL {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// Placeholders returns n placeholders separated by commas
func Placeholders(start, count int) string {
	parts := make([]string, count)
	for i := 0; i < count; i++ {
		parts[i] = Placeholder(start + i)
	}
	return strings.Join(parts, ", ")
}

// openDatabase opens a database connection using the appropriate driver
func openDatabase(driver, dsn string) (*sql.DB, error) {
	currentDriver = driver

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool based on driver
	if driver == DriverPostgreSQL {
		maxOpen := envIntOrDefault("DB_MAX_OPEN_CONNS", 25)
		maxIdle := envIntOrDefault("DB_MAX_IDLE_CONNS", 5)
		maxLifetime := envDurationOrDefault("DB_CONN_MAX_LIFETIME", 30*time.Minute)
		maxIdleTime := envDurationOrDefault("DB_CONN_MAX_IDLE_TIME", 5*time.Minute)

		db.SetMaxOpenConns(maxOpen)
		db.SetMaxIdleConns(maxIdle)
		db.SetConnMaxLifetime(maxLifetime)
		db.SetConnMaxIdleTime(maxIdleTime)

		log.Printf("Connected to PostgreSQL database (pool: maxOpen=%d, maxIdle=%d, maxLifetime=%s, maxIdleTime=%s)",
			maxOpen, maxIdle, maxLifetime, maxIdleTime)

		// Verify connection
		if err := db.Ping(); err != nil {
			return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
		}
	} else {
		// SQLite: single connection for write safety, enable WAL mode
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.Exec("PRAGMA journal_mode=WAL")
		db.Exec("PRAGMA foreign_keys=ON")
		db.Exec("PRAGMA busy_timeout=5000")
		log.Printf("Connected to SQLite database (WAL mode, busy_timeout=5s)")
	}

	return db, nil
}

// envIntOrDefault returns the integer value of the environment variable,
// or the default value if not set or invalid.
func envIntOrDefault(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		log.Printf("Warning: invalid %s value %q, using default %d", key, v, defaultVal)
	}
	return defaultVal
}

// envDurationOrDefault returns the duration value of the environment variable
// (supports Go duration strings like "30m", "5s", "1h30m"), or the default value
// if not set or invalid.
func envDurationOrDefault(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("Warning: invalid %s value %q, using default %s", key, v, defaultVal)
	}
	return defaultVal
}

// initSchemaForDriver returns the appropriate schema SQL for the current driver
func initSchemaForDriver() string {
	if currentDriver == DriverPostgreSQL {
		return pgSchema
	}
	return sqliteSchema
}

// SQLite schema (original)
const sqliteSchema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agents (
	id TEXT NOT NULL PRIMARY KEY,
	name TEXT NOT NULL DEFAULT '',
	model TEXT NOT NULL DEFAULT '',
	personality TEXT NOT NULL DEFAULT '',
	specialty TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'offline',
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
	edited_at TIMESTAMP,
	is_deleted BOOLEAN DEFAULT 0,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id)
);

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

CREATE TABLE IF NOT EXISTS notification_preferences (
	user_id TEXT NOT NULL,
	conversation_id TEXT NOT NULL,
	muted INTEGER NOT NULL DEFAULT 0,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (user_id, conversation_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS offline_queue (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	recipient TEXT NOT NULL,
	data BLOB NOT NULL,
	queued_at DATETIME NOT NULL,
	sent_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queue_recipient ON offline_queue(recipient);
`

// PostgreSQL schema (compatible version)
const pgSchema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agents (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL DEFAULT '',
	model TEXT NOT NULL DEFAULT '',
	personality TEXT NOT NULL DEFAULT '',
	specialty TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'offline',
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
	edited_at TIMESTAMP,
	is_deleted BOOLEAN DEFAULT FALSE,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id)
);

CREATE TABLE IF NOT EXISTS attachments (
	id TEXT PRIMARY KEY,
	message_id TEXT,
	user_id TEXT NOT NULL,
	filename TEXT NOT NULL,
	content_type TEXT NOT NULL,
	size BIGINT NOT NULL,
	sha256 TEXT NOT NULL,
	storage_path TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (message_id) REFERENCES messages(id),
	FOREIGN KEY (user_id) REFERENCES users(id)
);

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

CREATE TABLE IF NOT EXISTS notification_preferences (
	user_id TEXT NOT NULL,
	conversation_id TEXT NOT NULL,
	muted BOOLEAN DEFAULT FALSE,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (user_id, conversation_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS offline_queue (
	id SERIAL PRIMARY KEY,
	recipient TEXT NOT NULL,
	data BYTEA NOT NULL,
	queued_at TIMESTAMP NOT NULL,
	sent_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queue_recipient ON offline_queue(recipient);

CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER NOT NULL,
	name TEXT NOT NULL,
	applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (version)
);
`