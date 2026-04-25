package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// serverDBPath holds the database path for use by other modules (e.g. upload dir)
var serverDBPath string

func main() {
	// Command-line flags
	port := flag.String("port", "8080", "server listen port")
	dbDriver := flag.String("db-driver", "", "database driver: sqlite3 or postgres (env: DB_DRIVER)")
	dbPath := flag.String("db", "", "database path (SQLite) or connection string (PostgreSQL) (env: DB_PATH / DATABASE_URL)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	// Resolve driver from flag or env
	driverVal := *dbDriver
	if driverVal == "" {
		driverVal = os.Getenv("DB_DRIVER")
	}
	if driverVal == "" {
		// If DATABASE_URL is set, assume postgres
		if os.Getenv("DATABASE_URL") != "" {
			driverVal = DriverPostgreSQL
		} else {
			driverVal = DriverSQLite
		}
	}

	// Resolve DB path from flag or env
	dbPathVal := *dbPath
	if dbPathVal == "" {
		dbPathVal = os.Getenv("DATABASE_URL")
	}
	if dbPathVal == "" {
		dbPathVal = os.Getenv("DB_PATH")
	}
	if dbPathVal == "" {
		dbPathVal = "./data/agent-messenger.db"
	}

	serverDBPath = dbPathVal

	if *showVersion {
		fmt.Println("Agent Messenger v0.1.0")
		os.Exit(0)
	}

	// Ensure data directory exists (SQLite only)
	if driverVal == DriverSQLite {
		if dir := filepath.Dir(dbPathVal); dir != "" && dir != "." {
			os.MkdirAll(dir, 0755)
		}

		// Ensure upload directory exists
		if err := ensureUploadDir(); err != nil {
			log.Printf("Warning: could not create upload directory: %v", err)
		}
	}

	// Initialize database
	var err error
	db, err = openDatabase(driverVal, dbPathVal)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables
	if err := initSchema(db); err != nil {
		log.Fatal(err)
	}

	// Initialize hub
	hub = newHub()
	go hub.run()

	// Initialize metrics
	ServerMetrics = NewMetrics(hub)

	// Set up routes
	http.HandleFunc("/agent/connect", handleAgentConnect)
	http.HandleFunc("/client/connect", handleClientConnect)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/metrics", handleMetrics)

	// Auth endpoints
	http.HandleFunc("/auth/login", handleLogin)
	http.HandleFunc("/auth/agent", handleRegisterAgent)
	http.HandleFunc("/auth/user", handleRegisterUser)

	// Agent endpoints
	http.HandleFunc("/agents", handleListAgents)
	http.HandleFunc("/admin/agents", handleAdminAgents)

	// Conversation endpoints
	http.HandleFunc("/conversations/create", tieredRateLimitMiddleware(handleCreateConversation))
	http.HandleFunc("/conversations/list", tieredRateLimitMiddleware(handleListConversations))
	http.HandleFunc("/conversations/messages", tieredRateLimitMiddleware(handleGetMessages))
	http.HandleFunc("/conversations/delete", tieredRateLimitMiddleware(handleDeleteConversation))
	http.HandleFunc("/conversations/mark-read", tieredRateLimitMiddleware(handleMarkRead))

	// Message endpoints
	http.HandleFunc("/messages/search", tieredRateLimitMiddleware(handleSearchMessages))

	http.HandleFunc("/messages/edit", tieredRateLimitMiddleware(handleMessageEdit))
	http.HandleFunc("/messages/delete", tieredRateLimitMiddleware(handleMessageDelete))
	http.HandleFunc("/presence", tieredRateLimitMiddleware(handleGetPresence))
	http.HandleFunc("/presence/user", tieredRateLimitMiddleware(handleGetUserPresence))
	http.HandleFunc("/messages/react", tieredRateLimitMiddleware(handleReact))
	http.HandleFunc("/messages/reactions", tieredRateLimitMiddleware(handleGetReactions))
	http.HandleFunc("/conversations/tags/add", tieredRateLimitMiddleware(handleAddTag))
	http.HandleFunc("/conversations/tags/remove", tieredRateLimitMiddleware(handleRemoveTag))
	http.HandleFunc("/conversations/tags", tieredRateLimitMiddleware(handleGetTags))

	// Attachment endpoints
	http.HandleFunc("/attachments/upload", handleUpload)
	http.HandleFunc("/attachments/", handleGetAttachment)
	http.HandleFunc("/messages/attachments", handleListAttachments)

	// E2E encryption endpoints
	http.HandleFunc("/keys/upload", handleUploadPublicKey)
	http.HandleFunc("/keys/bundle", handleGetKeyBundle)
	http.HandleFunc("/keys/otpk-count", handleListOneTimePreKeys)
	http.HandleFunc("/messages/encrypted", handleStoreEncryptedMessage)
	http.HandleFunc("/messages/encrypted/list", handleGetEncryptedMessages)

	// Auth endpoints (extended)
	http.HandleFunc("/auth/change-password", handleChangePassword)

	// Push notification endpoints
	http.HandleFunc("/push/register", handleRegisterDeviceToken)
	http.HandleFunc("/push/unregister", handleUnregisterDeviceToken)

	// Admin rate limit tier endpoints
	http.HandleFunc("/admin/rate-limit/tier", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleSetRateLimitTier(w, r)
		} else {
			handleGetRateLimitTier(w, r)
		}
	})

	// Initialize push notifications
	initPushNotifications()

	// Serve WebChat if enabled
	webchatDir := os.Getenv("WEBCHAT_DIR")
	webchatEnabled := os.Getenv("WEBCHAT_ENABLED") == "true"
	if webchatEnabled && webchatDir != "" {
		fs := http.FileServer(http.Dir(webchatDir))
		http.Handle("/chat/", http.StripPrefix("/chat/", fs))
		log.Printf("WebChat enabled: serving from %s at /chat/", webchatDir)
	} else if webchatEnabled {
		// Try default path relative to server binary
		defaultPath := filepath.Join(filepath.Dir(*dbPath), "..", "webchat", "build")
		if abs, err := filepath.Abs(defaultPath); err == nil {
			if _, err := os.Stat(abs); err == nil {
				fs := http.FileServer(http.Dir(abs))
				http.Handle("/chat/", http.StripPrefix("/chat/", fs))
				log.Printf("WebChat enabled: serving from %s at /chat/", abs)
			}
		}
	}

	// Start server with graceful shutdown
	addr := ":" + *port
	srv := &http.Server{Addr: addr}

	go func() {
		log.Printf("Agent Messenger starting on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Start rate limiter cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			agentRateLimiter.Clean()
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received %v, shutting down gracefully...", sig)

	// Stop the hub (closes all WebSocket connections)
	hub.Stop()

	// Give connections 10 seconds to finish
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Forced shutdown: %v", err)
	}

	log.Printf("Agent Messenger stopped")
}

func initSchema(db *sql.DB) error {
	schema := initSchemaForDriver()
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Migrate: add model/personality/specialty columns if they don't exist
	// Also migrate from per-agent API keys to shared AGENT_SECRET
	//
	// Note: These inline migrations are mirrored in cmd/am-migrate/main.go.
	// When adding new migrations, update both places. The am-migrate tool
	// tracks versions in schema_migrations; the inline path creates the
	// table but does not record individual versions (for backward compat).
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER NOT NULL,
			name TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (version)
		);
	`); err != nil {
		return err
	}

	// Check if inline migrations were already recorded
	var migrationCount int
	db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migrationCount)

	if migrationCount == 0 {
		// Record the inline migrations as already applied
		inlineMigrations := []struct {
			version int
			name    string
		}{
			{1, "initial_schema"},
			{2, "agent_metadata_columns"},
			{3, "message_read_at"},
			{4, "attachments_table"},
			{5, "e2e_encryption_tables"},
			{6, "reactions_and_tags_tables"},
		{7, "message_edit_delete_columns"},
		{8, "rate_limit_tiers_table"},
		}
		for _, m := range inlineMigrations {
			if currentDriver == DriverPostgreSQL {
				db.Exec("INSERT INTO schema_migrations (version, name) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING", m.version, m.name)
			} else {
				db.Exec("INSERT OR IGNORE INTO schema_migrations (version, name) VALUES (?, ?)", m.version, m.name)
			}
		}
	}

	migrations := []string{
		"ALTER TABLE agents ADD COLUMN model TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE agents ADD COLUMN personality TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE agents ADD COLUMN specialty TEXT NOT NULL DEFAULT ''",
	}
	for _, m := range migrations {
		// ALTER TABLE ADD COLUMN may fail if column exists; ignore errors
		db.Exec(m)
	}

	// Add read_at column for read receipts
	migrations_read := []string{
		"ALTER TABLE messages ADD COLUMN read_at TIMESTAMP DEFAULT NULL",
	}
	for _, m := range migrations_read {
		db.Exec(m)
	}

	// Add edited_at and is_deleted columns for message edit/delete
	migrations_edit := []string{
		"ALTER TABLE messages ADD COLUMN edited_at TIMESTAMP DEFAULT NULL",
		"ALTER TABLE messages ADD COLUMN is_deleted BOOLEAN DEFAULT 0",
	}
	for _, m := range migrations_edit {
		db.Exec(m)
	}

	// Create reactions table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS reactions (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			emoji TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(message_id, user_id, emoji),
			FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`); err != nil {
		return err
	}

	// Create conversation_tags table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS conversation_tags (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(conversation_id, tag),
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		);
	`); err != nil {
		return err
	}

	// Create index on reactions.message_id for fast lookup
	db.Exec("CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id)")

	// Create index on conversation_tags.conversation_id for fast lookup
	db.Exec("CREATE INDEX IF NOT EXISTS idx_tags_conversation ON conversation_tags(conversation_id)")

	// Create user_rate_limit_tiers table for persistent tier storage
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user_rate_limit_tiers (
			user_id TEXT NOT NULL PRIMARY KEY,
			tier_name TEXT NOT NULL DEFAULT 'free',
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`); err != nil {
		return err
	}

	// Load persisted tiers into in-memory limiter
	loadTiersFromDB(globalTieredLimiter)

	// Migration: agents table no longer requires api_key_hash.
	// For existing DBs that have the column, it remains but is no longer used.
	// New DBs won't have it at all. No action needed either way.

	return nil
}