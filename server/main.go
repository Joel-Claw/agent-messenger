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
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// serverDBPath holds the database path for use by other modules (e.g. upload dir)
var serverDBPath string

// ServerVersion is the current server version, included in health/metrics responses.
var ServerVersion = "0.1.0"

// parseSize parses a human-readable size string (e.g., "50MB", "100M", "1GB") into bytes.
// Supports B, KB, MB, GB, TB suffixes (case-insensitive). Bare numbers are treated as bytes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}

	upper := strings.ToUpper(s)

	// Try to parse as plain number (bytes)
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, nil
	}

	multipliers := []struct {
		suffix string
		mult   int64
	}{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
		{"B", 1},
	}

	for _, m := range multipliers {
		if strings.HasSuffix(upper, m.suffix) {
			numStr := strings.TrimSpace(strings.TrimSuffix(upper, m.suffix))
			v, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size: %s", s)
			}
			return int64(v * float64(m.mult)), nil
		}
	}

	return 0, fmt.Errorf("invalid size format: %s (use B, KB, MB, GB, TB)", s)
}

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

	// Configure max upload size from environment
	if v := os.Getenv("MAX_UPLOAD_SIZE"); v != "" {
		size, err := parseSize(v)
		if err != nil {
			log.Printf("Invalid MAX_UPLOAD_SIZE %q, using default %d MB: %v", v, MaxUploadSize/(1<<20), err)
		} else {
			maxUploadSize = size
			log.Printf("Max upload size set to %d MB", maxUploadSize/(1<<20))
		}
	}

	// Configure agent presence heartbeat from environment (before hub init)
	if os.Getenv("AGENT_HEARTBEAT_ENABLED") == "true" {
		agentPresenceEnabled = true
		if v := os.Getenv("AGENT_HEARTBEAT_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				agentPresenceInterval = d
			} else {
				log.Printf("Invalid AGENT_HEARTBEAT_INTERVAL %q, using default %v", v, agentPresenceInterval)
			}
		}
		if v := os.Getenv("AGENT_HEARTBEAT_TIMEOUT"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				agentPresenceTimeout = d
			} else {
				log.Printf("Invalid AGENT_HEARTBEAT_TIMEOUT %q, using default %v", v, agentPresenceTimeout)
			}
		}
		// Timeout must be >= 2x interval to avoid false positives
		if agentPresenceTimeout < agentPresenceInterval*2 {
			agentPresenceTimeout = agentPresenceInterval * 2
			log.Printf("AGENT_HEARTBEAT_TIMEOUT too low, adjusted to %v (2x interval)", agentPresenceTimeout)
		}
		log.Printf("Agent presence heartbeat enabled: interval=%v, timeout=%v", agentPresenceInterval, agentPresenceTimeout)
	}

	// Initialize hub
	hub = newHub()
	go hub.run()

	// Initialize metrics
	ServerMetrics = NewMetrics(hub)

	// Set up routes
	// WebSocket endpoints (no CORS — handled by upgrade protocol)
	http.HandleFunc("/agent/connect", handleAgentConnect)
	http.HandleFunc("/client/connect", handleClientConnect)

	// REST endpoints (with CORS middleware for WebChat/SDK cross-origin access)
	http.HandleFunc("/health", corsMiddleware(handleHealth))
	http.HandleFunc("/metrics", corsMiddleware(handleMetrics))

	// Auth endpoints
	http.HandleFunc("/auth/login", corsMiddleware(handleLogin))
	http.HandleFunc("/auth/agent", corsMiddleware(handleRegisterAgent))
	http.HandleFunc("/auth/user", corsMiddleware(handleRegisterUser))

	// Agent endpoints
	http.HandleFunc("/agents", corsMiddleware(handleListAgents))
	http.HandleFunc("/admin/agents", corsMiddleware(handleAdminAgents))

	// Conversation endpoints
	http.HandleFunc("/conversations/create", corsMiddleware(tieredRateLimitMiddleware(handleCreateConversation)))
	http.HandleFunc("/conversations/list", corsMiddleware(tieredRateLimitMiddleware(handleListConversations)))
	http.HandleFunc("/conversations/messages", corsMiddleware(tieredRateLimitMiddleware(handleGetMessages)))
	http.HandleFunc("/conversations/delete", corsMiddleware(tieredRateLimitMiddleware(handleDeleteConversation)))
	http.HandleFunc("/conversations/mark-read", corsMiddleware(tieredRateLimitMiddleware(handleMarkRead)))

	// Message endpoints
	http.HandleFunc("/messages/search", corsMiddleware(tieredRateLimitMiddleware(handleSearchMessages)))
	http.HandleFunc("/messages/edit", corsMiddleware(tieredRateLimitMiddleware(handleMessageEdit)))
	http.HandleFunc("/messages/delete", corsMiddleware(tieredRateLimitMiddleware(handleMessageDelete)))
	http.HandleFunc("/presence", corsMiddleware(tieredRateLimitMiddleware(handleGetPresence)))
	http.HandleFunc("/presence/user", corsMiddleware(tieredRateLimitMiddleware(handleGetUserPresence)))
	http.HandleFunc("/messages/react", corsMiddleware(tieredRateLimitMiddleware(handleReact)))
	http.HandleFunc("/messages/reactions", corsMiddleware(tieredRateLimitMiddleware(handleGetReactions)))
	http.HandleFunc("/conversations/tags/add", corsMiddleware(tieredRateLimitMiddleware(handleAddTag)))
	http.HandleFunc("/conversations/tags/remove", corsMiddleware(tieredRateLimitMiddleware(handleRemoveTag)))
	http.HandleFunc("/conversations/tags", corsMiddleware(tieredRateLimitMiddleware(handleGetTags)))

	// Attachment endpoints
	http.HandleFunc("/attachments/upload", corsMiddleware(handleUpload))
	http.HandleFunc("/attachments/", corsMiddleware(handleGetAttachment))
	http.HandleFunc("/messages/attachments", corsMiddleware(handleListAttachments))

	// E2E encryption endpoints
	http.HandleFunc("/keys/upload", corsMiddleware(handleUploadPublicKey))
	http.HandleFunc("/keys/bundle", corsMiddleware(handleGetKeyBundle))
	http.HandleFunc("/keys/otpk-count", corsMiddleware(handleListOneTimePreKeys))
	http.HandleFunc("/messages/encrypted", corsMiddleware(handleStoreEncryptedMessage))
	http.HandleFunc("/messages/encrypted/list", corsMiddleware(handleGetEncryptedMessages))

	// Auth endpoints (extended)
	http.HandleFunc("/auth/change-password", corsMiddleware(handleChangePassword))

	// Push notification endpoints
	http.HandleFunc("/push/register", corsMiddleware(handleRegisterDeviceToken))
	http.HandleFunc("/push/unregister", corsMiddleware(handleUnregisterDeviceToken))
	http.HandleFunc("/push/vapid-key", corsMiddleware(handleGetVAPIDKey))
	http.HandleFunc("/push/web-subscribe", corsMiddleware(handleWebPushSubscribe))
	http.HandleFunc("/push/web-unsubscribe", corsMiddleware(handleWebPushUnsubscribe))

	// Admin rate limit tier endpoints
	http.HandleFunc("/admin/rate-limit/tier", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleSetRateLimitTier(w, r)
		} else {
			handleGetRateLimitTier(w, r)
		}
	}))

	// Initialize push notifications
	initPushNotifications()

	// Initialize VAPID public key for web push
	vapidPublicKey = os.Getenv("VAPID_PUBLIC_KEY")
	if vapidPublicKey != "" {
		log.Printf("VAPID public key configured for web push")
	}

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