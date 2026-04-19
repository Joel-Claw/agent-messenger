package main

import (
	"database/sql"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Command-line flags
	port := flag.String("port", "8080", "server listen port")
	dbPath := flag.String("db", "./data/agent-messenger.db", "SQLite database path")
	flag.Parse()

	// Ensure data directory exists
	if dir := filepath.Dir(*dbPath); dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}

	// Initialize database
	var err error
	db, err = sql.Open("sqlite3", *dbPath)
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
	http.HandleFunc("/conversations/create", handleCreateConversation)
	http.HandleFunc("/conversations/list", handleListConversations)
	http.HandleFunc("/conversations/messages", handleGetMessages)

	// Push notification endpoints
	http.HandleFunc("/push/register", handleRegisterDeviceToken)
	http.HandleFunc("/push/unregister", handleUnregisterDeviceToken)

	// Initialize push notifications
	initPushNotifications()

	// Start server
	addr := ":" + *port
	log.Printf("Agent Messenger starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func initSchema(db *sql.DB) error {
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
		email TEXT UNIQUE NOT NULL,
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
		sender_type TEXT NOT NULL, -- 'agent' or 'user'
		sender_id TEXT NOT NULL,
		content TEXT NOT NULL,
		metadata TEXT, -- JSON
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (conversation_id) REFERENCES conversations(id)
	);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Migrate: add model/personality/specialty columns if they don't exist
	migrations := []string{
		"ALTER TABLE agents ADD COLUMN model TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE agents ADD COLUMN personality TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE agents ADD COLUMN specialty TEXT NOT NULL DEFAULT ''",
	}
	for _, m := range migrations {
		// SQLite ALTER TABLE ADD COLUMN fails if column already exists;
		// we ignore the error since it just means the column is already there.
		db.Exec(m)
	}

	return nil
}