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

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Command-line flags
	port := flag.String("port", "8080", "server listen port")
	dbPath := flag.String("db", "./data/agent-messenger.db", "SQLite database path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("Agent Messenger v0.1.0")
		os.Exit(0)
	}

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