package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Initialize database
	var err error
	db, err = sql.Open("sqlite3", "./data/agent-messenger.db")
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

	// Set up routes
	http.HandleFunc("/agent/connect", handleAgentConnect)
	http.HandleFunc("/client/connect", handleClientConnect)
	http.HandleFunc("/health", handleHealth)

	// Auth endpoints
	http.HandleFunc("/auth/login", handleLogin)
	http.HandleFunc("/auth/agent", handleRegisterAgent)
	http.HandleFunc("/auth/user", handleRegisterUser)

	// Conversation endpoints
	http.HandleFunc("/conversations/create", handleCreateConversation)
	http.HandleFunc("/conversations/list", handleListConversations)
	http.HandleFunc("/conversations/messages", handleGetMessages)

	// Start server
	log.Println("Agent Messenger starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		api_key_hash TEXT NOT NULL,
		name TEXT NOT NULL,
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
	_, err := db.Exec(schema)
	return err
}