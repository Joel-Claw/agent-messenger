package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Initialize database
	db, err := sql.Open("sqlite3", "./data/agent-messenger.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables
	if err := initSchema(db); err != nil {
		log.Fatal(err)
	}

	// Set up routes
	http.HandleFunc("/agent/connect", handleAgentConnect)
	http.HandleFunc("/client/connect", handleClientConnect)
	http.HandleFunc("/health", handleHealth)

	// Start server
	log.Println("Agent Messenger starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleAgentConnect(w http.ResponseWriter, r *http.Request) {
	// TODO: Upgrade to WebSocket
	// TODO: Validate API key
	// TODO: Register agent connection
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Not implemented yet"))
}

func handleClientConnect(w http.ResponseWriter, r *http.Request) {
	// TODO: Upgrade to WebSocket
	// TODO: Validate JWT
	// TODO: Register user connection
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Not implemented yet"))
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