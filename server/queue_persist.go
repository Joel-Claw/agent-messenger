package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"
)

// PersistedQueue stores offline messages in SQLite so they survive server restarts.
// It wraps the in-memory OfflineQueue and adds a SQLite backing store.
// New messages are written to both memory and SQLite.
// On startup, SQLite messages are loaded back into memory.

// persistQueue writes a queued message to SQLite.
func persistQueue(db *sql.DB, recipient string, data []byte) {
	if db == nil {
		return
	}
	_, err := db.Exec(
		"INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		recipient, data, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		log.Printf("Failed to persist offline message for %s: %v", recipient, err)
	}
}

// deleteQueueMessages removes all persisted messages for a recipient after successful drain.
func deleteQueueMessages(db *sql.DB, recipient string) {
	if db == nil {
		return
	}
	_, err := db.Exec("DELETE FROM offline_queue WHERE recipient = ?", recipient)
	if err != nil {
		log.Printf("Failed to delete persisted queue for %s: %v", recipient, err)
	}
}

// loadQueueFromDB loads persisted offline messages from SQLite into the in-memory queue.
// Called on startup so that messages queued before a restart are not lost.
func loadQueueFromDB(db *sql.DB, q *OfflineQueue) {
	if db == nil {
		return
	}
	rows, err := db.Query("SELECT recipient, data, queued_at FROM offline_queue ORDER BY id ASC")
	if err != nil {
		log.Printf("Failed to load offline queue from DB: %v", err)
		return
	}
	defer rows.Close()

	loaded := 0
	for rows.Next() {
		var recipient string
		var data []byte
		var queuedAtStr string
		if err := rows.Scan(&recipient, &data, &queuedAtStr); err != nil {
			log.Printf("Failed to scan offline queue row: %v", err)
			continue
		}
		q.Enqueue(recipient, data)
		loaded++
	}
	if loaded > 0 {
		log.Printf("Loaded %d offline messages from SQLite into memory", loaded)
	}
}

// initQueueDB creates the offline_queue table if it doesn't exist.
// This ensures the table exists even in tests that don't run full initSchema.
func initQueueDB(db *sql.DB) {
	if db == nil {
		return
	}
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS offline_queue (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	recipient TEXT NOT NULL,
	data BLOB NOT NULL,
	queued_at DATETIME NOT NULL,
	sent_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queue_recipient ON offline_queue(recipient)`) //nolint:execinquery
	if err != nil {
		log.Printf("Failed to create offline_queue table: %v", err)
	}
}

// cleanStaleQueueMessages removes messages older than the TTL from SQLite.
// Called periodically (e.g., every hour) to prevent unbounded growth.
func cleanStaleQueueMessages(db *sql.DB, maxAge time.Duration) {
	if db == nil {
		return
	}
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339)
	result, err := db.Exec("DELETE FROM offline_queue WHERE queued_at < ?", cutoff)
	if err != nil {
		log.Printf("Failed to clean stale queue messages: %v", err)
		return
	}
	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		log.Printf("Cleaned %d stale offline queue messages (older than %s)", deleted, maxAge)
	}
}

// marshalOutgoingMessage is a helper to marshal an outgoing message for queue storage.
func marshalOutgoingMessage(msg OutgoingMessage) []byte {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal outgoing message for queue: %v", err)
		return nil
	}
	return data
}