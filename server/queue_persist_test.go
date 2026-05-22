package main

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestPersistQueue(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	initQueueDB(db)

	// Persist a message
	data := []byte(`{"type":"message","data":{"content":"hello"}}`)
	persistQueue(db, "user1", data)

	// Verify it's in the DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 persisted message, got %d", count)
	}
}

func TestPersistQueueNilDB(t *testing.T) {
	// Should not panic with nil db
	persistQueue(nil, "user1", []byte("test"))
}

func TestDeleteQueueMessages(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	initQueueDB(db)

	// Insert some messages
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("msg1"), time.Now().UTC().Format(time.RFC3339))
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("msg2"), time.Now().UTC().Format(time.RFC3339))
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user2", []byte("msg3"), time.Now().UTC().Format(time.RFC3339))

	// Delete messages for user1
	deleteQueueMessages(db, "user1")

	// user1 messages should be gone
	var count1 int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count1)
	if count1 != 0 {
		t.Fatalf("expected 0 messages for user1, got %d", count1)
	}

	// user2 messages should still be there
	var count2 int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user2").Scan(&count2)
	if count2 != 1 {
		t.Fatalf("expected 1 message for user2, got %d", count2)
	}
}

func TestDeleteQueueMessagesNilDB(t *testing.T) {
	// Should not panic with nil db
	deleteQueueMessages(nil, "user1")
}

func TestLoadQueueFromDB(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	initQueueDB(db)

	// Insert messages into DB
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte(`{"type":"message","data":{"content":"hello"}}`), time.Now().UTC().Format(time.RFC3339))
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte(`{"type":"message","data":{"content":"world"}}`), time.Now().UTC().Format(time.RFC3339))
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user2", []byte(`{"type":"message","data":{"content":"hi"}}`), time.Now().UTC().Format(time.RFC3339))

	// Load into in-memory queue
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	// Check that messages are in the in-memory queue
	if q.QueueDepth("user1") != 2 {
		t.Fatalf("expected 2 messages for user1, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 1 {
		t.Fatalf("expected 1 message for user2, got %d", q.QueueDepth("user2"))
	}
}

func TestLoadQueueFromDBNilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	// Should not panic with nil db
	loadQueueFromDB(nil, q)
}

func TestLoadQueueFromDBExpired(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	initQueueDB(db)

	// Insert an old message (8 days ago in DB)
	oldTime := time.Now().UTC().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("old_msg"), oldTime)

	// Insert a recent message
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("new_msg"), time.Now().UTC().Format(time.RFC3339))

	// Load into queue - Enqueue always sets queuedAt=time.Now()
	// so both messages have fresh timestamps and will be within TTL
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	// Both messages loaded with fresh timestamps
	if q.QueueDepth("user1") != 2 {
		t.Fatalf("expected 2 messages loaded, got %d", q.QueueDepth("user1"))
	}

	// Drain should return both (they get fresh timestamps on Enqueue)
	messages := q.Drain("user1")
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages after drain, got %d", len(messages))
	}

	// But cleanStaleQueueMessages should remove the old one from DB
	cleanStaleQueueMessages(db, 7*24*time.Hour)
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 persisted message after cleanup, got %d", count)
	}
}

func TestCleanStaleQueueMessages(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	initQueueDB(db)

	// Insert an old message
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("old_msg"), time.Now().UTC().Add(-8*24*time.Hour).Format(time.RFC3339))

	// Insert a recent message
	db.Exec("INSERT INTO offline_queue (recipient, data, queued_at, sent_count) VALUES (?, ?, ?, 0)",
		"user1", []byte("new_msg"), time.Now().UTC().Format(time.RFC3339))

	// Clean messages older than 7 days
	cleanStaleQueueMessages(db, 7*24*time.Hour)

	// Only recent message should remain
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 message after cleanup, got %d", count)
	}
}

func TestCleanStaleQueueMessagesNilDB(t *testing.T) {
	// Should not panic with nil db
	cleanStaleQueueMessages(nil, 7*24*time.Hour)
}

func TestMarshalOutgoingMessage(t *testing.T) {
	msg := OutgoingMessage{
		Type: "message",
		Data: map[string]string{"content": "hello world"},
	}

	data := marshalOutgoingMessage(msg)
	if data == nil {
		t.Fatal("expected non-nil data")
	}

	// Verify it's valid JSON
	var parsed OutgoingMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.Type != "message" {
		t.Fatalf("expected type 'message', got '%s'", parsed.Type)
	}
}

func TestPersistAndLoadRoundtrip(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	initQueueDB(db)

	// Create messages and persist them
	msg1 := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: map[string]string{"content": "hello"}})
	msg2 := marshalOutgoingMessage(OutgoingMessage{Type: "message", Data: map[string]string{"content": "world"}})

	persistQueue(db, "user1", msg1)
	persistQueue(db, "user1", msg2)
	persistQueue(db, "user2", msg1)

	// Load into a new in-memory queue
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(db, q)

	if q.QueueDepth("user1") != 2 {
		t.Fatalf("expected 2 messages for user1, got %d", q.QueueDepth("user1"))
	}
	if q.QueueDepth("user2") != 1 {
		t.Fatalf("expected 1 message for user2, got %d", q.QueueDepth("user2"))
	}

	// Drain user1 and verify delete works
	messages := q.Drain("user1")
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages drained, got %d", len(messages))
	}
	deleteQueueMessages(db, "user1")

	// Verify user1's persisted messages are gone
	var count int
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user1").Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 persisted messages for user1 after delete, got %d", count)
	}

	// user2 should still have 1
	db.QueryRow("SELECT COUNT(*) FROM offline_queue WHERE recipient = ?", "user2").Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 persisted message for user2, got %d", count)
	}
}
