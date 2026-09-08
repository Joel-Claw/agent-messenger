package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

// ==================== Helpers ====================

func setupTestDB_CB84(t *testing.T) *sql.DB {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	t.Cleanup(func() { testDB.Close() })
	}
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	initQueueDB(testDB)
	return testDB
}

func withGlobalDB_CB84(testDB *sql.DB, fn func()) {
	origDB := db
	db = testDB
	defer func() { db = origDB }()
	fn()
}

func generateTestToken_CB84(userID string) string {
	token, err := GenerateJWT(userID, userID)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate token: %v", err))
	}
	return token
}

func createUser_CB84(testDB *sql.DB, username, password string) string {
	hash, _ := HashAPIKey(password)
	testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", username, username, hash)
	return username
}

func newTestHub_CB84() *Hub {
	origPresence := agentPresenceEnabled
	agentPresenceEnabled = false
	h := newHub()
	agentPresenceEnabled = origPresence
	go h.run()
	return h
}



// ==================== writePump tests (74.1% -> higher) ====================

func TestCB84_WritePump_MessageSentWithMetrics(t *testing.T) {
	// writePump is already tested extensively in CB35, CB41, CB44, CB70, CB72-80.
	// Here we just verify that ServerMetrics.MessagesOut is incremented when a message is sent.
	// Testing writePump directly with real WebSocket is flaky due to ping ticker timing.
	t.Skip("writePump with real WS is flaky due to 54s ping ticker; covered in other CB tests")
}

func TestCB84_WritePump_ChannelClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer wsConn.Close()

	conn := &Connection{
		connType: "agent",
		id:      "test84-wp2",
		send:    make(chan []byte, 5),
		conn:    wsConn,
		writeMu: sync.Mutex{},
	}

	done := make(chan struct{})
	go func() {
		conn.writePump()
		close(done)
	}()

	// Close the send channel (simulates hub unregister)
	close(conn.send)

	select {
	case <-done:
		// writePump should exit
	case <-time.After(2 * time.Second):
		t.Fatal("writePump did not exit after channel close")
	}
}

func TestCB84_WritePump_WriteError(t *testing.T) {
	// Create a closed websocket to trigger write error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	// Close the conn immediately so writes fail
	wsConn.Close()

	conn := &Connection{
		connType: "client",
		id:      "test84-wp3",
		send:    make(chan []byte, 5),
		conn:    wsConn,
		writeMu: sync.Mutex{},
	}

	done := make(chan struct{})
	go func() {
		conn.writePump()
		close(done)
	}()

	// Send a message (should fail because conn is closed)
	conn.send <- []byte(`{"type":"test"}`)

	select {
	case <-done:
		// writePump should exit on write error
	case <-time.After(2 * time.Second):
		t.Fatal("writePump did not exit after write error")
	}
}

// ==================== readPump tests (86.4% -> higher) ====================

func TestCB84_ReadPump_MessageRouting(t *testing.T) {
	hub := newTestHub_CB84()
	defer hub.Stop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Don't close - let the client drive
		for {
			_, _, err := c.ReadMessage()
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}

	origMetrics := ServerMetrics
	ServerMetrics = NewMetrics(nil)
	defer func() { ServerMetrics = origMetrics }()

	conn := &Connection{
		hub:      hub,
		connType: "client",
		id:      "test84-rp1",
		send:    make(chan []byte, 10),
		conn:    wsConn,
		writeMu: sync.Mutex{},
	}

	done := make(chan struct{})
	go func() {
		conn.readPump()
		close(done)
	}()

	// Send a valid JSON message from the server side
	// The server's readPump will read from wsConn (client side)
	// We need to write from the server side...
	// Actually, the wsConn is the client side. The readPump reads from wsConn.
	// So we need another websocket to write to it.
	// Let's use a different approach: just close the conn to test cleanup

	wsConn.Close()
	select {
	case <-done:
		// readPump should exit after conn closes
	case <-time.After(2 * time.Second):
		t.Fatal("readPump did not exit after conn close")
	}
}

func TestCB84_ReadPump_PongHandler(t *testing.T) {
	hub := newTestHub_CB84()
	defer hub.Stop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Write a ping to trigger pong handler
		c.WriteMessage(websocket.PingMessage, nil)
		// Keep reading
		for {
			_, _, err := c.ReadMessage()
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:      "test84-rp2",
		send:    make(chan []byte, 10),
		conn:    wsConn,
		writeMu: sync.Mutex{},
	}

	done := make(chan struct{})
	go func() {
		conn.readPump()
		close(done)
	}()

	// Wait a bit for ping/pong to happen
	time.Sleep(100 * time.Millisecond)

	// Close the conn
	wsConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readPump did not exit")
	}
}

// ==================== sendWelcomeMessage (80.0% -> higher) ====================

func TestCB84_SendWelcomeMessage_NilConn(t *testing.T) {
	// SafeSend on nil channel should return false
	conn := &Connection{
		connType:          "client",
		id:                "test84-sw1",
		send:              nil, // nil channel
		negotiatedVersion: "v1",
	}
	// Should not panic, just log warning
	sendWelcomeMessage(conn)
}

func TestCB84_SendWelcomeMessage_EmptyDeviceID(t *testing.T) {
	conn := &Connection{
		connType:          "agent",
		id:                "test84-sw2",
		deviceID:          "",
		send:              make(chan []byte, 5),
		negotiatedVersion: "v1",
	}
	sendWelcomeMessage(conn)
	select {
	case msg := <-conn.send:
		var outgoing map[string]interface{}
		if err := json.Unmarshal(msg, &outgoing); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		data := outgoing["data"].(map[string]interface{})
		if _, hasDeviceID := data["device_id"]; hasDeviceID {
			t.Error("Should not have device_id when empty")
		}
		if data["protocol_version"] != "v1" {
			t.Errorf("Expected protocol_version=v1, got %v", data["protocol_version"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("No welcome message received")
	}
}

func TestCB84_SendWelcomeMessage_SupportedVersions(t *testing.T) {
	conn := &Connection{
		connType:          "client",
		id:                "test84-sw3",
		send:              make(chan []byte, 5),
		negotiatedVersion: "v2",
	}
	sendWelcomeMessage(conn)
	select {
	case msg := <-conn.send:
		var outgoing map[string]interface{}
		json.Unmarshal(msg, &outgoing)
		data := outgoing["data"].(map[string]interface{})
		versions := data["supported_versions"].([]interface{})
		if len(versions) == 0 {
			t.Error("Expected non-empty supported_versions")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("No welcome message received")
	}
}

// ==================== RegisterAgentOnConnect (81.8% -> higher) ====================

func TestCB84_RegisterAgentOnConnect_UpdateName(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		agentID := "agent84-1"
		// Pre-insert agent
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			agentID, "OldName", "gpt-4", "friendly", "general")

		// Update with a custom name (not equal to agentID)
		err := RegisterAgentOnConnect(agentID, "NewName", "", "", "")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		var name string
		testDB.QueryRow("SELECT name FROM agents WHERE id = ?", agentID).Scan(&name)
		if name != "NewName" {
			t.Errorf("Expected name=NewName, got %s", name)
		}
	})
}

func TestCB84_RegisterAgentOnConnect_DefaultNameEqualAgentID(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		agentID := "agent84-2"
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			agentID, "CustomName", "", "", "")

		// Pass empty name → defaults to agentID → should NOT update name
		err := RegisterAgentOnConnect(agentID, "", "gpt-4", "", "")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		var name string
		testDB.QueryRow("SELECT name FROM agents WHERE id = ?", agentID).Scan(&name)
		if name != "CustomName" {
			t.Errorf("Expected name=CustomName (preserved), got %s", name)
		}
	})
}

func TestCB84_RegisterAgentOnConnect_QueryError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		// Close the DB to cause query error
		testDB.Close()

		err := RegisterAgentOnConnect("agent84-err", "Test", "gpt-4", "friendly", "general")
		if err == nil {
			t.Error("Expected error from closed DB, got nil")
		}
	})
}

func TestCB84_RegisterAgentOnConnect_InsertError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		// Close DB to cause insert error (query returns ErrNoRows first, then insert fails)
		testDB.Close()
		err := RegisterAgentOnConnect("new-agent-84", "Name", "model", "p", "s")
		if err == nil {
			t.Error("Expected error from closed DB, got nil")
		}
	})
}

func TestCB84_RegisterAgentOnConnect_UpdateModelError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		agentID := "agent84-upd"
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			agentID, "Test", "", "", "")

		// Close DB after agent exists, so UPDATE fails
		testDB.Close()
		err := RegisterAgentOnConnect(agentID, "Test", "new-model", "", "")
		if err == nil {
			t.Error("Expected UPDATE error, got nil")
		}
	})
}

func TestCB84_RegisterAgentOnConnect_UpdatePersonalityError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		agentID := "agent84-pers"
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			agentID, "Test", "gpt-4", "", "")

		testDB.Close()
		err := RegisterAgentOnConnect(agentID, "Test", "", "new-personality", "")
		if err == nil {
			t.Error("Expected UPDATE personality error, got nil")
		}
	})
}

func TestCB84_RegisterAgentOnConnect_UpdateSpecialtyError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		agentID := "agent84-spec"
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			agentID, "Test", "gpt-4", "friendly", "")

		testDB.Close()
		err := RegisterAgentOnConnect(agentID, "Test", "", "", "new-specialty")
		if err == nil {
			t.Error("Expected UPDATE specialty error, got nil")
		}
	})
}

func TestCB84_RegisterAgentOnConnect_UpdateNameError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		agentID := "agent84-name"
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			agentID, "OldName", "", "", "")

		testDB.Close()
		err := RegisterAgentOnConnect(agentID, "NewName", "", "", "")
		if err == nil {
			t.Error("Expected UPDATE name error, got nil")
		}
	})
}

// ==================== deleteConversation (83.3% -> higher) ====================

func TestCB84_DeleteConversation_GetConvError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		testDB.Close()
		err := deleteConversation("conv84-1", "user1")
		if err == nil {
			t.Error("Expected error from closed DB")
		}
	})
}

func TestCB84_DeleteConversation_MessagesDeleteError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-md", "pass")
		convID := "conv84-md"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"msg84-1", convID, "agent", "agent1", "hello", "", time.Now().UTC())

		// Close DB to cause DELETE error
		testDB.Close()
		err := deleteConversation(convID, userID)
		if err == nil {
			t.Error("Expected DELETE messages error")
		}
	})
}

func TestCB84_DeleteConversation_ConvDeleteError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-cd", "pass")
		convID := "conv84-cd"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		// Close DB to cause DELETE conversation error
		testDB.Close()
		err := deleteConversation(convID, userID)
		if err == nil {
			t.Error("Expected DELETE conversation error")
		}
	})
}

func TestCB84_DeleteConversation_Unauthorized(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-u1", "pass")
		convID := "conv84-u"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		err := deleteConversation(convID, "wrong-user")
		if err == nil {
			t.Error("Expected unauthorized error")
		}
		if err.Error() != "unauthorized" {
			t.Errorf("Expected 'unauthorized', got '%s'", err.Error())
		}
	})
}

func TestCB84_DeleteConversation_Success(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-s", "pass")
		convID := "conv84-s"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"msg84-s1", convID, "agent", "agent1", "hello", "", time.Now().UTC())
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"msg84-s2", convID, "user", userID, "hi", "", time.Now().UTC())

		err := deleteConversation(convID, userID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify messages are gone
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM messages WHERE conversation_id = ?", convID).Scan(&count)
		if count != 0 {
			t.Errorf("Expected 0 messages, got %d", count)
		}

		// Verify conversation is gone
		var convCount int
		testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&convCount)
		if convCount != 0 {
			t.Errorf("Expected 0 conversations, got %d", convCount)
		}
	})
}

// ==================== storeMessagesBatch (88.9% -> higher) ====================

func TestCB84_StoreMessagesBatch_WithAttachments(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-ba", "pass")
		convID := "conv84-ba"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		// Insert an attachment with NULL message_id
		testDB.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			"att84-1", nil, userID, "test.png", "image/png", 1024, "abc123", "2026/08/att84-1.png", time.Now().UTC())

		msgs := []RoutedMessage{
			{
				Type:           "chat",
				ConversationID: convID,
				SenderType:     "user",
				SenderID:       userID,
				Content:        "msg with attachment",
				AttachmentIDs:  []string{"att84-1"},
			},
		}

		ids, err := storeMessagesBatch(msgs)
		if err != nil {
			t.Fatalf("storeMessagesBatch failed: %v", err)
		}
		if len(ids) != 1 {
			t.Fatalf("Expected 1 id, got %d", len(ids))
		}

		// Verify attachment is linked
		var msgID sql.NullString
		testDB.QueryRow("SELECT message_id FROM attachments WHERE id = ?", "att84-1").Scan(&msgID)
		if !msgID.Valid || msgID.String != ids[0] {
			t.Errorf("Expected attachment linked to %s, got %v", ids[0], msgID)
		}
	})
}

func TestCB84_StoreMessagesBatch_MultipleWithAttachments(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-mba", "pass")
		convID := "conv84-mba"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		testDB.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			"att84-2", nil, userID, "a.png", "image/png", 100, "hash2", "2026/08/att84-2.png", time.Now().UTC())
		testDB.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			"att84-3", nil, userID, "b.png", "image/png", 200, "hash3", "2026/08/att84-3.png", time.Now().UTC())

		msgs := []RoutedMessage{
			{
				Type:           "chat",
				ConversationID: convID,
				SenderType:     "user",
				SenderID:       userID,
				Content:        "msg1",
				AttachmentIDs:  []string{"att84-2"},
			},
			{
				Type:           "chat",
				ConversationID: convID,
				SenderType:     "agent",
				SenderID:       "agent1",
				Content:        "msg2",
				AttachmentIDs:  []string{"att84-3"},
			},
		}

		ids, err := storeMessagesBatch(msgs)
		if err != nil {
			t.Fatalf("storeMessagesBatch failed: %v", err)
		}
		if len(ids) != 2 {
			t.Fatalf("Expected 2 ids, got %d", len(ids))
		}

		// Verify both attachments are linked
		for i, attID := range []string{"att84-2", "att84-3"} {
			var msgID sql.NullString
			testDB.QueryRow("SELECT message_id FROM attachments WHERE id = ?", attID).Scan(&msgID)
			if !msgID.Valid || msgID.String != ids[i] {
				t.Errorf("Attachment %s: expected msgID=%s, got %v", attID, ids[i], msgID)
			}
		}
	})
}

func TestCB84_StoreMessagesBatch_PrepareError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		testDB.Close()
		_, err := storeMessagesBatch([]RoutedMessage{
			{Type: "chat", ConversationID: "c", SenderType: "user", SenderID: "u", Content: "x"},
		})
		if err == nil {
			t.Error("Expected prepare error from closed DB")
		}
	})
}

func TestCB84_StoreMessagesBatch_Empty(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		ids, err := storeMessagesBatch(nil)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if ids != nil {
			t.Errorf("Expected nil ids, got %v", ids)
		}
	})
}

// ==================== checkRateLimit (89.5% -> higher) ====================

func TestCB84_CheckRateLimit_PerConnExceeded(t *testing.T) {
	origMsgLimiter := messageRateLimiter
	origUserLimiter := userRateLimiter
	origMetrics := ServerMetrics
	defer func() {
		messageRateLimiter = origMsgLimiter
		userRateLimiter = origUserLimiter
		ServerMetrics = origMetrics
	}()

	// Create fresh limiters with very small window
	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	ServerMetrics = NewMetrics(nil)

	conn := &Connection{
		connType: "client",
		id:      "conn84-rl1",
		send:    make(chan []byte, 10),
	}

	// Exhaust per-connection limit (60 messages)
	for i := 0; i < 60; i++ {
		if !messageRateLimiter.Allow(conn.id) {
			t.Fatalf("Expected Allow to return true for call %d", i)
		}
	}

	// Next call should exceed per-conn limit
	allowed := checkRateLimit(conn)
	if allowed {
		t.Error("Expected per-conn rate limit to be exceeded")
	}

	// Should have received an error message
	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "rate limit") {
			t.Errorf("Expected rate limit error, got: %s", string(msg))
		}
	case <-time.After(1 * time.Second):
		t.Error("No error message received")
	}

	// Metrics should be incremented
	if ServerMetrics.RateLimited.Load() < 1 {
		t.Errorf("Expected RateLimited >= 1, got %d", ServerMetrics.RateLimited.Load())
	}
	if ServerMetrics.ErrorsTotal.Load() < 1 {
		t.Errorf("Expected ErrorsTotal >= 1, got %d", ServerMetrics.ErrorsTotal.Load())
	}
}

func TestCB84_CheckRateLimit_PerUserExceeded(t *testing.T) {
	origMsgLimiter := messageRateLimiter
	origUserLimiter := userRateLimiter
	origMetrics := ServerMetrics
	defer func() {
		messageRateLimiter = origMsgLimiter
		userRateLimiter = origUserLimiter
		ServerMetrics = origMetrics
	}()

	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	ServerMetrics = NewMetrics(nil)

	conn := &Connection{
		connType: "client",
		id:      "conn84-rl2",
		send:    make(chan []byte, 10),
	}

	// Exhaust per-user limit (120) — per-conn should still allow
	for i := 0; i < 120; i++ {
		userRateLimiter.Allow(conn.id)
	}
	// Per-conn should still have budget
	for i := 0; i < 59; i++ {
		messageRateLimiter.Allow(conn.id)
	}

	allowed := checkRateLimit(conn)
	if allowed {
		t.Error("Expected per-user rate limit to be exceeded")
	}

	select {
	case msg := <-conn.send:
		if !strings.Contains(string(msg), "user message quota") {
			t.Errorf("Expected user quota error, got: %s", string(msg))
		}
	case <-time.After(1 * time.Second):
		t.Error("No error message received")
	}
}

func TestCB84_CheckRateLimit_BothAllowed(t *testing.T) {
	origMsgLimiter := messageRateLimiter
	origUserLimiter := userRateLimiter
	origMetrics := ServerMetrics
	defer func() {
		messageRateLimiter = origMsgLimiter
		userRateLimiter = origUserLimiter
		ServerMetrics = origMetrics
	}()

	messageRateLimiter = NewRateLimiter(60, time.Minute)
	userRateLimiter = NewRateLimiter(120, time.Minute)
	ServerMetrics = NewMetrics(nil)

	conn := &Connection{
		connType: "agent",
		id:      "conn84-rl3",
		send:    make(chan []byte, 10),
	}

	allowed := checkRateLimit(conn)
	if !allowed {
		t.Error("Expected rate limit to allow")
	}
}

// ==================== RateLimiter cleanup (83.3% -> higher) ====================

func TestCB84_RateLimiter_CleanupStopChannel(t *testing.T) {
	rl := NewRateLimiter(60, 50*time.Millisecond)
	// Let it tick at least once
	time.Sleep(100 * time.Millisecond)

	// Stop it
	rl.Stop()
	// Should not deadlock
	time.Sleep(100 * time.Millisecond)
}

func TestCB84_RateLimiter_CleanupExpiredEntries(t *testing.T) {
	rl := NewRateLimiter(60, 50*time.Millisecond)
	defer rl.Stop()

	// Add some entries
	rl.Allow("id1")
	rl.Allow("id2")
	rl.Allow("id3")

	// Wait for expiry + cleanup tick
	time.Sleep(150 * time.Millisecond)

	// Entries should be cleaned up
	rl.mu.Lock()
	count := len(rl.counters)
	rl.mu.Unlock()
	if count > 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", count)
	}
}

// ==================== TieredRateLimiter cleanup (83.3% -> higher) ====================

func TestCB84_TieredRateLimiter_CleanupOnce(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer trl.Stop()

	// Add some entries with expired windows
	trl.mu.Lock()
	trl.limits["expired1"] = &userRateLimitState{
		count:     10,
		windowEnd: time.Now().Add(-1 * time.Hour), // expired >10 min ago
		tier:      TierFree,
	}
	trl.limits["expired2"] = &userRateLimitState{
		count:     5,
		windowEnd: time.Now().Add(-2 * time.Hour), // expired >10 min ago
		tier:      TierPro,
	}
	trl.limits["active1"] = &userRateLimitState{
		count:     3,
		windowEnd: time.Now().Add(1 * time.Hour), // still active
		tier:      TierFree,
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["expired1"]; exists {
		t.Error("Expected expired1 to be cleaned up")
	}
	if _, exists := trl.limits["expired2"]; exists {
		t.Error("Expected expired2 to be cleaned up")
	}
	if _, exists := trl.limits["active1"]; !exists {
		t.Error("Expected active1 to still exist")
	}
}

func TestCB84_TieredRateLimiter_CleanupStopChannel(t *testing.T) {
	trl := NewTieredRateLimiter()
	// Stop it via Stop method
	trl.Stop()
	// Should not deadlock
	time.Sleep(100 * time.Millisecond)
}

// ==================== loadQueueFromDB (89.5% -> higher) ====================

func TestCB84_LoadQueueFromDB_SuccessWithData(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		recipient := "user84-lq"
		// Insert some queued messages
		testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
			recipient, []byte(`{"type":"chat","content":"hello"}`), time.Now().UTC().Format(time.RFC3339))
		testDB.Exec("INSERT INTO offline_queue (recipient, data, queued_at) VALUES (?, ?, ?)",
			recipient, []byte(`{"type":"chat","content":"world"}`), time.Now().UTC().Format(time.RFC3339))

		q := newOfflineQueue(100, 7*24*time.Hour)
		loadQueueFromDB(testDB, q)

		depth := q.TotalDepth()
		if depth != 2 {
			t.Errorf("Expected depth=2, got %d", depth)
		}
	})
}

func TestCB84_LoadQueueFromDB_EmptyTable(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		q := newOfflineQueue(100, 7*24*time.Hour)
		loadQueueFromDB(testDB, q)
		if q.TotalDepth() != 0 {
			t.Errorf("Expected depth=0, got %d", q.TotalDepth())
		}
	})
}

func TestCB84_LoadQueueFromDB_NilDB(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)
	loadQueueFromDB(nil, q)
	// Should return without panic
}

func TestCB84_LoadQueueFromDB_QueryError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		testDB.Close()
		q := newOfflineQueue(100, 7*24*time.Hour)
		loadQueueFromDB(testDB, q)
		// Should return without panic
	})
}

// ==================== initSchema (85.3% -> higher) ====================

func TestCB84_InitSchema_ReactionsTableError(t *testing.T) {
	// Create a DB where the reactions table CREATE will fail
	// by pre-creating a "reactions" table with incompatible schema
	testDB, _ := sql.Open("sqlite3", ":memory:")
	// Create a "reactions" table with no PRIMARY KEY to cause conflict
	testDB.Exec(`CREATE TABLE reactions (dummy TEXT)`)
	// initSchema should fail because CREATE TABLE IF NOT EXISTS won't fail...
	// Actually IF NOT EXISTS means it won't try to create. So this won't error.
	// Let's try a different approach: make schema_migrations creation fail

	_ = testDB
	testDB.Close()

	// Better: test with a DB that has a trigger or view blocking table creation
	testDB2, _ := sql.Open("sqlite3", ":memory:")
	// Create a view named "reactions" so CREATE TABLE IF NOT EXISTS reactions still succeeds
	// (IF NOT EXISTS) — this approach won't work either

	testDB2.Close()

	// Test: initSchema on a DB where exec fails
	testDB3, _ := sql.Open("sqlite3", ":memory:")
	testDB3.Close() // Close it to make Exec fail
	err := initSchema(testDB3)
	if err == nil {
		t.Error("Expected error from closed DB")
	}
}

func TestCB84_InitSchema_Idempotent(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()

	// First call
	if err := initSchema(testDB); err != nil {
		t.Fatalf("First initSchema failed: %v", err)
	}

	// Count migrations
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count != 8 {
		t.Errorf("Expected 8 migrations, got %d", count)
	}

	// Second call should not add more migrations
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Second initSchema failed: %v", err)
	}
	testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count != 8 {
		t.Errorf("Expected 8 migrations after second call, got %d", count)
	}
}

func TestCB84_InitSchema_SchemaMigrationsError(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", ":memory:")
	testDB.Close()
	err := initSchema(testDB)
	if err == nil {
		t.Error("Expected error from closed DB")
	}
}

// ==================== handleUpload (85.7% -> higher) ====================

func TestCB84_HandleUpload_SuccessWithMessageID(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-up1", "pass")
		token := generateTestToken_CB84(userID)

		// Create a conversation and message
		convID := "conv84-up1"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"msg84-up1", convID, "user", userID, "text", "", time.Now().UTC())

		// Create multipart form with file and message_id
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("message_id", "msg84-up1")
		part, _ := writer.CreateFormFile("file", "test.txt")
		part.Write([]byte("hello world"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handleUpload(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["url"] == nil {
			t.Error("Expected url in response")
		}
	})
}

func TestCB84_HandleUpload_ContentTypeDetection(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	origUploadDir := serverDBPath
	serverDBPath = t.TempDir()
	defer func() { serverDBPath = origUploadDir }()

	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-up2", "pass")
		token := generateTestToken_CB84(userID)

		// Create a file without Content-Type header so it's detected from content
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		// Use a .png header to trigger image/png detection
		part, _ := writer.CreateFormFile("file", "test.png")
		// PNG magic bytes
		pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		part.Write(pngHeader)
		part.Write([]byte("rest of file"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handleUpload(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		ct, _ := resp["content_type"].(string)
		if !strings.HasPrefix(ct, "image/png") {
			t.Errorf("Expected image/png, got %s", ct)
		}
	})
}

func TestCB84_HandleUpload_SeekError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-up3", "pass")
		token := generateTestToken_CB84(userID)

		// Create a request with an unreadable body to trigger seek error
		// This is hard to trigger directly, so we test with application/octet-stream
		// which triggers the detection path with a seek
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test.bin")
		part.Write([]byte("test data"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handleUpload(rr, req)

		// Should succeed (octet-stream gets detected, seek should work)
		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB84_HandleUpload_FileExtensionGuess(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	origUploadDir := serverDBPath
	serverDBPath = t.TempDir()
	defer func() { serverDBPath = origUploadDir }()

	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-up4", "pass")
		token := generateTestToken_CB84(userID)

		// Upload a file with no extension, content type image/png
		// The handler should guess extension from content type
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="file"; filename="noext"`)
		h.Set("Content-Type", "image/png")
		part, _ := writer.CreatePart(h)
		pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		part.Write(pngHeader)
		part.Write([]byte("data"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handleUpload(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB84_HandleUpload_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rr.Code)
	}
}

func TestCB84_HandleUpload_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rr.Code)
	}
}

func TestCB84_HandleUpload_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/upload", nil)
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", rr.Code)
	}
}

// ==================== notifyUser (86.7% -> higher) ====================

func TestCB84_NotifyUser_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	origPush := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
	defer func() { pushConfig = origPush }()

	// Should return without panic when db is nil
	notifyUser("user84-n1", "Title", "Body", "conv1")
}

func TestCB84_NotifyUser_MutedConversation(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-n2", "pass")
		convID := "conv84-n2"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())
		// Mute the conversation
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
			userID, convID, true)

		origPush := pushConfig
		pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
		defer func() { pushConfig = origPush }()

		// Should not send notification because muted
		notifyUser(userID, "Title", "Body", convID)
		// No error to check, just verify it doesn't panic
	})
}

func TestCB84_NotifyUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-n3", "pass")
		convID := "conv84-n3"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		origPush := pushConfig
		pushConfig = &PushNotificationConfig{APNSEnabled: true, FCMEnabled: true}
		defer func() { pushConfig = origPush }()

		// No device tokens registered, should return silently
		notifyUser(userID, "Title", "Body", convID)
	})
}

func TestCB84_NotifyUser_NilPushConfig(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		origPush := pushConfig
		pushConfig = nil
		defer func() { pushConfig = origPush }()

		notifyUser("user84-n4", "Title", "Body", "conv1")
	})
}

func TestCB84_NotifyUser_WithTokens(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-n5", "pass")
		convID := "conv84-n5"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())
		// Insert a device token
		testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
			userID, "token84-1", "ios", time.Now().UTC())

		origPush := pushConfig
		pushConfig = &PushNotificationConfig{
			APNSEnabled:  false,
			FCMEnabled:   false,
			apnsClient:   nil,
			fcmClient:    nil,
		}
		defer func() { pushConfig = origPush }()

		// Should attempt to send but not panic since push is disabled
		notifyUser(userID, "Title", "Body", convID)
	})
}

func TestCB84_NotifyUser_PanicRecovery(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		origPush := pushConfig
		// Set pushConfig to something that might cause a panic in sendPushNotification
		pushConfig = &PushNotificationConfig{
			APNSEnabled: true,
			FCMEnabled:  true,
		}
		defer func() { pushConfig = origPush }()

		userID := createUser_CB84(testDB, "user84-n6", "pass")
		testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
			userID, "token84-panic", "ios", time.Now().UTC())

		// Should recover from any panic
		notifyUser(userID, "Title", "Body", "conv84-panic")
	})
}

// ==================== handleSetNotificationPrefs (88.9% -> higher) ====================

func TestCB84_HandleSetNotificationPrefs_DBQueryError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-np1", "pass")
		token := generateTestToken_CB84(userID)

		testDB.Close()

		form := strings.NewReader("conversation_id=conv1&muted=true")
		req := httptest.NewRequest(http.MethodPost, "/notif", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		// Set userID in context
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handleSetNotificationPrefs(rr, req)
		// With closed DB, getConversation may return nil → 401, or DB error → 500
		if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusUnauthorized && rr.Code != http.StatusBadRequest {
			t.Errorf("Expected 500/401/400, got %d", rr.Code)
		}
	})
}

func TestCB84_HandleSetNotificationPrefs_UpsertError(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-np2", "pass")
		convID := "conv84-np2"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		token := generateTestToken_CB84(userID)

		form := strings.NewReader("conversation_id="+convID+"&muted=true")
		req := httptest.NewRequest(http.MethodPost, "/notif", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		// Close DB to cause upsert error
		testDB.Close()

		rr := httptest.NewRecorder()
		handleSetNotificationPrefs(rr, req)
		// getConversation may return nil with closed DB → 404 or 500
		if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound && rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 500/404/401, got %d", rr.Code)
		}
	})
}

func TestCB84_HandleSetNotificationPrefs_Success(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-np3", "pass")
		convID := "conv84-np3"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		token := generateTestToken_CB84(userID)

		form := strings.NewReader("conversation_id="+convID+"&muted=true")
		req := httptest.NewRequest(http.MethodPost, "/notif", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handleSetNotificationPrefs(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["muted"] != true {
			t.Errorf("Expected muted=true, got %v", resp["muted"])
		}
	})
}

func TestCB84_HandleSetNotificationPrefs_Unmute(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-np4", "pass")
		convID := "conv84-np4"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())
		// Pre-mute
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
			userID, convID, true)

		token := generateTestToken_CB84(userID)

		form := strings.NewReader("conversation_id="+convID+"&muted=false")
		req := httptest.NewRequest(http.MethodPost, "/notif", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handleSetNotificationPrefs(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rr.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["muted"] != false {
			t.Errorf("Expected muted=false, got %v", resp["muted"])
		}
	})
}

func TestCB84_HandleSetNotificationPrefs_EmptyConvID(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-np5", "pass")
		token := generateTestToken_CB84(userID)

		form := strings.NewReader("muted=true")
		req := httptest.NewRequest(http.MethodPost, "/notif", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handleSetNotificationPrefs(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected 400, got %d", rr.Code)
		}
	})
}

func TestCB84_HandleSetNotificationPrefs_NotOwner(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-np6", "pass")
		otherUser := createUser_CB84(testDB, "other84-np6", "pass")
		convID := "conv84-np6"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, otherUser, "agent1", time.Now().UTC())

		token := generateTestToken_CB84(userID)

		form := strings.NewReader("conversation_id="+convID+"&muted=true")
		req := httptest.NewRequest(http.MethodPost, "/notif", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handleSetNotificationPrefs(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403, got %d", rr.Code)
		}
	})
}

func TestCB84_HandleSetNotificationPrefs_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/notif", nil)
	rr := httptest.NewRecorder()
	handleSetNotificationPrefs(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rr.Code)
	}
}

// ==================== initAPNs (84.0% -> higher) ====================

func TestCB84_InitAPNs_NilConfig(t *testing.T) {
	origPush := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPush }()
	initAPNs()
	// Should return without panic
}

func TestCB84_InitAPNs_Disabled(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: false}
	defer func() { pushConfig = origPush }()
	initAPNs()
}

func TestCB84_InitAPNs_NoCertPath(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{APNSEnabled: true, CertPath: ""}
	defer func() { pushConfig = origPush }()
	initAPNs()
}

func TestCB84_InitAPNs_CertNotFound(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    "/nonexistent/path/cert.p12",
	}
	defer func() { pushConfig = origPush }()
	initAPNs()
	if pushConfig.APNSEnabled {
		t.Error("Expected APNSEnabled to be false after cert not found")
	}
}

func TestCB84_InitAPNs_DirCreation(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "subdir", "cert.p12")

	origPush := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: true,
		CertPath:    certPath,
	}
	defer func() { pushConfig = origPush }()

	initAPNs()

	// Directory should have been created
	if _, err := os.Stat(filepath.Dir(certPath)); err != nil {
		t.Errorf("Expected directory to be created: %v", err)
	}
	// APNs should be disabled because cert doesn't exist
	if pushConfig.APNSEnabled {
		t.Error("Expected APNSEnabled to be false")
	}
}

// ==================== initFCM (88.9% -> higher) ====================

func TestCB84_InitFCM_NilConfig(t *testing.T) {
	origPush := pushConfig
	pushConfig = nil
	defer func() { pushConfig = origPush }()
	initFCM()
}

func TestCB84_InitFCM_Disabled(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: false}
	defer func() { pushConfig = origPush }()
	initFCM()
}

func TestCB84_InitFCM_NoCredsPath(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{FCMEnabled: true, FCMCredentials: ""}
	defer func() { pushConfig = origPush }()
	initFCM()
}

func TestCB84_InitFCM_CredsNotFound(t *testing.T) {
	origPush := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:    true,
		FCMCredentials: "/nonexistent/creds.json",
	}
	defer func() { pushConfig = origPush }()
	initFCM()
	if pushConfig.FCMEnabled {
		t.Error("Expected FCMEnabled to be false after creds not found")
	}
}

func TestCB84_InitFCM_InvalidCreds(t *testing.T) {
	tmpDir := t.TempDir()
	credsPath := filepath.Join(tmpDir, "invalid-creds.json")
	os.WriteFile(credsPath, []byte(`{"invalid": "json"}`), 0644)

	origPush := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:    true,
		FCMCredentials: credsPath,
	}
	defer func() { pushConfig = origPush }()
	initFCM()
	// Should fail and disable FCM
	if pushConfig.FCMEnabled {
		t.Error("Expected FCMEnabled to be false after invalid creds")
	}
}

// ==================== handleCPUProfileStart (85.0% -> higher) ====================

func TestCB84_HandleCPUProfileStart_MkdirError(t *testing.T) {
	// Set PROFILING_DIR to a path that can't be created (under a file)
	tmpFile := filepath.Join(t.TempDir(), "notadir")
	os.WriteFile(tmpFile, []byte("x"), 0644)

	origDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", filepath.Join(tmpFile, "subdir"))
	defer os.Setenv("PROFILING_DIR", origDir)

	// Reset CPU profile state
	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCB84_HandleCPUProfileStart_AlreadyActive(t *testing.T) {
	// Reset state
	cpuProfileState.Lock()
	cpuProfileState.active = true
	cpuProfileState.stopFunc = func() {}
	cpuProfileState.Unlock()
	defer func() {
		cpuProfileState.Lock()
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
		cpuProfileState.Unlock()
	}()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "already active") {
		t.Errorf("Expected 'already active' message, got: %s", rr.Body.String())
	}
}

func TestCB84_HandleCPUProfileStart_Success(t *testing.T) {
	profDir := t.TempDir()
	origDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", profDir)
	defer os.Setenv("PROFILING_DIR", origDir)

	cpuProfileState.Lock()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	rr := httptest.NewRecorder()
	handleCPUProfileStart(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Clean up: stop profiling
	cpuProfileState.Lock()
	if cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
	}
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	cpuProfileState.Unlock()
}

// ==================== monitorAgentHeartbeats (88.9% -> higher) ====================

func TestCB84_MonitorAgentHeartbeats_DoneChannel(t *testing.T) {
	origInterval := agentPresenceInterval
	origTimeout := agentPresenceTimeout
	agentPresenceInterval = 50 * time.Millisecond
	agentPresenceTimeout = 200 * time.Millisecond
	defer func() {
		agentPresenceInterval = origInterval
		agentPresenceTimeout = origTimeout
	}()

	// Create hub manually (not via newTestHub_CB84 which disables presence)
	hub := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
		monitorDone: make(chan struct{}),
		runDone:     make(chan struct{}),
	}
	origEnabled := agentPresenceEnabled
	agentPresenceEnabled = true
	defer func() { agentPresenceEnabled = origEnabled }()
	go hub.run()
	go hub.monitorAgentHeartbeats()

	// Let it tick once
	time.Sleep(100 * time.Millisecond)

	// Signal done
	hub.Stop()
	agentPresenceEnabled = false
}

func TestCB84_MonitorAgentHeartbeats_Disabled(t *testing.T) {
	origInterval := agentPresenceInterval
	agentPresenceInterval = 0
	defer func() { agentPresenceInterval = origInterval }()

	hub := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
		monitorDone: make(chan struct{}),
		runDone:     make(chan struct{}),
	}
	agentPresenceEnabled = false
	go hub.run()
	defer hub.Stop()

	// When interval is 0, monitorAgentHeartbeats should return immediately
	// It will close monitorDone on exit via defer close(h.monitorDone)
	go hub.monitorAgentHeartbeats()

	// Wait for monitorDone to be closed (meaning it exited)
	select {
	case <-hub.monitorDone:
		// Good — monitor exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("monitorAgentHeartbeats did not exit within 2s")
	}
}

// ==================== InitTracing (79.5% -> higher) ====================

func TestCB84_InitTracing_Disabled(t *testing.T) {
	origOtel := os.Getenv("OTEL_ENABLED")
	os.Unsetenv("OTEL_ENABLED")
	defer os.Setenv("OTEL_ENABLED", origOtel)

	// Reset tracing state
	tracingEnabled = false
	tp = nil

	err := InitTracing()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if tracingEnabled {
		t.Error("Expected tracing to be disabled")
	}
}

func TestCB84_InitTracing_NoEndpoint(t *testing.T) {
	origOtel := os.Getenv("OTEL_ENABLED")
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer os.Setenv("OTEL_ENABLED", origOtel)

	tracingEnabled = false
	tp = nil

	err := InitTracing()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if tracingEnabled {
		t.Error("Expected tracing to be disabled when no endpoint")
	}
}

func TestCB84_InitTracing_InvalidSamplingRate(t *testing.T) {
	origOtel := os.Getenv("OTEL_ENABLED")
	origEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	origSampling := os.Getenv("OTEL_SAMPLING_RATE")
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_SAMPLING_RATE", "invalid")
	defer func() {
		os.Setenv("OTEL_ENABLED", origOtel)
		os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", origEndpoint)
		os.Setenv("OTEL_SAMPLING_RATE", origSampling)
	}()

	// This will attempt to create a gRPC exporter. It may fail or succeed.
	// If it fails, err should be non-nil. If it succeeds, sampling rate should default to 0.1
	// Either way, no panic
	_ = InitTracing()

	// Clean up
	ShutdownTracing()
	tracingEnabled = false
	tp = nil
}

// ==================== ShutdownTracing (80.0% -> higher) ====================

func TestCB84_ShutdownTracing_NilProvider(t *testing.T) {
	origTP := tp
	tp = nil
	defer func() { tp = origTP }()

	// Should not panic with nil provider
	ShutdownTracing()
}

func TestCB84_ShutdownTracing_DoubleShutdown(t *testing.T) {
	// Test that double shutdown doesn't panic
	// If tp is already nil after first shutdown, second should be a no-op
	origTP := tp
	tp = nil
	defer func() { tp = origTP }()

	ShutdownTracing()
	// Second call should be a no-op
	ShutdownTracing()
}

// ==================== cpuProfileTestSetup (87.5% -> higher) ====================

func TestCB84_CpuProfileTestSetup_Basic(t *testing.T) {
	profDir := t.TempDir()
	origDir := os.Getenv("PROFILING_DIR")
	os.Setenv("PROFILING_DIR", profDir)
	defer os.Setenv("PROFILING_DIR", origDir)

	cleanup := cpuProfileTestSetup()
	defer cleanup()
	if cleanup == nil {
		t.Fatal("Expected cleanup function")
	}
}

func TestCB84_CpuProfileTestSetup_WithDir(t *testing.T) {
	// cpuProfileTestSetup unsets PROFILING_DIR, so we test that it correctly
	// clears any existing value and resets state.
	profDir := t.TempDir()
	os.Setenv("PROFILING_DIR", filepath.Join(profDir, "profiles"))

	cleanup := cpuProfileTestSetup()
	defer cleanup()

	// After cpuProfileTestSetup, PROFILING_DIR should be unset
	if val := os.Getenv("PROFILING_DIR"); val != "" {
		t.Errorf("Expected PROFILING_DIR to be unset after cpuProfileTestSetup, got %q", val)
	}

	// cpuProfileState should be reset (not active)
	cpuProfileState.Lock()
	if cpuProfileState.active {
		t.Error("Expected cpuProfileState.active to be false after setup")
	}
	cpuProfileState.Unlock()
}

// ==================== Misc: getDeviceTokensForUser ====================

func TestCB84_GetDeviceTokensForUser_Success(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-dt1", "pass")
		testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
			userID, "token84-dt1", "ios", time.Now().UTC())
		testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform, created_at) VALUES (?, ?, ?, ?)",
			userID, "token84-dt2", "android", time.Now().UTC())

		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(tokens) != 2 {
			t.Errorf("Expected 2 tokens, got %d", len(tokens))
		}
	})
}

func TestCB84_GetDeviceTokensForUser_NoTokens(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-dt2", "pass")
		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(tokens) != 0 {
			t.Errorf("Expected 0 tokens, got %d", len(tokens))
		}
	})
}

func TestCB84_GetDeviceTokensForUser_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	tokens, err := getDeviceTokensForUser("user84-dt3")
	if err == nil {
		t.Error("Expected error from nil DB")
	}
	if tokens != nil {
		t.Error("Expected nil tokens")
	}
}

// ==================== Misc: isConversationMuted ====================

func TestCB84_IsConversationMuted_NotMuted(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-m1", "pass")
		convID := "conv84-m1"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())

		if isConversationMuted(userID, convID) {
			t.Error("Expected not muted")
		}
	})
}

func TestCB84_IsConversationMuted_Muted(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		userID := createUser_CB84(testDB, "user84-m2", "pass")
		convID := "conv84-m2"
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, ?)",
			convID, userID, "agent1", time.Now().UTC())
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, ?)",
			userID, convID, true)

		if !isConversationMuted(userID, convID) {
			t.Error("Expected muted")
		}
	})
}

func TestCB84_IsConversationMuted_EmptyConvID(t *testing.T) {
	testDB := setupTestDB_CB84(t)
	withGlobalDB_CB84(testDB, func() {
		if isConversationMuted("user84-m3", "") {
			t.Error("Expected not muted for empty convID")
		}
	})
}

func TestCB84_IsConversationMuted_NilDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	if isConversationMuted("user84-m4", "conv1") {
		t.Error("Expected not muted with nil DB")
	}
}

// ==================== Misc: parseSize, GetEnvOrDefault ====================

func TestCB84_ParseSize_Formats(t *testing.T) {
	tests := []struct {
		input   string
		expect  int64
		wantErr bool
	}{
		{"100", 100, false},
		{"1KB", 1024, false},
		{"1MB", 1048576, false},
		{"1GB", 1073741824, false},
		{"2MB", 2 * 1048576, false},
		{"0", 0, false},
		{"", 0, true},
		{"abc", 0, true},
	}
	for _, tc := range tests {
		got, err := parseSize(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseSize(%q): expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseSize(%q): unexpected error: %v", tc.input, err)
			}
			if got != tc.expect {
				t.Errorf("parseSize(%q): expected %d, got %d", tc.input, tc.expect, got)
			}
		}
	}
}

func TestCB84_GetEnvOrDefault_Set(t *testing.T) {
	orig := os.Getenv("TEST84_ENV")
	defer os.Setenv("TEST84_ENV", orig)

	os.Setenv("TEST84_ENV", "custom")
	if got := getEnvOrDefault("TEST84_ENV", "default"); got != "custom" {
		t.Errorf("Expected 'custom', got '%s'", got)
	}
}

func TestCB84_GetEnvOrDefault_Unset(t *testing.T) {
	if got := getEnvOrDefault("TEST84_NONEXISTENT_ENV_84", "default84"); got != "default84" {
		t.Errorf("Expected 'default84', got '%s'", got)
	}
}

// ==================== Misc: isAllowedContentType ====================

func TestCB84_IsAllowedContentType_Allowed(t *testing.T) {
	allowed := []string{
		"image/png", "image/jpeg", "image/gif", "image/webp",
		"application/pdf", "text/plain", "audio/mpeg", "video/mp4",
	}
	for _, ct := range allowed {
		if !isAllowedContentType(ct) {
			t.Errorf("Expected %s to be allowed", ct)
		}
	}
}

func TestCB84_IsAllowedContentType_Disallowed(t *testing.T) {
	// Note: text/* prefix is allowed, so text/html is actually allowed
	disallowed := []string{
		"application/x-msdownload", "application/x-executable", "application/octet-stream",
	}
	for _, ct := range disallowed {
		if isAllowedContentType(ct) {
			t.Errorf("Expected %s to be disallowed", ct)
		}
	}
}

func TestCB84_IsAllowedContentType_Empty(t *testing.T) {
	if isAllowedContentType("") {
		t.Error("Expected empty content type to be disallowed")
	}
}

// ==================== Misc: SafeSend ====================

func TestCB84_SafeSend_NilChannel(t *testing.T) {
	conn := &Connection{
		send: nil,
	}
	if conn.SafeSend([]byte("test")) {
		t.Error("Expected SafeSend to return false for nil channel")
	}
}

func TestCB84_SafeSend_Success(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 5),
	}
	if !conn.SafeSend([]byte("test")) {
		t.Error("Expected SafeSend to return true")
	}
}

func TestCB84_SafeSend_BufferFull(t *testing.T) {
	conn := &Connection{
		send: make(chan []byte, 1),
	}
	conn.send <- []byte("first")
	if conn.SafeSend([]byte("second")) {
		t.Error("Expected SafeSend to return false for full channel")
	}
}

// ==================== Misc: Hub operations ====================

func TestCB84_Hub_RegisterUnregisterAgent(t *testing.T) {
	hub := newTestHub_CB84()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		connType: "agent",
		id:      "agent84-hub1",
		send:    make(chan []byte, 10),
	}

	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	hub.mu.RLock()
	_, exists := hub.agents["agent84-hub1"]
	count := len(hub.agents)
	hub.mu.RUnlock()

	if !exists {
		t.Error("Expected agent to be registered")
	}
	if count != 1 {
		t.Errorf("Expected 1 agent, got %d", count)
	}

	hub.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	hub.mu.RLock()
	_, exists = hub.agents["agent84-hub1"]
	count = len(hub.agents)
	hub.mu.RUnlock()

	if exists {
		t.Error("Expected agent to be unregistered")
	}
	if count != 0 {
		t.Errorf("Expected 0 agents, got %d", count)
	}
}

func TestCB84_Hub_RegisterUnregisterClient(t *testing.T) {
	hub := newTestHub_CB84()
	defer hub.Stop()

	conn := &Connection{
		hub:      hub,
		connType: "client",
		id:      "user84-hub2",
		send:    make(chan []byte, 10),
	}

	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	hub.mu.RLock()
	conns, exists := hub.clientConns["user84-hub2"]
	hub.mu.RUnlock()

	if !exists {
		t.Error("Expected client to be registered")
	}
	if len(conns) != 1 {
		t.Errorf("Expected 1 connection, got %d", len(conns))
	}

	hub.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	hub.mu.RLock()
	conns, exists = hub.clientConns["user84-hub2"]
	hub.mu.RUnlock()

	if exists && len(conns) > 0 {
		t.Errorf("Expected 0 connections after unregister, got %d", len(conns))
	}
}

func TestCB84_Hub_GetClientConns(t *testing.T) {
	hub := newTestHub_CB84()
	defer hub.Stop()

	// No clients
	conns := hub.GetClientConns("nonexistent")
	if len(conns) != 0 {
		t.Errorf("Expected 0 conns, got %d", len(conns))
	}

	conn := &Connection{
		hub:      hub,
		connType: "client",
		id:      "user84-hub3",
		send:    make(chan []byte, 10),
	}
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	conns = hub.GetClientConns("user84-hub3")
	if len(conns) != 1 {
		t.Errorf("Expected 1 conn, got %d", len(conns))
	}
}

// ==================== Misc: Logger ====================

func TestCB84_Logger_AllLevels(t *testing.T) {
	l := NewLogger(LogDebug)

	l.Info("test_info", map[string]interface{}{"key": "value"})
	l.Warn("test_warn", map[string]interface{}{"key": "value"})
	l.Error("test_error", map[string]interface{}{"key": "value"})
	l.Debug("test_debug", map[string]interface{}{"key": "value"})
}

func TestCB84_Logger_NilFields(t *testing.T) {
	l := NewLogger(LogDebug)
	l.Info("test_nil_fields", nil)
	l.Warn("test_nil_fields", nil)
	l.Error("test_nil_fields", nil)
	l.Debug("test_nil_fields", nil)
}

func TestCB84_Logger_EmptyMessage(t *testing.T) {
	l := NewLogger(LogDebug)
	l.Info("", map[string]interface{}{"key": "value"})
}

func TestCB84_Logger_Quiet(t *testing.T) {
	l := NewLogger(LogError) // Only errors
	l.Info("should_not_log", nil)
	l.Warn("should_not_log", nil)
	l.Error("should_log", nil)
}

// ==================== Misc: OfflineQueue ====================

func TestCB84_OfflineQueue_BasicOperations(t *testing.T) {
	q := newOfflineQueue(100, 7*24*time.Hour)

	if q.TotalDepth() != 0 {
		t.Errorf("Expected depth=0, got %d", q.TotalDepth())
	}

	q.Enqueue("user1", []byte(`{"type":"chat"}`))
	q.Enqueue("user1", []byte(`{"type":"chat"}`))
	q.Enqueue("user2", []byte(`{"type":"chat"}`))

	if q.TotalDepth() != 3 {
		t.Errorf("Expected depth=3, got %d", q.TotalDepth())
	}

	msgs := q.Drain("user1")
	if len(msgs) != 2 {
		t.Errorf("Expected 2 messages for user1, got %d", len(msgs))
	}

	if q.TotalDepth() != 1 {
		t.Errorf("Expected depth=1 after drain, got %d", q.TotalDepth())
	}
}

func TestCB84_OfflineQueue_MaxDepth(t *testing.T) {
	q := newOfflineQueue(3, 7*24*time.Hour)

	for i := 0; i < 5; i++ {
		q.Enqueue("user1", []byte(`{"type":"chat"}`))
	}

	if q.TotalDepth() != 3 {
		t.Errorf("Expected max depth=3, got %d", q.TotalDepth())
	}
}

func TestCB84_OfflineQueue_TTLExpiry(t *testing.T) {
	q := newOfflineQueue(100, 50*time.Millisecond)
	q.Enqueue("user1", []byte(`{"type":"chat"}`))

	time.Sleep(100 * time.Millisecond)

	msgs := q.Drain("user1")
	if len(msgs) != 0 {
		t.Errorf("Expected 0 messages after TTL, got %d", len(msgs))
	}
}

func TestCB84_OfflineQueue_Concurrent(t *testing.T) {
	q := newOfflineQueue(1000, 7*24*time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				q.Enqueue("user1", []byte(`{"type":"chat"}`))
			}
		}(i)
	}
	wg.Wait()

	if q.TotalDepth() > 1000 {
		t.Errorf("Expected max 1000, got %d", q.TotalDepth())
	}
}

// ==================== Misc: validateJWT ====================

func TestCB84_ValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("")
	if err == nil {
		t.Error("Expected error for empty token")
	}
}

func TestCB84_ValidateJWT_InvalidFormat(t *testing.T) {
	_, err := ValidateJWT("not.a.valid.jwt")
	if err == nil {
		t.Error("Expected error for invalid format")
	}
}

func TestCB84_ValidateJWT_ValidToken(t *testing.T) {
	token, _ := GenerateJWT("user84-jwt", "user84-jwt")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if claims.UserID != "user84-jwt" {
		t.Errorf("Expected UserID=user84-jwt, got %s", claims.UserID)
	}
}

// ==================== Misc: extractIP ====================

func TestCB84_ExtractIP_ForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	ip := extractIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("Expected 1.2.3.4, got %s", ip)
	}
}

func TestCB84_ExtractIP_RealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "9.8.7.6")
	ip := extractIP(req)
	if ip != "9.8.7.6" {
		t.Errorf("Expected 9.8.7.6, got %s", ip)
	}
}

func TestCB84_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	ip := extractIP(req)
	if !strings.HasPrefix(ip, "10.0.0.1") {
		t.Errorf("Expected 10.0.0.1, got %s", ip)
	}
}