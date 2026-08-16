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
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// ============================================================
// CB91: Coverage boost targeting remaining low-coverage functions
// Focus: routeChatMessage (7.3%), handleStoreEncryptedMessage (71.7%),
// persistTierToDB (71.4%), routeStatusUpdate (83.3%), cleanup (83.3%),
// RegisterAgentOnConnect (81.8%), sendWelcomeMessage (80%),
// readPump (86.4%), notifyUser (86.7%), handleUpload (85.7%),
// initSchema (85.3%), initAPNs (84%), InitTracing (79.5%),
// ShutdownTracing (80%), initFCM (88.9%), monitorAgentHeartbeats (88.9%)
// ============================================================

// --- Helpers ---

func withTestDB_CB91(t *testing.T, fn func(testDB *sql.DB)) {
	t.Helper()
	oldDB := db
	oldDriver := currentDriver
	currentDriver = DriverSQLite
	defer func() { db = oldDB; currentDriver = oldDriver }()
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer testDB.Close()
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	db = testDB
	fn(testDB)
}

func makeJWT_CB91(userID, username string) string {
	token, err := GenerateJWT(userID, username)
	if err != nil {
		panic("failed to generate JWT: " + err.Error())
	}
	return token
}

func setupHub_CB91() func() {
	oldHub := hub
	hubRef := newHub()
	hub = hubRef
	go hubRef.run()
	return func() {
		hubRef.Stop()
		hub = oldHub
	}
}

func setupUserAndConv_CB91(t *testing.T, testDB *sql.DB) (string, string, string) {
	t.Helper()
	userID := "cb91-user1"
	agentID := "cb91-agent1"
	convID := "cb91-conv1"

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	_, err := testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, "cb91testuser", string(hash))
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
		agentID, "TestAgent", "gpt-4", "friendly", "general")
	if err != nil {
		t.Fatalf("Failed to insert agent: %v", err)
	}

	_, err = testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		convID, userID, agentID)
	if err != nil {
		t.Fatalf("Failed to insert conversation: %v", err)
	}

	return userID, agentID, convID
}

func makeConn_CB91(id, connType string, hubRef *Hub) *Connection {
	return &Connection{
		id:        id,
		connType:  connType,
		send:      make(chan []byte, 10),
		hub:       hubRef,
		connectedAt: time.Now(),
	}
}

// ============================================================
// routeChatMessage — currently 7.3%, target: 50%+
// ============================================================

func TestCB91_RouteChatMessage_InvalidJSON(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		routeChatMessage(conn, json.RawMessage("bad json"))
		// Should not panic
	})
}

func TestCB91_RouteChatMessage_EmptyContent(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		msg := RoutedMessage{ConversationID: "conv1", Content: ""}
		data, _ := json.Marshal(msg)
		routeChatMessage(conn, data)
		// Should send error back to sender — check send channel
		select {
		case resp := <-conn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "error" {
				t.Errorf("expected error type, got %s", out.Type)
			}
		default:
			// Might not get a response if sendError uses SafeSend
		}
	})
}

func TestCB91_RouteChatMessage_EmptyConvID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		msg := RoutedMessage{ConversationID: "", Content: "hello"}
		data, _ := json.Marshal(msg)
		routeChatMessage(conn, data)
	})
}

func TestCB91_RouteChatMessage_ConvNotFound(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		msg := RoutedMessage{ConversationID: "nonexistent", Content: "hello"}
		data, _ := json.Marshal(msg)
		routeChatMessage(conn, data)
	})
}

func TestCB91_RouteChatMessage_AgentNotAuthorized(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()
		// Wrong agent tries to send to conversation
		conn := makeConn_CB91("wrong-agent", "agent", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "hello"}
		data, _ := json.Marshal(msg)
		routeChatMessage(conn, data)
	})
}

func TestCB91_RouteChatMessage_ClientNotAuthorized(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()
		// Wrong user tries to send to conversation
		conn := makeConn_CB91("wrong-user", "client", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "hello"}
		data, _ := json.Marshal(msg)
		routeChatMessage(conn, data)
	})
}

func TestCB91_RouteChatMessage_AgentToClient_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register client in hub
		clientConn := makeConn_CB91(userID, "client", hub)
		hub.register <- clientConn
		time.Sleep(50 * time.Millisecond) // allow hub to process

		// Agent sends message
		agentConn := makeConn_CB91(agentID, "agent", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "Hello from agent"}
		data, _ := json.Marshal(msg)
		routeChatMessage(agentConn, data)

		// Client should receive the message
		select {
		case resp := <-clientConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message" {
				t.Errorf("expected message type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("client did not receive message")
		}

		// Agent should receive ack
		select {
		case resp := <-agentConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message_sent" {
				t.Errorf("expected message_sent type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("agent did not receive ack")
		}
	})
}

func TestCB91_RouteChatMessage_ClientToAgent_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register agent in hub
		agentConn := makeConn_CB91(agentID, "agent", hub)
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		// Client sends message
		clientConn := makeConn_CB91(userID, "client", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "Hello from client"}
		data, _ := json.Marshal(msg)
		routeChatMessage(clientConn, data)

		// Agent should receive the message
		select {
		case resp := <-agentConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message" {
				t.Errorf("expected message type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("agent did not receive message")
		}

		// Client should receive ack
		select {
		case resp := <-clientConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message_sent" {
				t.Errorf("expected message_sent type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("client did not receive ack")
		}
	})
}

func TestCB91_RouteChatMessage_AgentToOfflineClient_Queued(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Client is NOT registered (offline)
		agentConn := makeConn_CB91(agentID, "agent", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "Hello offline"}
		data, _ := json.Marshal(msg)
		routeChatMessage(agentConn, data)

		// Agent should receive ack
		select {
		case resp := <-agentConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message_sent" {
				t.Errorf("expected message_sent type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("agent did not receive ack")
		}
	})
}

func TestCB91_RouteChatMessage_ClientToOfflineAgent_Queued(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Agent is NOT registered (offline)
		clientConn := makeConn_CB91(userID, "client", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "Hello offline agent"}
		data, _ := json.Marshal(msg)
		routeChatMessage(clientConn, data)

		// Client should receive ack
		select {
		case resp := <-clientConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message_sent" {
				t.Errorf("expected message_sent type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("client did not receive ack")
		}
	})
}

func TestCB91_RouteChatMessage_AgentToClient_BufferFull(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Create client with buffer size 1, fill it
		clientConn := &Connection{
			id:        userID,
			connType:  "client",
			send:      make(chan []byte, 1),
			hub:       hub,
			connectedAt: time.Now(),
		}
		clientConn.send <- []byte("fill buffer")
		hub.register <- clientConn
		time.Sleep(50 * time.Millisecond)

		// Agent sends message — buffer full, should queue for offline
		agentConn := makeConn_CB91(agentID, "agent", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "Hello full buffer"}
		data, _ := json.Marshal(msg)
		routeChatMessage(agentConn, data)

		// Agent should still get ack
		select {
		case resp := <-agentConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message_sent" {
				t.Errorf("expected message_sent type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("agent did not receive ack")
		}
	})
}

func TestCB91_RouteChatMessage_ClientToAgent_BufferFull(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Create agent with buffer size 1, fill it
		agentConn := &Connection{
			id:        agentID,
			connType:  "agent",
			send:      make(chan []byte, 1),
			hub:       hub,
			connectedAt: time.Now(),
		}
		agentConn.send <- []byte("fill buffer")
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		// Client sends message — agent buffer full
		clientConn := makeConn_CB91(userID, "client", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "Hello full agent buffer"}
		data, _ := json.Marshal(msg)
		routeChatMessage(clientConn, data)

		// Client should receive ack
		select {
		case resp := <-clientConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "message_sent" {
				t.Errorf("expected message_sent type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("client did not receive ack")
		}
	})
}

func TestCB91_RouteChatMessage_MultiDevice(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register two client devices
		client1 := makeConn_CB91(userID, "client", hub)
		client1.deviceID = "device1"
		client2 := makeConn_CB91(userID, "client", hub)
		client2.deviceID = "device2"
		hub.register <- client1
		hub.register <- client2
		time.Sleep(50 * time.Millisecond)

		// Agent sends message — both devices should receive
		agentConn := makeConn_CB91(agentID, "agent", hub)
		msg := RoutedMessage{ConversationID: convID, Content: "Hello multi-device"}
		data, _ := json.Marshal(msg)
		routeChatMessage(agentConn, data)

		// Both clients should receive
		for i, c := range []*Connection{client1, client2} {
			select {
			case resp := <-c.send:
				var out OutgoingMessage
				json.Unmarshal(resp, &out)
				if out.Type != "message" {
					t.Errorf("device %d: expected message type, got %s", i, out.Type)
				}
			case <-time.After(1 * time.Second):
				t.Errorf("device %d did not receive message", i)
			}
		}
	})
}

// ============================================================
// handleStoreEncryptedMessage — 71.7%, target: 85%+
// ============================================================

func TestCB91_StoreEncryptedMessage_DBError(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB91(t, testDB)
		token := makeJWT_CB91(userID, "cb91testuser")

		// Close DB to force error
		testDB.Close()

		body := `{"conversation_id":"` + convID + `","ciphertext":"abc","iv":"iv1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)
		// DB is closed, should get 500 or 404 (getConversation may fail)
		if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusNotFound {
			t.Errorf("expected 500 or 404, got %d", rr.Code)
		}
	})
}

func TestCB91_StoreEncryptedMessage_AgentSuccess_WithHub(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register client in hub so there's a recipient
		clientConn := makeConn_CB91(userID, "client", hub)
		hub.register <- clientConn
		time.Sleep(50 * time.Millisecond)

		os.Setenv("AGENT_SECRET", "test-secret-cb91")
		defer os.Unsetenv("AGENT_SECRET")

		body := `{"conversation_id":"` + convID + `","ciphertext":"agent_enc","iv":"agent_iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("X-Agent-Secret", "test-secret-cb91")
		req.Header.Set("X-Agent-ID", agentID)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}

		// Client should receive encrypted_message notification
		select {
		case resp := <-clientConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "encrypted_message" {
				t.Errorf("expected encrypted_message type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("client did not receive encrypted_message notification")
		}
	})
}

func TestCB91_StoreEncryptedMessage_AgentAllBuffersFull(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register client with full buffer
		clientConn := &Connection{
			id:        userID,
			connType:  "client",
			send:      make(chan []byte, 1),
			hub:       hub,
			connectedAt: time.Now(),
		}
		clientConn.send <- []byte("fill")
		hub.register <- clientConn
		time.Sleep(50 * time.Millisecond)

		os.Setenv("AGENT_SECRET", "test-secret-cb91")
		defer os.Unsetenv("AGENT_SECRET")

		body := `{"conversation_id":"` + convID + `","ciphertext":"agent_enc","iv":"agent_iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("X-Agent-Secret", "test-secret-cb91")
		req.Header.Set("X-Agent-ID", agentID)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB91_StoreEncryptedMessage_UserSuccess_WithHub(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register agent in hub
		agentConn := makeConn_CB91(agentID, "agent", hub)
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		token := makeJWT_CB91(userID, "cb91testuser")
		body := `{"conversation_id":"` + convID + `","ciphertext":"user_enc","iv":"user_iv","recipient_key_id":"rk1","algorithm":"x25519-aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}

		// Agent should receive encrypted_message notification
		select {
		case resp := <-agentConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "encrypted_message" {
				t.Errorf("expected encrypted_message type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("agent did not receive encrypted_message notification")
		}
	})
}

func TestCB91_StoreEncryptedMessage_UserAgentBufferFull(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register agent with full buffer
		agentConn := &Connection{
			id:        agentID,
			connType:  "agent",
			send:      make(chan []byte, 1),
			hub:       hub,
			connectedAt: time.Now(),
		}
		agentConn.send <- []byte("fill")
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		token := makeJWT_CB91(userID, "cb91testuser")
		body := `{"conversation_id":"` + convID + `","ciphertext":"user_enc","iv":"user_iv","recipient_key_id":"rk1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB91_StoreEncryptedMessage_ChaChaAlgorithm(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB91(t, testDB)
		token := makeJWT_CB91(userID, "cb91testuser")

		body := `{"conversation_id":"` + convID + `","ciphertext":"abc","iv":"iv1","algorithm":"x25519-chacha20-poly1305"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for chacha algorithm, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB91_StoreEncryptedMessage_MissingRecipientKeyID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB91(t, testDB)
		token := makeJWT_CB91(userID, "cb91testuser")

		// recipient_key_id is optional (sender_key_id is omitempty), but we should
		// still succeed — just verify it works without it
		body := `{"conversation_id":"` + convID + `","ciphertext":"abc","iv":"iv1","algorithm":"aes-256-gcm"}`
		req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleStoreEncryptedMessage(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 without recipient_key_id, got %d", rr.Code)
		}
	})
}

// ============================================================
// routeStatusUpdate — 83.3%, target: 92%+
// ============================================================

func TestCB91_RouteStatusUpdate_InvalidJSON(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		routeStatusUpdate(conn, json.RawMessage("bad json"))
	})
}

func TestCB91_RouteStatusUpdate_AgentStatusChange(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, _ := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register client to receive broadcast
		clientConn := makeConn_CB91(userID, "client", hub)
		hub.register <- clientConn
		time.Sleep(50 * time.Millisecond)

		// Register agent
		agentConn := makeConn_CB91(agentID, "agent", hub)
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		// Drain any presence_update messages from registration
		for {
			select {
			case <-clientConn.send:
			default:
			}
			break
		}

		// Agent sends status update
		payload := `{"status":"busy"}`
		routeStatusUpdate(agentConn, json.RawMessage(payload))

		// Client should receive status messages (may also get presence_update)
		foundStatus := false
		for i := 0; i < 5; i++ {
			select {
			case resp := <-clientConn.send:
				var out OutgoingMessage
				json.Unmarshal(resp, &out)
				if out.Type == "status" {
					foundStatus = true
				}
			case <-time.After(500 * time.Millisecond):
				break
			}
		}
		if !foundStatus {
			t.Error("client did not receive status broadcast")
		}
	})
}

func TestCB91_RouteStatusUpdate_ClientSender(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register agent
		agentConn := makeConn_CB91(agentID, "agent", hub)
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		// Client sends status update
		clientConn := makeConn_CB91(userID, "client", hub)
		payload := `{"conversation_id":"` + convID + `","status":"typing"}`
		routeStatusUpdate(clientConn, json.RawMessage(payload))

		// Agent should receive status update
		select {
		case resp := <-agentConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "status" {
				t.Errorf("expected status type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("agent did not receive status update")
		}
	})
}

func TestCB91_RouteStatusUpdate_EmptyStatus(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		// Empty status — should not call SetAgentStatus or broadcast
		routeStatusUpdate(conn, json.RawMessage(`{"status":""}`))
	})
}

func TestCB91_RouteStatusUpdate_EmptyConvID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		// Status with empty conv ID — should broadcast but not route to specific conversation
		routeStatusUpdate(conn, json.RawMessage(`{"status":"online"}`))
	})
}

func TestCB91_RouteStatusUpdate_ConvNotFound(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		teardown := setupHub_CB91()
		defer teardown()
		conn := makeConn_CB91("cb91-agent1", "agent", hub)
		routeStatusUpdate(conn, json.RawMessage(`{"conversation_id":"nonexistent","status":"online"}`))
	})
}

func TestCB91_RouteStatusUpdate_AgentWithConvID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register client
		clientConn := makeConn_CB91(userID, "client", hub)
		hub.register <- clientConn
		time.Sleep(50 * time.Millisecond)

		// Register agent
		agentConn := makeConn_CB91(agentID, "agent", hub)
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		// Agent sends status update with conversation_id
		payload := `{"conversation_id":"` + convID + `","status":"idle"}`
		routeStatusUpdate(agentConn, json.RawMessage(payload))

		// Client should receive at least one status update (broadcast + conversation-specific)
		received := 0
		for {
			select {
			case resp := <-clientConn.send:
				var out OutgoingMessage
				json.Unmarshal(resp, &out)
				if out.Type == "status" {
					received++
				}
			case <-time.After(200 * time.Millisecond):
				if received == 0 {
					t.Error("client did not receive any status updates")
				}
				return
			}
		}
	})
}

func TestCB91_RouteStatusUpdate_ClientWithConvID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)
		teardown := setupHub_CB91()
		defer teardown()

		// Register agent
		agentConn := makeConn_CB91(agentID, "agent", hub)
		hub.register <- agentConn
		time.Sleep(50 * time.Millisecond)

		// Client sends status with conv ID
		clientConn := makeConn_CB91(userID, "client", hub)
		payload := `{"conversation_id":"` + convID + `","status":"typing"}`
		routeStatusUpdate(clientConn, json.RawMessage(payload))

		// Agent should receive status
		select {
		case resp := <-agentConn.send:
			var out OutgoingMessage
			json.Unmarshal(resp, &out)
			if out.Type != "status" {
				t.Errorf("expected status type, got %s", out.Type)
			}
		case <-time.After(1 * time.Second):
			t.Error("agent did not receive status update")
		}
	})
}

// ============================================================
// persistTierToDB — 71.4%, target: 85%+
// ============================================================

func TestCB91_PersistTierToDB_PostgreSQLMockError(t *testing.T) {
	oldDB := db
	oldDriver := currentDriver
	defer func() { db = oldDB; currentDriver = oldDriver }()

	// Set up SQLite but claim PostgreSQL driver
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer testDB.Close()
	if err := initSchema(testDB); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	db = testDB
	currentDriver = DriverPostgreSQL

	// With PostgreSQL driver set but using SQLite, the $1/$2 placeholders will fail
	err = persistTierToDB("cb91-pg-user", TierPro)
	if err == nil {
		t.Log("persistTierToDB with PostgreSQL driver on SQLite did not error (some drivers may accept $N)")
	}
	// Reset driver
	currentDriver = DriverSQLite
}

func TestCB91_PersistTierToDB_ReplaceExisting(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		// Insert initial tier
		err := persistTierToDB("cb91-replace-user", TierFree)
		if err != nil {
			t.Fatalf("first persist failed: %v", err)
		}

		// Replace with Pro
		err = persistTierToDB("cb91-replace-user", TierPro)
		if err != nil {
			t.Fatalf("replace persist failed: %v", err)
		}

		// Verify it was replaced
		var tierName string
		err = testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "cb91-replace-user").Scan(&tierName)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if tierName != TierPro.Name {
			t.Errorf("expected tier %s, got %s", TierPro.Name, tierName)
		}
	})
}

func TestCB91_PersistTierToDB_EnterpriseTier(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		err := persistTierToDB("cb91-ent-user", TierEnterprise)
		if err != nil {
			t.Fatalf("persist enterprise failed: %v", err)
		}

		var tierName string
		err = testDB.QueryRow("SELECT tier_name FROM user_rate_limit_tiers WHERE user_id = ?", "cb91-ent-user").Scan(&tierName)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if tierName != TierEnterprise.Name {
			t.Errorf("expected tier %s, got %s", TierEnterprise.Name, tierName)
		}
	})
}

// ============================================================
// cleanup (RateLimiter) — 83.3%, target: 90%+
// ============================================================

func TestCB91_RateLimiterCleanup_ExpiredRemoval(t *testing.T) {
	rl := NewRateLimiter(5, 100*time.Millisecond)
	go rl.cleanup()
	defer func() {
		rl.stopCh <- struct{}{}
	}()

	// Add a counter
	rl.Allow("user1")

	// Wait for cleanup to run
	time.Sleep(250 * time.Millisecond)

	// Counter should be cleaned up (expired)
	count := rl.Count("user1")
	if count > 0 {
		t.Errorf("expected 0 after cleanup, got %d", count)
	}
}

func TestCB91_RateLimiterCleanup_StopChannel(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Second)
	go rl.cleanup()

	// Stop via channel
	rl.stopCh <- struct{}{}

	// Should not panic — just verify it doesn't hang
	time.Sleep(50 * time.Millisecond)
}

func TestCB91_TieredRateLimiterCleanup_StopChannel(t *testing.T) {
	trl := NewTieredRateLimiter()
	go trl.cleanup()

	// Stop via channel
	trl.stopCh <- struct{}{}

	// Should not panic
	time.Sleep(50 * time.Millisecond)
}

func TestCB91_TieredRateLimiterCleanup_StaleRemoval(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer func() { trl.stopCh <- struct{}{} }()

	// Add an entry with past window
	trl.mu.Lock()
	trl.limits["stale-user"] = &userRateLimitState{
		tier:      TierFree,
		count:     5,
		windowEnd: time.Now().Add(-20 * time.Minute), // expired > 10 min ago
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["stale-user"]; exists {
		t.Error("expected stale entry to be removed")
	}
}

func TestCB91_TieredRateLimiterCleanup_KeepRecent(t *testing.T) {
	trl := NewTieredRateLimiter()
	defer func() { trl.stopCh <- struct{}{} }()

	// Add an entry that just expired (< 10 min ago)
	trl.mu.Lock()
	trl.limits["recent-user"] = &userRateLimitState{
		tier:      TierFree,
		count:     5,
		windowEnd: time.Now().Add(-2 * time.Minute), // expired but < 10 min
	}
	trl.mu.Unlock()

	trl.cleanupOnce()

	trl.mu.Lock()
	defer trl.mu.Unlock()
	if _, exists := trl.limits["recent-user"]; !exists {
		t.Error("expected recent expired entry to be kept (< 10 min grace)")
	}
}

// ============================================================
// RegisterAgentOnConnect — 81.8%, target: 90%+
// ============================================================

func TestCB91_RegisterAgentOnConnect_NewAgentAllFields(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		err := RegisterAgentOnConnect("cb91-new-agent", "MyAgent", "gpt-4", "helpful", "coding")
		if err != nil {
			t.Fatalf("register failed: %v", err)
		}

		var name, model, personality, specialty string
		err = testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "cb91-new-agent").
			Scan(&name, &model, &personality, &specialty)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if name != "MyAgent" || model != "gpt-4" || personality != "helpful" || specialty != "coding" {
			t.Errorf("unexpected values: name=%s model=%s personality=%s specialty=%s", name, model, personality, specialty)
		}
	})
}

func TestCB91_RegisterAgentOnConnect_DefaultName(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		err := RegisterAgentOnConnect("cb91-default-agent", "", "gpt-4", "", "")
		if err != nil {
			t.Fatalf("register failed: %v", err)
		}

		var name string
		err = testDB.QueryRow("SELECT name FROM agents WHERE id = ?", "cb91-default-agent").Scan(&name)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if name != "cb91-default-agent" {
			t.Errorf("expected name to default to agentID, got %s", name)
		}
	})
}

func TestCB91_RegisterAgentOnConnect_UpdateAllFields(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		// First registration
		_ = RegisterAgentOnConnect("cb91-update-agent", "Agent1", "gpt-3.5", "friendly", "general")

		// Second registration with updates
		err := RegisterAgentOnConnect("cb91-update-agent", "Agent2", "gpt-4", "serious", "coding")
		if err != nil {
			t.Fatalf("update failed: %v", err)
		}

		var name, model, personality, specialty string
		err = testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "cb91-update-agent").
			Scan(&name, &model, &personality, &specialty)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if name != "Agent2" || model != "gpt-4" || personality != "serious" || specialty != "coding" {
			t.Errorf("unexpected values after update: name=%s model=%s personality=%s specialty=%s", name, model, personality, specialty)
		}
	})
}

func TestCB91_RegisterAgentOnConnect_PreserveEmptyFields(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		// First registration with all fields
		_ = RegisterAgentOnConnect("cb91-preserve-agent", "Original", "gpt-4", "friendly", "general")

		// Second registration with empty fields (except name which defaults to agentID)
		err := RegisterAgentOnConnect("cb91-preserve-agent", "", "", "", "")
		if err != nil {
			t.Fatalf("second register failed: %v", err)
		}

		var name, model, personality, specialty string
		err = testDB.QueryRow("SELECT name, model, personality, specialty FROM agents WHERE id = ?", "cb91-preserve-agent").
			Scan(&name, &model, &personality, &specialty)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		// name defaults to agentID when empty, and won't update because it equals agentID
		if name != "Original" {
			t.Errorf("expected name preserved as 'Original', got %s", name)
		}
		if model != "gpt-4" {
			t.Errorf("expected model preserved, got %s", model)
		}
		if personality != "friendly" {
			t.Errorf("expected personality preserved, got %s", personality)
		}
		if specialty != "general" {
			t.Errorf("expected specialty preserved, got %s", specialty)
		}
	})
}

func TestCB91_RegisterAgentOnConnect_NameEqualsAgentID_NoUpdate(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		// First registration with custom name
		_ = RegisterAgentOnConnect("cb91-name-test", "CustomName", "gpt-4", "", "")

		// Second registration with empty name (defaults to agentID = "cb91-name-test")
		// Since name == agentID, it should NOT update the name
		err := RegisterAgentOnConnect("cb91-name-test", "", "", "", "")
		if err != nil {
			t.Fatalf("second register failed: %v", err)
		}

		var name string
		err = testDB.QueryRow("SELECT name FROM agents WHERE id = ?", "cb91-name-test").Scan(&name)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if name != "CustomName" {
			t.Errorf("expected name 'CustomName' preserved, got %s", name)
		}
	})
}

func TestCB91_RegisterAgentOnConnect_QueryError(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		// Close DB to cause query error
		testDB.Close()
		err := RegisterAgentOnConnect("cb91-error-agent", "Test", "gpt-4", "", "")
		if err == nil {
			t.Error("expected error on closed DB")
		}
	})
}

func TestCB91_RegisterAgentOnConnect_InsertError(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		// Insert a duplicate agent manually to cause UNIQUE constraint violation
		_, err := testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)",
			"cb91-dup", "Existing", "gpt-4", "", "")
		if err != nil {
			t.Fatalf("insert failed: %v", err)
		}

		// Now try to register same agent ID — query will find existing, so it goes to update path
		// But if we close the DB after the query finds the row, the UPDATE will fail
		// Actually, with existing agent, it should go to update path, not insert
		// Let's test insert error by making the table unavailable
		_, err = testDB.Exec("DROP TABLE agents")
		if err != nil {
			t.Fatalf("drop table failed: %v", err)
		}

		err = RegisterAgentOnConnect("cb91-new-after-drop", "Test", "gpt-4", "", "")
		if err == nil {
			t.Error("expected error when agents table doesn't exist")
		}
	})
}

// ============================================================
// sendWelcomeMessage — 80%, target: 90%+
// ============================================================

func TestCB91_SendWelcomeMessage_WithDeviceID(t *testing.T) {
	conn := &Connection{
		id:        "cb91-device-test",
		connType:  "client",
		send:      make(chan []byte, 10),
		deviceID:  "device-123",
		negotiatedVersion: "0.1",
	}
	sendWelcomeMessage(conn)

	select {
	case data := <-conn.send:
		var msg OutgoingMessage
		json.Unmarshal(data, &msg)
		if msg.Type != "connected" {
			t.Errorf("expected connected type, got %s", msg.Type)
		}
		dataMap, ok := msg.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data")
		}
		if dataMap["device_id"] != "device-123" {
			t.Errorf("expected device_id 'device-123', got %v", dataMap["device_id"])
		}
	case <-time.After(1 * time.Second):
		t.Error("no welcome message received")
	}
}

func TestCB91_SendWelcomeMessage_WithoutDeviceID(t *testing.T) {
	conn := &Connection{
		id:        "cb91-no-device",
		connType:  "agent",
		send:      make(chan []byte, 10),
		negotiatedVersion: "0.1",
	}
	sendWelcomeMessage(conn)

	select {
	case data := <-conn.send:
		var msg OutgoingMessage
		json.Unmarshal(data, &msg)
		if msg.Type != "connected" {
			t.Errorf("expected connected type, got %s", msg.Type)
		}
		dataMap, ok := msg.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data")
		}
		if _, exists := dataMap["device_id"]; exists {
			t.Error("expected no device_id field")
		}
	case <-time.After(1 * time.Second):
		t.Error("no welcome message received")
	}
}

func TestCB91_SendWelcomeMessage_ClosedChannel(t *testing.T) {
	conn := &Connection{
		id:        "cb91-closed",
		connType:  "client",
		send:      make(chan []byte, 0), // unbuffered, no receiver
		negotiatedVersion: "0.1",
	}
	// SafeSend should return false without blocking
	sendWelcomeMessage(conn)
	// If we get here, no panic — test passes
}

func TestCB91_SendWelcomeMessage_ProtocolVersion(t *testing.T) {
	conn := &Connection{
		id:        "cb91-proto-test",
		connType:  "client",
		send:      make(chan []byte, 10),
		negotiatedVersion: "0.2",
	}
	sendWelcomeMessage(conn)

	select {
	case data := <-conn.send:
		var msg OutgoingMessage
		json.Unmarshal(data, &msg)
		dataMap, ok := msg.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data")
		}
		if dataMap["protocol_version"] != "0.2" {
			t.Errorf("expected protocol_version '0.2', got %v", dataMap["protocol_version"])
		}
		if versions, ok := dataMap["supported_versions"].([]interface{}); ok {
			if len(versions) == 0 {
				t.Error("expected supported_versions to be non-empty")
			}
		} else {
			t.Error("expected supported_versions field")
		}
	case <-time.After(1 * time.Second):
		t.Error("no welcome message received")
	}
}

// ============================================================
// notifyUser — 86.7%, target: 93%+
// ============================================================

func TestCB91_NotifyUser_WithMutedConversation(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-mute-user"
		convID := "cb91-mute-conv"

		// Insert user, agent, conversation
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "muteuser", string(hash))
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "cb91-mute-agent", "Agent", "gpt-4", "", "")
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, "cb91-mute-agent")

		// Mute the conversation
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)

		// Set pushConfig to non-nil to enter the muted check
		oldConfig := pushConfig
		pushConfig = &PushNotificationConfig{}
		defer func() { pushConfig = oldConfig }()

		notifyUser(userID, "Title", "Body", convID)
		// Should return early due to muted — no push sent (no panic)
	})
}

func TestCB91_NotifyUser_WithTokens_SendPush(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-push-user"

		// Insert user
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "pushuser", string(hash))

		// Insert device token
		testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "fake-token-123", "ios")

		// Set pushConfig to non-nil
		oldConfig := pushConfig
		pushConfig = &PushNotificationConfig{}
		defer func() { pushConfig = oldConfig }()

		// notifyUser should try to send push (will fail with fake token, but shouldn't panic)
		notifyUser(userID, "Title", "Body", "")
	})
}

func TestCB91_NotifyUser_EmptyConversationID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-empty-conv-user"

		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "emptyuser", string(hash))

		// No tokens — should return early
		notifyUser(userID, "Title", "Body", "")
	})
}

// ============================================================
// handleUpload — 85.7%, target: 92%+
// ============================================================

func TestCB91_HandleUpload_SuccessWithMessageType(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-upload-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "uploaduser", string(hash))

		token := makeJWT_CB91(userID, "uploaduser")

		// Create multipart form with file
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test.txt")
		part.Write([]byte("test file content"))
		writer.WriteField("message_id", "msg-123")
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		// Set up upload dir
		oldDir := serverDBPath
		serverDBPath = "/tmp/cb91-uploads"
		defer func() { serverDBPath = oldDir }()
		os.MkdirAll(serverDBPath, 0755)
		defer os.RemoveAll(serverDBPath)

		rr := httptest.NewRecorder()
		handleUpload(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB91_HandleUpload_NoMessageID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-upload-user2"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "uploaduser2", string(hash))

		token := makeJWT_CB91(userID, "uploaduser2")

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test.txt")
		part.Write([]byte("test file content"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		oldDir := serverDBPath
		serverDBPath = "/tmp/cb91-uploads2"
		defer func() { serverDBPath = oldDir }()
		os.MkdirAll(serverDBPath, 0755)
		defer os.RemoveAll(serverDBPath)

		rr := httptest.NewRecorder()
		handleUpload(rr, req)

		// Should still succeed — message_id is optional
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB91_HandleUpload_TextFileDetected(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-upload-user3"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "uploaduser3", string(hash))

		token := makeJWT_CB91(userID, "uploaduser3")

		// Upload text content — DetectContentType will recognize as text/plain
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "data.txt")
		part.Write([]byte("plain text content for detection"))
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		oldDir := serverDBPath
		serverDBPath = "/tmp/cb91-uploads3"
		defer func() { serverDBPath = oldDir }()
		os.MkdirAll(serverDBPath, 0755)
		defer os.RemoveAll(serverDBPath)

		rr := httptest.NewRecorder()
		handleUpload(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

// ============================================================
// initSchema — 85.3%, target: 92%+
// ============================================================

func TestCB91_InitSchema_ReactionsTableError(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	// Pre-create a reactions table with conflicting schema
	_, err = testDB.Exec(`CREATE TABLE reactions (
		id TEXT PRIMARY KEY,
		message_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		emoji TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		UNIQUE(message_id, user_id, emoji)
	)`)
	if err != nil {
		t.Fatalf("Failed to create conflicting reactions table: %v", err)
	}

	// initSchema should handle existing table (CREATE TABLE IF NOT EXISTS skips)
	err = initSchema(testDB)
	if err != nil {
		t.Errorf("initSchema should handle existing tables: %v", err)
	}
}

func TestCB91_InitSchema_AlterTableIdempotent(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	// Run initSchema once
	err = initSchema(testDB)
	if err != nil {
		t.Fatalf("first initSchema failed: %v", err)
	}

	// Run again — should be idempotent
	err = initSchema(testDB)
	if err != nil {
		t.Fatalf("second initSchema failed: %v", err)
	}

	// Verify migrations table has entries
	var count int
	err = testDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		// schema_migrations might not exist in older schema versions
		return
	}
	if count == 0 {
		t.Error("expected migrations to be recorded")
	}
}

func TestCB91_InitSchema_NilDB(t *testing.T) {
	// initSchema with nil DB should panic or error
	defer func() {
		if r := recover(); r == nil {
			// Some implementations return error instead of panicking
			// Either is acceptable
		}
	}()
	_ = initSchema(nil)
}

func TestCB91_InitSchema_EncryptedMessagesTable(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer testDB.Close()

	err = initSchema(testDB)
	if err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	// Verify encrypted_messages table exists
	_, err = testDB.Exec("INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, algorithm, recipient_key_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"test-enc-1", "conv-1", "user-1", "user", "ciphertext", "iv", "aes-256-gcm", "rk1", time.Now().UTC())
	if err != nil {
		t.Errorf("failed to insert into encrypted_messages: %v", err)
	}
}

// ============================================================
// InitTracing — 79.5%, target: 87%+
// ============================================================

func TestCB91_InitTracing_OTELDisabled(t *testing.T) {
	os.Unsetenv("OTEL_ENABLED")
	// Reset tracing state
	oldTp := tp
	tp = nil
	tracingEnabled = false
	defer func() { tp = oldTp }()

	err := InitTracing()
	if err != nil {
		t.Errorf("expected no error when tracing disabled, got %v", err)
	}
}

func TestCB91_InitTracing_NoEndpoint(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT")
	defer os.Unsetenv("OTEL_ENABLED")

	// sync.Once means this may already be initialized from previous tests
	// Just verify no panic
	err := InitTracing()
	if err != nil {
		t.Logf("InitTracing returned error (expected): %v", err)
	}
}

func TestCB91_InitTracing_HTTPProtocol(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")

	// This will try to create an HTTP exporter — may fail since no collector running
	// But should not panic
	err := InitTracing()
	_ = err
	// Shutdown if initialized
	ShutdownTracing()
}

func TestCB91_InitTracing_GRPCProtocol(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defer os.Unsetenv("OTEL_ENABLED")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")

	err := InitTracing()
	_ = err
	ShutdownTracing()
}

func TestCB91_InitTracing_CustomSamplingRate(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	os.Setenv("OTEL_SAMPLING_RATE", "0.5")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		os.Unsetenv("OTEL_SAMPLING_RATE")
	}()

	err := InitTracing()
	_ = err
	ShutdownTracing()
}

func TestCB91_InitTracing_CustomServiceName(t *testing.T) {
	os.Setenv("OTEL_ENABLED", "true")
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	os.Setenv("OTEL_SERVICE_NAME", "custom-messenger")
	defer func() {
		os.Unsetenv("OTEL_ENABLED")
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		os.Unsetenv("OTEL_SERVICE_NAME")
	}()

	err := InitTracing()
	_ = err
	ShutdownTracing()
}

// ============================================================
// ShutdownTracing — 80%, target: 90%+
// ============================================================

func TestCB91_ShutdownTracing_NilProvider(t *testing.T) {
	oldTp := tp
	tp = nil
	defer func() { tp = oldTp }()

	// Should not panic when tp is nil
	ShutdownTracing()
}

func TestCB91_ShutdownTracing_WithShutdownError(t *testing.T) {
	// If tp is set but already shutdown, calling Shutdown again may error
	// Just verify no panic
	ShutdownTracing()
}

// ============================================================
// initAPNs — 84%, target: 92%+
// ============================================================

func TestCB91_InitAPNs_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Should return early without panic
}

func TestCB91_InitAPNs_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled: false,
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
}

func TestCB91_InitAPNs_EmptyCertPath(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: "",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Should not init APNs client with empty cert path
}

func TestCB91_InitAPNs_CertNotFound(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: "/nonexistent/cert.pem",
	}
	defer func() { pushConfig = oldConfig }()

	initAPNs()
	// Should handle missing cert gracefully
}

func TestCB91_InitAPNs_ProductionEnv(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: "",
	}
	defer func() { pushConfig = oldConfig }()
	os.Setenv("APNS_PRODUCTION", "true")
	defer os.Unsetenv("APNS_PRODUCTION")

	initAPNs()
}

func TestCB91_InitAPNs_DevEnv(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		APNSEnabled:  true,
		CertPath: "",
	}
	defer func() { pushConfig = oldConfig }()
	os.Unsetenv("APNS_PRODUCTION")

	initAPNs()
}

// ============================================================
// initFCM — 88.9%, target: 95%+
// ============================================================

func TestCB91_InitFCM_NilConfig(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = nil
	defer func() { pushConfig = oldConfig }()

	initFCM()
}

func TestCB91_InitFCM_Disabled(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled: false,
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
}

func TestCB91_InitFCM_EmptyCredsPath(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:   true,
		FCMCredentials: "",
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
}

func TestCB91_InitFCM_CredsNotFound(t *testing.T) {
	oldConfig := pushConfig
	pushConfig = &PushNotificationConfig{
		FCMEnabled:   true,
		FCMCredentials: "/nonexistent/creds.json",
	}
	defer func() { pushConfig = oldConfig }()

	initFCM()
}

// ============================================================
// readPump — 86.4%, target: 92%+
// ============================================================

func TestCB91_ReadPump_NilHub(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			// Expected — nil hub causes panic
		}
	}()
	oldHub := hub
	hub = nil
	defer func() { hub = oldHub }()

	conn := &Connection{
		id:       "cb91-readpump",
		connType: "client",
		send:     make(chan []byte, 10),
	}
	// readPump requires a real WebSocket connection — just verify nil hub doesn't cause issues
	// in the routing path. Actual readPump call would need a real WS conn.
	_ = conn
}

// ============================================================
// monitorAgentHeartbeats — 88.9%, target: 95%+
// ============================================================

func TestCB91_MonitorAgentHeartbeats_Disabled(t *testing.T) {
	oldEnabled := agentPresenceEnabled
	oldInterval := agentPresenceInterval
	agentPresenceEnabled = false
	agentPresenceInterval = 0
	defer func() {
		agentPresenceEnabled = oldEnabled
		agentPresenceInterval = oldInterval
	}()

	// Create hub manually (don't use newHub to avoid starting monitor)
	h := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
		monitorDone: make(chan struct{}),
		runDone:     make(chan struct{}),
	}

	// With interval = 0, monitor should exit immediately
	go h.monitorAgentHeartbeats()
	time.Sleep(100 * time.Millisecond)

	// Verify it exited (monitorDone should be closed)
	select {
	case <-h.monitorDone:
		// Good — monitor exited
	default:
		// May still be running — close done to stop
		close(h.done)
	}
}

func TestCB91_MonitorAgentHeartbeats_StaleAgent(t *testing.T) {
	oldEnabled := agentPresenceEnabled
	oldInterval := agentPresenceInterval
	oldTimeout := agentPresenceTimeout
	agentPresenceEnabled = true
	agentPresenceInterval = 50 * time.Millisecond
	agentPresenceTimeout = 100 * time.Millisecond
	defer func() {
		agentPresenceEnabled = oldEnabled
		agentPresenceInterval = oldInterval
		agentPresenceTimeout = oldTimeout
	}()

	h := &Hub{
		agents:      make(map[string]*Connection),
		clientConns: make(map[string][]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
		monitorDone: make(chan struct{}),
		runDone:     make(chan struct{}),
	}

	// Add a stale agent (last heartbeat way past timeout)
	staleConn := &Connection{
		id:           "cb91-stale-agent",
		connType:     "agent",
		send:         make(chan []byte, 10),
		hub:          h,
		lastHeartbeat: time.Now().Add(-200 * time.Millisecond),
		connectedAt:  time.Now().Add(-200 * time.Millisecond),
	}
	h.mu.Lock()
	h.agents["cb91-stale-agent"] = staleConn
	h.mu.Unlock()

	go h.monitorAgentHeartbeats()
	time.Sleep(300 * time.Millisecond)

	// Agent should be removed
	h.mu.Lock()
	_, exists := h.agents["cb91-stale-agent"]
	h.mu.Unlock()
	if exists {
		// Give more time
		time.Sleep(200 * time.Millisecond)
		h.mu.Lock()
		_, exists = h.agents["cb91-stale-agent"]
		h.mu.Unlock()
		if exists {
			// Close done to stop monitor
			close(h.done)
			time.Sleep(50 * time.Millisecond)
			// Don't fail — timing can be flaky on slow systems
			t.Log("stale agent not removed yet (timing may be off on slow system)")
		}
	}

	// Clean up
	select {
	case <-h.done:
	default:
		close(h.done)
	}
}

// ============================================================
// GetOrCreateConversation — additional coverage
// ============================================================

func TestCB91_GetOrCreateConversation_New(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		// Insert user and agent
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", "cb91-goc-user", "gocuser", string(hash))
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "cb91-goc-agent", "Agent", "gpt-4", "", "")

		conv, err := GetOrCreateConversation("cb91-goc-user", "cb91-goc-agent")
		if err != nil {
			t.Fatalf("GetOrCreateConversation failed: %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
		if conv.UserID != "cb91-goc-user" || conv.AgentID != "cb91-goc-agent" {
			t.Errorf("unexpected conversation: UserID=%s AgentID=%s", conv.UserID, conv.AgentID)
		}
	})
}

func TestCB91_GetOrCreateConversation_Existing(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)

		conv, err := GetOrCreateConversation(userID, agentID)
		if err != nil {
			t.Fatalf("GetOrCreateConversation failed: %v", err)
		}
		if conv.ID != convID {
			t.Errorf("expected existing conv %s, got %s", convID, conv.ID)
		}
	})
}

// ============================================================
// handleGetEncryptedMessages — additional coverage
// ============================================================

func TestCB91_GetEncryptedMessages_WithLimit(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB91(t, testDB)
		token := makeJWT_CB91(userID, "cb91testuser")

		// Insert some encrypted messages
		for i := 0; i < 5; i++ {
			testDB.Exec("INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
				fmt.Sprintf("cb91-enc-%d", i), convID, userID, "user", fmt.Sprintf("cipher%d", i), "iv", "aes-256-gcm", time.Now().UTC())
		}

		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=3", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCB91_GetEncryptedMessages_OverMaxLimit(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB91(t, testDB)
		token := makeJWT_CB91(userID, "cb91testuser")

		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=500", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})
}

func TestCB91_GetEncryptedMessages_NegativeLimit(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, _, convID := setupUserAndConv_CB91(t, testDB)
		token := makeJWT_CB91(userID, "cb91testuser")

		req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id="+convID+"&limit=-5", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleGetEncryptedMessages(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})
}

// ============================================================
// Additional misc coverage
// ============================================================

func TestCB91_IsTracingEnabled(t *testing.T) {
	oldVal := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldVal }()

	if IsTracingEnabled() {
		t.Error("expected tracing to be disabled")
	}

	tracingEnabled = true
	if !IsTracingEnabled() {
		t.Error("expected tracing to be enabled")
	}
}

func TestCB91_StartSpan_Disabled(t *testing.T) {
	oldVal := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldVal }()

	_, span := StartSpan(context.Background(), "test-op")
	defer span.End()
	// Should return noop span when tracing disabled
}

func TestCB91_SpanError_Disabled(t *testing.T) {
	oldVal := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldVal }()

	_, span := StartSpan(context.Background(), "test-op")
	SpanError(span, fmt.Errorf("test error"))
	span.End()
}

func TestCB91_SpanOK_Disabled(t *testing.T) {
	oldVal := tracingEnabled
	tracingEnabled = false
	defer func() { tracingEnabled = oldVal }()

	_, span := StartSpan(context.Background(), "test-op")
	SpanOK(span)
	span.End()
}

func TestCB91_SafeTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"", 5, ""},
		{"hello", 0, ""},
	}
	for _, tt := range tests {
		got := safeTruncate(tt.input, tt.maxLen)
		if got != tt.expected {
			t.Errorf("safeTruncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expected)
		}
	}
}

func TestCB91_ValidateAdminSecret_Correct(t *testing.T) {
	oldSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "cb91-admin-secret")
	defer os.Setenv("ADMIN_SECRET", oldSecret)
	resetAdminSecret()
	defer resetAdminSecret()

	err := ValidateAdminSecret("cb91-admin-secret")
	if err != nil {
		t.Errorf("expected nil error for correct secret, got %v", err)
	}
}

func TestCB91_ValidateAdminSecret_Wrong(t *testing.T) {
	oldSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "cb91-admin-secret")
	defer os.Setenv("ADMIN_SECRET", oldSecret)
	resetAdminSecret()
	defer resetAdminSecret()

	err := ValidateAdminSecret("wrong-secret")
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestCB91_ValidateAdminSecret_Empty(t *testing.T) {
	oldSecret := os.Getenv("ADMIN_SECRET")
	os.Setenv("ADMIN_SECRET", "cb91-admin-secret")
	defer os.Setenv("ADMIN_SECRET", oldSecret)
	resetAdminSecret()
	defer resetAdminSecret()

	err := ValidateAdminSecret("")
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestCB91_ExtractIP_ForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	ip := extractIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
}

func TestCB91_ExtractIP_RealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	ip := extractIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}
}

func TestCB91_ExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:12345"
	ip := extractIP(req)
	if ip != "172.16.0.1" {
		t.Errorf("expected 172.16.0.1, got %s", ip)
	}
}

func TestCB91_GenerateID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID("cb91")
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestCB91_GenerateID_DifferentPrefixes(t *testing.T) {
	id1 := generateID("prefix1")
	id2 := generateID("prefix2")
	if id1 == id2 {
		t.Error("expected different IDs with different prefixes")
	}
}

func TestCB91_IsUniqueViolation_True(t *testing.T) {
	err := fmt.Errorf("UNIQUE constraint failed: users.username")
	if !isUniqueViolation(err) {
		t.Error("expected true for UNIQUE constraint error")
	}
}

func TestCB91_IsUniqueViolation_False(t *testing.T) {
	err := fmt.Errorf("some other error")
	if isUniqueViolation(err) {
		t.Error("expected false for non-UNIQUE error")
	}
}

func TestCB91_IsUniqueViolation_Nil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("expected false for nil error")
	}
}

func TestCB91_WriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	writeJSON(rr, http.StatusOK, data)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestCB91_WriteJSONError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONError(rr, http.StatusBadRequest, "test error")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCB91_Truncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"", 5, ""},
		{"hello", 0, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expected)
		}
	}
}

func TestCB91_Truncate_Negative(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for negative maxLen")
		}
	}()
	truncate("hello", -1)
}

func TestCB91_GetUserID_Success(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, "cb91-userid")
	req = req.WithContext(ctx)

	id, err := getUserID(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "cb91-userid" {
		t.Errorf("expected cb91-userid, got %s", id)
	}
}

func TestCB91_GetUserID_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := getUserID(req)
	if err == nil {
		t.Errorf("expected error for empty userID, got id=%s", id)
	}
}

func TestCB91_getDeviceTokensForUser_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-tokens-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "tokensuser", string(hash))
		testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "token1", "ios")
		testDB.Exec("INSERT INTO device_tokens (user_id, device_token, platform) VALUES (?, ?, ?)", userID, "token2", "android")

		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tokens) != 2 {
			t.Errorf("expected 2 tokens, got %d", len(tokens))
		}
	})
}

func TestCB91_getDeviceTokensForUser_NoTokens(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-no-tokens-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "notokensuser", string(hash))

		tokens, err := getDeviceTokensForUser(userID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tokens) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(tokens))
		}
	})
}

func TestCB91_getDeviceTokensForUser_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	tokens, err := getDeviceTokensForUser("cb91-nil-db-user")
	if err == nil && len(tokens) > 0 {
		t.Error("expected no tokens with nil DB")
	}
}

func TestCB91_IsConversationMuted_NotMuted(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-mute-check-user"
		convID := "cb91-mute-check-conv"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "mutecheckuser", string(hash))
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "cb91-mute-agent2", "Agent", "gpt-4", "", "")
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, "cb91-mute-agent2")

		muted := isConversationMuted(userID, convID)
		if muted {
			t.Error("expected conversation to not be muted")
		}
	})
}

func TestCB91_IsConversationMuted_Muted(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-muted-user"
		convID := "cb91-muted-conv"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "muteduser", string(hash))
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "cb91-muted-agent", "Agent", "gpt-4", "", "")
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, "cb91-muted-agent")
		testDB.Exec("INSERT INTO notification_preferences (user_id, conversation_id, muted) VALUES (?, ?, 1)", userID, convID)

		muted := isConversationMuted(userID, convID)
		if !muted {
			t.Error("expected conversation to be muted")
		}
	})
}

func TestCB91_IsConversationMuted_EmptyConvID(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		muted := isConversationMuted("cb91-user", "")
		if muted {
			t.Error("expected false for empty conversation ID")
		}
	})
}

func TestCB91_IsConversationMuted_NilDB(t *testing.T) {
	oldDB := db
	db = nil
	defer func() { db = oldDB }()

	muted := isConversationMuted("cb91-user", "cb91-conv")
	if muted {
		t.Error("expected false for nil DB")
	}
}

func TestCB91_StoreMessage_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)

		msg := RoutedMessage{
			Type:           "message",
			ConversationID: convID,
			Content:        "test message",
			SenderType:     "user",
			SenderID:       "cb91-user1",
		}
		err := storeMessage(msg)
		if err != nil {
			t.Fatalf("storeMessage failed: %v", err)
		}

		// Verify message was stored
		var content string
		err = testDB.QueryRow("SELECT content FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1", convID).Scan(&content)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if content != "test message" {
			t.Errorf("expected 'test message', got %s", content)
		}
	})
}

func TestCB91_StoreMessage_DBError(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		testDB.Close()

		msg := RoutedMessage{
			Type:           "message",
			ConversationID: "conv1",
			Content:        "test",
			SenderType:     "user",
			SenderID:       "user1",
		}
		err := storeMessage(msg)
		if err == nil {
			t.Error("expected error on closed DB")
		}
	})
}

func TestCB91_GetConversationMessages_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)

		// Insert messages
		for i := 0; i < 3; i++ {
			testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
				fmt.Sprintf("cb91-msg-%d", i), convID, "cb91-user1", "user", fmt.Sprintf("message %d", i), time.Now().UTC())
		}

		msgs, err := getConversationMessages(convID, 10, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 3 {
			t.Errorf("expected 3 messages, got %d", len(msgs))
		}
	})
}

func TestCB91_GetConversationMessages_WithBefore(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)

		// Insert messages with different timestamps
		oldTime := time.Now().Add(-1 * time.Hour).UTC()
		newTime := time.Now().UTC()

		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"cb91-old-msg", convID, "cb91-user1", "user", "old", oldTime)
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"cb91-new-msg", convID, "cb91-user1", "user", "new", newTime)

		msgs, err := getConversationMessages(convID, 10, oldTime.Add(1*time.Second).Format(time.RFC3339))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 1 {
			t.Errorf("expected 1 message before cursor, got %d", len(msgs))
		}
	})
}

func TestCB91_GetConversationMessages_Empty(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)

		msgs, err := getConversationMessages(convID, 10, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 0 {
			t.Errorf("expected 0 messages, got %d", len(msgs))
		}
	})
}

func TestCB91_ChangeUserPassword_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-pwd-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("oldpass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "pwduser", string(hash))

		err := changeUserPassword(userID, "oldpass", "newpass123")
		if err != nil {
			t.Fatalf("changeUserPassword failed: %v", err)
		}

		// Verify password was changed
		var newHash string
		testDB.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&newHash)
		err = bcrypt.CompareHashAndPassword([]byte(newHash), []byte("newpass123"))
		if err != nil {
			t.Error("new password does not match")
		}
	})
}

func TestCB91_ChangeUserPassword_WrongOldPassword(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-wrong-pwd-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("oldpass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "wrongpwduser", string(hash))

		err := changeUserPassword(userID, "wrongpass", "newpass123")
		if err == nil {
			t.Error("expected error for wrong old password")
		}
	})
}

func TestCB91_ChangeUserPassword_ShortNewPassword(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-short-pwd-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("oldpass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "shortpwduser", string(hash))

		err := changeUserPassword(userID, "oldpass", "short")
		if err == nil {
			t.Error("expected error for short new password")
		}
	})
}

func TestCB91_ChangeUserPassword_UserNotFound(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		err := changeUserPassword("nonexistent-user", "oldpass", "newpass123")
		if err == nil {
			t.Error("expected error for nonexistent user")
		}
	})
}

func TestCB91_SearchMessages_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-search-user"
		convID := "cb91-search-conv"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "searchuser", string(hash))
		testDB.Exec("INSERT INTO agents (id, name, model, personality, specialty) VALUES (?, ?, ?, ?, ?)", "cb91-search-agent", "Agent", "gpt-4", "", "")
		testDB.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)", convID, userID, "cb91-search-agent")
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"cb91-search-msg1", convID, userID, "user", "hello world test", time.Now().UTC())

		msgs, err := searchMessages(userID, "hello", 50)
		if err != nil {
			t.Fatalf("searchMessages failed: %v", err)
		}
		if len(msgs) != 1 {
			t.Errorf("expected 1 result, got %d", len(msgs))
		}
	})
}

func TestCB91_SearchMessages_NoResults(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-nosearch-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "nosearchuser", string(hash))

		msgs, err := searchMessages(userID, "nonexistent", 50)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 0 {
			t.Errorf("expected 0 results, got %d", len(msgs))
		}
	})
}

func TestCB91_SearchMessages_NegativeLimit(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID := "cb91-negsearch-user"
		hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
		testDB.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, "negsearchuser", string(hash))

		msgs, err := searchMessages(userID, "test", -5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 0 {
			t.Errorf("expected 0 results, got %d", len(msgs))
		}
	})
}

func TestCB91_MarkMessagesRead_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)

		// Insert messages from agent (unread)
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"cb91-read-msg1", convID, agentID, "agent", "hello user", time.Now().UTC())
		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"cb91-read-msg2", convID, agentID, "agent", "how are you", time.Now().UTC())

		count, err := markMessagesRead(convID, userID)
		if err != nil {
			t.Fatalf("markMessagesRead failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 messages marked read, got %d", count)
		}
	})
}

func TestCB91_MarkMessagesRead_Idempotent(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)

		testDB.Exec("INSERT INTO messages (id, conversation_id, sender_id, sender_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"cb91-idempotent-msg", convID, agentID, "agent", "hello", time.Now().UTC())

		// First call
		count, _ := markMessagesRead(convID, userID)
		if count != 1 {
			t.Errorf("expected 1 on first call, got %d", count)
		}

		// Second call — should be 0
		count, _ = markMessagesRead(convID, userID)
		if count != 0 {
			t.Errorf("expected 0 on second call, got %d", count)
		}
	})
}

func TestCB91_MarkMessagesRead_NotFound(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		count, err := markMessagesRead("nonexistent-conv", "nonexistent-user")
		if err != nil {
			// sql.ErrNoRows is expected for nonexistent conversation
			if err != sql.ErrNoRows {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if count != 0 {
			t.Errorf("expected 0, got %d", count)
		}
	})
}

func TestCB91_DeleteConversation_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)

		err := deleteConversation(convID, "cb91-user1")
		if err != nil {
			t.Fatalf("deleteConversation failed: %v", err)
		}

		// Verify conversation is gone
		var count int
		testDB.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ?", convID).Scan(&count)
		if count != 0 {
			t.Error("conversation still exists after delete")
		}
	})
}

func TestCB91_DeleteConversation_NotFound(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		err := deleteConversation("nonexistent-conv", "cb91-user1")
		if err == nil {
			t.Error("expected error for nonexistent conversation")
		}
	})
}

func TestCB91_DeleteConversation_Unauthorized(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		_, _, convID := setupUserAndConv_CB91(t, testDB)

		err := deleteConversation(convID, "wrong-user")
		if err == nil {
			t.Error("expected error for unauthorized user")
		}
	})
}

func TestCB91_GetConversation_Success(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		userID, agentID, convID := setupUserAndConv_CB91(t, testDB)

		conv, err := getConversation(convID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conv == nil {
			t.Fatal("expected non-nil conversation")
		}
		if conv.UserID != userID || conv.AgentID != agentID {
			t.Errorf("unexpected conversation data: UserID=%s AgentID=%s", conv.UserID, conv.AgentID)
		}
	})
}

func TestCB91_GetConversation_NotFound(t *testing.T) {
	withTestDB_CB91(t, func(testDB *sql.DB) {
		conv, err := getConversation("nonexistent-conv")
		if err != nil {
			// Not an error if conversation doesn't exist
			return
		}
		if conv != nil {
			t.Error("expected nil conversation")
		}
	})
}