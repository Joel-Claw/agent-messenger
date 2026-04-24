package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGetAgentPresence tests the GET /presence endpoint
func TestGetAgentPresence(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "presenceuser", "password123")

	// Create agent in DB
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name, status) VALUES (?, ?, ?)", "pres-agent", "Test Agent", "online")
	if err != nil {
		t.Fatal(err)
	}

	// Connect the agent via WebSocket
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "pres-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) == 0 {
		t.Fatal("expected at least one agent")
	}

	found := false
	for _, a := range agents {
		if a["id"] == "pres-agent" {
			found = true
			if a["online"] != true {
				t.Fatal("expected agent to be online")
			}
		}
	}
	if !found {
		t.Fatal("expected to find pres-agent in presence list")
	}
}

// TestGetAgentPresenceOffline tests that disconnected agents show as offline
func TestGetAgentPresenceOffline(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "offlineuser", "password123")

	// Create agent in DB but don't connect it
	_, err := db.Exec("INSERT OR IGNORE INTO agents (id, name, status) VALUES (?, ?, ?)", "offline-agent", "Offline Agent", "offline")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/presence", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetPresence(w, req)

	var agents []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &agents)
	if len(agents) == 0 {
		t.Fatal("expected at least one agent")
	}

	if agents[0]["online"] == true {
		t.Fatal("expected agent to be offline")
	}
}

// TestGetUserPresence tests the GET /presence/user endpoint
func TestGetUserPresence(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "selfpresuser", "password123")
	userID := getUserIDFromToken(t, token)

	// Connect user via WebSocket
	client := &Connection{
		hub:         hub,
		connType:    "client",
		id:          userID,
		deviceID:    "phone",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- client
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/presence/user?user_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["online"] != true {
		t.Fatal("expected user to be online")
	}
	if int(resp["device_count"].(float64)) != 1 {
		t.Fatalf("expected device_count 1, got %v", resp["device_count"])
	}
	if resp["last_seen"] == nil || resp["last_seen"] == "" {
		t.Fatal("expected last_seen to be set for online user")
	}
}

// TestGetUserPresenceOffline tests a user that's not connected
func TestGetUserPresenceOffline(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "offuser", "password123")
	userID := getUserIDFromToken(t, token)

	// Don't connect user. Insert a message to set last_seen.
	_, err := db.Exec("INSERT INTO conversations (id, user_id, agent_id, created_at) VALUES (?, ?, ?, datetime('now'))",
		"off-pres-conv", userID, "off-pres-agent")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"off-pres-msg", "off-pres-conv", "client", userID, "Last activity", time.Now().UTC().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/presence/user?user_id="+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetUserPresence(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["online"] == true {
		t.Fatal("expected user to be offline")
	}
	if resp["last_seen"] == nil || resp["last_seen"] == "" {
		t.Fatal("expected last_seen from message history")
	}
}

// TestPresenceUpdateEvent tests that presence_update WebSocket events are broadcast
func TestPresenceUpdateEvent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	token := registerUserAndGetToken(t, "presEvtUser", "password123")
	userID := getUserIDFromToken(t, token)

	// Connect a client that will receive the presence event
	client := &Connection{
		hub:         hub,
		connType:    "client",
		id:          userID,
		deviceID:    "listener",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- client
	time.Sleep(10 * time.Millisecond)

	// Connect an agent (this should trigger broadcastPresence)
	agent := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "pres-evt-agent",
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}
	hub.register <- agent
	time.Sleep(20 * time.Millisecond)

	// The client should receive a presence_update event
	select {
	case data := <-client.send:
		var msg OutgoingMessage
		json.Unmarshal(data, &msg)
		if msg.Type != "presence_update" {
			t.Fatalf("expected presence_update, got %s", msg.Type)
		}
		dataMap := msg.Data.(map[string]interface{})
		if dataMap["id"] != "pres-evt-agent" {
			t.Fatalf("expected id pres-evt-agent, got %v", dataMap["id"])
		}
		if dataMap["type"] != "agent" {
			t.Fatalf("expected type agent, got %v", dataMap["type"])
		}
		if dataMap["online"] != true {
			t.Fatal("expected online true")
		}
	default:
		t.Fatal("expected to receive presence_update event on agent connect")
	}

	// Now disconnect the agent
	hub.unregister <- agent
	time.Sleep(20 * time.Millisecond)

	// Client should receive offline presence_update
	select {
	case data := <-client.send:
		var msg OutgoingMessage
		json.Unmarshal(data, &msg)
		if msg.Type != "presence_update" {
			t.Fatalf("expected presence_update on disconnect, got %s", msg.Type)
		}
		dataMap := msg.Data.(map[string]interface{})
		if dataMap["online"] == true {
			t.Fatal("expected online false on disconnect")
		}
	default:
		t.Fatal("expected to receive presence_update event on agent disconnect")
	}

	_ = token
}