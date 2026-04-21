package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --- Multi-Agent Support Tests ---

// setupTestServerForMultiAgent creates a full test server with all routes including agent listing
func setupTestServerForMultiAgent(t *testing.T) *httptest.Server {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	hub = newHub()
	go hub.run()
	t.Cleanup(func() { hub.Stop() })

	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)
	mux.HandleFunc("/auth/user", handleRegisterUser)
	mux.HandleFunc("/agents", handleListAgents)
	mux.HandleFunc("/admin/agents", handleAdminAgents)
	mux.HandleFunc("/conversations/create", handleCreateConversation)
	mux.HandleFunc("/conversations/list", handleListConversations)
	mux.HandleFunc("/conversations/messages", handleGetMessages)

	server := httptest.NewServer(mux)
	t.Cleanup(func() { server.Close() })

	return server
}

// TestRegisterAgentWithMetadata verifies agents can be registered with model/personality/specialty
func TestRegisterAgentWithMetadata(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	resp, err := http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id":    {"gpt-agent"},
		"name":        {"GPT Assistant"},
		"agent_secret":     {agentSecret},
		"model":       {"gpt-4"},
		"personality": {"helpful"},
		"specialty":   {"general"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if result["status"] != "registered" {
		t.Fatalf("expected status=registered, got %s", result["status"])
	}
	if result["model"] != "gpt-4" {
		t.Fatalf("expected model=gpt-4, got %s", result["model"])
	}
	if result["personality"] != "helpful" {
		t.Fatalf("expected personality=helpful, got %s", result["personality"])
	}
	if result["specialty"] != "general" {
		t.Fatalf("expected specialty=general, got %s", result["specialty"])
	}
}

// TestRegisterAgentWithoutMetadata verifies agents can still be registered without optional fields
func TestRegisterAgentWithoutMetadata(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	resp, err := http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id": {"basic-agent"},
		"name":     {"Basic Agent"},
		"agent_secret":  {agentSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "registered" {
		t.Fatalf("expected status=registered, got %s", result["status"])
	}
}

// TestListAgentsEmpty verifies listing agents when none are registered
func TestListAgentsEmpty(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	resp, err := http.Get(server.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var agents []AgentInfo
	json.NewDecoder(resp.Body).Decode(&agents)
	if agents == nil || len(agents) != 0 {
		t.Fatalf("expected empty array, got %v", agents)
	}
}

// TestListAgentsWithMultiple verifies listing multiple registered agents with their status
func TestListAgentsWithMultiple(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	// Register multiple agents
	agents := []struct {
		id, name, model, personality, specialty string
	}{
		{"agent-alpha", "Alpha Agent", "gpt-4", "professional", "coding"},
		{"agent-beta", "Beta Agent", "claude-3", "friendly", "writing"},
		{"agent-gamma", "Gamma Agent", "llama-3", "casual", "general"},
	}

	for _, a := range agents {
		http.PostForm(server.URL+"/auth/agent", url.Values{
			"agent_id":    {a.id},
			"name":        {a.name},
			"agent_secret": {agentSecret},
			"model":       {a.model},
			"personality": {a.personality},
			"specialty":   {a.specialty},
		})
	}

	// List agents
	resp, err := http.Get(server.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var listed []AgentInfo
	json.NewDecoder(resp.Body).Decode(&listed)
	if len(listed) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(listed))
	}

	// All should be offline since none connected via WebSocket
	for _, a := range listed {
		if a.Status != "offline" {
			t.Fatalf("expected agent %s to be offline, got %s", a.ID, a.Status)
		}
	}

	// Verify they come back sorted by name
	if listed[0].Name != "Alpha Agent" {
		t.Fatalf("expected first agent Alpha Agent, got %s", listed[0].Name)
	}

	// Verify metadata
	alpha := listed[0]
	if alpha.Model != "gpt-4" {
		t.Fatalf("expected model gpt-4, got %s", alpha.Model)
	}
	if alpha.Personality != "professional" {
		t.Fatalf("expected personality professional, got %s", alpha.Personality)
	}
	if alpha.Specialty != "coding" {
		t.Fatalf("expected specialty coding, got %s", alpha.Specialty)
	}
}

// TestListAgentsOnlineStatus verifies that connected agents show as "online"
func TestListAgentsOnlineStatus(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	// Register two agents
	http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id": {"online-agent"},
		"name":     {"Online Agent"},
		"agent_secret":  {agentSecret},
	})
	http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id": {"offline-agent"},
		"name":     {"Offline Agent"},
		"agent_secret":  {agentSecret},
	})

	// Connect only the first agent via WebSocket
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=online-agent&agent_secret=" + url.QueryEscape(agentSecret)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WebSocket connect failed: %v", err)
	}
	defer conn.Close()

	// Read welcome message
	_, _, _ = conn.ReadMessage()

	// Give the hub a moment
	time.Sleep(50 * time.Millisecond)

	// List agents
	resp, err := http.Get(server.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var listed []AgentInfo
	json.NewDecoder(resp.Body).Decode(&listed)

	agentMap := make(map[string]AgentInfo)
	for _, a := range listed {
		agentMap[a.ID] = a
	}

	if agentMap["online-agent"].Status != "online" {
		t.Fatalf("expected online-agent to be 'online', got %s", agentMap["online-agent"].Status)
	}
	if agentMap["offline-agent"].Status != "offline" {
		t.Fatalf("expected offline-agent to be 'offline', got %s", agentMap["offline-agent"].Status)
	}
}

// TestAgentStatusTracking verifies that agent status changes (online/busy/idle) are tracked
func TestAgentStatusTracking(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	// Register agent directly in DB
	db.Exec("INSERT INTO agents (id, name) VALUES (?, ?)", "status-agent", "Status Agent")

	// Initially offline
	if hub.AgentStatus("status-agent") != "offline" {
		t.Fatal("expected agent to be offline before connecting")
	}

	// Simulate connecting
	conn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "status-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	hub.register <- conn
	time.Sleep(10 * time.Millisecond)

	// Should be online by default
	if hub.AgentStatus("status-agent") != "online" {
		t.Fatalf("expected agent to be online after connecting, got %s", hub.AgentStatus("status-agent"))
	}

	// Set to busy
	hub.SetAgentStatus("status-agent", "busy")
	if hub.AgentStatus("status-agent") != "busy" {
		t.Fatalf("expected agent to be busy, got %s", hub.AgentStatus("status-agent"))
	}

	// Set to idle
	hub.SetAgentStatus("status-agent", "idle")
	if hub.AgentStatus("status-agent") != "idle" {
		t.Fatalf("expected agent to be idle, got %s", hub.AgentStatus("status-agent"))
	}

	// Disconnect
	hub.unregister <- conn
	time.Sleep(10 * time.Millisecond)

	if hub.AgentStatus("status-agent") != "offline" {
		t.Fatalf("expected agent to be offline after disconnect, got %s", hub.AgentStatus("status-agent"))
	}
}

// TestAgentStatusViaWebSocketUpdate verifies that a status update message
// over WebSocket changes the agent's tracked status in the hub.
func TestAgentStatusViaWebSocketUpdate(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	// Create a conversation so status routing has a valid target
	conv, err := CreateConversation("status-user", "status-ws-agent")
	if err != nil {
		t.Fatal(err)
	}

	agentConn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "status-ws-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	clientConn := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "status-user",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	hub.register <- agentConn
	time.Sleep(10 * time.Millisecond)
	hub.register <- clientConn
	time.Sleep(10 * time.Millisecond)

	// Agent sends a status update
	statusMsg := IncomingMessage{
		Type: "status",
		Data: json.RawMessage(`{"conversation_id": "` + conv.ID + `", "status": "busy"}`),
	}
	raw, _ := json.Marshal(statusMsg)
	routeMessage(agentConn, raw)

	time.Sleep(10 * time.Millisecond)

	// Hub should now track agent as busy
	if hub.AgentStatus("status-ws-agent") != "busy" {
		t.Fatalf("expected agent status 'busy' after status update, got %s", hub.AgentStatus("status-ws-agent"))
	}

	// Client should receive the status update
	select {
	case resp := <-clientConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "status" {
			t.Fatalf("expected status message, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for status update on client")
	}
}

// TestAdminAgentsEndpoint verifies the admin endpoint shows connected_at for online agents
func TestAdminAgentsEndpoint(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	// Register agents
	http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id":    {"admin-agent"},
		"name":        {"Admin Agent"},
		"agent_secret":     {agentSecret},
		"model":       {"gpt-4"},
		"personality": {"professional"},
		"specialty":   {"admin"},
	})
	http.PostForm(server.URL+"/auth/agent", url.Values{
		"agent_id": {"admin-offline"},
		"name":     {"Admin Offline"},
		"agent_secret":  {agentSecret},
	})

	// Connect one agent
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/connect?agent_id=admin-agent&agent_secret=" + url.QueryEscape(agentSecret)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WebSocket connect failed: %v", err)
	}
	defer conn.Close()
	_, _, _ = conn.ReadMessage() // welcome
	time.Sleep(50 * time.Millisecond)

	// Hit admin endpoint
	resp, err := http.Get(server.URL + "/admin/agents")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var listed []AgentInfo
	json.NewDecoder(resp.Body).Decode(&listed)

	agentMap := make(map[string]AgentInfo)
	for _, a := range listed {
		agentMap[a.ID] = a
	}

	// Online agent should have connected_at
	onlineAgent := agentMap["admin-agent"]
	if onlineAgent.Status != "online" {
		t.Fatalf("expected admin-agent to be online, got %s", onlineAgent.Status)
	}
	if onlineAgent.ConnectedAt == "" {
		t.Fatal("expected connected_at for online agent")
	}
	if onlineAgent.Model != "gpt-4" {
		t.Fatalf("expected model gpt-4, got %s", onlineAgent.Model)
	}

	// Offline agent should NOT have connected_at
	offlineAgent := agentMap["admin-offline"]
	if offlineAgent.Status != "offline" {
		t.Fatalf("expected admin-offline to be offline, got %s", offlineAgent.Status)
	}
	if offlineAgent.ConnectedAt != "" {
		t.Fatalf("expected no connected_at for offline agent, got %s", offlineAgent.ConnectedAt)
	}
}

// TestListAgentsRejectsPost verifies the agent listing endpoint rejects non-GET
func TestListAgentsRejectsPost(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	resp, err := http.Post(server.URL+"/agents", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// TestAdminAgentsRejectsPost verifies the admin endpoint rejects non-GET
func TestAdminAgentsRejectsPost(t *testing.T) {
	server := setupTestServerForMultiAgent(t)

	resp, err := http.Post(server.URL+"/admin/agents", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// TestConversationWithSpecificAgent verifies that a user can create conversations
// with different agents and messages route to the correct one.
func TestConversationWithSpecificAgent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()
	ServerMetrics = NewMetrics(hub)

	// Create conversations between user and two different agents
	convAlpha, err := CreateConversation("multi-user", "alpha-agent")
	if err != nil {
		t.Fatal(err)
	}
	convBeta, err := CreateConversation("multi-user", "beta-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Connect both agents
	alphaConn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "alpha-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	betaConn := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          "beta-agent",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}
	userConn := &Connection{
		hub:         hub,
		connType:    "client",
		id:          "multi-user",
		send:        make(chan []byte, 10),
		connectedAt: time.Now(),
	}

	hub.register <- alphaConn
	time.Sleep(10 * time.Millisecond)
	hub.register <- betaConn
	time.Sleep(10 * time.Millisecond)
	hub.register <- userConn
	time.Sleep(10 * time.Millisecond)

	// Send message to alpha agent
	msgToAlpha := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "` + convAlpha.ID + `", "content": "Hello Alpha!"}`),
	}
	raw, _ := json.Marshal(msgToAlpha)
	routeMessage(userConn, raw)

	// Alpha should receive the message
	select {
	case resp := <-alphaConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "message" {
			t.Fatalf("expected message for alpha, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for alpha to receive message")
	}

	// Beta should NOT receive the message
	select {
	case <-betaConn.send:
		t.Fatal("beta should not have received a message for alpha")
	case <-time.After(100 * time.Millisecond):
		// Expected - no message for beta
	}

	// Send message to beta agent
	msgToBeta := IncomingMessage{
		Type: "message",
		Data: json.RawMessage(`{"conversation_id": "` + convBeta.ID + `", "content": "Hello Beta!"}`),
	}
	raw, _ = json.Marshal(msgToBeta)
	routeMessage(userConn, raw)

	// Beta should receive the message
	select {
	case resp := <-betaConn.send:
		var outMsg OutgoingMessage
		json.Unmarshal(resp, &outMsg)
		if outMsg.Type != "message" {
			t.Fatalf("expected message for beta, got %s", outMsg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for beta to receive message")
	}
}

// TestSetAgentStatusNonExistent verifies SetAgentStatus is safe for unknown agents
func TestSetAgentStatusNonExistent(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	// Should not panic
	hub.SetAgentStatus("nonexistent", "busy")

	if hub.AgentStatus("nonexistent") != "offline" {
		t.Fatalf("expected offline for nonexistent agent, got %s", hub.AgentStatus("nonexistent"))
	}
}

// TestMultipleAgentsSameUserConversation verifies that a single user
// can have separate conversations with different agents simultaneously.
func TestMultipleAgentsSameUserConversation(t *testing.T) {
	setupTestDB(t)

	// User creates conversation with agent A
	convA, err := GetOrCreateConversation("user-m", "agent-a")
	if err != nil {
		t.Fatal(err)
	}

	// User creates conversation with agent B
	convB, err := GetOrCreateConversation("user-m", "agent-b")
	if err != nil {
		t.Fatal(err)
	}

	// Conversations should be different
	if convA.ID == convB.ID {
		t.Fatal("conversations with different agents should have different IDs")
	}

	if convA.AgentID != "agent-a" || convB.AgentID != "agent-b" {
		t.Fatalf("conversation agent IDs wrong: A=%s, B=%s", convA.AgentID, convB.AgentID)
	}

	// Both should have the same user
	if convA.UserID != "user-m" || convB.UserID != "user-m" {
		t.Fatal("both conversations should belong to the same user")
	}

	// GetOrCreate should return existing conversations
	convA2, _ := GetOrCreateConversation("user-m", "agent-a")
	if convA2.ID != convA.ID {
		t.Fatal("GetOrCreateConversation should return existing conversation for same agent")
	}

	convB2, _ := GetOrCreateConversation("user-m", "agent-b")
	if convB2.ID != convB.ID {
		t.Fatal("GetOrCreateConversation should return existing conversation for same agent")
	}
}

// TestSchemaMigration verifies that initSchema can add new columns to existing tables
func TestSchemaMigration(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create the old-style schema (with api_key_hash, without model/personality/specialty)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		api_key_hash TEXT NOT NULL,
		name TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)

	// Insert a row with the old schema
	hash, _ := HashAPIKey("migration-key")
	_, _ = db.Exec("INSERT INTO agents (id, api_key_hash, name) VALUES (?, ?, ?)", "migrate-agent", hash, "Migration Agent")

	// Run initSchema (should add columns via migration)
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	// Verify the new columns exist by querying
	var model, personality, specialty string
	err = db.QueryRow("SELECT model, personality, specialty FROM agents WHERE id = ?", "migrate-agent").Scan(&model, &personality, &specialty)
	if err != nil {
		t.Fatalf("migration columns missing: %v", err)
	}
	if model != "" || personality != "" || specialty != "" {
		t.Fatalf("expected empty defaults for migrated columns, got model=%s personality=%s specialty=%s", model, personality, specialty)
	}
}