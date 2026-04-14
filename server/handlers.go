package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

)

// IncomingMessage is the JSON structure for messages received over WebSocket
type IncomingMessage struct {
	Type string          `json:"type"` // "message", "typing", "status"
	Data json.RawMessage `json:"data"`
}

// OutgoingMessage is the JSON structure for messages sent over WebSocket
type OutgoingMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func handleAgentConnect(w http.ResponseWriter, r *http.Request) {
	// Extract agent_id from query params
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "missing agent_id parameter", http.StatusBadRequest)
		return
	}

	apiKey := r.URL.Query().Get("api_key")
	if apiKey == "" {
		http.Error(w, "missing api_key parameter", http.StatusUnauthorized)
		return
	}

	// TODO: Validate API key (Task 2)
	// For now, accept any non-empty key
	_ = apiKey

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for agent %s: %v", agentID, err)
		return
	}

	// Create connection
	c := &Connection{
		hub:      hub,
		connType: "agent",
		id:       agentID,
		conn:     conn,
		send:     make(chan []byte, 256),
	}

	// Register with hub
	hub.register <- c

	// Start pumps
	go c.writePump()
	go c.readPump()

	// Send welcome message
	welcome := OutgoingMessage{
		Type: "connected",
		Data: map[string]string{
			"agent_id": agentID,
			"status":   "connected",
		},
	}
	data, _ := json.Marshal(welcome)
	c.send <- data
}

func handleClientConnect(w http.ResponseWriter, r *http.Request) {
	// Extract user_id from query params
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "missing user_id parameter", http.StatusBadRequest)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token parameter", http.StatusUnauthorized)
		return
	}

	// TODO: Validate JWT (Task 2)
	// For now, accept any non-empty token
	_ = token

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for client %s: %v", userID, err)
		return
	}

	// Create connection
	c := &Connection{
		hub:      hub,
		connType: "client",
		id:       userID,
		conn:     conn,
		send:     make(chan []byte, 256),
	}

	// Register with hub
	hub.register <- c

	// Start pumps
	go c.writePump()
	go c.readPump()

	// Send welcome message
	welcome := OutgoingMessage{
		Type: "connected",
		Data: map[string]string{
			"user_id": userID,
			"status":  "connected",
		},
	}
	data, _ := json.Marshal(welcome)
	c.send <- data
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	hub.mu.RLock()
	agentCount := len(hub.agents)
	clientCount := len(hub.clients)
	hub.mu.RUnlock()

	response := map[string]interface{}{
		"status":        "ok",
		"agents":        agentCount,
		"clients":       clientCount,
		"connections":   agentCount + clientCount,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DB is the global database reference (set in main)
var db *sql.DB
var hub *Hub