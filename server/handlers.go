package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
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

	// Validate API key against stored bcrypt hash
	if err := ValidateAPIKey(agentID, apiKey); err != nil {
		http.Error(w, "authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for agent %s: %v", agentID, err)
		return
	}

	// Create connection
	c := &Connection{
		hub:         hub,
		connType:    "agent",
		id:          agentID,
		conn:        conn,
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
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

	// Validate JWT token
	claims, err := ValidateJWT(token)
	if err != nil {
		http.Error(w, "authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Use the user ID from the JWT claims (don't trust query param)
	userID = claims.UserID

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for client %s: %v", userID, err)
		return
	}

	// Create connection
	c := &Connection{
		hub:         hub,
		connType:    "client",
		id:          userID,
		conn:        conn,
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
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
	messagesRouted := hub.messagesRouted
	hub.mu.RUnlock()

	response := map[string]interface{}{
		"status":          "ok",
		"agents":          agentCount,
		"clients":         clientCount,
		"connections":     agentCount + clientCount,
		"messages_routed": messagesRouted,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleLogin handles POST /auth/login - user login returning a JWT
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	if email == "" || password == "" {
		http.Error(w, "missing email or password", http.StatusBadRequest)
		return
	}

	// Look up user by email
	var userID, passwordHash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE email = ?", email).Scan(&userID, &passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT
	token, err := GenerateJWT(userID, email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":   token,
		"user_id": userID,
	})
}

// handleRegisterAgent handles POST /auth/agent - register a new agent with API key
func handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := r.FormValue("agent_id")
	name := r.FormValue("name")
	apiKey := r.FormValue("api_key")
	if agentID == "" || name == "" || apiKey == "" {
		http.Error(w, "missing agent_id, name, or api_key", http.StatusBadRequest)
		return
	}

	// Hash the API key for storage
	hash, err := HashAPIKey(apiKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT OR IGNORE INTO agents (id, api_key_hash, name) VALUES (?, ?, ?)", agentID, hash, name)
	if err != nil {
		http.Error(w, "failed to register agent: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"agent_id": agentID,
		"status":   "registered",
	})
}

// handleRegisterUser handles POST /auth/user - register a new user account
func handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	if email == "" || password == "" {
		http.Error(w, "missing email or password", http.StatusBadRequest)
		return
	}

	// Hash the password
	hash, err := HashAPIKey(password) // bcrypt works for passwords too
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Generate a user ID from email
	userID := generateID("user")

	_, err = db.Exec("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)", userID, email, hash)
	if err != nil {
		http.Error(w, "failed to register user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"user_id": userID,
		"email":   email,
		"status":  "registered",
	})
}

// generateID creates a simple unique ID with a prefix
func generateID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

// DB is the global database reference (set in main)
var db *sql.DB
var hub *Hub

// handleCreateConversation handles POST /conversations/create
func handleCreateConversation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	agentID := r.FormValue("agent_id")
	if agentID == "" {
		http.Error(w, "missing agent_id", http.StatusBadRequest)
		return
	}

	conv, err := GetOrCreateConversation(claims.UserID, agentID)
	if err != nil {
		http.Error(w, "failed to create conversation", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"conversation_id": conv.ID,
		"user_id":         conv.UserID,
		"agent_id":        conv.AgentID,
	})
}

// handleListConversations handles GET /conversations/list
func handleListConversations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query(
		"SELECT id, user_id, agent_id, created_at FROM conversations WHERE user_id = ? ORDER BY created_at DESC",
		claims.UserID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ConvInfo struct {
		ID        string `json:"id"`
		UserID    string `json:"user_id"`
		AgentID   string `json:"agent_id"`
		CreatedAt string `json:"created_at"`
	}

	var conversations []ConvInfo
	for rows.Next() {
		var c ConvInfo
		if err := rows.Scan(&c.ID, &c.UserID, &c.AgentID, &c.CreatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		conversations = append(conversations, c)
	}

	w.Header().Set("Content-Type", "application/json")
	if conversations == nil {
		conversations = []ConvInfo{}
	}
	json.NewEncoder(w).Encode(conversations)
}

// handleGetMessages handles GET /conversations/messages
func handleGetMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	convID := r.URL.Query().Get("conversation_id")
	if convID == "" {
		http.Error(w, "missing conversation_id", http.StatusBadRequest)
		return
	}

	// Verify user is participant
	conv, err := getConversation(convID)
	if err != nil || conv == nil {
		http.Error(w, "conversation not found", http.StatusNotFound)
		return
	}
	if conv.UserID != claims.UserID {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	messages, err := getConversationMessages(convID, 50)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if messages == nil {
		messages = []StoredMessage{}
	}
	json.NewEncoder(w).Encode(messages)
}