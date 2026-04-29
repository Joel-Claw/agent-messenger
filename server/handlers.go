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
		writeJSONError(w, http.StatusBadRequest, "missing agent_id parameter")
		return
	}

	secret := r.URL.Query().Get("agent_secret")
	if secret == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing agent_secret parameter")
		return
	}

	// Validate against shared AGENT_SECRET
	if err := ValidateAgentSecret(agentID, secret); err != nil {
		if ServerMetrics != nil { ServerMetrics.ErrorsTotal.Add(1) }
		status := http.StatusUnauthorized
		if err.Error() == "rate limited: too many connection attempts" {
			status = http.StatusTooManyRequests
		}
		writeJSONError(w, status, "authentication failed: "+err.Error())
		return
	}

	// Self-register: ensure agent exists in database
	name := r.URL.Query().Get("name")
	model := r.URL.Query().Get("model")
	personality := r.URL.Query().Get("personality")
	specialty := r.URL.Query().Get("specialty")
	if err := RegisterAgentOnConnect(agentID, name, model, personality, specialty); err != nil {
		log.Printf("Failed to self-register agent %s: %v", agentID, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	// Negotiate sub-protocol version
	protocolVersion := negotiateProtocol(r)
	upgradeWithProtocol(w, r, protocolVersion)

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

	// Replay any offline messages queued for this agent
	go replayOfflineMessages(c)

	// Send welcome message with protocol version
	sendWelcomeMessage("agent", agentID, "", protocolVersion, c.send)
}

func handleClientConnect(w http.ResponseWriter, r *http.Request) {
	// Extract user_id from query params
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing user_id parameter")
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing token parameter")
		return
	}

	// Validate JWT token
	claims, err := ValidateJWT(token)
	if err != nil {
		if ServerMetrics != nil { ServerMetrics.ErrorsTotal.Add(1) }
		writeJSONError(w, http.StatusUnauthorized, "authentication failed: "+err.Error())
		return
	}

	// Use the user ID from the JWT claims (don't trust query param)
	userID = claims.UserID

	// Negotiate sub-protocol version
	protocolVersion := negotiateProtocol(r)
	upgradeWithProtocol(w, r, protocolVersion)

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for client %s: %v", userID, err)
		return
	}

	// Create connection
	deviceID := r.URL.Query().Get("device_id")
	c := &Connection{
		hub:         hub,
		connType:    "client",
		id:          userID,
		deviceID:    deviceID,
		conn:        conn,
		send:        make(chan []byte, 256),
		connectedAt: time.Now(),
	}

	// Register with hub
	hub.register <- c

	// Start pumps
	go c.writePump()
	go c.readPump()

	// Replay any offline messages queued for this client
	go replayOfflineMessages(c)

	// Send welcome message with device info + protocol version
	sendWelcomeMessage("client", userID, deviceID, protocolVersion, c.send)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var snapshot map[string]interface{}
	if ServerMetrics != nil {
		snapshot = ServerMetrics.Snapshot()
	} else {
		snapshot = make(map[string]interface{})
	}
	snapshot["status"] = "ok"
	snapshot["version"] = ServerVersion

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

// handleLogin handles POST /auth/login - user login returning a JWT
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		writeJSONError(w, http.StatusBadRequest, "missing username or password")
		return
	}

	// Look up user by username
	var userID, passwordHash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&userID, &passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Generate JWT
	token, err := GenerateJWT(userID, username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":    token,
		"user_id":  userID,
		"username": username,
	})
}

// handleRegisterAgent handles POST /auth/agent - pre-register an agent with metadata.
// Agents can also self-register on connect, but this endpoint allows pre-seeding
// metadata. Requires the AGENT_SECRET for authentication.
func handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Authenticate with AGENT_SECRET
	secret := r.Header.Get("X-Agent-Secret")
	if secret == "" {
		secret = r.FormValue("agent_secret")
	}
	if secret != agentSecret {
		writeJSONError(w, http.StatusUnauthorized, "invalid agent secret")
		return
	}

	agentID := r.FormValue("agent_id")
	name := r.FormValue("name")
	model := r.FormValue("model")
	personality := r.FormValue("personality")
	specialty := r.FormValue("specialty")
	if agentID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing agent_id")
		return
	}
	if name == "" {
		name = agentID
	}

	_, err := db.Exec(`
		INSERT INTO agents (id, name, model, personality, specialty) 
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=?, model=?, personality=?, specialty=?`,
		agentID, name, model, personality, specialty,
		name, model, personality, specialty,
	)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to register agent: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"agent_id":    agentID,
		"status":      "registered",
		"model":       model,
		"personality": personality,
		"specialty":   specialty,
	})
}

// handleRegisterUser handles POST /auth/user - register a new user account
func handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		writeJSONError(w, http.StatusBadRequest, "missing username or password")
		return
	}

	// Validate username: 3-50 chars, alphanumeric + underscore
	if len(username) < 3 || len(username) > 50 {
		writeJSONError(w, http.StatusBadRequest, "username must be between 3 and 50 characters")
		return
	}
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			writeJSONError(w, http.StatusBadRequest, "username must contain only letters, numbers, and underscores")
			return
		}
	}

	// Hash the password
	hash, err := HashAPIKey(password) // bcrypt works for passwords too
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Generate a user ID
	userID := generateID("user")

	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", userID, username, hash)
	if err != nil {
		if isUniqueViolation(err) {
			writeJSONError(w, http.StatusConflict, "username already exists")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to register user: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"user_id":  userID,
		"username": username,
		"status":   "registered",
	})
}

// generateID creates a simple unique ID with a prefix
func generateID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

// handleListAgents handles GET /agents - lists all registered agents with their current status
// This is for clients to discover and choose which agent to talk to.
func handleListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	rows, err := db.Query("SELECT id, name, model, personality, specialty FROM agents ORDER BY name ASC")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	var agents []AgentInfo
	for rows.Next() {
		var a AgentInfo
		if err := rows.Scan(&a.ID, &a.Name, &a.Model, &a.Personality, &a.Specialty); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		a.Status = hub.AgentStatus(a.ID)
		agents = append(agents, a)
	}

	w.Header().Set("Content-Type", "application/json")
	if agents == nil {
		agents = []AgentInfo{}
	}
	json.NewEncoder(w).Encode(agents)
}

// handleAdminAgents handles GET /admin/agents - lists all connected agents with detailed status
// This is an admin endpoint for monitoring which agents are online.
func handleAdminAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Get all registered agents from DB
	rows, err := db.Query("SELECT id, name, model, personality, specialty, created_at FROM agents ORDER BY name ASC")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	var agents []AgentInfo
	for rows.Next() {
		var a AgentInfo
		var createdAt string
		if err := rows.Scan(&a.ID, &a.Name, &a.Model, &a.Personality, &a.Specialty, &createdAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		a.Status = hub.AgentStatus(a.ID)
		// Only include connected_at for online agents
		if a.Status != "offline" {
			if conn := hub.GetAgent(a.ID); conn != nil {
				a.ConnectedAt = conn.connectedAt.Format(time.RFC3339)
			}
		}
		agents = append(agents, a)
	}

	w.Header().Set("Content-Type", "application/json")
	if agents == nil {
		agents = []AgentInfo{}
	}
	json.NewEncoder(w).Encode(agents)
}

// DB is the global database reference (set in main)
var db *sql.DB
var hub *Hub

// handleChangePassword handles POST /auth/change-password - change user password
func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")
	if oldPassword == "" || newPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "missing old_password or new_password")
		return
	}

	if err := changeUserPassword(claims.UserID, oldPassword, newPassword); err != nil {
		if err.Error() == "invalid old password" {
			writeJSONError(w, http.StatusUnauthorized, "invalid old password")
			return
		}
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "user not found")
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "password_changed",
	})
}

// handleDeleteConversation handles DELETE /conversations/delete - delete a conversation
func handleDeleteConversation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	convID := r.URL.Query().Get("conversation_id")
	if convID == "" {
		convID = r.FormValue("conversation_id")
	}
	if convID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conversation_id")
		return
	}

	if err := deleteConversation(convID, claims.UserID); err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "conversation not found")
			return
		}
		if err.Error() == "unauthorized" {
			writeJSONError(w, http.StatusUnauthorized, "not your conversation")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":          "deleted",
		"conversation_id": convID,
	})
}

// handleSearchMessages handles GET /messages/search - search messages by content
func handleSearchMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		writeJSONError(w, http.StatusBadRequest, "missing search query (q)")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := fmt.Sscanf(limitStr, "%d", &limit); l != 1 || err != nil {
			limit = 50
		}
		if limit > 200 {
			limit = 200
		}
	}

	messages, err := searchMessages(claims.UserID, query, limit)
	if err != nil {
		if err.Error() == "empty search query" {
			writeJSONError(w, http.StatusBadRequest, "empty search query")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if messages == nil {
		messages = []StoredMessage{}
	}
	json.NewEncoder(w).Encode(messages)
}

// handleMarkRead handles POST /conversations/mark-read - mark messages as read
func handleMarkRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	convID := r.FormValue("conversation_id")
	if convID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conversation_id")
		return
	}

	count, err := markMessagesRead(convID, claims.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "conversation not found")
			return
		}
		if err.Error() == "unauthorized" {
			writeJSONError(w, http.StatusUnauthorized, "not your conversation")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Notify the agent via WebSocket that messages were read
	conv, _ := getConversation(convID)
	if conv != nil {
		if agent := hub.GetAgent(conv.AgentID); agent != nil {
			readMsg := OutgoingMessage{
				Type: "read_receipt",
				Data: map[string]interface{}{
					"conversation_id": convID,
					"read_by":         claims.UserID,
					"count":           count,
				},
			}
			data, _ := json.Marshal(readMsg)
			select {
			case agent.send <- data:
			default:
			}
		}

		// Also broadcast read_receipt to the user's other devices for cross-device read sync
		for _, clientConn := range hub.GetClientConns(claims.UserID) {
			readMsg := OutgoingMessage{
				Type: "read_receipt",
				Data: map[string]interface{}{
					"conversation_id": convID,
					"read_by":         claims.UserID,
					"count":           count,
				},
			}
			data, _ := json.Marshal(readMsg)
			select {
			case clientConn.send <- data:
			default:
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "marked_read",
		"conversation_id": convID,
		"count":           count,
	})
}

// handleCreateConversation handles POST /conversations/create
func handleCreateConversation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	agentID := r.FormValue("agent_id")
	if agentID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing agent_id")
		return
	}

	conv, err := GetOrCreateConversation(claims.UserID, agentID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create conversation")
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
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := db.Query(`
		SELECT c.id, c.user_id, c.agent_id, c.created_at,
		       COALESCE(lm.content, ''), COALESCE(lm.sender_type, ''), COALESCE(lm.created_at, ''),
		       COALESCE(uc.unread_count, 0)
		FROM conversations c
		LEFT JOIN (
		    SELECT m.conversation_id, m.content, m.sender_type, m.created_at,
		           ROW_NUMBER() OVER (PARTITION BY m.conversation_id ORDER BY m.created_at DESC) as rn
		    FROM messages m WHERE m.is_deleted = 0 OR m.is_deleted IS NULL
		) lm ON lm.conversation_id = c.id AND lm.rn = 1
		LEFT JOIN (
		    SELECT conversation_id, COUNT(*) as unread_count
		    FROM messages
		    WHERE read_at IS NULL AND (is_deleted = 0 OR is_deleted IS NULL)
		    GROUP BY conversation_id
		) uc ON uc.conversation_id = c.id
		WHERE c.user_id = ?
		ORDER BY c.created_at DESC`,
		claims.UserID,
	)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	type LastMessage struct {
		Content   string `json:"content"`
		SenderType string `json:"sender_type"`
		CreatedAt string `json:"created_at"`
	}

	type ConvInfo struct {
		ID          string      `json:"id"`
		UserID      string      `json:"user_id"`
		AgentID     string      `json:"agent_id"`
		CreatedAt   string      `json:"created_at"`
		LastMessage *LastMessage `json:"last_message"`
		UnreadCount int         `json:"unread_count"`
	}

	var conversations []ConvInfo
	for rows.Next() {
		var c ConvInfo
		var lmContent, lmSenderType, lmCreatedAt string
		if err := rows.Scan(&c.ID, &c.UserID, &c.AgentID, &c.CreatedAt, &lmContent, &lmSenderType, &lmCreatedAt, &c.UnreadCount); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if lmContent != "" {
			c.LastMessage = &LastMessage{
				Content:    lmContent,
				SenderType: lmSenderType,
				CreatedAt:  lmCreatedAt,
			}
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
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	convID := r.URL.Query().Get("conversation_id")
	if convID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conversation_id")
		return
	}

	// Verify user is participant
	conv, err := getConversation(convID)
	if err != nil || conv == nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	if conv.UserID != claims.UserID {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	messages, err := getConversationMessages(convID, 50)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if messages == nil {
		messages = []StoredMessage{}
	}
	json.NewEncoder(w).Encode(messages)
}