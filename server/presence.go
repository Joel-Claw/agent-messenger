package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleGetPresence handles GET /presence - get online status of agents
func handleGetPresence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	_, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Get all agents with their online status
	rows, err := db.Query("SELECT id, name, status FROM agents")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	type AgentPresence struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Online    bool   `json:"online"`
		Status    string `json:"status"`
		LastSeen  string `json:"last_seen,omitempty"`
	}

	var agents []AgentPresence
	for rows.Next() {
		var a AgentPresence
		if err := rows.Scan(&a.ID, &a.Name, &a.Status); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Check if agent is connected via WebSocket
		if agent := hub.GetAgent(a.ID); agent != nil {
			a.Online = true
			a.LastSeen = time.Now().UTC().Format(time.RFC3339)
		} else {
			a.Online = false
		}
		agents = append(agents, a)
	}

	w.Header().Set("Content-Type", "application/json")
	if agents == nil {
		agents = []AgentPresence{}
	}
	json.NewEncoder(w).Encode(agents)
}

// handleGetUserPresence handles GET /presence/user - get online status of a specific user
func handleGetUserPresence(w http.ResponseWriter, r *http.Request) {
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

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		userID = claims.UserID
	}

	conns := hub.GetClientConns(userID)
	online := len(conns) > 0
	deviceCount := len(conns)

	var lastSeen string
	if online {
		lastSeen = time.Now().UTC().Format(time.RFC3339)
	} else {
		// Check DB for last activity
		var lastActivity *time.Time
		err := db.QueryRow("SELECT created_at FROM messages WHERE sender_id = ? ORDER BY created_at DESC LIMIT 1", userID).Scan(&lastActivity)
		if err == nil && lastActivity != nil {
			lastSeen = lastActivity.Format(time.RFC3339)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":      userID,
		"online":       online,
		"device_count": deviceCount,
		"last_seen":    lastSeen,
	})
}