package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MessageReaction represents a reaction (emoji) on a message
type MessageReaction struct {
	ID        string `json:"id"`
	MessageID string `json:"message_id"`
	UserID    string `json:"user_id"`
	Emoji     string `json:"emoji"`
	CreatedAt string `json:"created_at"`
}

// addReaction adds a reaction to a message.
// A user can only have one reaction per message (toggles: add or remove).
func addReaction(messageID, userID, emoji string) (*MessageReaction, bool, error) {
	// Verify the user can see this message (is a participant in the conversation)
	var convID string
	err := db.QueryRow("SELECT conversation_id FROM messages WHERE id = ?", messageID).Scan(&convID)
	if err == sql.ErrNoRows {
		return nil, false, fmt.Errorf("message not found")
	}
	if err != nil {
		return nil, false, err
	}

	conv, err := getConversation(convID)
	if err != nil {
		return nil, false, err
	}
	if conv == nil {
		return nil, false, fmt.Errorf("conversation not found")
	}
	if conv.UserID != userID && conv.AgentID != userID {
		return nil, false, fmt.Errorf("unauthorized")
	}

	// Toggle: if same user+message+emoji exists, remove it
	var existingID string
	err = db.QueryRow(
		"SELECT id FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
		messageID, userID, emoji,
	).Scan(&existingID)
	if err == nil {
		// Reaction exists, remove it (toggle off)
		_, err := db.Exec("DELETE FROM reactions WHERE id = ?", existingID)
		return nil, false, err
	}
	if err != sql.ErrNoRows {
		return nil, false, err
	}

	// Add new reaction
	id := generateID("rxn")
	now := time.Now().UTC()
	_, err = db.Exec(
		"INSERT INTO reactions (id, message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?, ?)",
		id, messageID, userID, emoji, now,
	)
	if err != nil {
		return nil, false, err
	}

	return &MessageReaction{
		ID:        id,
		MessageID: messageID,
		UserID:    userID,
		Emoji:     emoji,
		CreatedAt: now.Format(time.RFC3339),
	}, true, nil
}

// getMessageReactions retrieves all reactions for a message
func getMessageReactions(messageID string) ([]MessageReaction, error) {
	rows, err := db.Query(
		"SELECT id, message_id, user_id, emoji, created_at FROM reactions WHERE message_id = ? ORDER BY created_at ASC",
		messageID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reactions []MessageReaction
	for rows.Next() {
		var r MessageReaction
		if err := rows.Scan(&r.ID, &r.MessageID, &r.UserID, &r.Emoji, &r.CreatedAt); err != nil {
			return nil, err
		}
		reactions = append(reactions, r)
	}
	return reactions, rows.Err()
}

// handleReact handles POST /messages/react - add or toggle a reaction on a message
func handleReact(w http.ResponseWriter, r *http.Request) {
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

	messageID := r.FormValue("message_id")
	emoji := r.FormValue("emoji")
	if messageID == "" || emoji == "" {
		writeJSONError(w, http.StatusBadRequest, "missing message_id or emoji")
		return
	}

	// Limit emoji length (single emoji, max 10 bytes to cover complex emoji)
	if len(emoji) > 10 {
		writeJSONError(w, http.StatusBadRequest, "emoji too long")
		return
	}

	reaction, added, err := addReaction(messageID, claims.UserID, emoji)
	if err != nil {
		if err.Error() == "message not found" {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		if err.Error() == "unauthorized" {
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Notify the other party via WebSocket
	var convID string
	var agentID string
	db.QueryRow("SELECT conversation_id FROM messages WHERE id = ?", messageID).Scan(&convID)
	if convID != "" {
		conv, _ := getConversation(convID)
		if conv != nil {
			agentID = conv.AgentID
		}
	}

	eventType := "reaction_added"
	if !added {
		eventType = "reaction_removed"
	}

	wsMsg := OutgoingMessage{
		Type: eventType,
		Data: map[string]interface{}{
			"message_id":     messageID,
			"conversation_id": convID,
			"user_id":        claims.UserID,
			"emoji":          emoji,
		},
	}
	wsData, _ := json.Marshal(wsMsg)

	// Send to agent if online
	if agentID != "" {
		if agent := hub.GetAgent(agentID); agent != nil {
			select {
			case agent.send <- wsData:
			default:
			}
		}
	}

	// Send to all of the user's other devices (multi-device sync)
	for _, client := range hub.GetClientConns(claims.UserID) {
		select {
		case client.send <- wsData:
		default:
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if added {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "reaction_added",
			"reaction":  reaction,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "reaction_removed",
			"message_id": messageID,
			"emoji":     emoji,
		})
	}
}

// handleGetReactions handles GET /messages/reactions - get reactions for a message
func handleGetReactions(w http.ResponseWriter, r *http.Request) {
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

	messageID := r.URL.Query().Get("message_id")
	if messageID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing message_id")
		return
	}

	// Verify user can see this message
	var convID string
	err = db.QueryRow("SELECT conversation_id FROM messages WHERE id = ?", messageID).Scan(&convID)
	if err == sql.ErrNoRows {
		writeJSONError(w, http.StatusNotFound, "message not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	conv, _ := getConversation(convID)
	if conv == nil || (conv.UserID != claims.UserID && conv.AgentID != claims.UserID) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	reactions, err := getMessageReactions(messageID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if reactions == nil {
		reactions = []MessageReaction{}
	}
	json.NewEncoder(w).Encode(reactions)
}