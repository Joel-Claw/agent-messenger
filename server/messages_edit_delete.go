package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// handleMessageEdit handles POST /messages/edit - edit a message's content
func handleMessageEdit(w http.ResponseWriter, r *http.Request) {
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
	content := r.FormValue("content")
	if messageID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing message_id")
		return
	}
	if content == "" {
		writeJSONError(w, http.StatusBadRequest, "content cannot be empty")
		return
	}

	// Fetch the message
	var msg StoredMessage
	err = db.QueryRow(
		"SELECT id, conversation_id, sender_type, sender_id, content, COALESCE(metadata, ''), created_at, read_at, edited_at, COALESCE(is_deleted, 0) FROM messages WHERE id = ?",
		messageID,
	).Scan(&msg.ID, &msg.ConversationID, &msg.SenderType, &msg.SenderID, &msg.Content, &msg.Metadata, &msg.CreatedAt, &msg.ReadAt, &msg.EditedAt, &msg.IsDeleted)
	if err == sql.ErrNoRows {
		writeJSONError(w, http.StatusNotFound, "message not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if msg.IsDeleted {
		writeJSONError(w, http.StatusBadRequest, "cannot edit a deleted message")
		return
	}

	// Verify the user is the sender
	if msg.SenderType != "client" || msg.SenderID != claims.UserID {
		writeJSONError(w, http.StatusUnauthorized, "can only edit your own messages")
		return
	}

	// Update the message
	now := time.Now().UTC()
	_, err = db.Exec("UPDATE messages SET content = ?, edited_at = ? WHERE id = ?", content, now, messageID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to update message")
		return
	}

	msg.Content = content
	msg.EditedAt = &now

	// Notify all participants via WebSocket
	conv, _ := getConversation(msg.ConversationID)
	if conv != nil {
		editEvent := OutgoingMessage{
			Type: "message_edited",
			Data: map[string]interface{}{
				"message_id":      messageID,
				"conversation_id": msg.ConversationID,
				"content":         content,
				"edited_at":        now.Format(time.RFC3339),
				"edited_by":       claims.UserID,
			},
		}
		editData, _ := json.Marshal(editEvent)

		// Send to all user devices
		for _, clientConn := range hub.GetClientConns(conv.UserID) {
			select {
			case clientConn.send <- editData:
			default:
			}
		}
		// Send to agent
		if agent := hub.GetAgent(conv.AgentID); agent != nil {
			select {
			case agent.send <- editData:
			default:
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "edited",
		"message_id":     messageID,
		"conversation_id": msg.ConversationID,
		"content":         content,
		"edited_at":        now.Format(time.RFC3339),
	})
}

// handleMessageDelete handles POST /messages/delete - soft delete a message
func handleMessageDelete(w http.ResponseWriter, r *http.Request) {
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
	if messageID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing message_id")
		return
	}

	// Fetch the message
	var msg StoredMessage
	err = db.QueryRow(
		"SELECT id, conversation_id, sender_type, sender_id, content, COALESCE(metadata, ''), created_at, read_at, edited_at, COALESCE(is_deleted, 0) FROM messages WHERE id = ?",
		messageID,
	).Scan(&msg.ID, &msg.ConversationID, &msg.SenderType, &msg.SenderID, &msg.Content, &msg.Metadata, &msg.CreatedAt, &msg.ReadAt, &msg.EditedAt, &msg.IsDeleted)
	if err == sql.ErrNoRows {
		writeJSONError(w, http.StatusNotFound, "message not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if msg.IsDeleted {
		writeJSONError(w, http.StatusBadRequest, "message already deleted")
		return
	}

	// Verify the user is the sender (or owns the conversation)
	conv, _ := getConversation(msg.ConversationID)
	if conv == nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	isSender := msg.SenderType == "client" && msg.SenderID == claims.UserID
	isOwner := conv.UserID == claims.UserID
	if !isSender && !isOwner {
		writeJSONError(w, http.StatusUnauthorized, "can only delete your own messages or messages in your conversations")
		return
	}

	// Soft delete: set is_deleted = true, blank content
	now := time.Now().UTC()
	_, err = db.Exec("UPDATE messages SET is_deleted = 1, content = '[deleted]', edited_at = ? WHERE id = ?", now, messageID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to delete message")
		return
	}

	// Notify all participants via WebSocket
	deleteEvent := OutgoingMessage{
		Type: "message_deleted",
		Data: map[string]interface{}{
			"message_id":      messageID,
			"conversation_id": msg.ConversationID,
			"deleted_by":      claims.UserID,
			"deleted_at":      now.Format(time.RFC3339),
		},
	}
	deleteData, _ := json.Marshal(deleteEvent)

	// Send to all user devices
	for _, clientConn := range hub.GetClientConns(conv.UserID) {
		select {
		case clientConn.send <- deleteData:
		default:
		}
	}
	// Send to agent
	if agent := hub.GetAgent(conv.AgentID); agent != nil {
		select {
		case agent.send <- deleteData:
		default:
		}
	}

	log.Printf("Message %s deleted by %s", messageID, claims.UserID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "deleted",
		"message_id":     messageID,
		"conversation_id": msg.ConversationID,
		"deleted_at":      now.Format(time.RFC3339),
	})
}