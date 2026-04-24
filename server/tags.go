package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ConversationTag represents a tag/label on a conversation
type ConversationTag struct {
	ID        string `json:"id"`
	Tag       string `json:"tag"`
	CreatedAt string `json:"created_at"`
}

// addConversationTag adds a tag to a conversation. Tags are unique per conversation.
func addConversationTag(convID, userID, tag string) (*ConversationTag, error) {
	// Verify user owns the conversation
	conv, err := getConversation(convID)
	if err != nil {
		return nil, err
	}
	if conv == nil {
		return nil, fmt.Errorf("conversation not found")
	}
	if conv.UserID != userID {
		return nil, fmt.Errorf("unauthorized")
	}

	// Validate tag: 1-50 chars, no whitespace-only
	if len(tag) == 0 || len(tag) > 50 {
		return nil, fmt.Errorf("tag must be 1-50 characters")
	}

	// Check if tag already exists
	var existingID string
	err = db.QueryRow(
		"SELECT id FROM conversation_tags WHERE conversation_id = ? AND tag = ?",
		convID, tag,
	).Scan(&existingID)
	if err == nil {
		return nil, fmt.Errorf("tag already exists")
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	id := generateID("tag")
	now := time.Now().UTC()
	_, err = db.Exec(
		"INSERT INTO conversation_tags (id, conversation_id, tag, created_at) VALUES (?, ?, ?, ?)",
		id, convID, tag, now,
	)
	if err != nil {
		return nil, err
	}

	return &ConversationTag{
		ID:        id,
		Tag:       tag,
		CreatedAt: now.Format(time.RFC3339),
	}, nil
}

// removeConversationTag removes a tag from a conversation
func removeConversationTag(convID, userID, tag string) error {
	conv, err := getConversation(convID)
	if err != nil {
		return err
	}
	if conv == nil {
		return fmt.Errorf("conversation not found")
	}
	if conv.UserID != userID {
		return fmt.Errorf("unauthorized")
	}

	result, err := db.Exec(
		"DELETE FROM conversation_tags WHERE conversation_id = ? AND tag = ?",
		convID, tag,
	)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tag not found")
	}
	return nil
}

// getConversationTags retrieves all tags for a conversation
func getConversationTags(convID string) ([]ConversationTag, error) {
	rows, err := db.Query(
		"SELECT id, tag, created_at FROM conversation_tags WHERE conversation_id = ? ORDER BY tag ASC",
		convID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []ConversationTag
	for rows.Next() {
		var t ConversationTag
		if err := rows.Scan(&t.ID, &t.Tag, &t.CreatedAt); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

// handleAddTag handles POST /conversations/tags/add - add a tag to a conversation
func handleAddTag(w http.ResponseWriter, r *http.Request) {
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
	tag := r.FormValue("tag")
	if convID == "" || tag == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conversation_id or tag")
		return
	}

	result, err := addConversationTag(convID, claims.UserID, tag)
	if err != nil {
		switch err.Error() {
		case "conversation not found":
			writeJSONError(w, http.StatusNotFound, err.Error())
		case "unauthorized":
			writeJSONError(w, http.StatusUnauthorized, err.Error())
		case "tag already exists":
			writeJSONError(w, http.StatusConflict, err.Error())
		default:
			if err.Error() == "tag must be 1-50 characters" {
				writeJSONError(w, http.StatusBadRequest, err.Error())
			} else {
				writeJSONError(w, http.StatusInternalServerError, "internal error")
			}
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "tag_added",
		"tag":    result,
	})
}

// handleRemoveTag handles POST /conversations/tags/remove - remove a tag from a conversation
func handleRemoveTag(w http.ResponseWriter, r *http.Request) {
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
	tag := r.FormValue("tag")
	if convID == "" || tag == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conversation_id or tag")
		return
	}

	if err := removeConversationTag(convID, claims.UserID, tag); err != nil {
		switch err.Error() {
		case "conversation not found":
			writeJSONError(w, http.StatusNotFound, err.Error())
		case "unauthorized":
			writeJSONError(w, http.StatusUnauthorized, err.Error())
		case "tag not found":
			writeJSONError(w, http.StatusNotFound, err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "tag_removed",
		"tag":    tag,
	})
}

// handleGetTags handles GET /conversations/tags - get tags for a conversation
func handleGetTags(w http.ResponseWriter, r *http.Request) {
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

	// Verify user owns the conversation
	conv, _ := getConversation(convID)
	if conv == nil || conv.UserID != claims.UserID {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	tags, err := getConversationTags(convID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if tags == nil {
		tags = []ConversationTag{}
	}
	json.NewEncoder(w).Encode(tags)
}