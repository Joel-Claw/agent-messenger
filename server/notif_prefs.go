package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// NotificationPreferences stores per-conversation mute settings.
type NotificationPreferences struct {
	ConversationID string `json:"conversation_id"`
	Muted          bool   `json:"muted"`
}

// handleGetNotificationPrefs returns all notification preferences for the authenticated user.
func handleGetNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := db.Query(`
		SELECT conversation_id, muted
		FROM notification_preferences
		WHERE user_id = ?`, userID)
	if err != nil {
		DefaultLogger.Error("notif_prefs_query_error", map[string]interface{}{"error": err.Error()})
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	prefs := []NotificationPreferences{}
	for rows.Next() {
		var p NotificationPreferences
		if err := rows.Scan(&p.ConversationID, &p.Muted); err != nil {
			continue
		}
		prefs = append(prefs, p)
	}

	writeJSON(w, http.StatusOK, prefs)
}

// handleSetNotificationPrefs sets notification preference for a specific conversation.
func handleSetNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	conversationID := r.FormValue("conversation_id")
	muted := r.FormValue("muted") == "true"

	if conversationID == "" {
		writeJSONError(w, http.StatusBadRequest, "conversation_id required")
		return
	}

	// Verify the user owns this conversation
	var owner string
	err = db.QueryRow(`SELECT user_id FROM conversations WHERE id = ?`, conversationID).Scan(&owner)
	if err == sql.ErrNoRows {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	} else if err != nil {
		DefaultLogger.Error("notif_prefs_conv_lookup_error", map[string]interface{}{"error": err.Error()})
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if owner != userID {
		writeJSONError(w, http.StatusForbidden, "not your conversation")
		return
	}

	_, err = db.Exec(fmt.Sprintf(`
		INSERT INTO notification_preferences (user_id, conversation_id, muted)
		VALUES (%s, %s, %s)
		ON CONFLICT(user_id, conversation_id) DO UPDATE SET muted = %s`,
		Placeholder(1), Placeholder(2), Placeholder(3), Placeholder(4)),
		userID, conversationID, muted, muted)
	if err != nil {
		DefaultLogger.Error("notif_prefs_upsert_error", map[string]interface{}{"error": err.Error()})
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, NotificationPreferences{
		ConversationID: conversationID,
		Muted:          muted,
	})
}

// handleDeleteNotificationPrefs removes notification preference for a conversation.
func handleDeleteNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	conversationID := r.FormValue("conversation_id")
	if conversationID == "" {
		writeJSONError(w, http.StatusBadRequest, "conversation_id required")
		return
	}

	db.Exec(`DELETE FROM notification_preferences WHERE user_id = ? AND conversation_id = ?`,
		userID, conversationID)

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// isConversationMuted checks if a user has muted notifications for a conversation.
func isConversationMuted(userID, conversationID string) bool {
	var muted bool
	err := db.QueryRow(`
		SELECT muted FROM notification_preferences
		WHERE user_id = ? AND conversation_id = ?`,
		userID, conversationID).Scan(&muted)
	if err != nil {
		return false // Default: not muted
	}
	return muted
}
