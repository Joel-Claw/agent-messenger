package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Conversation represents a conversation between a user and an agent
type Conversation struct {
	ID        string
	UserID    string
	AgentID   string
	CreatedAt time.Time
}

// MessageReadReceipt tracks which messages a user has read
const (
	ReadReceiptRead      = "read"
	ReadReceiptDelivered = "delivered"
)

// StoredMessage represents a persisted message
type StoredMessage struct {
	ID             string            `json:"id"`
	ConversationID string            `json:"conversation_id"`
	SenderType     string            `json:"sender_type"`
	SenderID       string            `json:"sender_id"`
	Content        string            `json:"content"`
	Metadata       string            `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	ReadAt         *time.Time        `json:"read_at,omitempty"`
	EditedAt       *time.Time        `json:"edited_at,omitempty"`
	IsDeleted      bool              `json:"is_deleted"`
	Reactions      []MessageReaction `json:"reactions,omitempty"`
}

// getConversation fetches a conversation by ID
func getConversation(convID string) (*Conversation, error) {
	var conv Conversation
	err := db.QueryRow(
		"SELECT id, user_id, agent_id, created_at FROM conversations WHERE id = ?",
		convID,
	).Scan(&conv.ID, &conv.UserID, &conv.AgentID, &conv.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &conv, nil
}

// storeMessage persists a message to the database
func storeMessage(msg RoutedMessage) error {
	id := generateID("msg")
	metadataMap := map[string]interface{}{
		"sender_type": msg.SenderType,
		"sender_id":   msg.SenderID,
	}
	if len(msg.AttachmentIDs) > 0 {
		metadataMap["attachment_ids"] = msg.AttachmentIDs
	}
	metadataJSON, _ := json.Marshal(metadataMap)
	_, err := db.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES ("+Placeholder(1)+", "+Placeholder(2)+", "+Placeholder(3)+", "+Placeholder(4)+", "+Placeholder(5)+", "+Placeholder(6)+", "+Placeholder(7)+")",
		id, msg.ConversationID, msg.SenderType, msg.SenderID, msg.Content, string(metadataJSON), time.Now().UTC(),
	)
	if err != nil {
		return err
	}

	// Link attachments to this message
	for _, attachID := range msg.AttachmentIDs {
		db.Exec("UPDATE attachments SET message_id = "+Placeholder(1)+" WHERE id = "+Placeholder(2)+" AND message_id IS NULL", id, attachID)
	}

	return nil
}

// storeMessagesBatch inserts multiple messages in a single transaction.
// This is significantly faster than individual inserts for high-throughput
// conversations (e.g., bulk message replay, history import).
// Returns the IDs of the inserted messages in order, or an error if any insert fails.
func storeMessagesBatch(msgs []RoutedMessage) ([]string, error) {
	if len(msgs) == 0 {
		return nil, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (" +
			Placeholder(1) + ", " + Placeholder(2) + ", " + Placeholder(3) + ", " + Placeholder(4) + ", " + Placeholder(5) + ", " + Placeholder(6) + ", " + Placeholder(7) + ")")
	if err != nil {
		return nil, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	ids := make([]string, len(msgs))
	now := time.Now().UTC()

	for i, msg := range msgs {
		id := generateID("msg")
		ids[i] = id

		metadataMap := map[string]interface{}{
			"sender_type": msg.SenderType,
			"sender_id":   msg.SenderID,
		}
		if len(msg.AttachmentIDs) > 0 {
			metadataMap["attachment_ids"] = msg.AttachmentIDs
		}
		metadataJSON, _ := json.Marshal(metadataMap)

		_, err = stmt.Exec(id, msg.ConversationID, msg.SenderType, msg.SenderID, msg.Content, string(metadataJSON), now)
		if err != nil {
			return nil, fmt.Errorf("insert message %d: %w", i, err)
		}

		// Link attachments
		for _, attachID := range msg.AttachmentIDs {
			tx.Exec("UPDATE attachments SET message_id = "+Placeholder(1)+" WHERE id = "+Placeholder(2)+" AND message_id IS NULL", id, attachID)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return ids, nil
}

// getConversationMessages retrieves messages for a conversation, ordered by time.
// If before is non-empty, only messages with created_at < before are returned (cursor pagination).
func getConversationMessages(convID string, limit int, before string) ([]StoredMessage, error) {
	if limit <= 0 {
		limit = 50
	}

	var rows *sql.Rows
	var err error
	if before != "" {
		rows, err = db.Query(
			"SELECT id, conversation_id, sender_type, sender_id, content, COALESCE(metadata, ''), created_at, read_at, edited_at, COALESCE(is_deleted, 0) FROM messages WHERE conversation_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?",
			convID, before, limit)
	} else {
		rows, err = db.Query(
			"SELECT id, conversation_id, sender_type, sender_id, content, COALESCE(metadata, ''), created_at, read_at, edited_at, COALESCE(is_deleted, 0) FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT ?",
			convID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []StoredMessage
	for rows.Next() {
		var m StoredMessage
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.SenderType, &m.SenderID, &m.Content, &m.Metadata, &m.CreatedAt, &m.ReadAt, &m.EditedAt, &m.IsDeleted); err != nil {
			return nil, err
		}
		// Load reactions for this message
		reactions, err := getMessageReactions(m.ID)
		if err == nil && len(reactions) > 0 {
			m.Reactions = reactions
		}
		messages = append(messages, m)
	}

	// When using cursor pagination, results come in DESC order (newest first).
	// Reverse to get chronological order.
	if before != "" && len(messages) > 0 {
		for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
			messages[i], messages[j] = messages[j], messages[i]
		}
	}

	return messages, rows.Err()
}

// deleteConversation deletes a conversation and all its messages.
// Only the owning user can delete a conversation.
func deleteConversation(convID, userID string) error {
	// Verify conversation exists and user owns it
	conv, err := getConversation(convID)
	if err != nil {
		return err
	}
	if conv == nil {
		return sql.ErrNoRows // not found
	}
	if conv.UserID != userID {
		return fmt.Errorf("unauthorized")
	}

	// Delete messages first (foreign key)
	if _, err := db.Exec("DELETE FROM messages WHERE conversation_id = ?", convID); err != nil {
		return err
	}
	// Delete conversation
	if _, err := db.Exec("DELETE FROM conversations WHERE id = ?", convID); err != nil {
		return err
	}
	return nil
}

// changeUserPassword updates a user's password after verifying the old one.
func changeUserPassword(userID, oldPassword, newPassword string) error {
	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&passwordHash)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("invalid old password")
	}

	// Validate new password
	if len(newPassword) < 6 {
		return fmt.Errorf("new password must be at least 6 characters")
	}

	// Hash new password
	newHash, err := HashAPIKey(newPassword)
	if err != nil {
		return err
	}

	_, err = db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, userID)
	return err
}

// searchMessages searches messages across a user's conversations by content.
// Returns matching messages ordered by creation time (newest first).
func searchMessages(userID, query string, limit int) ([]StoredMessage, error) {
	if limit <= 0 {
		limit = 50
	}
	if query == "" {
		return nil, fmt.Errorf("empty search query")
	}

	rows, err := db.Query(`
		SELECT m.id, m.conversation_id, m.sender_type, m.sender_id, m.content, COALESCE(m.metadata, ''), m.created_at, m.read_at, m.edited_at, COALESCE(m.is_deleted, 0)
		FROM messages m
		JOIN conversations c ON m.conversation_id = c.id
		WHERE c.user_id = ? AND m.content LIKE ?
		ORDER BY m.created_at DESC
		LIMIT ?`,
		userID, "%"+query+"%", limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []StoredMessage
	for rows.Next() {
		var m StoredMessage
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.SenderType, &m.SenderID, &m.Content, &m.Metadata, &m.CreatedAt, &m.ReadAt, &m.EditedAt, &m.IsDeleted); err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

// markMessagesRead marks all unread messages in a conversation as read by the user.
// Returns the number of messages marked as read.
func markMessagesRead(convID, userID string) (int64, error) {
	// Verify user owns the conversation
	conv, err := getConversation(convID)
	if err != nil {
		return 0, err
	}
	if conv == nil {
		return 0, sql.ErrNoRows
	}
	if conv.UserID != userID {
		return 0, fmt.Errorf("unauthorized")
	}

	result, err := db.Exec(
		"UPDATE messages SET read_at = ? WHERE conversation_id = ? AND sender_type = 'agent' AND read_at IS NULL",
		time.Now().UTC(), convID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// CreateConversation creates a new conversation between a user and an agent
func CreateConversation(userID, agentID string) (*Conversation, error) {
	id := fmt.Sprintf("conv_%d", time.Now().UnixNano())
	_, err := db.Exec(
		"INSERT INTO conversations (id, user_id, agent_id) VALUES ("+Placeholder(1)+", "+Placeholder(2)+", "+Placeholder(3)+")",
		id, userID, agentID,
	)
	if err != nil {
		return nil, err
	}
	return &Conversation{ID: id, UserID: userID, AgentID: agentID}, nil
}

// GetOrCreateConversation finds an existing conversation or creates a new one
func GetOrCreateConversation(userID, agentID string) (*Conversation, error) {
	var conv Conversation
	err := db.QueryRow(
		"SELECT id, user_id, agent_id, created_at FROM conversations WHERE user_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 1",
		userID, agentID,
	).Scan(&conv.ID, &conv.UserID, &conv.AgentID, &conv.CreatedAt)
	if err == sql.ErrNoRows {
		return CreateConversation(userID, agentID)
	}
	if err != nil {
		return nil, err
	}
	return &conv, nil
}
