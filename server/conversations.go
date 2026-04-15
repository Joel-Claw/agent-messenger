package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Conversation represents a conversation between a user and an agent
type Conversation struct {
	ID        string
	UserID    string
	AgentID   string
	CreatedAt time.Time
}

// StoredMessage represents a persisted message
type StoredMessage struct {
	ID             string
	ConversationID string
	SenderType     string
	SenderID       string
	Content        string
	Metadata       string
	CreatedAt      time.Time
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
	metadataJSON, _ := json.Marshal(map[string]string{
		"sender_type": msg.SenderType,
		"sender_id":   msg.SenderID,
	})
	_, err := db.Exec(
		"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, msg.ConversationID, msg.SenderType, msg.SenderID, msg.Content, string(metadataJSON), time.Now().UTC(),
	)
	return err
}

// getConversationMessages retrieves messages for a conversation, ordered by time
func getConversationMessages(convID string, limit int) ([]StoredMessage, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.Query(
		"SELECT id, conversation_id, sender_type, sender_id, content, COALESCE(metadata, ''), created_at FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT ?",
		convID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []StoredMessage
	for rows.Next() {
		var m StoredMessage
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.SenderType, &m.SenderID, &m.Content, &m.Metadata, &m.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

// CreateConversation creates a new conversation between a user and an agent
func CreateConversation(userID, agentID string) (*Conversation, error) {
	id := fmt.Sprintf("conv_%d", time.Now().UnixNano())
	_, err := db.Exec(
		"INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
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