package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// E2E encryption key types
const (
	KeyTypeIdentity    = "identity"     // Long-term identity key pair (Ed25519/X25519)
	KeyTypeSignedPreKey  = "signed_prekey" // Medium-term signed pre-key
	KeyTypeOneTimePreKey = "one_time_prekey" // Single-use one-time pre-key
)

// KeyBundle represents a public key uploaded by a user or agent
type KeyBundle struct {
	ID         string `json:"id"`
	OwnerID    string `json:"owner_id"`
	OwnerType  string `json:"owner_type"` // "user" or "agent"
	KeyType    string `json:"key_type"`
	PublicKey  string `json:"public_key"`  // base64-encoded public key
	Signature  string `json:"signature,omitempty"` // base64-encoded signature (for signed pre-keys)
	KeyID      int    `json:"key_id,omitempty"` // one-time pre-key sequential ID
	CreatedAt  string `json:"created_at"`
}

// EncryptedMessage represents an encrypted message envelope
type EncryptedMessage struct {
	ID              string `json:"id"`
	ConversationID  string `json:"conversation_id"`
	SenderID        string `json:"sender_id"`
	SenderType      string `json:"sender_type"`
	Ciphertext      string `json:"ciphertext"`       // base64-encoded encrypted content
	Iv              string `json:"iv"`                // base64-encoded initialization vector
	RecipientKeyID  string `json:"recipient_key_id"`  // which key was used to encrypt
	SenderKeyID     string `json:"sender_key_id,omitempty"` // sender's key used for signing/DH
	Algorithm       string `json:"algorithm"`         // e.g. "aes-256-gcm", "x25519-aes-256-gcm"
	CreatedAt       string `json:"created_at"`
}

// handleUploadPublicKey handles POST /keys/upload
// Users and agents upload their public keys for E2E encryption key exchange
func handleUploadPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ownerID, ownerType, err := authenticateRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req struct {
		KeyType   string `json:"key_type"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature,omitempty"`
		KeyID     int    `json:"key_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.PublicKey == "" {
		writeJSONError(w, http.StatusBadRequest, "public_key is required")
		return
	}

	validTypes := map[string]bool{
		KeyTypeIdentity:      true,
		KeyTypeSignedPreKey:  true,
		KeyTypeOneTimePreKey: true,
	}
	if !validTypes[req.KeyType] {
		writeJSONError(w, http.StatusBadRequest, "invalid key_type, must be identity/signed_prekey/one_time_prekey")
		return
	}

	// For identity keys, replace if one already exists (one identity key per owner)
	if req.KeyType == KeyTypeIdentity {
		var existingID string
		err := db.QueryRow(
			"SELECT id FROM key_bundles WHERE owner_id = ? AND owner_type = ? AND key_type = 'identity'",
			ownerID, ownerType,
		).Scan(&existingID)
		if err == nil {
			// Replace existing identity key
			db.Exec("DELETE FROM key_bundles WHERE id = ?", existingID)
		}
	}

	// For one-time pre-keys, just add (they're consumed on use)
	keyID := generateID("key")

	_, err = db.Exec(`
		INSERT INTO key_bundles (id, owner_id, owner_type, key_type, public_key, signature, key_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, keyID, ownerID, ownerType, req.KeyType, req.PublicKey, req.Signature, req.KeyID, time.Now().UTC())
	if err != nil {
		log.Printf("Error storing key bundle: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to store key")
		return
	}

	bundle := KeyBundle{
		ID:        keyID,
		OwnerID:   ownerID,
		OwnerType: ownerType,
		KeyType:   req.KeyType,
		PublicKey: req.PublicKey,
		Signature: req.Signature,
		KeyID:     req.KeyID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

// handleGetKeyBundle handles GET /keys/bundle/{owner_id}
// Returns the pre-key bundle for a user or agent (identity key + signed pre-key + one-time pre-key)
func handleGetKeyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	_, _, err := authenticateRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Extract target owner_id and owner_type from query params
	targetID := r.URL.Query().Get("owner_id")
	targetType := r.URL.Query().Get("owner_type")
	if targetID == "" {
		writeJSONError(w, http.StatusBadRequest, "owner_id is required")
		return
	}
	if targetType == "" {
		targetType = "user" // default to user
	}

	bundle := map[string]interface{}{}

	// Get identity key
	var identityKey KeyBundle
	err = db.QueryRow(
		"SELECT id, owner_id, owner_type, key_type, public_key, COALESCE(signature, ''), created_at FROM key_bundles WHERE owner_id = ? AND owner_type = ? AND key_type = 'identity'",
		targetID, targetType,
	).Scan(&identityKey.ID, &identityKey.OwnerID, &identityKey.OwnerType, &identityKey.KeyType, &identityKey.PublicKey, &identityKey.Signature, &identityKey.CreatedAt)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no identity key found for this owner")
		return
	}
	bundle["identity_key"] = identityKey

	// Get signed pre-key
	var signedPreKey KeyBundle
	err = db.QueryRow(
		"SELECT id, owner_id, owner_type, key_type, public_key, COALESCE(signature, ''), created_at FROM key_bundles WHERE owner_id = ? AND owner_type = ? AND key_type = 'signed_prekey' ORDER BY created_at DESC LIMIT 1",
		targetID, targetType,
	).Scan(&signedPreKey.ID, &signedPreKey.OwnerID, &signedPreKey.OwnerType, &signedPreKey.KeyType, &signedPreKey.PublicKey, &signedPreKey.Signature, &signedPreKey.CreatedAt)
	if err == nil {
		bundle["signed_prekey"] = signedPreKey
	}

	// Get and consume one one-time pre-key (Signal protocol: consumed on use)
	var otpKey KeyBundle
	err = db.QueryRow(
		"SELECT id, owner_id, owner_type, key_type, public_key, COALESCE(signature, ''), key_id, created_at FROM key_bundles WHERE owner_id = ? AND owner_type = ? AND key_type = 'one_time_prekey' ORDER BY key_id ASC LIMIT 1",
		targetID, targetType,
	).Scan(&otpKey.ID, &otpKey.OwnerID, &otpKey.OwnerType, &otpKey.KeyType, &otpKey.PublicKey, &otpKey.Signature, &otpKey.KeyID, &otpKey.CreatedAt)
	if err == nil {
		bundle["one_time_prekey"] = otpKey
		// Consume (delete) the one-time pre-key
		db.Exec("DELETE FROM key_bundles WHERE id = ?", otpKey.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

// handleListOneTimePreKeys handles GET /keys/otpk-count
// Returns the count of remaining one-time pre-keys for the authenticated owner
func handleListOneTimePreKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ownerID, ownerType, err := authenticateRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var count int
	db.QueryRow(
		"SELECT COUNT(*) FROM key_bundles WHERE owner_id = ? AND owner_type = ? AND key_type = 'one_time_prekey'",
		ownerID, ownerType,
	).Scan(&count)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"one_time_prekey_count": count,
	})
}

// handleStoreEncryptedMessage handles POST /messages/encrypted
// Stores an encrypted message envelope (ciphertext only, server never sees plaintext)
func handleStoreEncryptedMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	senderID, senderType, err := authenticateRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req struct {
		ConversationID string `json:"conversation_id"`
		Ciphertext     string `json:"ciphertext"`
		Iv             string `json:"iv"`
		RecipientKeyID string `json:"recipient_key_id"`
		SenderKeyID    string `json:"sender_key_id,omitempty"`
		Algorithm      string `json:"algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.ConversationID == "" || req.Ciphertext == "" || req.Iv == "" || req.Algorithm == "" {
		writeJSONError(w, http.StatusBadRequest, "conversation_id, ciphertext, iv, and algorithm are required")
		return
	}

	validAlgorithms := map[string]bool{
		"aes-256-gcm":          true,
		"x25519-aes-256-gcm":   true,
		"x25519-chacha20-poly1305": true,
	}
	if !validAlgorithms[req.Algorithm] {
		writeJSONError(w, http.StatusBadRequest, "unsupported algorithm")
		return
	}

	// Verify conversation exists and sender is a participant
	conv, err := getConversation(req.ConversationID)
	if err != nil || conv == nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	// Verify sender is participant
	if senderType == "user" && conv.UserID != senderID {
		writeJSONError(w, http.StatusForbidden, "not a participant in this conversation")
		return
	}
	if senderType == "agent" && conv.AgentID != senderID {
		writeJSONError(w, http.StatusForbidden, "not a participant in this conversation")
		return
	}

	msgID := generateID("emsg")
	_, err = db.Exec(`
		INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, sender_key_id, algorithm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, msgID, req.ConversationID, senderID, senderType, req.Ciphertext, req.Iv, req.RecipientKeyID, req.SenderKeyID, req.Algorithm, time.Now().UTC())
	if err != nil {
		log.Printf("Error storing encrypted message: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to store encrypted message")
		return
	}

	// Deliver via WebSocket (notify recipient that an encrypted message is available)
	routedMsg := RoutedMessage{
		Type:           "encrypted_message",
		ConversationID: req.ConversationID,
		Content:        fmt.Sprintf("encrypted:%s", msgID), // pointer, not plaintext
		SenderType:     senderType,
		SenderID:       senderID,
	}

	outgoing, _ := json.Marshal(OutgoingMessage{Type: "encrypted_message", Data: routedMsg})

	if hub != nil {
		if senderType == "user" {
			// Deliver to agent
			if agent := hub.GetAgent(conv.AgentID); agent != nil {
				select {
				case agent.send <- outgoing:
				default:
					log.Printf("Agent %s send buffer full, dropping encrypted message", conv.AgentID)
				}
			}
		} else {
			// Deliver to user
			if client := hub.GetClient(conv.UserID); client != nil {
				select {
				case client.send <- outgoing:
				default:
					log.Printf("Client %s send buffer full, dropping encrypted message", conv.UserID)
				}
			} else {
				go notifyUser(conv.UserID, "New Encrypted Message", "🔒 Encrypted message", req.ConversationID)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":      msgID,
		"status":  "stored",
		"message": "encrypted message stored and delivered",
	})
}

// handleGetEncryptedMessages handles GET /messages/encrypted
// Retrieves encrypted messages for a conversation
func handleGetEncryptedMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ownerID, ownerType, err := authenticateRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	conversationID := r.URL.Query().Get("conversation_id")
	if conversationID == "" {
		writeJSONError(w, http.StatusBadRequest, "conversation_id is required")
		return
	}

	// Verify conversation exists and user is participant
	conv, err := getConversation(conversationID)
	if err != nil || conv == nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	if ownerType == "user" && conv.UserID != ownerID {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	if ownerType == "agent" && conv.AgentID != ownerID {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
		if limit <= 0 || limit > 200 {
			limit = 50
		}
	}

	rows, err := db.Query(`
		SELECT id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, COALESCE(sender_key_id, ''), algorithm, created_at
		FROM encrypted_messages
		WHERE conversation_id = ?
		ORDER BY created_at ASC
		LIMIT ?
	`, conversationID, limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to fetch encrypted messages")
		return
	}
	defer rows.Close()

	messages := []EncryptedMessage{}
	for rows.Next() {
		var m EncryptedMessage
		var createdAt string
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.SenderID, &m.SenderType, &m.Ciphertext, &m.Iv, &m.RecipientKeyID, &m.SenderKeyID, &m.Algorithm, &createdAt); err != nil {
			continue
		}
		m.CreatedAt = createdAt
		messages = append(messages, m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// authenticateRequest extracts identity from JWT or agent secret
func authenticateRequest(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateJWT(token)
		if err != nil {
			return "", "", fmt.Errorf("invalid token")
		}
		return claims.UserID, "user", nil
	}

	agentSecret := r.Header.Get("X-Agent-Secret")
	if agentSecret != "" && agentSecret == getAgentSecret() {
		agentID := r.Header.Get("X-Agent-ID")
		if agentID == "" {
			return "", "", fmt.Errorf("X-Agent-ID header required with agent auth")
		}
		return agentID, "agent", nil
	}

	return "", "", fmt.Errorf("authorization required")
}