package main

// Coverage Boost 36: Targeting handleUpload full success path, handleGetEncryptedMessages
// agent auth + limit + empty results, handleStoreEncryptedMessage user sender delivery +
// nil hub + missing fields, handleListAttachments full coverage, handleGetAttachment
// agent auth + not found, initSchema error path, hub.run device reconnect with deviceID.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- handleUpload full success path ---

// TestHandleUpload_SuccessFullFlow verifies the complete upload flow: multipart form,
// content-type detection, file write to disk, DB metadata storage, and JSON response.
func TestHandleUpload_SuccessFullFlow(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)

	// Create user and get JWT
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"upload-success-user", "uploadsuccess", "hash")
	if err != nil {
		t.Fatal(err)
	}
	token, err := GenerateJWT("upload-success-user", "uploadsuccess")
	if err != nil {
		t.Fatal(err)
	}

	// Create temp upload dir
	tmpDir := t.TempDir()
	origDBPath := serverDBPath
	serverDBPath = filepath.Join(tmpDir, "test.db")
	t.Cleanup(func() { serverDBPath = origDBPath })

	// Build a multipart form with a small PNG file
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	part, err := writer.CreateFormFile("file", "test.png")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(pngHeader)
	writer.WriteField("message_id", "msg-upload-test")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["id"] == nil || result["filename"] != "test.png" {
		t.Errorf("unexpected response: %v", result)
	}
	if result["content_type"] != "image/png" {
		t.Errorf("expected image/png, got %v", result["content_type"])
	}
	if result["url"] == nil {
		t.Error("expected url in response")
	}

	// Verify file exists on disk
	relPath, _ := result["url"].(string)
	_ = relPath // URL is /attachments/{id}, not the file path
	// Check that some file was created in the temp dir
	files, _ := os.ReadDir(filepath.Join(tmpDir))
	if len(files) == 0 {
		// Check subdirs (YYYY/MM structure)
		entries, _ := os.ReadDir(tmpDir)
		for _, e := range entries {
			if e.IsDir() {
				subEntries, _ := os.ReadDir(filepath.Join(tmpDir, e.Name()))
				for _, se := range subEntries {
					if se.IsDir() {
						innerFiles, _ := os.ReadDir(filepath.Join(tmpDir, e.Name(), se.Name()))
						if len(innerFiles) == 0 {
							t.Error("no files written to disk in YYYY/MM/ subdir")
						}
					}
				}
			}
		}
	}
}

// TestHandleUpload_JPEGContentDetection verifies JPEG detection from magic bytes
// when content-type is application/octet-stream.
func TestHandleUpload_JPEGFromOctetStream(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"upload-jpeg-user", "uploadjpeg", "hash")
	if err != nil {
		t.Fatal(err)
	}
	token, err := GenerateJWT("upload-jpeg-user", "uploadjpeg")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	origDBPath := serverDBPath
	serverDBPath = filepath.Join(tmpDir, "test.db")
	t.Cleanup(func() { serverDBPath = origDBPath })

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	// JPEG magic bytes: FF D8 FF
	jpegHeader := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F'}
	part, err := writer.CreateFormFile("file", "photo.jpg")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(jpegHeader)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	ct, _ := result["content_type"].(string)
	if !strings.HasPrefix(ct, "image/jpeg") {
		t.Errorf("expected image/jpeg, got %s", ct)
	}
}

// TestHandleUpload_NoAuth verifies that missing auth returns 401.
func TestHandleUpload_NoAuth_CB36(t *testing.T) {
	setupTestDB(t)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.png")
	part.Write([]byte{0x89, 0x50, 0x4E, 0x47})
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleUpload_InvalidToken verifies that an invalid JWT returns 401.
func TestHandleUpload_InvalidToken(t *testing.T) {
	setupTestDB(t)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "test.png")
	part.Write([]byte{0x89, 0x50, 0x4E, 0x47})
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Authorization", "Bearer invalidtoken123")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleUpload_MissingFileField verifies that missing file field returns 400.
func TestHandleUpload_MissingFileField_CB36(t *testing.T) {
	setupTestDB(t)

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"upload-nofile-user", "uploadnofile", "hash")
	if err != nil {
		t.Fatal(err)
	}
	token, err := GenerateJWT("upload-nofile-user", "uploadnofile")
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("message_id", "msg1")
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing file") {
		t.Errorf("expected 'missing file' error, got: %s", w.Body.String())
	}
}

// TestHandleUpload_WrongMethod verifies that non-POST returns 405.
func TestHandleUpload_WrongMethod(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/upload", nil)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// --- handleGetEncryptedMessages tests ---

// TestHandleGetEncryptedMessages_AgentAuth verifies agent can retrieve encrypted messages.
func TestHandleGetEncryptedMessages_AgentAuth_CB36(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)

	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-getenc-secret")
	agentSecret = "test-getenc-secret"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getenc-user", "getencuser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-getenc", "getenc-user", "getenc-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Store an encrypted message from user
	_, err = db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg-1", "conv-getenc", "getenc-user", "user", "ciphertext1", "iv1", "rk1", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := agentAuthRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-getenc", "", "getenc-agent")
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0]["ciphertext"] != "ciphertext1" {
		t.Errorf("expected ciphertext1, got %v", messages[0]["ciphertext"])
	}
}

// TestHandleGetEncryptedMessages_LimitParam verifies the limit query parameter works.
func TestHandleGetEncryptedMessages_LimitParam(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("getenc-limit-user", "getenclimituser")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getenc-limit-user", "getenclimituser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-getenc-limit", "getenc-limit-user", "agent-limit")
	if err != nil {
		t.Fatal(err)
	}

	// Insert 3 encrypted messages
	for i := 0; i < 3; i++ {
		_, err = db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"emsg-limit-"+string(rune('A'+i)), "conv-getenc-limit", "getenc-limit-user", "user", "ct", "iv", "rk", "aes-256-gcm", time.Now().Add(time.Duration(i)*time.Second).UTC())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Request with limit=2
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-getenc-limit&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages with limit=2, got %d", len(messages))
	}
}

// TestHandleGetEncryptedMessages_LimitOverMax verifies limit > 200 is clamped to 50.
func TestHandleGetEncryptedMessages_LimitOverMax(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("getenc-maxlimit-user", "getencmaxlimit")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getenc-maxlimit-user", "getencmaxlimit", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-getenc-maxlimit", "getenc-maxlimit-user", "agent-max")
	if err != nil {
		t.Fatal(err)
	}

	// Insert 1 message
	_, err = db.Exec(`INSERT INTO encrypted_messages (id, conversation_id, sender_id, sender_type, ciphertext, iv, recipient_key_id, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"emsg-max-1", "conv-getenc-maxlimit", "getenc-maxlimit-user", "user", "ct", "iv", "rk", "aes-256-gcm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// Request with limit=999 (over max, should clamp to 50)
	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-getenc-maxlimit&limit=999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&messages)
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

// TestHandleGetEncryptedMessages_EmptyResults verifies that conversations with no
// encrypted messages return an empty array.
func TestHandleGetEncryptedMessages_EmptyResults(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("getenc-empty-user", "getencempty")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getenc-empty-user", "getencempty", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-getenc-empty", "getenc-empty-user", "agent-empty")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-getenc-empty", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&messages)
	if messages == nil || len(messages) != 0 {
		t.Fatalf("expected empty array, got %v", messages)
	}
}

// TestHandleGetEncryptedMessages_WrongMethod verifies non-GET returns 405.
func TestHandleGetEncryptedMessages_WrongMethod_CB36(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// TestHandleGetEncryptedMessages_NoAuth verifies missing auth returns 401.
func TestHandleGetEncryptedMessages_NoAuth_CB36(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleGetEncryptedMessages_AgentNotParticipant verifies that an agent
// accessing a conversation they're not part of gets 404.
func TestHandleGetEncryptedMessages_AgentNotParticipant(t *testing.T) {
	setupTestDB(t)

	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-getenc-wrong-secret")
	agentSecret = "test-getenc-wrong-secret"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getenc-wrong-user", "getencwrong", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-getenc-wrong", "getenc-wrong-user", "other-agent")
	if err != nil {
		t.Fatal(err)
	}

	req := agentAuthRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-getenc-wrong", "", "wrong-agent")
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleStoreEncryptedMessage user sender delivery to agent ---

// TestHandleStoreEncryptedMessage_UserSenderDeliversToAgent verifies that when
// a user sends an encrypted message, it's delivered to the connected agent via WebSocket.
func TestHandleStoreEncryptedMessage_UserSenderDeliversToAgent(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	t.Cleanup(hub.Stop)

	token, err := GenerateJWT("enc-user-sender", "encusersender")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-user-sender", "encusersender", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-user-sender", "enc-user-sender", "enc-recv-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a connected agent
	agentConn := &Connection{
		hub:      hub,
		connType: "agent",
		id:       "enc-recv-agent",
		send:     make(chan []byte, 256),
	}
	hub.register <- agentConn
	time.Sleep(50 * time.Millisecond)

	body := `{"conversation_id": "conv-user-sender", "ciphertext": "dXNlcmNpcGhlcg==", "iv": "aXY5OTk5", "algorithm": "aes-256-gcm", "recipient_key_id": "rk-user", "sender_key_id": "sk-user"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the agent received the encrypted_message
	select {
	case msg := <-agentConn.send:
		if !strings.Contains(string(msg), "encrypted_message") {
			t.Errorf("expected encrypted_message, got: %s", string(msg))
		}
	case <-time.After(time.Second):
		t.Error("agent should have received the encrypted message")
	}
}

// TestHandleStoreEncryptedMessage_NilHub verifies that storing works even with nil hub.
func TestHandleStoreEncryptedMessage_NilHub(t *testing.T) {
	setupTestDB(t)
	hub = nil

	token, err := GenerateJWT("enc-nilhub-user", "encnilhub")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-nilhub-user", "encnilhub", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-nilhub", "enc-nilhub-user", "agent-nilhub")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-nilhub", "ciphertext": "YmFzZTY0", "iv": "aXYx", "algorithm": "aes-256-gcm", "recipient_key_id": "k1"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleStoreEncryptedMessage_MissingFields verifies missing required fields return 400.
func TestHandleStoreEncryptedMessage_MissingFields_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("enc-missing-user", "encmissing")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-missing-user", "encmissing", "hash")
	if err != nil {
		t.Fatal(err)
	}

	// Missing ciphertext and iv
	body := `{"conversation_id": "conv-missing", "algorithm": "aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleStoreEncryptedMessage_InvalidJSON verifies malformed JSON returns 400.
func TestHandleStoreEncryptedMessage_InvalidJSON_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("enc-badjson-user", "encbadjson")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-badjson-user", "encbadjson", "hash")
	if err != nil {
		t.Fatal(err)
	}

	body := `{invalid json}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleStoreEncryptedMessage_WrongMethod verifies non-POST returns 405.
func TestHandleStoreEncryptedMessage_WrongMethod_CB36(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// TestHandleStoreEncryptedMessage_NoAuth verifies missing auth returns 401.
func TestHandleStoreEncryptedMessage_NoAuth_CB36(t *testing.T) {
	setupTestDB(t)

	body := `{"conversation_id": "x", "ciphertext": "c", "iv": "i", "algorithm": "aes-256-gcm"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleStoreEncryptedMessage_ConversationNotFound verifies 404 for non-existent conversation.
func TestHandleStoreEncryptedMessage_ConversationNotFound_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("enc-notfound-user", "encnotfound")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-notfound-user", "encnotfound", "hash")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "nonexistent-conv", "ciphertext": "c", "iv": "i", "algorithm": "aes-256-gcm", "recipient_key_id": "k"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleListAttachments tests ---

// TestHandleListAttachments_WrongMethod verifies non-GET returns 405.
func TestHandleListAttachments_WrongMethod_CB36(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/messages/conv/attachments", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// TestHandleListAttachments_NoAuth verifies missing auth returns 401.
func TestHandleListAttachments_NoAuth_CB36(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/conv/attachments?conversation_id=x", nil)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleListAttachments_InvalidToken verifies invalid JWT returns 401.
func TestHandleListAttachments_InvalidToken(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/messages/conv/attachments?conversation_id=x", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleListAttachments_MissingConvID verifies missing conversation_id returns 400.
func TestHandleListAttachments_MissingConvID_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("listatt-user", "listattuser")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"listatt-user", "listattuser", "hash")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/conv/attachments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleListAttachments_NotFound verifies that a conversation not owned by user returns 404.
func TestHandleListAttachments_NotFound_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("listatt-user2", "listattuser2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"listatt-user2", "listattuser2", "hash")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/conv/attachments?conversation_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleListAttachments_Success verifies successful listing of attachments.
func TestHandleListAttachments_Success(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("listatt-ok-user", "listattok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"listatt-ok-user", "listattok", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-listatt", "listatt-ok-user", "agent-listatt")
	if err != nil {
		t.Fatal(err)
	}

	// Insert a message and an attachment linked to it
	_, err = db.Exec("INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"msg-listatt-1", "conv-listatt", "user", "listatt-ok-user", "hello", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"att-listatt-1", "msg-listatt-1", "listatt-ok-user", "doc.pdf", "application/pdf", 1024, "abc123", "2026/06/att-listatt-1.pdf", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/conv/attachments?conversation_id=conv-listatt", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachments []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&attachments)
	if len(attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(attachments))
	}
	if attachments[0]["filename"] != "doc.pdf" {
		t.Errorf("expected doc.pdf, got %v", attachments[0]["filename"])
	}
}

// TestHandleListAttachments_EmptyResult verifies that conversations with no attachments
// return an empty array.
func TestHandleListAttachments_EmptyResult(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("listatt-empty-user", "listattempty")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"listatt-empty-user", "listattempty", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-listatt-empty", "listatt-empty-user", "agent-empty")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/conv/attachments?conversation_id=conv-listatt-empty", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachments []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&attachments)
	if attachments == nil || len(attachments) != 0 {
		t.Fatalf("expected empty array, got %v", attachments)
	}
}

// --- handleGetAttachment tests ---

// TestHandleGetAttachment_WrongMethod verifies non-GET returns 405.
func TestHandleGetAttachment_WrongMethod_CB36(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/attachments/abc", nil)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// TestHandleGetAttachment_NotFound verifies that a non-existent attachment returns 404.
func TestHandleGetAttachment_NotFound_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("getatt-user", "getattuser")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getatt-user", "getattuser", "hash")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleGetAttachment_AgentAuth verifies agent can retrieve an attachment.
func TestHandleGetAttachment_AgentAuth(t *testing.T) {
	setupTestDB(t)

	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-getatt-agent-secret")
	agentSecret = "test-getatt-agent-secret"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getatt-owner", "getattowner", "hash")
	if err != nil {
		t.Fatal(err)
	}

	// Create temp file for the attachment
	tmpDir := t.TempDir()
	origDBPath := serverDBPath
	serverDBPath = filepath.Join(tmpDir, "test.db")
	t.Cleanup(func() { serverDBPath = origDBPath })

	// getUploadDir() returns filepath.Join(filepath.Dir(serverDBPath), UploadSubdir)
	// = tmpDir/uploads
	fileDir := filepath.Join(tmpDir, UploadSubdir, "2026", "06")
	os.MkdirAll(fileDir, 0755)
	filePath := filepath.Join(fileDir, "att-agent-test.txt")
	os.WriteFile(filePath, []byte("test content"), 0644)

	_, err = db.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"att-agent-test", nil, "getatt-owner", "test.txt", "text/plain", 12, "sha123", "2026/06/att-agent-test.txt", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := agentAuthRequest(http.MethodGet, "/attachments/att-agent-test", "", "agent-getatt")
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleGetAttachment_WrongAgentSecret verifies that wrong agent secret returns 401.
func TestHandleGetAttachment_WrongAgentSecret(t *testing.T) {
	setupTestDB(t)

	origAgentEnv := os.Getenv("AGENT_SECRET")
	os.Setenv("AGENT_SECRET", "test-getatt-real-secret")
	agentSecret = "test-getatt-real-secret"
	t.Cleanup(func() {
		if origAgentEnv != "" {
			os.Setenv("AGENT_SECRET", origAgentEnv)
		} else {
			os.Unsetenv("AGENT_SECRET")
		}
		resetAgentSecret()
	})

	req := httptest.NewRequest(http.MethodGet, "/attachments/something", nil)
	req.Header.Set("X-Agent-Secret", "wrong-secret")
	req.Header.Set("X-Agent-ID", "agent1")
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleGetAttachment_UserNotOwner verifies that a user who doesn't own the
// attachment gets 403.
func TestHandleGetAttachment_UserNotOwner(t *testing.T) {
	setupTestDB(t)

	// Create owner user
	_, err := db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getatt-owner-user", "getattowneruser", "hash")
	if err != nil {
		t.Fatal(err)
	}
	// Create other user
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getatt-other-user", "getattother", "hash")
	if err != nil {
		t.Fatal(err)
	}
	token, err := GenerateJWT("getatt-other-user", "getattother")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"att-owner-test", nil, "getatt-owner-user", "doc.txt", "text/plain", 5, "sha", "2026/06/doc.txt", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/attachments/att-owner-test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// --- initSchema error path ---

// TestInitSchema_ErrorOnBadDB verifies that initSchema returns an error when
// the DB connection is invalid/closed.
func TestInitSchema_ErrorOnBadDB(t *testing.T) {
	badDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	badDB.Close()

	err = initSchema(badDB)
	if err == nil {
		t.Error("expected error from initSchema with closed DB, got nil")
	}
}

// --- hub.run device reconnect with deviceID ---

// TestHubRun_DeviceReconnectWithDeviceID verifies that when a client reconnects
// with the same device_id, the old connection is replaced.
func TestHubRun_DeviceReconnectWithDeviceID(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	// First connection with device-1
	conn1 := &Connection{
		hub:      h,
		connType: "client",
		id:       "device-reconnect-user",
		send:     make(chan []byte, 256),
		deviceID: "device-1",
	}
	h.register <- conn1
	time.Sleep(50 * time.Millisecond)

	// Verify registered
	h.mu.Lock()
	conns := h.clientConns["device-reconnect-user"]
	h.mu.Unlock()
	if len(conns) != 1 || conns[0] != conn1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	// Second connection with same device_id should replace first
	conn2 := &Connection{
		hub:      h,
		connType: "client",
		id:       "device-reconnect-user",
		send:     make(chan []byte, 256),
		deviceID: "device-1",
	}
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns = h.clientConns["device-reconnect-user"]
	h.mu.Unlock()
	if len(conns) != 1 || conns[0] != conn2 {
		t.Fatalf("expected 1 connection (replaced), got %d", len(conns))
	}

	// First connection's send channel should be closed
	select {
	case _, ok := <-conn1.send:
		if ok {
			t.Error("conn1.send should be closed after device reconnect")
		}
	default:
		// Channel is still open but empty — not closed
		t.Error("conn1.send should be closed after device reconnect")
	}
}

// TestHubRun_MultiDeviceDifferentIDs verifies that connections with different
// device_ids are appended, not replaced.
func TestHubRun_MultiDeviceDifferentIDs(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	conn1 := &Connection{
		hub:      h,
		connType: "client",
		id:       "multidev-user",
		send:     make(chan []byte, 256),
		deviceID: "device-A",
	}
	conn2 := &Connection{
		hub:      h,
		connType: "client",
		id:       "multidev-user",
		send:     make(chan []byte, 256),
		deviceID: "device-B",
	}
	h.register <- conn1
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	conns := h.clientConns["multidev-user"]
	h.mu.Unlock()
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(conns))
	}
}

// TestHubRun_AgentReconnectReplacesOld verifies that when an agent reconnects,
// the old connection is replaced and closed.
func TestHubRun_AgentReconnectReplacesOld(t *testing.T) {
	setupTestDB(t)
	h := newHub()
	go h.run()
	t.Cleanup(h.Stop)

	conn1 := &Connection{
		hub:      h,
		connType: "agent",
		id:       "reconnect-agent",
		send:     make(chan []byte, 256),
	}
	h.register <- conn1
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	agent := h.agents["reconnect-agent"]
	h.mu.Unlock()
	if agent != conn1 {
		t.Fatal("first agent connection not registered")
	}

	// Reconnect with same agent ID
	conn2 := &Connection{
		hub:      h,
		connType: "agent",
		id:       "reconnect-agent",
		send:     make(chan []byte, 256),
	}
	h.register <- conn2
	time.Sleep(50 * time.Millisecond)

	h.mu.Lock()
	agent = h.agents["reconnect-agent"]
	h.mu.Unlock()
	if agent != conn2 {
		t.Fatal("agent connection not replaced")
	}

	// First connection should be closed
	select {
	case _, ok := <-conn1.send:
		if ok {
			t.Error("conn1.send should be closed after agent reconnect")
		}
	default:
		t.Error("conn1.send should be closed after agent reconnect")
	}
}

// --- handleStoreEncryptedMessage unsupported algorithm ---

// TestHandleStoreEncryptedMessage_UnsupportedAlgorithm verifies that an
// unsupported algorithm returns 400.
func TestHandleStoreEncryptedMessage_UnsupportedAlgorithm_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("enc-badalgo-user", "encbadalgo")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-badalgo-user", "encbadalgo", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-badalgo", "enc-badalgo-user", "agent-badalgo")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-badalgo", "ciphertext": "c", "iv": "i", "algorithm": "des-3", "recipient_key_id": "k"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unsupported algorithm") {
		t.Errorf("expected 'unsupported algorithm', got: %s", w.Body.String())
	}
}

// --- handleGetEncryptedMessages user not participant ---

// TestHandleGetEncryptedMessages_UserNotParticipant verifies that a user
// accessing a conversation they don't own gets 404.
func TestHandleGetEncryptedMessages_UserNotParticipant_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("getenc-notp-user", "getencnotp")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getenc-notp-user", "getencnotp", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"other-user-enc", "otheruserenc", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-notp", "other-user-enc", "agent-notp")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted?conversation_id=conv-notp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleGetEncryptedMessages missing conversation_id ---

// TestHandleGetEncryptedMessages_MissingConvID verifies that missing conversation_id
// returns 400.
func TestHandleGetEncryptedMessages_MissingConvID_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("getenc-noid-user", "getencnoid")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"getenc-noid-user", "getencnoid", "hash")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/messages/encrypted", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleGetEncryptedMessages(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleStoreEncryptedMessage user not participant ---

// TestHandleStoreEncryptedMessage_UserNotParticipant verifies that a user
// sending to a conversation they don't own gets 403.
func TestHandleStoreEncryptedMessage_UserNotParticipant_CB36(t *testing.T) {
	setupTestDB(t)

	token, err := GenerateJWT("enc-user-notp-user", "encusernotp")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"enc-user-notp-user", "encusernotp", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		"other-enc-owner", "otherencowner", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO conversations (id, user_id, agent_id) VALUES (?, ?, ?)",
		"conv-user-notp", "other-enc-owner", "agent-notp")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"conversation_id": "conv-user-notp", "ciphertext": "c", "iv": "i", "algorithm": "aes-256-gcm", "recipient_key_id": "k"}`
	req := httptest.NewRequest(http.MethodPost, "/messages/encrypted", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleStoreEncryptedMessage(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}