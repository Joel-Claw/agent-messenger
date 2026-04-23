package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupAttachmentTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	serverDBPath = filepath.Join(dir, "test.db")
	var err error
	db, err = sql.Open("sqlite3", serverDBPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
}

func createTestUser(t *testing.T, username string) string {
	t.Helper()

	// Register the user
	form := "username=" + username + "&password=testpass123"
	req := httptest.NewRequest("POST", "/auth/user", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegisterUser(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to register user: %d %s", w.Code, w.Body.String())
	}

	// Login to get JWT
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != 200 {
		t.Fatalf("Failed to login: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatal("No token in login response")
	}
	return token
}

func makeUploadRequest(filename, content, token string) *http.Request {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", filename)
	part.Write([]byte(content))
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestAttachmentUpload(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "uploaduser")
	req := makeUploadRequest("test.png", "fake image content for testing", token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var attachment Attachment
	if err := json.NewDecoder(w.Body).Decode(&attachment); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if attachment.ID == "" {
		t.Error("Expected attachment ID")
	}
	if attachment.Filename != "test.png" {
		t.Errorf("Expected filename test.png, got %s", attachment.Filename)
	}
	if attachment.Size == 0 {
		t.Error("Expected non-zero size")
	}
	if attachment.Sha256 == "" {
		t.Error("Expected SHA256")
	}
	if attachment.URL == "" {
		t.Error("Expected URL")
	}

	// Verify file exists on disk
	relPath := ""
	err := db.QueryRow("SELECT storage_path FROM attachments WHERE id = ?", attachment.ID).Scan(&relPath)
	if err != nil {
		t.Fatalf("Failed to query attachment: %v", err)
	}
	fullPath := filepath.Join(getUploadDir(), relPath)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Errorf("File not found at %s", fullPath)
	}
}

func TestAttachmentUploadNoAuth(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	req := makeUploadRequest("test.txt", "hello", "")
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 401 {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestAttachmentUploadNoFile(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "nofileuser")

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.Close()

	req := httptest.NewRequest("POST", "/attachments/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAttachmentUploadDisallowedType(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "disalloweduser")

	// Create a file with MZ header (DOS/PE executable)
	req := makeUploadRequest("malware.exe", "MZ\x90\x00", token)
	w := httptest.NewRecorder()
	handleUpload(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for disallowed type, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIsAllowedContentType(t *testing.T) {
	tests := []struct {
		ct       string
		expected bool
	}{
		{"image/jpeg", true},
		{"image/png", true},
		{"image/gif", true},
		{"image/webp", true},
		{"application/pdf", true},
		{"text/plain", true},
		{"audio/mpeg", true},
		{"video/mp4", true},
		{"application/x-executable", false},
		{"application/x-msdos-program", false},
	}

	for _, tt := range tests {
		got := isAllowedContentType(tt.ct)
		if got != tt.expected {
			t.Errorf("isAllowedContentType(%q) = %v, want %v", tt.ct, got, tt.expected)
		}
	}
}

func TestAttachmentGetNotFound(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "getuser")

	req := httptest.NewRequest("GET", "/attachments/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleGetAttachment(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestAttachmentListEmpty(t *testing.T) {
	setupAttachmentTestDB(t)
	defer db.Close()

	token := createTestUser(t, "listuser")

	req := httptest.NewRequest("GET", "/messages/attachments?conversation_id=conv-nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	handleListAttachments(w, req)

	if w.Code != 404 {
		t.Errorf("Expected 404 for nonexistent conversation, got %d", w.Code)
	}
}

func TestEnsureUploadDir(t *testing.T) {
	dir := t.TempDir()
	serverDBPath = filepath.Join(dir, "data", "test.db")

	if err := ensureUploadDir(); err != nil {
		t.Fatalf("ensureUploadDir failed: %v", err)
	}

	uploadDir := getUploadDir()
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		t.Errorf("Upload directory not created at %s", uploadDir)
	}
}