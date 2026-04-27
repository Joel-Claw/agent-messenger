package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// MaxUploadSize is the maximum file upload size (default 50 MB, can be overridden via MAX_UPLOAD_SIZE env)
	MaxUploadSize = 50 << 20
	// UploadSubdir is the subdirectory under DB_PATH parent for uploads
	UploadSubdir = "uploads"
)

// maxUploadSize holds the effective upload size limit (initialized from env in main)
var maxUploadSize int64 = MaxUploadSize

// getMaxUploadSize returns the effective upload size limit
func getMaxUploadSize() int64 {
	return maxUploadSize
}

// Attachment represents a stored file attachment
type Attachment struct {
	ID           string `json:"id"`
	MessageID    string `json:"message_id,omitempty"`
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type"`
	Size         int64  `json:"size"`
	Sha256       string `json:"sha256"`
	StoragePath  string `json:"-"` // not exposed in API
	URL          string `json:"url"`
	CreatedAt    string `json:"created_at"`
}

// getUploadDir returns the directory for storing uploaded files
func getUploadDir() string {
	// Place uploads next to the database
	dbDir := filepath.Dir(serverDBPath)
	return filepath.Join(dbDir, UploadSubdir)
}

// ensureUploadDir creates the upload directory if it doesn't exist
func ensureUploadDir() error {
	dir := getUploadDir()
	return os.MkdirAll(dir, 0755)
}

// handleUpload handles POST /attachments/upload
func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Authenticate user via JWT
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSONError(w, http.StatusUnauthorized, "authorization required")
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, getMaxUploadSize())

	// Parse multipart form
	if err := r.ParseMultipartForm(getMaxUploadSize()); err != nil {
		writeJSONError(w, http.StatusBadRequest, "file too large or invalid form data")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	// Validate file size
	if header.Size > getMaxUploadSize() {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("file too large (max %d MB)", getMaxUploadSize()/(1<<20)))
		return
	}

	// Detect content type
	contentType := header.Header.Get("Content-Type")
	if contentType == "" || contentType == "application/octet-stream" {
		// Try to detect from first 512 bytes
		buf := make([]byte, 512)
		n, _ := file.Read(buf)
		contentType = http.DetectContentType(buf[:n])
		// Reset reader
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to process file")
			return
		}
	}

	// Validate content type (allow common image, document, and media types)
	if !isAllowedContentType(contentType) {
		writeJSONError(w, http.StatusBadRequest, "file type not allowed: "+contentType)
		return
	}

	// Compute SHA256 hash
	hasher := sha256.New()
	tee := io.TeeReader(file, hasher)

	// Generate unique ID
	attachID := generateID("att")

	// Determine file extension
	ext := filepath.Ext(header.Filename)
	if ext == "" {
		// Guess from content type
		exts, _ := mime.ExtensionsByType(contentType)
		if len(exts) > 0 {
			ext = exts[0]
		}
	}

	// Create storage path: uploads/YYYY/MM/attachID.ext
	now := time.Now()
	dateDir := filepath.Join(
		getUploadDir(),
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", now.Month()),
	)
	if err := os.MkdirAll(dateDir, 0755); err != nil {
		log.Printf("Error creating upload directory: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to store file")
		return
	}

	storageName := attachID + ext
	storagePath := filepath.Join(dateDir, storageName)

	// Write file to disk
	dst, err := os.Create(storagePath)
	if err != nil {
		log.Printf("Error creating file %s: %v", storagePath, err)
		writeJSONError(w, http.StatusInternalServerError, "failed to store file")
		return
	}
	defer dst.Close()

	size, err := io.Copy(dst, tee)
	if err != nil {
		log.Printf("Error writing file %s: %v", storagePath, err)
		os.Remove(storagePath)
		writeJSONError(w, http.StatusInternalServerError, "failed to store file")
		return
	}

	sha := hex.EncodeToString(hasher.Sum(nil))

	// Compute relative path from upload dir for DB storage
	relPath := filepath.Join(
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", now.Month()),
		storageName,
	)

	// Store attachment metadata in database
	var messageID *string
	if mid := r.FormValue("message_id"); mid != "" {
		messageID = &mid
	}

	_, err = db.Exec(`
		INSERT INTO attachments (id, message_id, user_id, filename, content_type, size, sha256, storage_path, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		attachID, messageID, claims.UserID, header.Filename, contentType, size, sha, relPath, now.UTC(),
	)
	if err != nil {
		log.Printf("Error storing attachment metadata: %v", err)
		os.Remove(storagePath)
		writeJSONError(w, http.StatusInternalServerError, "failed to store attachment")
		return
	}

	attachment := Attachment{
		ID:          attachID,
		Filename:    header.Filename,
		ContentType: contentType,
		Size:        size,
		Sha256:      sha,
		URL:         fmt.Sprintf("/attachments/%s", attachID),
		CreatedAt:   now.UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attachment)
}

// handleGetAttachment handles GET /attachments/{id}
func handleGetAttachment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract attachment ID from path: /attachments/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/attachments/"), "/")
	attachID := pathParts[0]
	if attachID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing attachment id")
		return
	}

	// Authenticate (either JWT or agent secret)
	var userID string
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateJWT(token)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		userID = claims.UserID
	} else {
		// Check agent secret for agent access
		agentSecret := r.Header.Get("X-Agent-Secret")
		if agentSecret == "" || agentSecret != getAgentSecret() {
			writeJSONError(w, http.StatusUnauthorized, "authorization required")
			return
		}
	}

	// Look up attachment metadata
	var relPath, filename, contentType string
	err := db.QueryRow(`
		SELECT storage_path, filename, content_type FROM attachments WHERE id = ?
	`, attachID).Scan(&relPath, &filename, &contentType)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "attachment not found")
		return
	}

	// If user auth, verify ownership or message participation
	if userID != "" {
		var ownerID string
		err := db.QueryRow("SELECT user_id FROM attachments WHERE id = ?", attachID).Scan(&ownerID)
		if err != nil || ownerID != userID {
			writeJSONError(w, http.StatusForbidden, "not authorized to access this attachment")
			return
		}
	}

	// Serve the file
	filePath := filepath.Join(getUploadDir(), relPath)
	http.ServeFile(w, r, filePath)
}

// handleListAttachments handles GET /messages/{conversation_id}/attachments
func handleListAttachments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSONError(w, http.StatusUnauthorized, "authorization required")
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := ValidateJWT(token)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	conversationID := r.URL.Query().Get("conversation_id")
	if conversationID == "" {
		writeJSONError(w, http.StatusBadRequest, "conversation_id is required")
		return
	}

	// Verify user owns the conversation
	conv, err := getConversation(conversationID)
	if err != nil || conv == nil || conv.UserID != claims.UserID {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	rows, err := db.Query(`
		SELECT a.id, a.filename, a.content_type, a.size, a.sha256, a.created_at
		FROM attachments a
		JOIN messages m ON a.message_id = m.id
		WHERE m.conversation_id = ?
		ORDER BY a.created_at DESC
	`, conversationID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list attachments")
		return
	}
	defer rows.Close()

	attachments := []Attachment{}
	for rows.Next() {
		var a Attachment
		var createdAt string
		if err := rows.Scan(&a.ID, &a.Filename, &a.ContentType, &a.Size, &a.Sha256, &createdAt); err != nil {
			continue
		}
		a.URL = fmt.Sprintf("/attachments/%s", a.ID)
		a.CreatedAt = createdAt
		attachments = append(attachments, a)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attachments)
}

// isAllowedContentType checks if a content type is allowed for upload
func isAllowedContentType(ct string) bool {
	allowed := map[string]bool{
		// Images
		"image/jpeg": true, "image/png": true, "image/gif": true,
		"image/webp": true, "image/svg+xml": true, "image/bmp": true,
		// Documents
		"application/pdf": true,
		"text/plain": true, "text/csv": true, "text/markdown": true,
		"application/json": true,
		// Audio
		"audio/mpeg": true, "audio/ogg": true, "audio/wav": true,
		"audio/webm": true, "audio/mp4": true,
		// Video
		"video/mp4": true, "video/webm": true, "video/ogg": true,
	}

	// Also allow anything that starts with image/, audio/, video/
	prefixes := []string{"image/", "audio/", "video/", "text/"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}

	return allowed[ct]
}