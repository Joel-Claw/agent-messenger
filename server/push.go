package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
)

// PushNotificationConfig holds APNs configuration
type PushNotificationConfig struct {
	Enabled     bool
	CertPath    string // Path to .p8 or .p12 certificate
	Password    string // Password for .p12 (empty for .p8)
	KeyID       string // Key ID for .p8 token
	TeamID      string // Team ID for .p8 token
	BundleID    string // App bundle ID (e.g., com.agentmessenger.ios)
	Environment string // "production" or "development"
}

var pushConfig *PushNotificationConfig
var apnsClient *apns2.Client

// initPushNotifications initializes the APNs client
func initPushNotifications() {
	pushConfig = &PushNotificationConfig{
		Enabled:     os.Getenv("APNS_ENABLED") == "true",
		CertPath:    os.Getenv("APNS_CERT_PATH"),
		Password:    os.Getenv("APNS_CERT_PASSWORD"),
		KeyID:       os.Getenv("APNS_KEY_ID"),
		TeamID:      os.Getenv("APNS_TEAM_ID"),
		BundleID:    getEnvOrDefault("APNS_BUNDLE_ID", "com.agentmessenger.ios"),
		Environment: getEnvOrDefault("APNS_ENVIRONMENT", "development"),
	}

	if !pushConfig.Enabled {
		log.Println("Push notifications disabled (APNS_ENABLED not set)")
		return
	}

	if pushConfig.CertPath == "" {
		log.Println("WARNING: APNS_ENABLED but no APNS_CERT_PATH set, push will fail")
		return
	}

	// Ensure cert directory exists
	if dir := filepath.Dir(pushConfig.CertPath); dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}

	// Check if cert file exists
	if _, err := os.Stat(pushConfig.CertPath); err != nil {
		log.Printf("WARNING: APNs certificate not found at %s: %v", pushConfig.CertPath, err)
		log.Println("Push notifications will be unavailable until certificate is installed")
		pushConfig.Enabled = false
		return
	}

	cert, err := certificate.FromP12File(pushConfig.CertPath, pushConfig.Password)
	if err != nil {
		log.Printf("WARNING: Failed to load APNs certificate: %v", err)
		pushConfig.Enabled = false
		return
	}

	if pushConfig.Environment == "production" {
		apnsClient = apns2.NewClient(cert).Production()
	} else {
		apnsClient = apns2.NewClient(cert).Development()
	}

	log.Printf("APNs push notifications enabled (%s)", pushConfig.Environment)
}

// sendPushNotification sends a push notification to a device token
func sendPushNotification(deviceToken, title, body, conversationID string) error {
	if !pushConfig.Enabled || apnsClient == nil {
		return nil // Silently skip if not configured
	}

	p := payload.NewPayload().
		AlertTitle(title).
		AlertBody(body).
		Badge(1).
		Sound("default")

	if conversationID != "" {
		p.Custom("conversation_id", conversationID)
	}

	notification := &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       pushConfig.BundleID,
		Payload:     p,
	}

	response, err := apnsClient.Push(notification)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		log.Printf("APNs push rejected for %s...%s: %s", deviceToken[:8], deviceToken[len(deviceToken)-8:], response.Reason)
		return nil // Don't treat APNs rejection as a fatal error
	}

	log.Printf("Push notification sent to %s...%s", deviceToken[:8], deviceToken[len(deviceToken)-8:])
	return nil
}

// handleRegisterDeviceToken registers a device token for push notifications
func handleRegisterDeviceToken(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		DeviceToken string `json:"device_token"`
		Platform    string `json:"platform"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DeviceToken == "" {
		writeJSONError(w, http.StatusBadRequest, "device_token is required")
		return
	}

	if req.Platform == "" {
		req.Platform = "ios"
	}

	_, err = db.Exec(`
		INSERT INTO device_tokens (user_id, device_token, platform, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, device_token) DO UPDATE SET
			updated_at = CURRENT_TIMESTAMP
	`, claims.UserID, req.DeviceToken, req.Platform)

	if err != nil {
		log.Printf("Error storing device token: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to store device token")
		return
	}

	log.Printf("Device token registered for user %s (%s)", claims.UserID[:8], req.Platform)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleUnregisterDeviceToken removes a device token
func handleUnregisterDeviceToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
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

	var req struct {
		DeviceToken string `json:"device_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DeviceToken == "" {
		writeJSONError(w, http.StatusBadRequest, "device_token is required")
		return
	}

	_, err = db.Exec("DELETE FROM device_tokens WHERE user_id = ? AND device_token = ?", claims.UserID, req.DeviceToken)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to remove device token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// getDeviceTokensForUser returns all device tokens for a user
func getDeviceTokensForUser(userID string) ([]string, error) {
	rows, err := db.Query("SELECT device_token FROM device_tokens WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			continue
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// notifyUser sends a push notification to all devices for a user
func notifyUser(userID, title, body, conversationID string) {
	if pushConfig == nil || !pushConfig.Enabled {
		return
	}

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil || len(tokens) == 0 {
		return
	}

	for _, token := range tokens {
		if err := sendPushNotification(token, title, body, conversationID); err != nil {
			log.Printf("Failed to send push to %s...%s: %v", token[:8], token[len(token)-8:], err)
		}
	}
}

// getEnvOrDefault returns the environment variable or a default value
func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}