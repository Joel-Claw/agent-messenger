package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
	"golang.org/x/net/context"
	"google.golang.org/api/option"
)

// PushNotificationConfig holds push notification configuration
type PushNotificationConfig struct {
	APNSEnabled bool
	CertPath    string // Path to .p8 or .p12 certificate
	Password    string // Password for .p12 (empty for .p8)
	KeyID       string // Key ID for .p8 token
	TeamID      string // Team ID for .p8 token
	BundleID    string // App bundle ID (e.g., com.agentmessenger.ios)
	Environment string // "production" or "development"

	FCMEnabled     bool
	FCMCredentials string // Path to Firebase service account JSON

	apnsClient *apns2.Client
	fcmClient  *messaging.Client
}

var pushConfig *PushNotificationConfig

// initPushNotifications initializes push notification clients (APNs + FCM)
func initPushNotifications() {
	pushConfig = &PushNotificationConfig{
		APNSEnabled:    os.Getenv("APNS_ENABLED") == "true",
		CertPath:       os.Getenv("APNS_CERT_PATH"),
		Password:       os.Getenv("APNS_CERT_PASSWORD"),
		KeyID:          os.Getenv("APNS_KEY_ID"),
		TeamID:         os.Getenv("APNS_TEAM_ID"),
		BundleID:       getEnvOrDefault("APNS_BUNDLE_ID", "com.agentmessenger.ios"),
		Environment:    getEnvOrDefault("APNS_ENVIRONMENT", "development"),
		FCMEnabled:     os.Getenv("FCM_ENABLED") == "true",
		FCMCredentials: os.Getenv("FCM_CREDENTIALS_PATH"),
	}

	// Initialize APNs
	initAPNs()

	// Initialize FCM
	initFCM()
}

func initAPNs() {
	if !pushConfig.APNSEnabled {
		DefaultLogger.Info("apns_disabled", nil)
		return
	}

	if pushConfig.CertPath == "" {
		DefaultLogger.Warn("apns_no_cert_path", nil)
		return
	}

	if dir := filepath.Dir(pushConfig.CertPath); dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}

	if _, err := os.Stat(pushConfig.CertPath); err != nil {
		DefaultLogger.Warn("apns_cert_not_found", map[string]interface{}{"cert_path": pushConfig.CertPath, "error": err.Error()})
		DefaultLogger.Warn("apns_unavailable_no_cert", nil)
		pushConfig.APNSEnabled = false
		return
	}

	cert, err := certificate.FromP12File(pushConfig.CertPath, pushConfig.Password)
	if err != nil {
		DefaultLogger.Warn("apns_cert_load_failed", map[string]interface{}{"error": err.Error()})
		pushConfig.APNSEnabled = false
		return
	}

	if pushConfig.Environment == "production" {
		pushConfig.apnsClient = apns2.NewClient(cert).Production()
	} else {
		pushConfig.apnsClient = apns2.NewClient(cert).Development()
	}

	DefaultLogger.Info("apns_enabled", map[string]interface{}{"environment": pushConfig.Environment})
}

func initFCM() {
	if !pushConfig.FCMEnabled {
		DefaultLogger.Info("fcm_disabled", nil)
		return
	}

	if pushConfig.FCMCredentials == "" {
		DefaultLogger.Warn("fcm_no_creds_path", nil)
		return
	}

	if _, err := os.Stat(pushConfig.FCMCredentials); err != nil {
		DefaultLogger.Warn("fcm_creds_not_found", map[string]interface{}{"creds_path": pushConfig.FCMCredentials, "error": err.Error()})
		DefaultLogger.Warn("fcm_unavailable_no_creds", nil)
		pushConfig.FCMEnabled = false
		return
	}

	ctx := context.Background()
	app, err := firebase.NewApp(ctx, nil, option.WithCredentialsFile(pushConfig.FCMCredentials))
	if err != nil {
		DefaultLogger.Warn("fcm_init_failed", map[string]interface{}{"error": err.Error()})
		pushConfig.FCMEnabled = false
		return
	}

	client, err := app.Messaging(ctx)
	if err != nil {
		DefaultLogger.Warn("fcm_client_failed", map[string]interface{}{"error": err.Error()})
		pushConfig.FCMEnabled = false
		return
	}

	pushConfig.fcmClient = client
	DefaultLogger.Info("fcm_enabled", nil)
}

// sendAPNSNotification sends a push notification via APNs (iOS)
func sendAPNSNotification(deviceToken, title, body, conversationID string) error {
	if pushConfig == nil || !pushConfig.APNSEnabled || pushConfig.apnsClient == nil {
		return nil
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

	response, err := pushConfig.apnsClient.Push(notification)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		DefaultLogger.Warn("apns_push_rejected", map[string]interface{}{"token_prefix": deviceToken[:8], "reason": response.Reason})
		return nil
	}

	DefaultLogger.Info("apns_push_sent", map[string]interface{}{"token_prefix": deviceToken[:8]})
	return nil
}

// sendFCMNotification sends a push notification via FCM (Android)
func sendFCMNotification(deviceToken, title, body, conversationID string) error {
	if pushConfig == nil || !pushConfig.FCMEnabled || pushConfig.fcmClient == nil {
		return nil
	}

	ctx := context.Background()
	msg := &messaging.Message{
		Token: deviceToken,
		Data: map[string]string{
			"title":           title,
			"body":            body,
			"conversation_id": conversationID,
		},
		Notification: &messaging.Notification{
			Title: title,
			Body:  body,
		},
		Android: &messaging.AndroidConfig{
			Priority: "high",
			Notification: &messaging.AndroidNotification{
				ChannelID: "agent_messenger_messages",
				Sound:     "default",
			},
		},
	}

	_, err := pushConfig.fcmClient.Send(ctx, msg)
	if err != nil {
		return fmt.Errorf("FCM send failed: %w", err)
	}

	DefaultLogger.Info("fcm_push_sent", map[string]interface{}{"token_prefix": deviceToken[:8]})
	return nil
}

// sendPushNotification sends a push notification to the appropriate platform
func sendPushNotification(deviceToken, title, body, conversationID string, platform string) error {
	switch strings.ToLower(platform) {
	case "android", "fcm":
		return sendFCMNotification(deviceToken, title, body, conversationID)
	default:
		// Default to APNs for iOS and unknown platforms
		return sendAPNSNotification(deviceToken, title, body, conversationID)
	}
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
			platform = ?,
			updated_at = CURRENT_TIMESTAMP
	`, claims.UserID, req.DeviceToken, req.Platform, req.Platform)

	if err != nil {
		DefaultLogger.Error("device_token_store_error", map[string]interface{}{"error": err.Error()})
		writeJSONError(w, http.StatusInternalServerError, "failed to store device token")
		return
	}

	DefaultLogger.Info("device_token_registered", map[string]interface{}{"user_id": claims.UserID[:8], "platform": req.Platform})
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

// deviceTokenWithPlatform holds a token and its platform
type deviceTokenWithPlatform struct {
	Token    string
	Platform string
}

// getDeviceTokensForUser returns all device tokens with platforms for a user
func getDeviceTokensForUser(userID string) ([]deviceTokenWithPlatform, error) {
	rows, err := db.Query("SELECT device_token, platform FROM device_tokens WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []deviceTokenWithPlatform
	for rows.Next() {
		var t deviceTokenWithPlatform
		if err := rows.Scan(&t.Token, &t.Platform); err != nil {
			continue
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// notifyUser sends a push notification to all devices for a user
func notifyUser(userID, title, body, conversationID string) {
	if pushConfig == nil {
		return
	}

	// Check if user has muted this conversation
	if conversationID != "" && isConversationMuted(userID, conversationID) {
		return
	}

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil || len(tokens) == 0 {
		return
	}

	for _, t := range tokens {
		if err := sendPushNotification(t.Token, title, body, conversationID, t.Platform); err != nil {
			DefaultLogger.Warn("push_send_failed", map[string]interface{}{"token_prefix": t.Token[:8], "platform": t.Platform, "error": err.Error()})
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

// --- Web Push (VAPID) Support ---

// vapidPublicKey holds the VAPID public key (set via VAPID_PUBLIC_KEY env)
var vapidPublicKey string

// handleGetVAPIDKey handles GET /push/vapid-key
// Returns the VAPID public key for web push subscription
func handleGetVAPIDKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Authenticate
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSONError(w, http.StatusUnauthorized, "authorization required")
		return
	}

	if vapidPublicKey == "" {
		writeJSONError(w, http.StatusNotFound, "VAPID not configured on server")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"public_key": vapidPublicKey})
}

// handleWebPushSubscribe handles POST /push/web-subscribe
// Registers a web push subscription (endpoint + keys) for the authenticated user
func handleWebPushSubscribe(w http.ResponseWriter, r *http.Request) {
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
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256DH string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Endpoint == "" || req.Keys.P256DH == "" || req.Keys.Auth == "" {
		writeJSONError(w, http.StatusBadRequest, "endpoint, p256dh, and auth keys are required")
		return
	}

	// Store as a device token with platform "web"
	// Use endpoint as the token identifier
	_, err = db.Exec(`
		INSERT OR REPLACE INTO device_tokens (user_id, device_token, platform, created_at)
		VALUES (?, ?, 'web', ?)
	`, claims.UserID, req.Endpoint, time.Now().UTC())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to store subscription")
		return
	}

	// Also store the encryption keys in a separate table for web push
	// (needed to encrypt payloads with the subscription keys)
	db.Exec(`CREATE TABLE IF NOT EXISTS web_push_subscriptions (
		user_id TEXT NOT NULL,
		endpoint TEXT NOT NULL UNIQUE,
		p256dh TEXT NOT NULL,
		auth TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	_, err = db.Exec(`
		INSERT OR REPLACE INTO web_push_subscriptions (user_id, endpoint, p256dh, auth, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, claims.UserID, req.Endpoint, req.Keys.P256DH, req.Keys.Auth, time.Now().UTC())
	if err != nil {
		DefaultLogger.Warn("web_push_keys_store_error", map[string]interface{}{"error": err.Error()})
		// Non-fatal — the device token is already registered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "subscribed"})
}

// handleWebPushUnsubscribe handles POST /push/web-unsubscribe
// Removes a web push subscription
func handleWebPushUnsubscribe(w http.ResponseWriter, r *http.Request) {
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
		Endpoint string `json:"endpoint"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Endpoint == "" {
		writeJSONError(w, http.StatusBadRequest, "endpoint is required")
		return
	}

	db.Exec("DELETE FROM device_tokens WHERE user_id = ? AND device_token = ? AND platform = 'web'", claims.UserID, req.Endpoint)
	db.Exec("DELETE FROM web_push_subscriptions WHERE user_id = ? AND endpoint = ?", claims.UserID, req.Endpoint)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "unsubscribed"})
}
