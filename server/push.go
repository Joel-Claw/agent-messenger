package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	APNSEnabled  bool
	CertPath     string // Path to .p8 or .p12 certificate
	Password     string // Password for .p12 (empty for .p8)
	KeyID        string // Key ID for .p8 token
	TeamID       string // Team ID for .p8 token
	BundleID     string // App bundle ID (e.g., com.agentmessenger.ios)
	Environment  string // "production" or "development"

	FCMEnabled     bool
	FCMCredentials string // Path to Firebase service account JSON

	apnsClient *apns2.Client
	fcmClient  *messaging.Client
}

var pushConfig *PushNotificationConfig

// initPushNotifications initializes push notification clients (APNs + FCM)
func initPushNotifications() {
	pushConfig = &PushNotificationConfig{
		APNSEnabled:  os.Getenv("APNS_ENABLED") == "true",
		CertPath:     os.Getenv("APNS_CERT_PATH"),
		Password:     os.Getenv("APNS_CERT_PASSWORD"),
		KeyID:        os.Getenv("APNS_KEY_ID"),
		TeamID:       os.Getenv("APNS_TEAM_ID"),
		BundleID:     getEnvOrDefault("APNS_BUNDLE_ID", "com.agentmessenger.ios"),
		Environment:  getEnvOrDefault("APNS_ENVIRONMENT", "development"),
		FCMEnabled:   os.Getenv("FCM_ENABLED") == "true",
		FCMCredentials: os.Getenv("FCM_CREDENTIALS_PATH"),
	}

	// Initialize APNs
	initAPNs()

	// Initialize FCM
	initFCM()
}

func initAPNs() {
	if !pushConfig.APNSEnabled {
		log.Println("APNs push notifications disabled (APNS_ENABLED not set)")
		return
	}

	if pushConfig.CertPath == "" {
		log.Println("WARNING: APNS_ENABLED but no APNS_CERT_PATH set, APNs will fail")
		return
	}

	if dir := filepath.Dir(pushConfig.CertPath); dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}

	if _, err := os.Stat(pushConfig.CertPath); err != nil {
		log.Printf("WARNING: APNs certificate not found at %s: %v", pushConfig.CertPath, err)
		log.Println("APNs will be unavailable until certificate is installed")
		pushConfig.APNSEnabled = false
		return
	}

	cert, err := certificate.FromP12File(pushConfig.CertPath, pushConfig.Password)
	if err != nil {
		log.Printf("WARNING: Failed to load APNs certificate: %v", err)
		pushConfig.APNSEnabled = false
		return
	}

	if pushConfig.Environment == "production" {
		pushConfig.apnsClient = apns2.NewClient(cert).Production()
	} else {
		pushConfig.apnsClient = apns2.NewClient(cert).Development()
	}

	log.Printf("APNs push notifications enabled (%s)", pushConfig.Environment)
}

func initFCM() {
	if !pushConfig.FCMEnabled {
		log.Println("FCM push notifications disabled (FCM_ENABLED not set)")
		return
	}

	if pushConfig.FCMCredentials == "" {
		log.Println("WARNING: FCM_ENABLED but no FCM_CREDENTIALS_PATH set, FCM will fail")
		return
	}

	if _, err := os.Stat(pushConfig.FCMCredentials); err != nil {
		log.Printf("WARNING: FCM credentials not found at %s: %v", pushConfig.FCMCredentials, err)
		log.Println("FCM will be unavailable until credentials are installed")
		pushConfig.FCMEnabled = false
		return
	}

	ctx := context.Background()
	app, err := firebase.NewApp(ctx, nil, option.WithCredentialsFile(pushConfig.FCMCredentials))
	if err != nil {
		log.Printf("WARNING: Failed to initialize Firebase app: %v", err)
		pushConfig.FCMEnabled = false
		return
	}

	client, err := app.Messaging(ctx)
	if err != nil {
		log.Printf("WARNING: Failed to create FCM client: %v", err)
		pushConfig.FCMEnabled = false
		return
	}

	pushConfig.fcmClient = client
	log.Println("FCM push notifications enabled")
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
		log.Printf("APNs push rejected for %s...%s: %s", deviceToken[:8], deviceToken[len(deviceToken)-8:], response.Reason)
		return nil
	}

	log.Printf("APNs notification sent to %s...%s", deviceToken[:8], deviceToken[len(deviceToken)-8:])
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

	log.Printf("FCM notification sent to %s...%s", deviceToken[:8], deviceToken[len(deviceToken)-8:])
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

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil || len(tokens) == 0 {
		return
	}

	for _, t := range tokens {
		if err := sendPushNotification(t.Token, title, body, conversationID, t.Platform); err != nil {
			log.Printf("Failed to send push to %s (%s): %v", t.Token[:8], t.Platform, err)
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