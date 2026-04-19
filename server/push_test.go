package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegisterDeviceToken(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	userID, token := createPushTestUser(t, "pushuser@test.com", "password123")

	tests := []struct {
		name       string
		method     string
		body       string
		authToken  string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "valid registration",
			method:     "POST",
			body:       `{"device_token":"abc123def456","platform":"ios"}`,
			authToken:  token,
			wantStatus: http.StatusOK,
			wantBody:   `"status":"ok"`,
		},
		{
			name:       "missing device_token",
			method:     "POST",
			body:       `{"platform":"ios"}`,
			authToken:  token,
			wantStatus: http.StatusBadRequest,
			wantBody:   "device_token is required",
		},
		{
			name:       "unauthorized - no token",
			method:     "POST",
			body:       `{"device_token":"abc123","platform":"ios"}`,
			authToken:  "",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "",
		},
		{
			name:       "wrong method",
			method:     "GET",
			body:       "",
			authToken:  token,
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/push/register", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.authToken)
			}

			rr := httptest.NewRecorder()
			handleRegisterDeviceToken(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d; body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantBody != "" && !strings.Contains(rr.Body.String(), tt.wantBody) {
				t.Errorf("body: want %q in %q", tt.wantBody, rr.Body.String())
			}
		})
	}

	// Verify token is in database
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM device_tokens WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		t.Fatalf("Error querying device_tokens: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 device token, got %d", count)
	}
}

func TestUnregisterDeviceToken(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	_, token := createPushTestUser(t, "unreguser@test.com", "password123")

	// First register
	body := `{"device_token":"abc123def456","platform":"ios"}`
	req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handleRegisterDeviceToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("register failed: %d %s", rr.Code, rr.Body.String())
	}

	// Now unregister
	req = httptest.NewRequest("DELETE", "/push/unregister", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	handleUnregisterDeviceToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("unregister: got %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify token is gone
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM device_tokens").Scan(&count)
	if err != nil {
		t.Fatalf("Error querying device_tokens: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 device tokens after unregister, got %d", count)
	}
}

func TestGetDeviceTokensForUser(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM device_tokens")
	db.Exec("DELETE FROM users")

	userID, token := createPushTestUser(t, "tokens@test.com", "password123")

	devices := []string{"token_ios_1", "token_ios_2"}
	for _, dt := range devices {
		body := `{"device_token":"` + dt + `","platform":"ios"}`
		req := httptest.NewRequest("POST", "/push/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handleRegisterDeviceToken(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("register failed for %s: %d", dt, rr.Code)
		}
	}

	tokens, err := getDeviceTokensForUser(userID)
	if err != nil {
		t.Fatalf("Error getting tokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestTruncateHelper(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10ch", 10, "exactly..."},
		{"this is a longer string", 10, "this is..."},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestNotifyUserWhenDisabled(t *testing.T) {
	// When push is disabled, notifyUser should be a no-op (no crash)
	// pushConfig is nil in tests, so the nil check should handle it
	notifyUser("test-user", "Test", "Body", "conv-1")
	// If we got here without panicking, the test passes
}

// Helper to create a test user and get their auth token
func createPushTestUser(t *testing.T, email, password string) (userID, authToken string) {
	t.Helper()

	// Register using form values
	form := url.Values{"email": {email}, "password": {password}}.Encode()
	req := httptest.NewRequest("POST", "/auth/user", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRegisterUser(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("register user failed: %d %s", rr.Code, rr.Body.String())
	}

	var regResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &regResp)
	userID = regResp["user_id"]

	// Login to get token
	form = url.Values{"email": {email}, "password": {password}}.Encode()
	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rr.Code, rr.Body.String())
	}

	var authResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &authResp)
	authToken = authResp["token"]

	return userID, authToken
}