package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func setupWebPushTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/user", handleRegisterUser)
	mux.HandleFunc("/push/vapid-key", handleGetVAPIDKey)
	mux.HandleFunc("/push/web-subscribe", handleWebPushSubscribe)
	mux.HandleFunc("/push/web-unsubscribe", handleWebPushUnsubscribe)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// Register a test user and get token
	form := url.Values{}
	form.Set("username", "webpush_tester")
	form.Set("password", "testpass123")
	resp, err := http.PostForm(server.URL+"/auth/user", form)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	defer resp.Body.Close()

	var regResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&regResp)

	// Login to get token
	loginForm := url.Values{}
	loginForm.Set("username", "webpush_tester")
	loginForm.Set("password", "testpass123")
	loginResp, err := http.PostForm(server.URL+"/auth/login", loginForm)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	defer loginResp.Body.Close()

	var loginData map[string]interface{}
	json.NewDecoder(loginResp.Body).Decode(&loginData)
	token, ok := loginData["token"].(string)
	if !ok {
		t.Fatalf("No token in login response: %v", loginData)
	}

	return server, token
}

func TestGetVAPIDKey(t *testing.T) {
	server, token := setupWebPushTestServer(t)

	// Without VAPID key configured
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	vapidPublicKey = ""
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 without VAPID key, got %d", w.Code)
	}

	// With VAPID key configured
	vapidPublicKey = "test-vapid-public-key-base64"
	defer func() { vapidPublicKey = "" }()

	req2 := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	handleGetVAPIDKey(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w2.Code)
	}

	var resp map[string]string
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["public_key"] != "test-vapid-public-key-base64" {
		t.Errorf("Expected VAPID key, got %v", resp)
	}

	_ = server // avoid unused variable
}

func TestGetVAPIDKeyAuth(t *testing.T) {
	setupWebPushTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	handleGetVAPIDKey(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without auth, got %d", w.Code)
	}
}

func TestWebPushSubscribe(t *testing.T) {
	_, token := setupWebPushTestServer(t)

	body := `{"endpoint":"https://push.example.com/sub/123","keys":{"p256dh":"BEl62iUYR4F8s","auth":"tBWV4n9"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "subscribed" {
		t.Errorf("Expected status subscribed, got %v", resp)
	}
}

func TestWebPushSubscribeMissingFields(t *testing.T) {
	_, token := setupWebPushTestServer(t)

	body := `{"endpoint":"https://push.example.com/sub/123","keys":{"p256dh":"","auth":"abc"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWebPushSubscribe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing keys, got %d", w.Code)
	}
}

func TestWebPushUnsubscribe(t *testing.T) {
	_, token := setupWebPushTestServer(t)

	// First subscribe
	body := `{"endpoint":"https://push.example.com/sub/456","keys":{"p256dh":"key123","auth":"auth123"}}`
	req := httptest.NewRequest(http.MethodPost, "/push/web-subscribe", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleWebPushSubscribe(w, req)

	// Then unsubscribe
	unsubBody := `{"endpoint":"https://push.example.com/sub/456"}`
	req2 := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", bytes.NewBufferString(unsubBody))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handleWebPushUnsubscribe(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w2.Code)
	}

	var resp map[string]string
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["status"] != "unsubscribed" {
		t.Errorf("Expected status unsubscribed, got %v", resp)
	}
}

func TestWebPushUnsubscribeAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/push/web-unsubscribe", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	handleWebPushUnsubscribe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without auth, got %d", w.Code)
	}
}