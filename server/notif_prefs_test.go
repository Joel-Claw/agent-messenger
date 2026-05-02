package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// authGetReq creates an authenticated GET request with user ID in context.
func authGetReq(path, token string) *http.Request {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	claims, _ := ValidateJWT(token)
	if claims != nil {
		ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
		req = req.WithContext(ctx)
	}
	return req
}

// authPostReq creates an authenticated POST request with form values and user ID in context.
func authPostReq(path, token string, form url.Values) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	claims, _ := ValidateJWT(token)
	if claims != nil {
		ctx := context.WithValue(req.Context(), contextKeyUserID, claims.UserID)
		req = req.WithContext(ctx)
	}
	return req
}

func TestGetNotificationPrefsEmpty(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notifuser1")

	req := authGetReq("/notification-prefs", token)
	w := httptest.NewRecorder()
	handleGetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var prefs []NotificationPreferences
	json.Unmarshal(w.Body.Bytes(), &prefs)
	if len(prefs) != 0 {
		t.Fatalf("expected empty prefs, got %d", len(prefs))
	}
}

func TestSetAndGetNotificationPrefs(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notifuser2")
	createTestAgent(t, "notifagent1", "notif-bot")
	convID := createTestConversation(t, token, "notifagent1")

	// Set muted
	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var pref NotificationPreferences
	json.Unmarshal(w.Body.Bytes(), &pref)
	if !pref.Muted {
		t.Fatal("expected muted=true")
	}

	// Get prefs
	req2 := authGetReq("/notification-prefs", token)
	w2 := httptest.NewRecorder()
	handleGetNotificationPrefs(w2, req2)

	var prefs []NotificationPreferences
	json.Unmarshal(w2.Body.Bytes(), &prefs)
	if len(prefs) != 1 {
		t.Fatalf("expected 1 pref, got %d", len(prefs))
	}
	if !prefs[0].Muted {
		t.Fatal("expected muted=true")
	}
}

func TestSetNotificationPrefsUnmute(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notifuser3")
	createTestAgent(t, "notifagent2", "unmute-bot")
	convID := createTestConversation(t, token, "notifagent2")

	// Mute
	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	// Unmute
	req2 := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"false"},
	})
	w2 := httptest.NewRecorder()
	handleSetNotificationPrefs(w2, req2)

	var pref NotificationPreferences
	json.Unmarshal(w2.Body.Bytes(), &pref)
	if pref.Muted {
		t.Fatal("expected muted=false after unmute")
	}
}

func TestSetNotificationPrefsNotOwner(t *testing.T) {
	setupTestDB(t)
	ownerToken := createTestUser(t, "notifowner")
	token2 := createTestUser(t, "notifother")
	createTestAgent(t, "notifagent3", "owner-bot")
	convID := createTestConversation(t, ownerToken, "notifagent3")

	// Try to set pref on someone else's conversation
	req := authPostReq("/notification-prefs/set", token2, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestSetNotificationPrefsMissingID(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notifuser4")

	req := authPostReq("/notification-prefs/set", token, url.Values{})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDeleteNotificationPrefs(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notifuser5")
	createTestAgent(t, "notifagent4", "delete-bot")
	convID := createTestConversation(t, token, "notifagent4")

	// Set muted
	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	// Delete pref
	req2 := authPostReq("/notification-prefs/delete", token, url.Values{
		"conversation_id": {convID},
	})
	w2 := httptest.NewRecorder()
	handleDeleteNotificationPrefs(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	// Verify empty
	req3 := authGetReq("/notification-prefs", token)
	w3 := httptest.NewRecorder()
	handleGetNotificationPrefs(w3, req3)

	var prefs []NotificationPreferences
	json.Unmarshal(w3.Body.Bytes(), &prefs)
	if len(prefs) != 0 {
		t.Fatalf("expected empty prefs after delete, got %d", len(prefs))
	}
}

func TestIsConversationMuted(t *testing.T) {
	setupTestDB(t)
	token := createTestUser(t, "notifuser6")
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Invalid token: %v", err)
	}
	createTestAgent(t, "notifagent5", "mute-check-bot")
	convID := createTestConversation(t, token, "notifagent5")

	// Not muted by default
	if isConversationMuted(claims.UserID, convID) {
		t.Fatal("expected not muted by default")
	}

	// Mute it
	req := authPostReq("/notification-prefs/set", token, url.Values{
		"conversation_id": {convID},
		"muted":           {"true"},
	})
	w := httptest.NewRecorder()
	handleSetNotificationPrefs(w, req)

	if !isConversationMuted(claims.UserID, convID) {
		t.Fatal("expected muted after set")
	}
}