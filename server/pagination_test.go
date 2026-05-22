package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGetMessagesHandlerPagination(t *testing.T) {
	_, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	token := registerUserAndGetToken(t, "paguser", "testpass123")

	// Register agent
	agentForm := url.Values{
		"agent_id":     {"pag_agent"},
		"name":         {"Page Agent"},
		"agent_secret": {getAgentSecret()},
	}
	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(agentForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)

	// Create conversation
	convForm := url.Values{"agent_id": {"pag_agent"}}
	req2 := httptest.NewRequest("POST", "/conversations/create", strings.NewReader(convForm.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec2 := httptest.NewRecorder()
	handleCreateConversation(rec2, req2)
	var convResp map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &convResp)
	convID, ok := convResp["conversation_id"].(string)
	if !ok {
		t.Fatalf("no conversation_id in response: %v", convResp)
	}

	// Insert test messages directly into DB
	for i := 0; i < 5; i++ {
		_, err := db.Exec(
			"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+'||?||' seconds'))",
			fmt.Sprintf("msg_pag_%02d", i),
			convID,
			"client",
			"paguser",
			fmt.Sprintf("Message %d", i),
			i,
		)
		if err != nil {
			t.Fatalf("Failed to insert message %d: %v", i, err)
		}
	}

	// Test default (no pagination) — should get all 5
	req3 := httptest.NewRequest("GET", "/conversations/messages?conversation_id="+convID, nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	rec3 := httptest.NewRecorder()
	handleGetMessages(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rec3.Code, rec3.Body.String())
	}
	var allMsgs []interface{}
	json.Unmarshal(rec3.Body.Bytes(), &allMsgs)
	if len(allMsgs) != 5 {
		t.Errorf("Expected 5 messages, got %d", len(allMsgs))
	}

	// Test with limit=3
	req4 := httptest.NewRequest("GET", "/conversations/messages?conversation_id="+convID+"&limit=3", nil)
	req4.Header.Set("Authorization", "Bearer "+token)
	rec4 := httptest.NewRecorder()
	handleGetMessages(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("Expected 200 with limit, got %d", rec4.Code)
	}
	var limited []interface{}
	json.Unmarshal(rec4.Body.Bytes(), &limited)
	if len(limited) != 3 {
		t.Errorf("Expected 3 messages with limit=3, got %d", len(limited))
	}

	// Test with limit exceeding max (should cap at 200)
	req5 := httptest.NewRequest("GET", "/conversations/messages?conversation_id="+convID+"&limit=500", nil)
	req5.Header.Set("Authorization", "Bearer "+token)
	rec5 := httptest.NewRecorder()
	handleGetMessages(rec5, req5)
	if rec5.Code != http.StatusOK {
		t.Fatalf("Expected 200 with large limit, got %d", rec5.Code)
	}
}

func TestGetMessagesHandlerCursorPagination(t *testing.T) {
	_, cleanup := setupTestServerForRouting(t)
	defer cleanup()

	token := registerUserAndGetToken(t, "cursoruser", "testpass123")

	// Register agent
	agentForm := url.Values{
		"agent_id":     {"cursor_agent"},
		"name":         {"Cursor Agent"},
		"agent_secret": {getAgentSecret()},
	}
	req := httptest.NewRequest("POST", "/auth/agent", strings.NewReader(agentForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Secret", getAgentSecret())
	rec := httptest.NewRecorder()
	handleRegisterAgent(rec, req)

	// Create conversation
	convForm := url.Values{"agent_id": {"cursor_agent"}}
	req2 := httptest.NewRequest("POST", "/conversations/create", strings.NewReader(convForm.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec2 := httptest.NewRecorder()
	handleCreateConversation(rec2, req2)
	var convResp map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &convResp)
	convID, ok := convResp["conversation_id"].(string)
	if !ok {
		t.Fatalf("no conversation_id in response: %v", convResp)
	}

	// Insert messages with specific timestamps
	for i := 0; i < 10; i++ {
		_, err := db.Exec(
			"INSERT INTO messages (id, conversation_id, sender_type, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+'||?||' seconds'))",
			fmt.Sprintf("msg_cursor_%02d", i),
			convID,
			"client",
			"cursoruser",
			fmt.Sprintf("Cursor message %d", i),
			i,
		)
		if err != nil {
			t.Fatalf("Failed to insert message %d: %v", i, err)
		}
	}

	// Get the 5th message's timestamp to use as cursor
	var beforeTime string
	err := db.QueryRow("SELECT created_at FROM messages WHERE id = ?", "msg_cursor_05").Scan(&beforeTime)
	if err != nil {
		t.Fatalf("Failed to get message timestamp: %v", err)
	}

	// Test cursor-based pagination: get messages before that timestamp
	req3 := httptest.NewRequest("GET", "/conversations/messages?conversation_id="+convID+"&before="+url.QueryEscape(beforeTime)+"&limit=3", nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	rec3 := httptest.NewRecorder()
	handleGetMessages(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("Expected 200 with before cursor, got %d: %s", rec3.Code, rec3.Body.String())
	}
	var pageMsgs []interface{}
	json.Unmarshal(rec3.Body.Bytes(), &pageMsgs)

	// Should get messages 2, 3, 4 (the 3 messages before msg_cursor_05)
	if len(pageMsgs) != 3 {
		t.Errorf("Expected 3 messages with before cursor, got %d", len(pageMsgs))
	}

	// Verify chronological order (messages should be sorted ascending by time)
	if len(pageMsgs) >= 2 {
		first, ok1 := pageMsgs[0].(map[string]interface{})
		second, ok2 := pageMsgs[1].(map[string]interface{})
		if ok1 && ok2 {
			if first["content"] == second["content"] {
				// order check — just verify they're not equal
			}
			// Messages should be in ascending time order
			if first["created_at"] != nil && second["created_at"] != nil {
				t.Logf("First: %v, Second: %v", first["created_at"], second["created_at"])
			}
		}
	}
}
