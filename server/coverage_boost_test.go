package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIsUniqueViolation tests the unique constraint violation checker
func TestIsUniqueViolationDirect(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "UNIQUE constraint failed",
			err:  errors.New("UNIQUE constraint failed: users.username"),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("no such table: users"),
			want: false,
		},
		{
			name: "partial match",
			err:  errors.New("sqlite3: UNIQUE constraint failed: conversations.id"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUniqueViolation(tt.err)
			if got != tt.want {
				t.Errorf("isUniqueViolation() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetClientNoConnections tests GetClient with no connections
func TestGetClientNoConnections(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	conn := hub.GetClient("nonexistent")
	if conn != nil {
		t.Error("expected nil for nonexistent client")
	}
}

// TestHubAgentStatusDirect tests agent status without WebSocket
func TestHubAgentStatusDirect(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	// Nonexistent agent should be offline
	status := hub.AgentStatus("nonexistent")
	if status != "offline" {
		t.Errorf("expected offline, got %s", status)
	}

	// Set status on nonexistent agent (should not panic)
	hub.SetAgentStatus("ghost", "busy")
	status = hub.AgentStatus("ghost")
	// ghost has no connection, so it should still be offline
	if status != "offline" {
		t.Errorf("expected offline for disconnected agent, got %s", status)
	}
}

// TestHubCountsEmpty tests counts with empty hub
func TestHubCountsEmpty(t *testing.T) {
	setupTestDB(t)
	hub = newHub()
	go hub.run()
	defer hub.Stop()

	if hub.AgentCount() != 0 {
		t.Errorf("expected 0 agents, got %d", hub.AgentCount())
	}
	if hub.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", hub.ClientCount())
	}
	if hub.ClientConnCount() != 0 {
		t.Errorf("expected 0 client connections, got %d", hub.ClientConnCount())
	}
}

// TestHubStopAndCheckStale tests hub Stop and stale agent checker
func TestHubStopAndCheckStale(t *testing.T) {
	h := newHub()
	go h.run()

	// Stop should not panic
	h.Stop()

	// Stale check should not panic on empty hub
	h.checkStaleAgents()
}

// TestRateLimiterCleanDirect tests rate limiter cleanup
func TestRateLimiterCleanDirect(t *testing.T) {
	rl := NewRateLimiter(100, 50*time.Millisecond)

	// Fill the limiter
	for i := 0; i < 10; i++ {
		rl.Allow("clean-test")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Clean should remove expired entries without panic
	// (Clean is called internally by rateLimiter, but we verify the
	//  Allow method still works after expiry)
	result := rl.Allow("clean-test")
	if !result {
		t.Error("expected Allow to return true after expiry and cleanup")
	}
}

// TestOfflineQueueCreation tests queue creation parameters
func TestOfflineQueueCreation(t *testing.T) {
	q := newOfflineQueue(50, time.Hour)
	if q == nil {
		t.Fatal("expected non-nil queue")
	}
	if q.TotalDepth() != 0 {
		t.Errorf("expected 0 total depth, got %d", q.TotalDepth())
	}

	// Purge empty queue should not panic
	q.Purge("nonexistent")
}

// TestOfflineQueueMultiUser tests queue with multiple users
func TestOfflineQueueMultiUser(t *testing.T) {
	q := newOfflineQueue(5, time.Hour)

	q.Enqueue("user1", []byte(`{"type":"message","content":"hello1"}`))
	q.Enqueue("user1", []byte(`{"type":"message","content":"hello2"}`))
	q.Enqueue("user2", []byte(`{"type":"message","content":"hello3"}`))

	if q.TotalDepth() != 3 {
		t.Errorf("expected total depth 3, got %d", q.TotalDepth())
	}

	// Drain user1
	msgs1 := q.Drain("user1")
	if len(msgs1) != 2 {
		t.Fatalf("expected 2 messages for user1, got %d", len(msgs1))
	}

	// user2 should still have 1 message queued
	if q.TotalDepth() != 1 {
		t.Errorf("expected total depth 1, got %d", q.TotalDepth())
	}

	// Drain user2
	msgs2 := q.Drain("user2")
	if len(msgs2) != 1 {
		t.Fatalf("expected 1 message for user2, got %d", len(msgs2))
	}

	// Both should be empty now
	if q.TotalDepth() != 0 {
		t.Errorf("expected total depth 0 after drain, got %d", q.TotalDepth())
	}
}

// TestWriteJSONErrorResponse verifies JSON error response format
func TestWriteJSONErrorResponseFormat(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusTooManyRequests, "rate limited")

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.Contains(body, "rate limited") {
		t.Errorf("expected error message in body, got %s", body)
	}
}

// TestProtocolVersionNegotiation tests protocol version handling
func TestProtocolVersionNegotiation(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{"supported v1", "v1", true},
		{"unsupported v99", "v99", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSupportedVersion(tt.version)
			if got != tt.want {
				t.Errorf("isSupportedVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}