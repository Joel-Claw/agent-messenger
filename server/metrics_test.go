package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthEndpoint(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health status = %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse health response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("health status = %v, want ok", result["status"])
	}
	if _, ok := result["uptime_seconds"]; !ok {
		t.Error("health response missing uptime_seconds")
	}
	if _, ok := result["version"]; !ok {
		t.Error("health response missing version")
	}
	if _, ok := result["messages_in"]; !ok {
		t.Error("health response missing messages_in")
	}
	if _, ok := result["agents_connected"]; !ok {
		t.Error("health response missing agents_connected")
	}
	if _, ok := result["goroutines"]; !ok {
		t.Error("health response missing goroutines")
	}
	if _, ok := result["db"]; !ok {
		t.Error("health response missing db connectivity status")
	}
}

func TestHealthRejectsPost(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("health POST status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	ServerMetrics = NewMetrics(hub)
	// Increment some counters to verify they show up
	ServerMetrics.MessagesIn.Add(42)
	ServerMetrics.MessagesOut.Add(10)
	ServerMetrics.ConnectionsTotal.Add(3)
	ServerMetrics.ErrorsTotal.Add(1)
	ServerMetrics.RateLimited.Add(2)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("metrics status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	// Check for Prometheus-format metrics
	expectedMetrics := []string{
		"agent_messenger_messages_in_total",
		"agent_messenger_messages_out_total",
		"agent_messenger_connections_total",
		"agent_messenger_agents_connected",
		"agent_messenger_clients_connected",
		"agent_messenger_errors_total",
		"agent_messenger_rate_limited_total",
		"agent_messenger_uptime_seconds",
		"agent_messenger_goroutines",
		"agent_messenger_memory_alloc_bytes",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("metrics missing %q", metric)
		}
	}

	// Check counter values
	if !strings.Contains(body, "agent_messenger_messages_in_total 42") {
		t.Errorf("messages_in_total not 42, got:\n%s", body)
	}
	if !strings.Contains(body, "agent_messenger_connections_total 3") {
		t.Errorf("connections_total not 3, got:\n%s", body)
	}
	if !strings.Contains(body, "agent_messenger_errors_total 1") {
		t.Errorf("errors_total not 1, got:\n%s", body)
	}
	if !strings.Contains(body, "agent_messenger_rate_limited_total 2") {
		t.Errorf("rate_limited_total not 2, got:\n%s", body)
	}

	// Check Prometheus format (TYPE and HELP headers)
	if !strings.Contains(body, "# TYPE agent_messenger_messages_in_total counter") {
		t.Error("missing TYPE header for messages_in_total")
	}
	if !strings.Contains(body, "# HELP agent_messenger_messages_in_total Total messages received") {
		t.Error("missing HELP header for messages_in_total")
	}
}

func TestMetricsRejectsPost(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("metrics POST status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestMetricsContentType(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("metrics content-type = %q, want text/plain", ct)
	}
}

func TestMetricsSnapshotUptime(t *testing.T) {
	hub := newHub()
	ServerMetrics = NewMetrics(hub)

	// Uptime should be very small (just created)
	snapshot := ServerMetrics.Snapshot()
	uptime, ok := snapshot["uptime_seconds"].(int)
	if !ok {
		t.Fatalf("uptime_seconds is not int, got %T", snapshot["uptime_seconds"])
	}
	if uptime > 10 {
		t.Errorf("uptime_seconds = %d, expected near 0", uptime)
	}

	// Wait a bit and check again
	time.Sleep(2 * time.Second)
	snapshot = ServerMetrics.Snapshot()
	uptime = snapshot["uptime_seconds"].(int)
	if uptime < 1 {
		t.Errorf("uptime_seconds = %d after 2s sleep, expected >= 1", uptime)
	}
}

func TestMetricsSnapshotVersion(t *testing.T) {
	hub := newHub()
	ServerMetrics = NewMetrics(hub)

	snapshot := ServerMetrics.Snapshot()
	version, ok := snapshot["version"].(string)
	if !ok {
		t.Fatalf("version is not string, got %T", snapshot["version"])
	}
	if version != "0.2.0" {
		t.Errorf("version = %q, want 0.2.0", version)
	}
}

func TestMetricsAtomicCounters(t *testing.T) {
	hub := newHub()
	ServerMetrics = NewMetrics(hub)

	// Simulate concurrent increments
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			ServerMetrics.MessagesIn.Add(1)
			ServerMetrics.ErrorsTotal.Add(1)
			done <- true
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}

	if ServerMetrics.MessagesIn.Load() != 100 {
		t.Errorf("MessagesIn = %d, want 100", ServerMetrics.MessagesIn.Load())
	}
	if ServerMetrics.ErrorsTotal.Load() != 100 {
		t.Errorf("ErrorsTotal = %d, want 100", ServerMetrics.ErrorsTotal.Load())
	}
}

func TestHealthReflectsHubState(t *testing.T) {
	hub := newHub()
	go hub.run()
	defer hub.Stop()

	ServerMetrics = NewMetrics(hub)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)

	// No connections — should be 0
	agents := result["agents_connected"]
	if agents != float64(0) {
		t.Errorf("agents_connected = %v, want 0", agents)
	}
	clients := result["clients_connected"]
	if clients != float64(0) {
		t.Errorf("clients_connected = %v, want 0", clients)
	}
}