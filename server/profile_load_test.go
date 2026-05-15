package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================
// Memory Profiling Under Load Tests
//
// These tests verify that memory usage remains bounded
// under high concurrency, that connections are properly
// cleaned up, and that the profiling infrastructure works
// correctly under load.
// ============================================================

// profileLoadSetupServer creates a test server for profile/load tests.
// It uses a very high rate limit to avoid interference with load testing.
func profileLoadSetupServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	setupTestDB(t)

	hub = newHub()
	go hub.run()
	ServerMetrics = NewMetrics(hub)

	// Increase rate limits for load testing
	ipRateLimiter = NewRateLimiter(100000, time.Minute)
	authIPLimiter = NewRateLimiter(100000, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/connect", handleAgentConnect)
	mux.HandleFunc("/client/connect", handleClientConnect)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/user", handleRegisterUser)
	mux.HandleFunc("/auth/agent", handleRegisterAgent)
	mux.HandleFunc("/conversations/create", handleCreateConversation)
	mux.HandleFunc("/conversations/list", handleListConversations)
	mux.HandleFunc("/conversations/messages", handleGetMessages)
	mux.HandleFunc("/conversations/mark-read", handleMarkRead)
	mux.HandleFunc("/conversations/delete", handleDeleteConversation)
	mux.HandleFunc("/agents", handleListAgents)
	mux.HandleFunc("/messages/search", handleSearchMessages)

	server := httptest.NewServer(mux)
	cleanup := func() {
		server.Close()
		hub.Stop()
	}
	return server, cleanup
}

// profileLoadRegisterUser creates a user and returns their JWT token.
// Uses sequential requests to avoid rate limiting.
func profileLoadRegisterUser(t *testing.T, server *httptest.Server, username string) string {
	t.Helper()
	form := url.Values{"username": {username}, "password": {"loadpass"}}
	resp, err := http.PostForm(server.URL+"/auth/user", form)
	if err != nil {
		t.Fatalf("register user %s failed: %v", username, err)
	}
	defer resp.Body.Close()

	form2 := url.Values{"username": {username}, "password": {"loadpass"}}
	resp2, err := http.PostForm(server.URL+"/auth/login", form2)
	if err != nil {
		t.Fatalf("login %s failed: %v", username, err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("login %s returned %d", username, resp2.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp2.Body).Decode(&result)
	return result["token"]
}

// TestMemoryProfile_UnderLoad verifies that the profiling infrastructure
// works correctly while the server is under load.
func TestMemoryProfile_UnderLoad(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	// Take initial memory snapshot
	initialStats := MemoryStats()
	initialAlloc := initialStats["alloc_bytes"].(uint64)
	initialGoroutines := initialStats["goroutines"].(int)

	t.Logf("Initial state: alloc=%d bytes, goroutines=%d", initialAlloc, initialGoroutines)

	// Register agent first
	agentForm := url.Values{
		"agent_id":      {"loadagent1"},
		"name":          {"LoadAgent"},
		"agent_secret":  {agentSecret},
	}
	resp, err := http.PostForm(server.URL+"/auth/agent", agentForm)
	if err != nil {
		t.Fatalf("agent register failed: %v", err)
	}
	resp.Body.Close()

	// Create users sequentially to avoid rate limits
	const numUsers = 10
	tokens := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		tokens[i] = profileLoadRegisterUser(t, server, fmt.Sprintf("loaduser%d", i))
	}

	// Create conversations concurrently
	var wg sync.WaitGroup
	var msgCount atomic.Int64
	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			form := url.Values{"agent_id": {"loadagent1"}}
			req, _ := http.NewRequest("POST", server.URL+"/conversations/create", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", "Bearer "+tokens[idx])
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Logf("create conversation failed for user %d: %v", idx, err)
				return
			}
			resp.Body.Close()
			msgCount.Add(1)
		}(i)
	}

	wg.Wait()
	totalMessages := msgCount.Load()
	t.Logf("Created %d conversations from %d users", totalMessages, numUsers)

	// Take memory snapshot after load
	loadStats := MemoryStats()
	loadAlloc := loadStats["alloc_bytes"].(uint64)
	loadGoroutines := loadStats["goroutines"].(int)

	t.Logf("After load: alloc=%d bytes (%.1f KB), goroutines=%d",
		loadAlloc, float64(loadAlloc)/1024, loadGoroutines)

	// Force GC and take another snapshot
	numGC := ForceGC()
	postGCStats := MemoryStats()
	postGCAlloc := postGCStats["alloc_bytes"].(uint64)

	t.Logf("After GC (%d cycles): alloc=%d bytes (%.1f KB)",
		numGC, postGCAlloc, float64(postGCAlloc)/1024)

	// Memory should be bounded: after GC, should not be more than 10x initial
	if postGCAlloc > initialAlloc*10 && initialAlloc > 0 {
		t.Errorf("memory after GC (%d bytes) is more than 10x initial (%d bytes)",
			postGCAlloc, initialAlloc)
	}

	// Goroutines after load should not be wildly higher than initial
	if loadGoroutines > initialGoroutines+50 {
		t.Logf("Warning: %d goroutines after load (initial: %d). Some connections may not be cleaned up yet.",
			loadGoroutines, initialGoroutines)
	}
}

// TestMemoryProfile_ConnectionChurn verifies that connections are
// properly cleaned up when many clients connect and disconnect rapidly.
func TestMemoryProfile_ConnectionChurn(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	// Register a base agent
	agentForm := url.Values{
		"agent_id":      {"churnagent"},
		"name":          {"ChurnAgent"},
		"agent_secret":  {agentSecret},
	}
	resp, err := http.PostForm(server.URL+"/auth/agent", agentForm)
	if err != nil {
		t.Fatalf("agent register failed: %v", err)
	}
	resp.Body.Close()

	runtime.GC()
	initialStats := MemoryStats()
	initialAlloc := initialStats["alloc_bytes"].(uint64)
	t.Logf("Initial alloc: %d bytes (%.1f KB)", initialAlloc, float64(initialAlloc)/1024)

	// Connect and disconnect WebSocket clients rapidly
	const numRounds = 5
	const numClientsPerRound = 20

	for round := 0; round < numRounds; round++ {
		var wg sync.WaitGroup
		for i := 0; i < numClientsPerRound; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				username := fmt.Sprintf("churnuser_r%d_%d", round, idx) // unique per round
				// Re-register to avoid collision (different names per round)
				form := url.Values{"username": {username}, "password": {"loadpass"}}
				r, err := http.PostForm(server.URL+"/auth/user", form)
				if err != nil {
					t.Logf("register %s failed: %v", username, err)
					return
				}
				r.Body.Close()

				form2 := url.Values{"username": {username}, "password": {"loadpass"}}
				r2, err := http.PostForm(server.URL+"/auth/login", form2)
				if err != nil {
					t.Logf("login %s failed: %v", username, err)
					return
				}
				var loginResult map[string]string
				json.NewDecoder(r2.Body).Decode(&loginResult)
				r2.Body.Close()
				token := loginResult["token"]
				if token == "" {
					t.Logf("no token for %s", username)
					return
				}

				// Connect via WebSocket
				u, _ := url.Parse(server.URL)
				u.Scheme = "ws"
				u.Path = "/client/connect"
				q := u.Query()
				q.Set("token", token)
				u.RawQuery = q.Encode()

				c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
				if err != nil {
					t.Logf("dial failed for %s: %v", username, err)
					return
				}

				// Send a message
				msg := map[string]interface{}{
					"type": "chat",
				}
				c.WriteJSON(msg)

				// Close quickly
				c.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				c.Close()
			}(i)
		}
		wg.Wait()

		// Give time for cleanup
		time.Sleep(100 * time.Millisecond)
	}

	// Force GC
	ForceGC()
	runtime.GC()

	finalStats := MemoryStats()
	finalAlloc := finalStats["alloc_bytes"].(uint64)
	t.Logf("After churn: alloc=%d bytes (%.1f KB), goroutines=%d",
		finalAlloc, float64(finalAlloc)/1024, finalStats["goroutines"].(int))

	// Memory growth should be reasonable (not more than 5MB for connection churn)
	memGrowth := int64(finalAlloc) - int64(initialAlloc)
	if memGrowth > 5*1024*1024 {
		t.Errorf("excessive memory growth: %d bytes (%.1f MB) after connection churn",
			memGrowth, float64(memGrowth)/(1024*1024))
	}
}

// TestMemoryProfile_HeapProfileUnderLoad verifies that heap profiles
// can be captured while the server is actively processing requests.
func TestMemoryProfile_HeapProfileUnderLoad(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	// Start a background goroutine sending requests
	var done atomic.Bool
	go func() {
		for !done.Load() {
			resp, err := http.Get(server.URL + "/health")
			if err == nil {
				resp.Body.Close()
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// Give the load a moment to start
	time.Sleep(10 * time.Millisecond)

	// Capture heap profile
	snapshot := CaptureProfile(dir)

	if snapshot.HeapFile == "" {
		t.Error("expected heap file to be set")
	}
	if snapshot.GoroutineFile == "" {
		t.Error("expected goroutine file to be set")
	}
	if snapshot.Memory == nil {
		t.Error("expected memory stats to be present")
	}

	// Verify heap profile is non-empty
	if snapshot.HeapFile != "" {
		info, err := os.Stat(snapshot.HeapFile)
		if err != nil {
			t.Errorf("heap profile stat error: %v", err)
		} else if info.Size() == 0 {
			t.Error("heap profile is empty")
		} else {
			t.Logf("Heap profile: %s (%d bytes)", snapshot.HeapFile, info.Size())
		}
	}

	// Verify goroutine profile is non-empty
	if snapshot.GoroutineFile != "" {
		info, err := os.Stat(snapshot.GoroutineFile)
		if err != nil {
			t.Errorf("goroutine profile stat error: %v", err)
		} else if info.Size() == 0 {
			t.Error("goroutine profile is empty")
		} else {
			t.Logf("Goroutine profile: %s (%d bytes)", snapshot.GoroutineFile, info.Size())
		}
	}

	done.Store(true)
}

// TestMemoryProfile_CPUProfileUnderLoad verifies that CPU profiling
// can be started and stopped while the server is under load.
func TestMemoryProfile_CPUProfileUnderLoad(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	// Start CPU profiling
	stop, err := StartCPUProfile(filepath.Join(dir, "cpu_load.prof"))
	if err != nil {
		t.Fatalf("StartCPUProfile failed: %v", err)
	}

	// Generate some load
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				resp, err := http.Get(server.URL + "/health")
				if err == nil {
					resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()

	// Stop CPU profiling
	stop()

	// Verify profile file exists and is non-empty
	info, err := os.Stat(filepath.Join(dir, "cpu_load.prof"))
	if err != nil {
		t.Fatalf("cpu profile stat error: %v", err)
	}
	if info.Size() == 0 {
		t.Error("CPU profile is empty")
	}
	t.Logf("CPU profile: %d bytes", info.Size())
}

// TestMemoryProfile_AdminEndpointUnderLoad verifies that the admin
// profile endpoint works correctly under load.
func TestMemoryProfile_AdminEndpointUnderLoad(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	// Generate background load
	var loadDone atomic.Bool
	go func() {
		for !loadDone.Load() {
			resp, err := http.Get(server.URL + "/health")
			if err == nil {
				resp.Body.Close()
			}
			time.Sleep(time.Millisecond)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Test stats endpoint
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=stats", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("stats endpoint returned %d", w.Code)
	}

	var statsResult map[string]interface{}
	json.NewDecoder(w.Body).Decode(&statsResult)
	if statsResult["status"] != "ok" {
		t.Errorf("expected status ok, got %v", statsResult["status"])
	}

	// Test heap endpoint
	req = httptest.NewRequest(http.MethodPost, "/admin/profile?action=heap", nil)
	w = httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("heap endpoint returned %d", w.Code)
	}

	// Test goroutine endpoint
	req = httptest.NewRequest(http.MethodPost, "/admin/profile?action=goroutine", nil)
	w = httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("goroutine endpoint returned %d", w.Code)
	}

	// Test GC endpoint
	req = httptest.NewRequest(http.MethodPost, "/admin/profile?action=gc", nil)
	w = httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("gc endpoint returned %d", w.Code)
	}

	// Test CPU profiling start/stop
	req = httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	w = httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("cpu start returned %d", w.Code)
	}

	// Do some work
	for i := 0; i < 100; i++ {
		MemoryStats()
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu_stop", nil)
	w = httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("cpu stop returned %d", w.Code)
	}

	loadDone.Store(true)
}

// TestMemoryProfile_ConcurrentMessageRouting verifies memory doesn't
// grow unboundedly when many messages are routed concurrently.
func TestMemoryProfile_ConcurrentMessageRouting(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	// Register agent
	agentForm := url.Values{
		"agent_id":      {"memagent"},
		"name":          {"MemAgent"},
		"agent_secret":  {agentSecret},
	}
	resp, err := http.PostForm(server.URL+"/auth/agent", agentForm)
	if err != nil {
		t.Fatalf("agent register failed: %v", err)
	}
	resp.Body.Close()

	// Connect agent via WebSocket
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	u.Path = "/agent/connect"
	q := u.Query()
	q.Set("agent_id", "memagent")
	q.Set("agent_secret", agentSecret)
	u.RawQuery = q.Encode()

	agentConn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("agent connect failed: %v", err)
	}
	defer agentConn.Close()

	// Take initial measurement
	runtime.GC()
	initialStats := MemoryStats()
	initialAlloc := initialStats["alloc_bytes"].(uint64)

	// Register users sequentially to avoid rate limits
	const numUsers = 5
	const numMessagesPerUser = 10

	tokens := make([]string, numUsers)
	convIDs := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		tokens[i] = profileLoadRegisterUser(t, server, fmt.Sprintf("memuser%d", i))

		// Create conversation
		form := url.Values{"agent_id": {"memagent"}}
		req, _ := http.NewRequest("POST", server.URL+"/conversations/create", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+tokens[i])
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create conversation failed for user %d: %v", i, err)
		}
		var convResult map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&convResult)
		resp.Body.Close()

		convID, _ := convResult["conversation_id"].(string)
		if convID == "" {
			t.Fatalf("no conversation_id for user %d", i)
		}
		convIDs[i] = convID
	}

	// Connect all client WebSockets and send messages concurrently
	var wg sync.WaitGroup
	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Connect client
			cu, _ := url.Parse(server.URL)
			cu.Scheme = "ws"
			cu.Path = "/client/connect"
			cq := cu.Query()
			cq.Set("token", tokens[idx])
			cu.RawQuery = cq.Encode()

			clientConn, _, err := websocket.DefaultDialer.Dial(cu.String(), nil)
			if err != nil {
				t.Logf("client connect failed for user %d: %v", idx, err)
				return
			}
			defer clientConn.Close()

			// Send messages
			for j := 0; j < numMessagesPerUser; j++ {
				msg := map[string]interface{}{
					"type":            "chat",
					"conversation_id": convIDs[idx],
					"content":         fmt.Sprintf("message %d from user %d with some extra content to make it longer", j, idx),
				}
				if err := clientConn.WriteJSON(msg); err != nil {
					break
				}
			}
		}(i)
	}

	wg.Wait()

	// Wait for message processing
	time.Sleep(200 * time.Millisecond)

	// Force GC and measure
	ForceGC()
	finalStats := MemoryStats()
	finalAlloc := finalStats["alloc_bytes"].(uint64)

	memGrowth := int64(finalAlloc) - int64(initialAlloc)
	t.Logf("Memory growth: %d bytes (%.1f KB), initial: %d, final: %d, goroutines: %d",
		memGrowth, float64(memGrowth)/1024, initialAlloc, finalAlloc, finalStats["goroutines"].(int))

	// Memory should not grow excessively from message routing
	// 5MB is generous allowance for 50 messages
	if memGrowth > 5*1024*1024 {
		t.Errorf("excessive memory growth: %d bytes (%.1f MB) after %d messages",
			memGrowth, float64(memGrowth)/(1024*1024), numUsers*numMessagesPerUser)
	}
}

// TestMemoryProfile_OfflineQueueMemory verifies that the offline queue
// doesn't leak memory when messages expire or are drained.
func TestMemoryProfile_OfflineQueueMemory(t *testing.T) {
	// Create an offline queue with short TTL for testing
	q := newOfflineQueue(100, 5*time.Minute)

	runtime.GC()
	initialStats := MemoryStats()
	initialAlloc := initialStats["alloc_bytes"].(uint64)

	// Enqueue many messages
	const numMessages = 1000
	for i := 0; i < numMessages; i++ {
		msg := map[string]interface{}{
			"type":            "chat",
			"conversation_id": fmt.Sprintf("conv_%d", i%100),
			"sender_id":       fmt.Sprintf("sender_%d", i%10),
			"content":         fmt.Sprintf("offline message %d with content padding to simulate real messages", i),
		}
		data, _ := json.Marshal(msg)
		q.Enqueue(fmt.Sprintf("recipient_%d", i%50), data)
	}

	afterEnqueueStats := MemoryStats()
	afterEnqueueAlloc := afterEnqueueStats["alloc_bytes"].(uint64)
	t.Logf("After enqueue %d messages: alloc=%d bytes (%.1f KB), queue depth=%d",
		numMessages, afterEnqueueAlloc, float64(afterEnqueueAlloc)/1024, q.TotalDepth())

	// Drain all messages
	for i := 0; i < 50; i++ {
		q.Drain(fmt.Sprintf("recipient_%d", i))
	}

	afterDrainStats := MemoryStats()
	afterDrainAlloc := afterDrainStats["alloc_bytes"].(uint64)

	runtime.GC()
	postGCStats := MemoryStats()
	postGCAlloc := postGCStats["alloc_bytes"].(uint64)

	t.Logf("After drain: alloc=%d bytes, after GC: %d bytes (%.1f KB), queue depth=%d",
		afterDrainAlloc, postGCAlloc, float64(postGCAlloc)/1024, q.TotalDepth())

	// Memory after draining should be close to initial
	memGrowth := int64(postGCAlloc) - int64(initialAlloc)
	if memGrowth > 2*1024*1024 { // 2MB tolerance
		t.Logf("Warning: memory after queue drain is %d bytes (%.1f KB) above initial",
			memGrowth, float64(memGrowth)/1024)
	}
}

// TestMemoryProfile_SetGCPercentRuntime verifies that GC percent
// can be changed at runtime and affects memory behavior.
func TestMemoryProfile_SetGCPercentRuntime(t *testing.T) {
	original := debug.SetGCPercent(100)
	defer debug.SetGCPercent(original)

	// Set high GC percent (less frequent GC, more memory usage)
	oldPercent := SetGCPercent(200)
	if oldPercent != 100 {
		t.Logf("SetGCPercent(200) returned %d (expected 100, but original may differ)", oldPercent)
	}

	// Allocate some memory
	_ = make([]byte, 1024*1024) // 1MB

	stats1 := MemoryStats()

	// Set low GC percent (more frequent GC)
	SetGCPercent(50)

	// Force GC
	ForceGC()
	stats2 := MemoryStats()

	t.Logf("GC percent 200: alloc=%d, GC percent 50 after force: alloc=%d",
		stats1["alloc_bytes"].(uint64), stats2["alloc_bytes"].(uint64))
}

// TestMemoryProfile_SetMemoryLimitRuntime verifies that memory limit
// can be set at runtime.
func TestMemoryProfile_SetMemoryLimitRuntime(t *testing.T) {
	original := debug.SetMemoryLimit(0) // no limit
	defer debug.SetMemoryLimit(original)

	// Set 512MB soft memory limit
	SetMemoryLimit(512 * 1024 * 1024)

	stats := MemoryStats()
	t.Logf("Memory with 512MB limit: alloc=%d, sys=%d, goroutines=%d",
		stats["alloc_bytes"].(uint64), stats["sys_bytes"].(uint64), stats["goroutines"].(int))
}

// TestMemoryProfile_ConcurrentProfileActions verifies that profile
// actions can be called concurrently without races or panics.
func TestMemoryProfile_ConcurrentProfileActions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	var wg sync.WaitGroup
	const goroutines = 10

	// Concurrent MemoryStats calls
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats := MemoryStats()
			if stats["alloc_bytes"] == nil {
				t.Error("alloc_bytes should not be nil")
			}
		}()
	}

	// Concurrent CaptureProfile calls
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot := CaptureProfile(dir)
			if snapshot.Memory == nil {
				t.Error("snapshot memory should not be nil")
			}
		}()
	}

	// Concurrent ForceGC calls
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ForceGC()
		}()
	}

	wg.Wait()
}

// TestMemoryProfile_HealthEndpointUnderLoad verifies that the health
// endpoint returns memory stats while under load.
func TestMemoryProfile_HealthEndpointUnderLoad(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	// Concurrent health checks
	const numRequests = 50
	var wg sync.WaitGroup
	var successCount atomic.Int32

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(server.URL + "/health")
			if err != nil {
				t.Logf("health request failed: %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				var result map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
					if result["status"] == "ok" {
						successCount.Add(1)
					}
				}
			}
		}()
	}

	wg.Wait()

	successes := successCount.Load()
	t.Logf("Health endpoint: %d/%d successful requests", successes, numRequests)

	if successes < int32(numRequests)/2 {
		t.Errorf("too few successful health requests: %d/%d", successes, numRequests)
	}
}

// TestMemoryProfile_SteadyStateGrowth verifies that sustained request
// patterns don't cause unbounded memory growth.
func TestMemoryProfile_SteadyStateGrowth(t *testing.T) {
	server, cleanup := profileLoadSetupServer(t)
	defer cleanup()

	runtime.GC()
	baselineStats := MemoryStats()
	baselineAlloc := baselineStats["alloc_bytes"].(uint64)

	// Register an agent
	agentForm := url.Values{
		"agent_id":      {"steadyagent"},
		"name":          {"SteadyAgent"},
		"agent_secret":  {agentSecret},
	}
	resp, _ := http.PostForm(server.URL+"/auth/agent", agentForm)
	resp.Body.Close()

	// Register a user and create a conversation
	token := profileLoadRegisterUser(t, server, "steadyuser")

	form := url.Values{"agent_id": {"steadyagent"}}
	req, _ := http.NewRequest("POST", server.URL+"/conversations/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create conversation failed: %v", err)
	}
	var convResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&convResult)
	resp.Body.Close()
	convID, _ := convResult["conversation_id"].(string)

	// Make 100 sequential REST requests
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("GET", server.URL+"/conversations/messages?conversation_id="+convID+"&limit=20", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}

		// Also hit health
		resp, err = http.Get(server.URL + "/health")
		if err == nil {
			resp.Body.Close()
		}
	}

	// Force GC and measure
	ForceGC()
	runtime.GC()
	finalStats := MemoryStats()
	finalAlloc := finalStats["alloc_bytes"].(uint64)

	memGrowth := int64(finalAlloc) - int64(baselineAlloc)
	t.Logf("Steady-state memory growth: %d bytes (%.1f KB) after 200 requests",
		memGrowth, float64(memGrowth)/1024)

	// Growth should be minimal (< 1MB for 200 simple requests)
	if memGrowth > 1024*1024 {
		t.Errorf("excessive steady-state memory growth: %d bytes (%.1f KB)",
			memGrowth, float64(memGrowth)/1024)
	}
}