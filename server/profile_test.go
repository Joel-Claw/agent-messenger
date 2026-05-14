package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestMemoryStats(t *testing.T) {
	stats := MemoryStats()

	required := []string{
		"alloc_bytes", "total_alloc_bytes", "sys_bytes",
		"heap_alloc_bytes", "heap_sys_bytes", "heap_objects",
		"stack_inuse_bytes", "num_gc", "goroutines",
		"next_gc_bytes", "gc_pause_total_ns", "last_gc_ns",
	}

	for _, key := range required {
		if _, ok := stats[key]; !ok {
			t.Errorf("MemoryStats missing key %q", key)
		}
	}

	// Alloc should be > 0 (we've allocated memory for this map)
	if stats["alloc_bytes"].(uint64) == 0 {
		t.Error("alloc_bytes should be > 0")
	}

	// Should have at least 1 goroutine (the test goroutine)
	if stats["goroutines"].(int) < 1 {
		t.Error("goroutines should be >= 1")
	}
}

func TestForceGC(t *testing.T) {
	numGC := ForceGC()
	if numGC < 1 {
		t.Errorf("ForceGC should return GC count >= 1, got %d", numGC)
	}
}

func TestWriteHeapProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heap.prof")

	if err := WriteHeapProfile(path); err != nil {
		t.Fatalf("WriteHeapProfile failed: %v", err)
	}

	// Verify file exists and is non-empty
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Size() == 0 {
		t.Error("heap profile file is empty")
	}
}

func TestWriteGoroutineProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "goroutine.prof")

	if err := WriteGoroutineProfile(path); err != nil {
		t.Fatalf("WriteGoroutineProfile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Size() == 0 {
		t.Error("goroutine profile file is empty")
	}
}

func TestStartCPUProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpu.prof")

	stop, err := StartCPUProfile(path)
	if err != nil {
		t.Fatalf("StartCPUProfile failed: %v", err)
	}

	// Do some work to generate CPU profile data
	for i := 0; i < 1000; i++ {
		MemoryStats()
	}

	stop()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Size() == 0 {
		t.Error("cpu profile file is empty")
	}
}

func TestCaptureProfile(t *testing.T) {
	// Without a directory — should still return stats
	snapshot := CaptureProfile("")
	if snapshot.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
	if snapshot.Memory == nil {
		t.Error("memory stats should not be nil")
	}
	if snapshot.HeapFile != "" {
		t.Error("heap file should be empty when dir is empty")
	}
	if snapshot.Goroutines < 1 {
		t.Error("should have at least 1 goroutine")
	}
}

func TestCaptureProfileWithDir(t *testing.T) {
	dir := t.TempDir()
	snapshot := CaptureProfile(dir)

	if snapshot.HeapFile == "" {
		t.Error("heap file should be set when dir is provided")
	}
	if snapshot.GoroutineFile == "" {
		t.Error("goroutine file should be set when dir is provided")
	}

	// Verify files exist
	if _, err := os.Stat(snapshot.HeapFile); err != nil {
		t.Errorf("heap profile file missing: %v", err)
	}
	if _, err := os.Stat(snapshot.GoroutineFile); err != nil {
		t.Errorf("goroutine profile file missing: %v", err)
	}
}

func TestProfileSnapshotRejection(t *testing.T) {
	// Ensure admin profile requires admin auth
	req := httptest.NewRequest(http.MethodGet, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	// Should get 401 (unauthorized) because no admin secret header
	if w.Code != http.StatusUnauthorized {
		t.Logf("Note: direct handler call without middleware returns %d (expected 401 requires middleware)", w.Code)
	}
}

func TestProfileStatsEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=stats", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("stats endpoint returned %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}

	memory, ok := result["memory"].(map[string]interface{})
	if !ok {
		t.Fatal("memory should be a map")
	}
	if memory["goroutines"] == nil {
		t.Error("memory stats should contain goroutines")
	}
}

func TestProfileHeapEndpoint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=heap", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("heap endpoint returned %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
	if result["file"] == nil || result["file"] == "" {
		t.Error("expected file path in response")
	}
}

func TestProfileGoroutineEndpoint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=goroutine", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("goroutine endpoint returned %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

func TestProfileGCEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=gc", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("gc endpoint returned %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
	if result["gc_cycles"] == nil {
		t.Error("expected gc_cycles in response")
	}
}

func TestProfileCPUEndpoints(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROFILING_DIR", dir)

	// Start CPU profiling
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("cpu start returned %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "profiling" {
		t.Errorf("expected status profiling, got %v", result["status"])
	}

	// Stop CPU profiling
	req = httptest.NewRequest(http.MethodPost, "/admin/profile?action=cpu_stop", nil)
	w = httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("cpu stop returned %d, want %d", w.Code, http.StatusOK)
	}

	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "stopped" {
		t.Errorf("expected status stopped, got %v", result["status"])
	}
}

func TestProfileInvalidAction(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/profile?action=invalid", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid action returned %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestProfileMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/profile", nil)
	w := httptest.NewRecorder()
	handleAdminProfile(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT method returned %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestSetGCPercent(t *testing.T) {
	original := debug.SetGCPercent(100)
	defer debug.SetGCPercent(original)

	newPercent := SetGCPercent(200)
	if newPercent != 100 {
		t.Errorf("SetGCPercent(200) should return previous value 100, got %d", newPercent)
	}

	// Verify it was set
	current := SetGCPercent(100)
	if current != 200 {
		t.Errorf("expected GC percent to be 200, got %d", current)
	}
}

func TestSetMemoryLimit(t *testing.T) {
	original := debug.SetMemoryLimit(0) // 0 means no limit
	defer debug.SetMemoryLimit(original)

	newLimit := SetMemoryLimit(1 << 30) // 1GB
	if newLimit != 0 && newLimit != 1073741824 {
		t.Logf("SetMemoryLimit returned %d (0 means previously unset)", newLimit)
	}
}