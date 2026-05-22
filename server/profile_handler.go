package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

// handleAdminProfile captures a memory profile and returns stats.
// POST /admin/profile with optional action:
//   - action=heap     → write heap profile to PROFILING_DIR
//   - action=goroutine → write goroutine dump to PROFILING_DIR
//   - action=cpu      → start CPU profiling (POST again with action=cpu_stop to stop)
//   - action=cpu_stop → stop CPU profiling
//   - action=gc       → force GC and return stats
//   - (default)       → return current memory stats as JSON
func handleAdminProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	action := r.URL.Query().Get("action")
	if action == "" && r.Method == http.MethodPost {
		// Try JSON body
		var body struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.Action != "" {
			action = body.Action
		}
	}

	switch action {
	case "heap":
		handleHeapProfile(w, r)
	case "goroutine":
		handleGoroutineProfile(w, r)
	case "cpu":
		handleCPUProfileStart(w, r)
	case "cpu_stop":
		handleCPUProfileStop(w, r)
	case "gc":
		handleForceGC(w, r)
	case "stats", "":
		handleMemoryStats(w, r)
	default:
		http.Error(w, fmt.Sprintf("unknown action: %s (valid: heap, goroutine, cpu, cpu_stop, gc, stats)", action), http.StatusBadRequest)
	}
}

func handleHeapProfile(w http.ResponseWriter, r *http.Request) {
	dir := os.Getenv("PROFILING_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "agent-messenger-profiles")
	}

	ts := time.Now().UTC().Format("20060102_150405")
	path := filepath.Join(dir, "heap_"+ts+".prof")

	if err := os.MkdirAll(dir, 0755); err != nil {
		writeProfileError(w, "create dir", err)
		return
	}

	if err := WriteHeapProfile(path); err != nil {
		writeProfileError(w, "write heap profile", err)
		return
	}

	stats := MemoryStats()
	writeProfileJSON(w, map[string]interface{}{
		"status":    "ok",
		"action":    "heap",
		"file":      path,
		"memory":    stats,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func handleGoroutineProfile(w http.ResponseWriter, r *http.Request) {
	dir := os.Getenv("PROFILING_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "agent-messenger-profiles")
	}

	ts := time.Now().UTC().Format("20060102_150405")
	path := filepath.Join(dir, "goroutine_"+ts+".prof")

	if err := os.MkdirAll(dir, 0755); err != nil {
		writeProfileError(w, "create dir", err)
		return
	}

	if err := WriteGoroutineProfile(path); err != nil {
		writeProfileError(w, "write goroutine profile", err)
		return
	}

	stats := MemoryStats()
	writeProfileJSON(w, map[string]interface{}{
		"status":    "ok",
		"action":    "goroutine",
		"file":      path,
		"goroutines": stats["goroutines"],
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// cpuProfileState tracks an in-progress CPU profile
var cpuProfileState struct {
	sync.Mutex
	stopFunc func()
	active   bool
}

func handleCPUProfileStart(w http.ResponseWriter, r *http.Request) {
	cpuProfileState.Lock()
	defer cpuProfileState.Unlock()

	if cpuProfileState.active {
		writeProfileError(w, "cpu profile already active", nil)
		return
	}

	dir := os.Getenv("PROFILING_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "agent-messenger-profiles")
	}

	ts := time.Now().UTC().Format("20060102_150405")
	path := filepath.Join(dir, "cpu_"+ts+".prof")

	if err := os.MkdirAll(dir, 0755); err != nil {
		writeProfileError(w, "create dir", err)
		return
	}

	stop, err := StartCPUProfile(path)
	if err != nil {
		writeProfileError(w, "start cpu profile", err)
		return
	}

	cpuProfileState.stopFunc = stop
	cpuProfileState.active = true

	writeProfileJSON(w, map[string]interface{}{
		"status":    "profiling",
		"action":    "cpu",
		"file":      path,
		"message":   "CPU profiling started. POST /admin/profile?action=cpu_stop to stop.",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func handleCPUProfileStop(w http.ResponseWriter, r *http.Request) {
	cpuProfileState.Lock()
	defer cpuProfileState.Unlock()

	if !cpuProfileState.active {
		writeProfileError(w, "no cpu profile active", nil)
		return
	}

	cpuProfileState.stopFunc()
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil

	stats := MemoryStats()
	writeProfileJSON(w, map[string]interface{}{
		"status":    "stopped",
		"action":    "cpu_stop",
		"memory":    stats,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func handleForceGC(w http.ResponseWriter, r *http.Request) {
	before := MemoryStats()
	numGC := ForceGC()
	after := MemoryStats()

	writeProfileJSON(w, map[string]interface{}{
		"status":    "ok",
		"action":    "gc",
		"gc_cycles":  numGC,
		"before":     before,
		"after":      after,
		"freed_bytes": before["alloc_bytes"].(uint64) - after["alloc_bytes"].(uint64),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

func handleMemoryStats(w http.ResponseWriter, r *http.Request) {
	stats := MemoryStats()
	writeProfileJSON(w, map[string]interface{}{
		"status":    "ok",
		"action":    "stats",
		"memory":    stats,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

func writeProfileJSON(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeProfileError(w http.ResponseWriter, context string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "error",
		"context": context,
		"detail":  detail,
	})
}

// SetGCPercent allows configuring the GC target percentage at runtime.
// A higher percentage means less frequent GC cycles but more memory usage.
// Default is 100 (from GOGC). Set to -1 to disable GC entirely.
func SetGCPercent(percent int) int {
	return debug.SetGCPercent(percent)
}

// SetMemoryLimit sets the soft memory limit for the GC.
// The GC will run more aggressively when memory exceeds this limit.
// Returns the previous limit. Available since Go 1.19.
func SetMemoryLimit(limit int64) int64 {
	return debug.SetMemoryLimit(limit)
}