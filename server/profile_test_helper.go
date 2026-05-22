package main

import (
	"os"
	"sync"
)

// cpuProfileMu serializes all CPU profile operations across tests.
// Go's runtime only allows one active CPU profile at a time (pprof.StartCPUProfile),
// so parallel tests that start CPU profiles will fail with "cpu profile already active".
// This mutex ensures only one test uses CPU profiling at a time.
var cpuProfileMu sync.Mutex

// cpuProfileTestSetup acquires the CPU profile mutex and resets the cpuProfileState.
// Returns a cleanup function that releases the mutex.
// Usage: defer cpuProfileTestSetup(t)()
func cpuProfileTestSetup() func() {
	cpuProfileMu.Lock()
	// Reset state in case a previous test left it dirty
	if cpuProfileState.active && cpuProfileState.stopFunc != nil {
		cpuProfileState.stopFunc()
	}
	cpuProfileState.active = false
	cpuProfileState.stopFunc = nil
	// Clear PROFILING_DIR to avoid cross-test interference
	os.Unsetenv("PROFILING_DIR")
	return func() {
		// Clean up any active profile before releasing the lock
		if cpuProfileState.active && cpuProfileState.stopFunc != nil {
			cpuProfileState.stopFunc()
		}
		cpuProfileState.active = false
		cpuProfileState.stopFunc = nil
		cpuProfileMu.Unlock()
	}
}