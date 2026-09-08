package main

import (
	"os"
	"testing"
)

// TestMain stops all rate limiter goroutines after tests complete.
// Without this, the cleanup goroutines started by NewRateLimiter and
// NewTieredRateLimiter in both package init and test files leak and
// cause the test process to hang.
func TestMain(m *testing.M) {
	code := m.Run()

	// Stop ALL rate limiters ever created (globals + test instances).
	allRateLimitersMu.Lock()
	for _, stop := range allRateLimiters {
		stop()
	}
	allRateLimiters = nil
	allRateLimitersMu.Unlock()

	// Shutdown any leaked tracing providers.
	ShutdownTracing()

	os.Exit(code)
}