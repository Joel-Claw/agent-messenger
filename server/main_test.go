package main

import (
	"os"
	"testing"
)

// TestMain stops global rate limiter goroutines after all tests complete.
// Without this, the cleanup goroutines started by NewRateLimiter in package
// init leak and cause the test process to hang indefinitely.
func TestMain(m *testing.M) {
	code := m.Run()

	// Stop all global rate limiters to unblock their cleanup goroutines.
	messageRateLimiter.Stop()
	userRateLimiter.Stop()
	ipRateLimiter.Stop()
	authIPLimiter.Stop()
	if globalTieredLimiter != nil {
		globalTieredLimiter.Stop()
	}

	// Shutdown any leaked tracing providers.
	ShutdownTracing()

	os.Exit(code)
}