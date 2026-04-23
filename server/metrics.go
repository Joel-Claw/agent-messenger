package main

import (
	"runtime"
	"sync/atomic"
	"time"
)

// Metrics tracks server-level statistics
type Metrics struct {
	// Counters (atomic for thread-safe increments)
	MessagesIn      atomic.Int64 // total messages received
	MessagesOut     atomic.Int64 // total messages sent
	ConnectionsTotal atomic.Int64 // total connections ever made (agents + clients)
	ErrorsTotal     atomic.Int64 // total errors (auth failures, rate limits, write errors)
	RateLimited     atomic.Int64 // total rate-limited messages

	// Gauges (updated via hub)
	AgentsConnected  func() int
	ClientsConnected func() int

	// Server metadata
	StartTime time.Time
	Version   string
}

// ServerMetrics holds the global metrics instance
var ServerMetrics *Metrics

// NewMetrics creates a new Metrics instance
func NewMetrics(h *Hub) *Metrics {
	return &Metrics{
		StartTime:        time.Now(),
		Version:          "0.1.0",
		AgentsConnected:  h.AgentCount,
		ClientsConnected: h.ClientCount,
	}
}

// Uptime returns the server uptime as a duration
func (m *Metrics) Uptime() time.Duration {
	return time.Since(m.StartTime)
}

// Snapshot returns a map of all metrics for the health/metrics endpoints
func (m *Metrics) Snapshot() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"version":           m.Version,
		"uptime_seconds":    int(m.Uptime().Seconds()),
		"start_time":        m.StartTime.Format(time.RFC3339),
		"messages_in":       m.MessagesIn.Load(),
		"messages_out":      m.MessagesOut.Load(),
		"connections_total": m.ConnectionsTotal.Load(),
		"agents_connected":  m.AgentsConnected(),
		"clients_connected":  m.ClientsConnected(),
		"errors_total":      m.ErrorsTotal.Load(),
		"rate_limited":      m.RateLimited.Load(),
		"goroutines":        runtime.NumGoroutine(),
		"memory_alloc_mb":   float64(memStats.Alloc) / 1024 / 1024,
		"memory_sys_mb":     float64(memStats.Sys) / 1024 / 1024,
		"offline_queue_depth": func() int {
			if offlineQueue != nil {
				return offlineQueue.TotalDepth()
			}
			return 0
		}(),
	}
}