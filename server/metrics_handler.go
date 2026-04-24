package main

import (
	"fmt"
	"net/http"
	"strings"
)

// handleMetrics returns Prometheus-compatible metrics
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	snapshot := ServerMetrics.Snapshot()

	var sb strings.Builder

	// Helper to write a Prometheus metric
	writeMetric := func(name, mtype, help string, value interface{}) {
		sb.WriteString(fmt.Sprintf("# HELP agent_messenger_%s %s\n", name, help))
		sb.WriteString(fmt.Sprintf("# TYPE agent_messenger_%s %s\n", name, mtype))
		sb.WriteString(fmt.Sprintf("agent_messenger_%s %v\n", name, value))
	}

	writeMetric("messages_in_total", "counter", "Total messages received", snapshot["messages_in"])
	writeMetric("messages_out_total", "counter", "Total messages sent", snapshot["messages_out"])
	writeMetric("connections_total", "counter", "Total connections since startup", snapshot["connections_total"])
	writeMetric("agents_connected", "gauge", "Currently connected agents", snapshot["agents_connected"])
	writeMetric("clients_connected", "gauge", "Currently connected unique client users", snapshot["clients_connected"])
	writeMetric("client_conns_total", "gauge", "Total client connections including multi-device", snapshot["client_conns_total"])
	writeMetric("errors_total", "counter", "Total errors", snapshot["errors_total"])
	writeMetric("rate_limited_total", "counter", "Total rate-limited messages", snapshot["rate_limited"])
	writeMetric("uptime_seconds", "gauge", "Server uptime in seconds", snapshot["uptime_seconds"])
	writeMetric("goroutines", "gauge", "Number of goroutines", snapshot["goroutines"])
	writeMetric("memory_alloc_bytes", "gauge", "Allocated memory in bytes",
		fmt.Sprintf("%.0f", snapshot["memory_alloc_mb"].(float64)*1024*1024))
	writeMetric("memory_sys_bytes", "gauge", "System memory in bytes",
		fmt.Sprintf("%.0f", snapshot["memory_sys_mb"].(float64)*1024*1024))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(sb.String()))
}