# Agent Messenger - Monitoring

This directory contains monitoring configurations for Agent Messenger server.

## Prometheus Alert Rules

`alerts.yml` contains Prometheus alerting rules for:

| Alert | Condition | Severity |
|-------|-----------|----------|
| HighErrorRate | >10 errors/sec over 5m | Warning |
| CriticalErrorRate | >50 errors/sec over 5m | Critical |
| ErrorSpike | >100 errors in 1 minute | Warning |
| HighRateLimiting | >30 rate-limited req/sec over 5m | Warning |
| StaleAgents | >0 stale agents for 2m | Warning |
| NoAgentsConnected | 0 agents for 5m | Critical |
| AgentHeartbeatMonitoringDisabled | Heartbeat monitoring off for 10m | Info |
| OfflineQueueGrowing | >50 queue growth in 5m | Warning |
| OfflineQueueBacklog | >500 messages queued for 5m | Warning |
| OfflineQueueCritical | >2000 messages queued for 5m | Critical |
| HighConnectionRate | >50 new connections/sec over 5m | Warning |
| MessageThroughputDrop | <1 msg/sec for 10m with connected users | Warning |
| HighGoroutineCount | >1000 goroutines for 5m | Warning |
| HighMemoryUsage | >512MB allocated for 5m | Warning |
| ServerRestart | Uptime <300s | Info |

### Installing Alert Rules

**Docker Compose**: Add to your `prometheus.yml`:
```yaml
rule_files:
  - "alerts.yml"
```

And mount the file in `docker-compose.yml`:
```yaml
prometheus:
  volumes:
    - ./monitoring/alerts.yml:/etc/prometheus/alerts.yml
```

**Kubernetes**: Create a ConfigMap and reference it in your Prometheus config.

## Grafana Dashboard

`grafana-dashboard.json` is a Grafana dashboard template with panels for:

- **Overview**: Connected agents/clients, queue depth, error rate, stale agents, uptime
- **Message Throughput**: Messages in/out rate, error/rate-limit rate over time
- **Connections**: Active connections (agents, unique clients, total client conns), connection rate
- **Resources**: Memory usage (alloc/sys), goroutine count
- **Offline Queue**: Queue depth over time

### Installing the Dashboard

1. Open Grafana → Dashboards → Import
2. Upload `grafana-dashboard.json` or paste its contents
3. Select your Prometheus data source
4. Click Import

Or via the Grafana API:
```bash
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -d @grafana-dashboard.json
```

## Docker Compose Monitoring Stack

Add Prometheus and Grafana to your `docker-compose.yml`:

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./monitoring/alerts.yml:/etc/prometheus/alerts.yml
    depends_on:
      - agent-messenger

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - prometheus

volumes:
  grafana-data:
```

## Prometheus Configuration

Example `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alerts.yml"

scrape_configs:
  - job_name: "agent-messenger"
    static_configs:
      - targets: ["agent-messenger:8080"]
    metrics_path: "/metrics"
    scrape_interval: 10s
```

## Metrics Reference

All metrics are prefixed with `agent_messenger_`:

| Metric | Type | Description |
|--------|------|-------------|
| `messages_in_total` | Counter | Total messages received |
| `messages_out_total` | Counter | Total messages sent |
| `connections_total` | Counter | Total connections since startup |
| `agents_connected` | Gauge | Currently connected agents |
| `clients_connected` | Gauge | Currently connected unique client users |
| `client_conns_total` | Gauge | Total client connections (multi-device) |
| `errors_total` | Counter | Total errors |
| `rate_limited_total` | Counter | Total rate-limited requests |
| `offline_queue_depth` | Gauge | Messages queued for offline recipients |
| `stale_agents` | Gauge | Agents that missed heartbeat timeout |
| `agent_heartbeat_enabled` | Gauge | Heartbeat monitoring enabled (1=on, 0=off) |
| `uptime_seconds` | Gauge | Server uptime in seconds |
| `goroutines` | Gauge | Number of goroutines |
| `memory_alloc_bytes` | Gauge | Allocated memory in bytes |
| `memory_sys_bytes` | Gauge | System memory in bytes |