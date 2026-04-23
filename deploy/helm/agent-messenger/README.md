# Agent Messenger Helm Chart

Helm chart for deploying Agent Messenger to Kubernetes.

## Quick Start

```bash
# Install with default values (set required secrets)
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set auth.agentSecret=your-agent-secret \
  --set auth.jwtSecret=your-jwt-secret

# Or use an existing Kubernetes Secret
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set existingSecret=am-secrets
```

## Configuration

### Required Settings

| Parameter | Description |
|-----------|-------------|
| `auth.agentSecret` | Shared secret for agent authentication |
| `auth.jwtSecret` | JWT signing secret for user authentication |

Either set these directly in values or use `existingSecret` with a Secret containing `AGENT_SECRET` and `JWT_SECRET` keys.

### Common Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `replicaCount` | `1` | Number of pods (1 recommended for SQLite) |
| `image.repository` | `agent-messenger` | Container image |
| `image.tag` | Chart appVersion | Image tag |
| `server.port` | `8080` | Server listen port |
| `server.dbDriver` | `sqlite3` | Database driver: `sqlite3` or `postgres` |
| `server.dbPath` | `/data/agent-messenger.db` | SQLite database path |
| `server.databaseUrl` | `""` | PostgreSQL connection string |
| `persistence.enabled` | `true` | Enable PVC for SQLite data |
| `persistence.size` | `1Gi` | PVC size |
| `service.type` | `ClusterIP` | Service type |
| `ingress.enabled` | `false` | Enable Ingress |

### PostgreSQL

For production deployments with multiple replicas, use PostgreSQL instead of SQLite:

```bash
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set auth.agentSecret=your-agent-secret \
  --set auth.jwtSecret=your-jwt-secret \
  --set server.dbDriver=postgres \
  --set server.databaseUrl="postgres://user:pass@postgres-host:5432/dbname?sslmode=disable"
```

Or enable the bundled PostgreSQL sub-chart:

```bash
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set auth.agentSecret=your-agent-secret \
  --set auth.jwtSecret=your-jwt-secret \
  --set server.dbDriver=postgres \
  --set postgresql.enabled=true \
  --set postgresql.auth.password=your-pg-password
```

### Push Notifications

```bash
# APNs (iOS)
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set push.apns.enabled=true \
  --set push.apns.keyID=YOUR_KEY_ID \
  --set push.apns.teamID=YOUR_TEAM_ID \
  --set pushSecrets.existingSecret=push-certs

# FCM (Android)
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set push.fcm.enabled=true \
  --set pushSecrets.existingSecret=push-certs
```

### Ingress Example

```bash
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=messenger.example.com' \
  --set 'ingress.hosts[0].paths[0].path=/'
```

### WebChat UI

```bash
helm install agent-messenger ./deploy/helm/agent-messenger \
  --set webchat.enabled=true \
  --set webchat.dir=/webchat
```

## ⚠️ SQLite and Scaling

The default SQLite backend requires a persistent volume with `ReadWriteOnce` access.
This means **only one replica** can use the database at a time. Do not enable
HorizontalPodAutoscaler with `maxReplicas > 1` when using SQLite.

For multi-replica deployments, use PostgreSQL (future support).

## Migration Tool

The `am-migrate` CLI manages database schema migrations independently:

```bash
# Build the migration tool
make migrate

# Check migration status
./server/am-migrate -db ./data/agent-messenger.db -action status

# Run pending migrations
./server/am-migrate -db ./data/agent-messenger.db -action up

# Rollback to specific version
./server/am-migrate -db ./data/agent-messenger.db -action down -target 1
```