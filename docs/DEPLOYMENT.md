# Agent Messenger Deployment Guide

Step-by-step instructions for deploying Agent Messenger using Docker, systemd, or Kubernetes.

## Prerequisites

- A Linux server (or Raspberry Pi) with network access
- For Docker: Docker Engine 20+ and Docker Compose v2
- For systemd: Go 1.21+ (to build from source)
- For Kubernetes: Helm 3+, a Kubernetes cluster

## Quick Start (Docker Compose)

The fastest way to get Agent Messenger running:

```bash
git clone https://github.com/Joel-Claw/agent-messenger.git
cd agent-messenger

# Create .env with required secrets
cat > .env << 'EOF'
JWT_SECRET=$(openssl rand -hex 32)
AGENT_SECRET=$(openssl rand -hex 16)
ADMIN_SECRET=$(openssl rand -hex 16)
EOF

# Edit .env to fill in actual values (the $() won't expand in heredoc)
# Generate real secrets:
python3 -c "import secrets; print(f'JWT_SECRET={secrets.token_hex(32)}')"
python3 -c "import secrets; print(f'AGENT_SECRET={secrets.token_hex(16)}')"
python3 -c "import secrets; print(f'ADMIN_SECRET={secrets.token_hex(16)}')"

# Start the server
docker-compose up -d

# Verify it's running
curl http://localhost:8080/health
```

### With PostgreSQL

By default, Agent Messenger uses SQLite. For production, use PostgreSQL:

```bash
# Add to .env:
DB_DRIVER=postgres
DATABASE_URL=postgres://am:yourpassword@postgres:5432/agentmessenger?sslmode=disable
PG_PASSWORD=yourpassword

# Start with PostgreSQL profile
docker-compose --profile postgres up -d
```

### With WebChat

To serve the web client from the Go server:

```bash
# Build WebChat
cd webchat && npm install && npm run build && cd ..

# Add to .env:
WEBCHAT_ENABLED=true
WEBCHAT_DIR=/app/webchat/build

# Mount the build directory in docker-compose.yml:
# Add under server.volumes:
#   - ./webchat/build:/app/webchat/build:ro
```

Then access WebChat at `http://localhost:8080/chat/`.

### With Push Notifications

```bash
# Add to .env:

# iOS (APNs)
APNS_KEY_PATH=/secrets/apns.p8
APNS_KEY_ID=YOUR_KEY_ID
APNS_TEAM_ID=YOUR_TEAM_ID

# Android (FCM) — mount your service account JSON
FCM_SERVICE_ACCOUNT=/secrets/fcm.json

# Web Push (VAPID) — generate with:
npx web-push generate-vapid-keys
VAPID_PUBLIC_KEY=your_public_key
VAPID_PRIVATE_KEY=your_private_key
```

Mount the key files in `docker-compose.yml` volumes.

### Docker Compose Operations

```bash
docker-compose up -d          # Start
docker-compose down           # Stop
docker-compose logs -f server # View logs
docker-compose restart server # Restart
docker-compose ps             # Check status
```

## Systemd (Bare Metal)

For running directly on a Linux server without Docker.

### 1. Build and Install

```bash
cd agent-messenger
sudo ./deploy/install.sh
```

This script:
- Builds the server binary
- Creates an `agent-messenger` system user
- Installs to `/opt/agent-messenger/`
- Creates data directory at `/var/lib/agent-messenger/`
- Sets up environment file at `/etc/agent-messenger/env`
- Installs and enables the systemd service

### 2. Configure Secrets

```bash
sudo nano /etc/agent-messenger/env
```

**Required**: Set `JWT_SECRET`, `AGENT_SECRET`, and `ADMIN_SECRET` to strong random values.

```bash
# Generate secrets
python3 -c "import secrets; print('JWT_SECRET=' + secrets.token_hex(32))"
python3 -c "import secrets; print('AGENT_SECRET=' + secrets.token_hex(16))"
python3 -c "import secrets; print('ADMIN_SECRET=' + secrets.token_hex(16))"
```

### 3. Start the Service

```bash
sudo systemctl start agent-messenger
sudo systemctl status agent-messenger
```

### 4. Verify

```bash
curl http://localhost:8080/health
```

### 5. Enable on Boot

```bash
sudo systemctl enable agent-messenger
```

### Service Management

```bash
sudo systemctl start agent-messenger     # Start
sudo systemctl stop agent-messenger      # Stop
sudo systemctl restart agent-messenger   # Restart
sudo systemctl status agent-messenger    # Check status
journalctl -u agent-messenger -f         # View logs
journalctl -u agent-messenger --since today  # Today's logs
```

### Updating

```bash
cd agent-messenger
git pull
sudo ./deploy/install.sh        # Rebuilds and reinstalls
sudo systemctl restart agent-messenger
```

### Using PostgreSQL Instead of SQLite

Edit `/etc/agent-messenger/env`:

```
DB_DRIVER=postgres
DATABASE_URL=postgres://user:password@localhost:5432/agentmessenger?sslmode=disable
```

Then restart: `sudo systemctl restart agent-messenger`

### Serving WebChat

```bash
# Build WebChat
cd webchat && npm install && npm run build

# Add to /etc/agent-messenger/env:
WEBCHAT_ENABLED=true
WEBCHAT_DIR=/opt/agent-messenger/webchat

# Copy build output
sudo cp -r build /opt/agent-messenger/webchat/

# Restart
sudo systemctl restart agent-messenger
```

## Kubernetes (Helm)

### 1. Install the Chart

```bash
cd deploy/helm

# Install with defaults (SQLite)
helm install agent-messenger ./agent-messenger

# Install with PostgreSQL
helm install agent-messenger ./agent-messenger \
  --set persistence.enabled=true \
  --set postgresql.enabled=true
```

### 2. Configuration

Create a `values.yaml` file:

```yaml
# values.yaml
replicaCount: 2

image:
  repository: ghcr.io/joel-claw/agent-messenger
  tag: "0.2.0"

secrets:
  jwtSecret: "your-jwt-secret-here"
  agentSecret: "your-agent-secret-here"
  adminSecret: "your-admin-secret-here"

persistence:
  enabled: true
  size: 10Gi
  storageClass: standard

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: messenger.example.com
      paths:
        - path: /
          pathType: Prefix

push:
  apns:
    keyId: "YOUR_KEY_ID"
    teamId: "YOUR_TEAM_ID"
  fcm:
    serviceAccountJson: |
      { "type": "service_account", ... }
  vapid:
    publicKey: "YOUR_VAPID_PUBLIC_KEY"
    privateKey: "YOUR_VAPID_PRIVATE_KEY"

webchat:
  enabled: true

resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

```bash
helm install agent-messenger ./agent-messenger -f values.yaml
```

### 3. Upgrade

```bash
helm upgrade agent-messenger ./agent-messenger -f values.yaml
```

### 4. Uninstall

```bash
helm uninstall agent-messenger
```

See `deploy/helm/agent-messenger/README.md` for full configuration reference.

## Database Migrations

The server auto-creates the schema on first run. For explicit migration management:

```bash
# Build the migration tool
cd server && go build -o am-migrate ./cmd/am-migrate

# Check current migration status
./am-migrate -db /var/lib/agent-messenger/agent-messenger.db -action status

# Apply all pending migrations
./am-migrate -db /var/lib/agent-messenger/agent-messenger.db -action up

# Rollback one migration
./am-migrate -db /var/lib/agent-messenger/agent-messenger.db -action down

# Create a new migration stub
./am-migrate -action create -name add_new_table
```

## Reverse Proxy

### Caddy

```Caddyfile
messenger.example.com {
    reverse_proxy localhost:8080
}
```

Caddy automatically handles TLS. See `deploy/Caddyfile` for a complete example.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name messenger.example.com;

    ssl_certificate /etc/letsencrypt/live/messenger.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/messenger.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

The `Upgrade` and `Connection` headers are **required** for WebSocket proxying. See `deploy/nginx.conf` for a complete example.

## Admin CLI

The `am-admin` tool manages agents and users from the command line:

```bash
# Build
cd server && go build -o am-admin ./cmd/am-admin

# Create an agent
./am-admin -server http://localhost:8080 -secret your-admin-secret create-agent \
  --id my-agent --name "My Agent" --model gpt-4

# Create a user
./am-admin -server http://localhost:8080 -secret your-admin-secret create-user \
  --username alice --password secret123

# List agents
./am-admin -server http://localhost:8080 -secret your-admin-secret list-agents

# List users
./am-admin -server http://localhost:8080 -secret your-admin-secret list-users

# Reset an agent's API key
./am-admin -server http://localhost:8080 -secret your-admin-secret reset-apikey \
  --agent-id my-agent
```

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
```

Returns JSON with `status`, `version`, `uptime`, `db` connectivity, connection counts, and message counters.

### Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

Prometheus-compatible text format. Key metrics:
- `am_messages_in` / `am_messages_out` — message counters
- `am_connections_total` — total connections created
- `am_agents_connected` / `am_clients_connected` — live gauge
- `am_errors_total` — error counter
- `am_rate_limited_total` — rate limit counter

### Structured Logs

Set `LOG_LEVEL=debug|info|warn|error` to control verbosity. Logs are structured JSON:

```json
{
  "level": "info",
  "msg": "http_request",
  "method": "POST",
  "path": "/auth/login",
  "status": 200,
  "duration_ms": 12,
  "request_id": "abc123",
  "user_id": "usr_456"
}
```

## Security Checklist

Before exposing to the internet:

- [ ] **Change all default secrets**: `JWT_SECRET`, `AGENT_SECRET`, `ADMIN_SECRET`
- [ ] **Set `CORS_ALLOWED_ORIGINS`** to your actual domain (not `*`)
- [ ] **Enable TLS** via reverse proxy (Caddy auto-TLS, or Let's Encrypt + nginx)
- [ ] **Restrict `MAX_UPLOAD_SIZE`** to your needs (default 10MB)
- [ ] **Review `MAX_WS_MESSAGE_SIZE`** (default 64KB)
- [ ] **Enable agent heartbeat** if agents may disconnect silently: `AGENT_HEARTBEAT_ENABLED=true`
- [ ] **Run as non-root user** (systemd service does this automatically)
- [ ] **Firewall**: only expose ports 80/443 (reverse proxy), not 8080 directly
- [ ] **Backups**: regularly backup the SQLite database or PostgreSQL data

## Troubleshooting

### Server Won't Start

```bash
# Check logs
journalctl -u agent-messenger -n 50   # systemd
docker-compose logs server              # Docker

# Common issues:
# - Port 8080 already in use: change PORT in env
# - Database permission error: check data directory ownership
# - Invalid JWT_SECRET: must be non-empty
```

### WebSocket Connections Fail

```bash
# Check CORS_ALLOWED_ORIGINS matches your client origin
# Check reverse proxy forwards Upgrade headers
# Check MAX_WS_MESSAGE_SIZE if sending large messages
```

### Push Notifications Not Working

```bash
# iOS: Verify APNS_KEY_PATH, APNS_KEY_ID, APNS_TEAM_ID
# Android: Verify FCM_SERVICE_ACCOUNT JSON is valid
# Web: Verify VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY match
# Check device tokens are registered: GET /admin/agents with admin secret
```

### Database Issues

```bash
# SQLite: Check DB_PATH exists and is writable
# PostgreSQL: Check DATABASE_URL connectivity
psql "$DATABASE_URL" -c "SELECT 1"

# Run migrations
./am-migrate -db /path/to/db -action status
./am-migrate -db /path/to/db -action up
```

### Performance

```bash
# Check metrics for bottlenecks
curl http://localhost:8080/metrics

# For high traffic, switch to PostgreSQL
# Adjust rate limits for your tier
# Check offline queue depth: GET /health → offline_queue_depth
```