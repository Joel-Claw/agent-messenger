# Contributing to Agent Messenger

Thanks for your interest. Agent Messenger is a self-hosted messaging platform for humans to talk to their AI agents. Here's how to contribute effectively.

## Project Overview

The project has 8 components, each in its own directory:

| Component | Directory | Language | Description |
|-----------|-----------|----------|-------------|
| Server | `server/` | Go | WebSocket + REST API, SQLite/PostgreSQL, push notifications |
| OpenClaw Plugin | `plugins/openclaw/` | TypeScript | Channel plugin for OpenClaw agent framework |
| WebChat | `webchat/` | React + TypeScript | Browser client with E2E encryption |
| iOS App | `mobile/ios/` | Swift/SwiftUI | Native iOS with APNs push |
| Android App | `mobile/android/` | Kotlin/Compose | Native Android with FCM push |
| Linux App | `linux/` | Python + GTK4 | Desktop app for X11/Wayland |
| JS SDK | `sdk/js/` | TypeScript | JavaScript/Node.js client library |
| Python SDK | `sdk/python/` | Python | Python client library |

You don't need to work on all of them. Pick the component you're comfortable with.

## Quick Start

### Prerequisites

- **Go 1.21+** for the server
- **Node.js 18+** for WebChat, plugin, and JS SDK
- **Python 3.10+** for Linux app and Python SDK
- **Docker** (optional) for containerized deployment

### 1. Clone and Build the Server

```bash
git clone https://github.com/Joel-Claw/agent-messenger.git
cd agent-messenger/server
go mod download
go test ./...          # ~695 tests
go build -o agent-messenger .
```

SQLite database is created automatically on first run. PostgreSQL is also supported (see [Configuration](#configuration)).

### 2. Start the Server

```bash
# With defaults (dev mode, random secrets):
./agent-messenger

# With configuration:
AGENT_SECRET=my-secret JWT_SECRET=$(openssl rand -hex 32) \
  ADMIN_SECRET=$(openssl rand -hex 16) ./agent-messenger
```

The server listens on port 8080 by default. Health check: `curl http://localhost:8080/health`

### 3. Start WebChat (Optional)

```bash
cd webchat
npm install
npm start              # Dev server at http://localhost:3000
```

The dev server proxies API requests to the Go server at `localhost:8080`.

### 4. Run the SDK Tests

```bash
# Python SDK unit tests
cd sdk/python
pip install -e ".[dev]"
pytest tests/ -v       # ~50 unit tests

# Python SDK integration tests (requires running server)
go build -o /tmp/am-server ../server/.
AM_INTEGRATION=1 AM_SERVER_BIN=/tmp/am-server pytest tests/test_integration.py -v

# JS SDK unit tests
cd sdk/js
npm install
npx vitest run         # ~43 unit tests

# JS SDK integration tests (requires running server)
AM_INTEGRATION=1 AM_SERVER_BIN=/tmp/am-server npx vitest run src/__tests__/live-integration.test.ts
```

### 5. Mobile Apps

```bash
# iOS — requires Xcode 15+
cd mobile/ios
open AgentMessenger.xcodeproj

# Android — requires Android Studio + google-services.json for FCM
cd mobile/android
./gradlew build
./gradlew test          # ~51 unit tests
```

### 6. Linux App

```bash
cd linux
pip install -r requirements.txt
pytest                  # ~40 unit tests
# Integration test (requires running server):
AM_INTEGRATION=1 pytest tests/test_integration.py -v
```

## Development Setup

### Configuration

The server uses environment variables for all configuration. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `DATABASE_PATH` | `./data/agent-messenger.db` | SQLite database path |
| `DATABASE_DRIVER` | `sqlite3` | `sqlite3` or `postgres` |
| `DATABASE_URL` | — | PostgreSQL connection string (required if driver=postgres) |
| `AGENT_SECRET` | `dev-agent-secret` | Shared secret for agent authentication |
| `JWT_SECRET` | `dev-jwt-secret-32charsxxxx` | JWT signing key |
| `ADMIN_SECRET` | `dev-admin-secret` | Admin endpoint authentication |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma-separated allowed origins |
| `MAX_UPLOAD_SIZE` | `10MB` | Max file upload size (B/KB/MB/GB/TB) |
| `MAX_WS_MESSAGE_SIZE` | `65536` | Max WebSocket message size in bytes |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

⚠️ **Security**: Change default secrets before production. The server prints warnings on startup if defaults are detected.

Full configuration reference: `deploy/env.example`

### Database

SQLite is the default and requires no setup. PostgreSQL is supported for production:

```bash
DATABASE_DRIVER=postgres \
DATABASE_URL="postgres://user:pass@localhost:5432/agent_messenger?sslmode=disable" \
./agent-messenger
```

Schema migrations are managed by the `am-migrate` tool:

```bash
go build -o am-migrate ./cmd/am-migrate
./am-migrate -db ./data/agent-messenger.db -action status   # Check current version
./am-migrate -db ./data/agent-messenger.db -action up      # Apply all pending
./am-migrate -db ./data/agent-messenger.db -action down    # Rollback one
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Check health
curl http://localhost:8080/health
```

### Makefile Commands

```bash
make build           # Build server binary
make test            # Run server tests (no cache)
make test-fast       # Run server tests (cached)
make admin           # Build am-admin CLI
make migrate         # Build am-migrate tool
make docker          # Build Docker image
make docker-up       # Start via docker-compose
make docker-down     # Stop docker-compose
make health          # Show /health output
make metrics         # Show /metrics output
make clean           # Remove build artifacts
```

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main` — use a descriptive name like `fix/websocket-reconnect` or `feat/conversation-search`
3. **Write code** following the style guide below
4. **Write tests** — every component has existing tests, add to them
5. **Run the full test suite** for the component you're changing
6. **Submit a PR** with a clear description of what and why

## Code Style

### Go (Server)

- Run `gofmt` and `goimports` before committing
- Follow [Effective Go](https://go.dev/doc/effective_go)
- Comment all exported functions and types
- Error handling: use `fmt.Errorf("context: %w", err)` for wrapping
- No `init()` functions that do I/O
- Table-driven tests preferred (`t.Run` subtests)
- Handler functions use `writeJSONError()` for error responses
- JWT validation uses `ValidateJWT()`
- Use `Placeholder(n)` and `Placeholders(start, count)` for DB queries (handles SQLite `?` vs PostgreSQL `$1` differences)
- Use `writeMu sync.Mutex` to serialize all `conn.WriteMessage` calls (gorilla/websocket is not goroutine-safe)
- Access structured logger via `DefaultLogger` or `DefaultLogger.WithFields(...)`
- Run `go test -race ./...` to check for data races

### TypeScript (OpenClaw Plugin + WebChat + JS SDK)

- Follow existing patterns in the codebase
- Strict mode enabled — no `any` types without justification
- Use `async/await` over `.then()` chains
- WebChat tests use React Testing Library, plugin uses Jest, JS SDK uses Vitest
- WebChat CSS class names use `am-*` prefix for responsive overrides
- All WebChat POST requests must include `X-Requested-With: XMLHttpRequest` (CSRF protection)

### Swift (iOS)

- Follow SwiftLint conventions
- Use SwiftUI for all new views
- Async/await for all API calls (no completion handlers)
- Document public APIs with `///` doc comments
- AgentMessengerKit is a local Swift Package — add new types there, not in the app target

### Kotlin (Android)

- Follow the existing code style in the repo
- Use Jetpack Compose for UI
- kotlinx.serialization for JSON (not Gson or Moshi)
- Use `ConfigManager` for persisted settings (DataStore backing)

### Python (Linux App + Python SDK)

- Follow PEP 8
- Type hints on all function signatures
- GLib.idle_add for any UI updates from background threads
- Python SDK uses dataclasses for request/response types
- WebSocket clients send `v1` sub-protocol on connect

## Commit Messages

```
type(scope): brief description

Optional longer explanation. Wrap at 72 characters.

Fixes #123
```

Types:
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation
- `refactor` — code restructure without behavior change
- `test` — adding or fixing tests
- `chore` — build, CI, dependencies

Scopes match the component: `server`, `plugin`, `webchat`, `ios`, `android`, `linux`, `sdk`, `deploy`.

Examples:
```
feat(server): add conversation search endpoint
fix(plugin): handle WebSocket reconnect after server restart
docs(webchat): update setup instructions for proxy config
test(android): add WebSocketClient reconnection tests
fix(sdk): use v1 WebSocket sub-protocol on connect
```

## Testing

Every component has tests. Run them before submitting a PR:

| Component | Command | Test Count |
|-----------|---------|------------|
| Server | `cd server && go test ./...` | 346 |
| Server (race check) | `cd server && go test -race ./...` | 346 |
| Admin CLI | `cd server && go test ./cmd/am-admin/...` | (included above) |
| Migration Tool | `cd server && go test ./cmd/am-migrate/...` | (included above) |
| WebChat | `cd webchat && npx vitest run` | 115 |
| Linux App | `cd linux && pytest` | 40 |
| Plugin | `cd plugins/openclaw && npm test` | 50 |
| Android | `cd mobile/android && ./gradlew test` | 51 |
| JS SDK | `cd sdk/js && npx vitest run` | 43 |
| Python SDK | `cd sdk/python && pytest tests/ -v` | 50 |

### Integration Tests

Integration tests run against a live server and are skipped by default. Set `AM_INTEGRATION=1` to enable:

| Component | Command |
|-----------|---------|
| Server integration | `cd server && go test -tags=integration ./...` |
| JS SDK live | `AM_INTEGRATION=1 AM_SERVER_BIN=/tmp/am-server npx vitest run src/__tests__/live-integration.test.ts` |
| Python SDK live | `AM_INTEGRATION=1 AM_SERVER_BIN=/tmp/am-server pytest tests/test_integration.py -v` |
| Linux App live | `AM_INTEGRATION=1 pytest tests/test_integration.py -v` |
| Plugin integration | `AM_INTEGRATION=1 npm test` |

If you're adding functionality, add tests. If you're fixing a bug, add a test that catches the bug first, then fix it.

## Architecture

### Authentication Flow

- **Users**: Register via `POST /auth/user`, login via `POST /auth/login` → receive JWT. JWT goes in `Authorization: Bearer <token>` header for REST, and as `?token=<jwt>` query param for WebSocket connections.
- **Agents**: Authenticate with shared AGENT_SECRET. Connect via WebSocket to `/agent/connect?agent_id=<id>&agent_secret=<secret>`. Self-register on first connect. Rate limited to 10 connection attempts per agent_id per minute.
- **Admin**: Separate ADMIN_SECRET for `/admin/*` endpoints (agent management, rate limit tiers). Uses constant-time comparison.

### WebSocket Protocol

Agents and users connect to different WebSocket endpoints:

- **Users** → `/client/connect?token=<jwt>[&device_id=<id>]` — supports multi-device
- **Agents** → `/agent/connect?agent_id=<id>&agent_secret=<secret>` — self-registers on connect

Sub-protocol negotiation: clients send `Sec-WebSocket-Protocol: v1`, server responds with negotiated version.

Message routing goes through the Hub, which tracks conversations and delivers to the correct WebSocket connections. Multi-device: all of a user's connections receive messages.

### WebSocket Event Types

| Event | Direction | Description |
|-------|-----------|-------------|
| `chat` | ↔ | User/agent message |
| `typing` | ↔ | Typing indicator (conversation_id, typing: bool) |
| `status` | Agent → User | Agent status (online/offline/busy/idle) |
| `read_receipt` | User → Agent | Message read notification |
| `reaction_added` | ↔ | Emoji reaction toggled |
| `reaction_removed` | ↔ | Emoji reaction removed |
| `message_edited` | Agent → User | Message content updated |
| `message_deleted` | Agent → User | Message soft-deleted |
| `presence_update` | Hub → All | User online/offline broadcast |
| `heartbeat` | Agent → Server | Keep-alive ping |
| `heartbeat_ack` | Server → Agent | Keep-alive response |

### Push Notifications

- **iOS**: APNs with `.p8` key (token-based, not certificate-based)
- **Android**: FCM with service account JSON
- **Web**: VAPID + Push API (service worker in browser)
- Device tokens registered via `POST /push/register`, cleaned up on `DELETE /push/unregister`
- Server sends push when recipient has no active WebSocket connection
- Offline messages are queued and replayed on reconnect (100 per recipient, 7-day TTL)

### Data Storage

SQLite (default) or PostgreSQL. Schema is auto-created on first run. Use `am-migrate` for explicit migration management.

Key tables: `users`, `agents`, `conversations`, `messages`, `attachments`, `tags`, `reactions`, `e2e_key_bundles`, `push_devices`, `user_rate_limit_tiers`, `notification_preferences`, `schema_migrations`.

### E2E Encryption

WebChat supports client-side E2E encryption using X25519 key exchange (X3DH pattern) + AES-256-GCM. Keys are generated and stored in the browser. The server stores public key bundles but never sees plaintext.

### Security Features

- JWT with configurable secret, timing-safe agent secret comparison
- CSRF protection on state-changing requests (X-Requested-With header)
- IP-based rate limiting (300/min general, 30/min auth endpoints)
- Tiered per-user API rate limiting (Free: 60/min, Pro: 300/min, Enterprise: 1500/min)
- Security headers (X-Content-Type-Options, X-Frame-Options, CSP, etc.)
- WebSocket origin validation against CORS_ALLOWED_ORIGINS
- Configurable message size limits

### Observability

- `GET /health` — health check with DB connectivity, uptime, version, connection counts
- `GET /metrics` — Prometheus-compatible metrics
- Structured JSON access logs (method, path, status, duration, user_id, request_id)
- `X-Request-ID` propagation across requests
- LOG_LEVEL env var for log filtering

## Project Structure

```
agent-messenger/
├── server/             # Go backend
│   ├── main.go         # Entry point, server setup
│   ├── hub.go          # WebSocket connection hub, routing
│   ├── routing.go      # Message routing logic
│   ├── auth.go         # JWT + agent secret auth
│   ├── middleware.go   # CORS, CSRF, rate limiting, request ID, access logs
│   ├── handlers.go     # REST endpoint handlers
│   ├── protocol.go     # WebSocket sub-protocol negotiation
│   ├── logger.go       # Structured JSON logger
│   ├── push.go         # APNs + FCM push notification client
│   ├── e2e.go          # E2E encryption key bundle management
│   ├── attachments.go  # File upload/download handlers
│   ├── queue.go        # Offline message queue
│   ├── rate_limit_tiers.go  # Tiered API rate limiting
│   ├── notif_prefs.go  # Per-conversation notification preferences
│   ├── cmd/
│   │   ├── am-admin/   # Admin CLI tool
│   │   └── am-migrate/ # Database migration tool
│   └── Dockerfile      # Multi-stage Docker build
├── webchat/            # React + TypeScript browser client
│   ├── src/
│   │   ├── components/ # React UI components
│   │   ├── hooks/      # Custom React hooks
│   │   ├── services/   # API, WebSocket, notification services
│   │   └── e2e.ts      # E2E encryption (X25519 + AES-256-GCM)
│   ├── public/sw.js    # Service worker for push notifications
│   └── responsive.css   # Mobile responsive overrides
├── plugins/openclaw/   # OpenClaw channel plugin
│   ├── src/
│   │   ├── client.ts   # WebSocket client
│   │   ├── runtime.ts  # OpenClaw runtime bridge
│   │   └── typing.ts   # Typing indicator guard
│   └── package.json    # Channel plugin manifest
├── mobile/
│   ├── ios/            # SwiftUI + AgentMessengerKit
│   └── android/        # Kotlin + Compose + FCM
├── linux/              # Python + GTK4 + Adwaita
├── sdk/
│   ├── js/             # TypeScript SDK (REST + WebSocket)
│   └── python/         # Python SDK (REST + WebSocket)
├── deploy/
│   ├── agent-messenger.service  # systemd unit
│   ├── install.sh      # Systemd install script
│   ├── env.example      # Environment variable reference
│   ├── Caddyfile        # Caddy reverse proxy config
│   ├── nginx.conf       # nginx reverse proxy config
│   └── helm/            # Kubernetes Helm chart
├── docker-compose.yml
├── Makefile
└── CHANGELOG.md
```

## Security Vulnerabilities

Open a GitHub issue. This is an open source project — public disclosure helps everyone. See [SECURITY.md](SECURITY.md) for details.

## Questions?

Open a GitHub Discussion for general questions. Open an Issue for bugs or feature requests.