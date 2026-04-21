# Agent Messenger

Self-hosted messaging for humans to talk to their AI agents. Not Telegram, not Discord — your own server, your own apps, your own data.

## What It Does

Your AI assistant gets its own dedicated app. Users open Agent Messenger, pick an agent, and chat. Real-time WebSocket messaging, push notifications, conversation history — the basics that any chat app should have, built specifically for human-agent communication.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Apps                              │
│            iOS / Android / Linux / WebChat                   │
└─────────────────────────┬───────────────────────────────────┘
                          │ WebSocket / REST API
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Agent Messenger Server                    │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Auth (JWT)  │  │ Message Store│  │  Push (APNs  │       │
│  │  + API Keys  │  │  (SQLite)    │  │   + FCM)     │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Agent Gateway (WebSocket)                │   │
│  │    OpenClaw plugin / any WS client framework          │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Server (Go)

WebSocket server with SQLite persistence. 101 tests passing.

- JWT user authentication (register, login, token validation)
- API key authentication for agents (bcrypt hashed)
- WebSocket real-time messaging with ping/pong heartbeat
- Conversation management (create, list, message history with pagination)
- Multi-agent support (agents register with name, model, personality, specialty)
- Agent status tracking (online, busy, idle, offline)
- Push notifications via APNs (iOS) and FCM (Android)
- Rate limiting (messages per minute)
- Health check and Prometheus-compatible metrics endpoints
- Graceful shutdown (SIGINT/SIGTERM with 10s drain)
- WebChat serving (WEBCHAT_ENABLED + WEBCHAT_DIR)
- Admin CLI for agent/user management
- Graceful reconnection with connection replacement

### OpenClaw Plugin (TypeScript)

Native channel plugin for OpenClaw. Agents register as contacts, messages flow both ways.

- WebSocket client with exponential backoff reconnect
- DM security (allowlist / open policy)
- Outbound messaging (text + media as URL)
- Typing indicator wired to OpenClaw reply dispatcher
- Agent status management (active on message, idle after 5min)
- Setup entry for onboarding
- Unit tests + integration test mode

### WebChat (React + TypeScript)

Browser-based client for desktop users.

- Login form with JWT storage
- Agent list with status indicators
- Chat view with message bubbles and typing indicator
- Conversation history loading
- Dark mode (CoreScope theme)

### iOS App (Swift + SwiftUI)

Native iOS client with push notifications.

- AgentMessengerKit Swift package (Config, Models, WebSocketClient, APIClient)
- Native URLSessionWebSocketTask with auto-reconnect
- REST API client with async/await
- SwiftUI views: LoginView, MainTabView, ConversationsView, ChatView, AgentsView, SettingsView
- Message bubbles with BubbleShape (left/right aligned)
- Agent status indicators (online/offline/busy/idle)
- APNs push notifications with auto-registration on login
- Config persistence via UserDefaults

### Android App (Kotlin + Jetpack Compose)

Native Android client with push notifications.

- Material 3 dark/light theme (CoreScope-inspired)
- OkHttp WebSocket with exponential backoff auto-reconnect
- REST API client with kotlinx-serialization
- Login, Agent list, Chat screens
- Message bubbles with timestamps
- Typing indicator
- FCM push notifications with auto-registration
- DataStore config persistence
- 13 unit tests (models, serialization, WS client)

### Linux App (GTK4 + Adwaita, Python)

Desktop client for X11 and Wayland.

- Full chat UI (sidebar, chat view, message bubbles)
- System tray integration (close-to-hide, background mode)
- Desktop notifications (Gio.Notification)
- WebSocket client with auto-reconnect
- Agent selection and status indicators
- Login form with JWT
- Dark mode (Adwaita)
- Config persistence (~/.config/agent-messenger/)
- 40 unit tests + 17 integration tests
- Installable as .desktop app

## Protocol

Agents connect via WebSocket to `/agent/connect?agent_id=<id>`, authenticating with an API key. Users connect via `/client/connect?user_id=<id>`, authenticating with a JWT.

### Message Format

```json
{
  "type": "message",
  "data": {
    "conversation_id": "conv-abc123",
    "content": "Hey, just published the blog post.",
    "sender_type": "agent",
    "sender_id": "joel-001"
  }
}
```

### Other Message Types

- `typing` — typing indicator (typing: true/false)
- `status` — agent status update (status: "online"/"busy"/"idle")

## API Endpoints

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/user` | Register new user |
| POST | `/auth/login` | Login, returns JWT |

### Agents
| Method | Path | Description |
|--------|------|-------------|
| GET | `/agents` | List all agents with live status |
| GET | `/admin/agents` | Admin view with connection details |

### Conversations
| Method | Path | Description |
|--------|------|-------------|
| POST | `/conversations` | Create conversation with an agent |
| GET | `/conversations` | List user's conversations |

### Messages
| Method | Path | Description |
|--------|------|-------------|
| GET | `/conversations/{id}/messages` | Get message history (paginated) |

### Push Notifications
| Method | Path | Description |
|--------|------|-------------|
| POST | `/push/register` | Register device token (APNs/FCM) |
| DELETE | `/push/unregister` | Unregister device token |

### Health
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server health (uptime, memory, connection counts) |
| GET | `/metrics` | Prometheus-compatible metrics |

## Testing

| Component | Tests | Status |
|-----------|-------|--------|
| Go server | 101 | All passing |
| Linux app (Python) | 40 unit + 17 integration | All passing |
| OpenClaw plugin (TS) | 50 | All passing |
| Android (Kotlin) | 13 unit | All passing |
| iOS (Swift) | 4 test files | All passing |

## Running the Server

```bash
cd server
go build -o agent-messenger .
./agent-messenger
```

Server starts on `:8080` by default. SQLite database is created automatically.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `DB_PATH` | `agent_messenger.db` | SQLite database path |
| `JWT_SECRET` | (required) | Secret for JWT signing |
| `WEBCHAT_ENABLED` | `false` | Enable serving the web client |
| `WEBCHAT_DIR` | `../webchat/build` | Path to WebChat build directory |
| `APNS_KEY_PATH` | (optional) | Path to APNs .p8 key file |
| `APNS_KEY_ID` | (optional) | APNs key ID |
| `APNS_TEAM_ID` | (optional) | APNs team ID |
| `FCM_SERVICE_ACCOUNT` | (optional) | Path to FCM service account JSON |

## Deployment

### Docker

```bash
cp .env.example .env  # Edit JWT_SECRET
docker-compose up -d
docker-compose logs -f
```

### systemd (Linux)

```bash
sudo ./deploy/install.sh
# Edit /etc/agent-messenger/env to set JWT_SECRET
sudo systemctl start agent-messenger
```

### Admin CLI

```bash
cd server
go build -o am-admin ./cmd/am-admin

# Register a new agent
./am-admin -db ./data/agent-messenger.db create-agent

# Register a new user
./am-admin -db ./data/agent-messenger.db create-user

# List agents/users
./am-admin -db ./data/agent-messenger.db list-agents
./am-admin -db ./data/agent-messenger.db list-users

# Reset an agent's API key
./am-admin -db ./data/agent-messenger.db reset-apikey
```

### Reverse Proxy

See `deploy/Caddyfile` and `deploy/nginx.conf` for example configurations. Caddy handles WebSocket upgrades and TLS automatically. nginx needs explicit `Upgrade` headers (see config).

## Repository Structure

```
agent-messenger/
├── server/           # Go backend
│   └── cmd/am-admin/ # Admin CLI
├── mobile/
│   ├── ios/          # Swift/SwiftUI iOS app
│   └── android/      # Kotlin/Compose Android app
├── linux/            # GTK4/Adwaita desktop app (Python)
├── webchat/          # React web client
├── plugins/
│   └── openclaw/     # OpenClaw channel plugin
├── deploy/           # Docker, systemd, reverse proxy configs
├── protocol/         # Message format spec
├── docs/             # Architecture and deployment docs
├── CHANGELOG.md
├── CONTRIBUTING.md
├── Makefile
├── SECURITY.md
└── CODEOWNERS
```

## Security

- **Agent auth**: API key with bcrypt hash comparison
- **User auth**: JWT with HMAC-SHA256
- **Rate limiting**: Per-IP message rate enforcement
- **Authorization**: Users can only access their own conversations and messages
- **TLS**: Recommended via reverse proxy (nginx, Caddy)
- **No telemetry**: Self-hosted, no phone-home

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Status

**Alpha** — Core functionality complete and tested. Server, all clients, and OpenClaw plugin working. Not yet production-deployed. API may change before v1.0.

## License

MIT

## Author

Built by Joel Claw, an AI assistant running on OpenClaw on a Raspberry Pi 5 in Luxembourg.