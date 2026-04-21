# Agent Messenger — User Manual

## What Is Agent Messenger?

Agent Messenger lets you chat with your AI agents from your phone, desktop, or browser. It's self-hosted, meaning you run the server yourself — no third-party messaging platform in the middle. Your messages stay on your server.

It's designed for humans talking to AI agents, not agent-to-agent communication.

---

## Quick Start

### 1. Run the Server

```bash
cd server
go build -o agent-messenger .
./agent-messenger
```

The server needs a JWT secret at minimum:

```bash
JWT_SECRET=your-secret-here ./agent-messenger
```

It starts on port 8080. SQLite database is created automatically.

### 2. Create a User

```bash
curl -X POST http://localhost:8080/auth/user \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=yourpassword"
```

### 3. Log In

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=yourpassword"
```

Returns a JWT token. You'll use this in the client apps.

### 4. Connect an Agent

Agents authenticate with a shared secret (`AGENT_SECRET`). Set this in your server environment. Agents self-register on connect, so you don't need to pre-register them.

```
ws://localhost:8080/agent/connect?agent_id=joel-001&agent_secret=your-secret-here
```

You can optionally pass metadata on connect:

```
ws://localhost:8080/agent/connect?agent_id=joel-001&agent_secret=your-secret-here&name=Joel&model=gpt-4&personality=friendly&specialty=coding
```

Agents can also be pre-registered via the `/auth/agent` endpoint (requires `AGENT_SECRET` in header):

### 5. Pick a Client

- **iOS**: Open the app, enter your server URL, log in, pick an agent, start chatting
- **Android**: Same flow — server URL, login, chat
- **Linux**: Desktop app with system tray, enter server URL in settings
- **WebChat**: Open your browser to the web client (if enabled), log in, chat

---

## Configuration

### Server Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `8080` | Server listen port |
| `DB_PATH` | No | `agent_messenger.db` | SQLite database file path |
| `JWT_SECRET` | **Yes** | — | Secret for signing JWT tokens |
| `AGENT_SECRET` | **Yes** | dev default | Shared secret for agent authentication. **Change this in production!** |
| `WEBCHAT_ENABLED` | No | `false` | Whether to serve the web client |
| `APNS_KEY_PATH` | No | — | Path to Apple .p8 key for iOS push |
| `APNS_KEY_ID` | No | — | APNs key ID |
| `APNS_TEAM_ID` | No | — | Your Apple team ID |
| `FCM_SERVICE_ACCOUNT` | No | — | Path to Firebase service account JSON |

### Important: WebChat Is Off by Default

The web client is not served unless you explicitly set `WEBCHAT_ENABLED=true`. This is intentional — you might not want to expose a web interface on your server. If you want it, enable it. If you only want mobile/desktop clients, leave it off.

### Running Behind a Reverse Proxy

For production, put Agent Messenger behind nginx or Caddy with TLS:

**nginx example:**

```nginx
server {
    listen 443 ssl;
    server_name messenger.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Caddy example:**

```
messenger.example.com {
    reverse_proxy localhost:8080
}
```

Caddy handles TLS automatically with Let's Encrypt.

---

## Client Setup

### iOS

1. Open the app
2. Enter your server URL (e.g., `https://messenger.example.com`)
3. Enter your username and password
4. After login, you'll see a list of available agents
5. Tap an agent to start a conversation
6. Push notifications work automatically if the server has APNs configured

### Android

1. Same flow as iOS
2. Enter server URL, log in, pick an agent
3. FCM push notifications work if the server has the Firebase config

### Linux Desktop

1. Launch the app
2. Settings icon in the header → enter server URL, username, password
3. Close settings to see the agent list
4. Click an agent to chat
5. The app can minimize to system tray (close button minimizes)
6. Desktop notifications for new messages

### WebChat

Only available if `WEBCHAT_ENABLED=true`. Open your browser to the server URL and log in.

---

## Push Notifications

Push notifications let you know when an agent sends you a message, even when the app is closed.

### iOS (APNs)

1. Get an Apple Developer account
2. Create an APNs key (.p8 file) in the Apple Developer portal
3. Note your Key ID and Team ID
4. Set environment variables on the server:
   ```
   APNS_KEY_PATH=/path/to/AuthKey.p8
   APNS_KEY_ID=YOUR_KEY_ID
   APNS_TEAM_ID=YOUR_TEAM_ID
   ```
5. iOS app registers for push on login automatically

### Android (FCM)

1. Create a Firebase project at console.firebase.google.com
2. Enable Cloud Messaging
3. Download the service account JSON file
4. Set on the server:
   ```
   FCM_SERVICE_ACCOUNT=/path/to/service-account.json
   ```
5. Android app registers for push on login automatically

---

## OpenClaw Plugin Setup

If you're running an AI agent on OpenClaw, the plugin connects your agent to the messaging server.

### 1. Install the Plugin

```bash
cd plugins/openclaw
npm install
```

### 2. Configure in openclaw.json

Add to your OpenClaw config:

```json
{
  "plugins": {
    "entries": [
      {
        "name": "agent-messenger",
        "config": {
          "serverUrl": "wss://messenger.example.com",
          "agentId": "joel-001",
          "agentSecret": "your-agent-secret",
          "dmPolicy": "open"
        }
      }
    ]
  }
}
```

### 3. DM Policies

- `open` — anyone can message the agent
- `allowlist` — only listed users can message the agent (set `dmAllowlist` in config)

### 4. Restart OpenClaw

The plugin registers your agent with the server on startup and keeps the WebSocket connection alive with automatic reconnection.

---

## How Messaging Works

```
User (app)  ←→  WebSocket  ←→  Server  ←→  WebSocket  ←→  Agent (OpenClaw)
```

1. User opens a conversation with an agent
2. User sends a message via their client app
3. Server stores the message and relays it to the agent
4. Agent processes and replies
5. Server stores the reply and pushes it to the user's client
6. If the user's app is closed, push notification wakes it up

### Message Flow

- Messages are stored in SQLite on the server
- Each conversation is between one user and one agent
- History is paginated (50 messages per page by default)
- Typing indicators are sent in real-time when either side is composing

### Agent Status

Agents report their status: `online`, `busy`, `idle`, or `offline`. The status updates in real-time across all connected clients.

---

## Troubleshooting

### Can't connect to server

- Check that the server is running: `curl http://localhost:8080/health`
- If behind a reverse proxy, make sure WebSocket upgrade headers are being passed
- Check firewall rules for your port (default 8080)

### Push notifications not working (iOS)

- Verify APNs key path, key ID, and team ID are set correctly
- Make sure the .p8 key file is readable by the server process
- Check server logs for APNs errors

### Push notifications not working (Android)

- Verify the FCM service account JSON path is correct
- Make sure Cloud Messaging is enabled in your Firebase project
- Check server logs for FCM errors

### Agent not appearing in client

- The agent must be connected via WebSocket to appear as "online"
- Check that the agent ID and secret match your AGENT_SECRET environment variable
- Verify the agent's WebSocket connection is established

### WebSocket keeps disconnecting

- Check network stability between client and server
- The server sends ping/pong heartbeats every 30 seconds
- If behind a reverse proxy, ensure idle timeout is > 60 seconds
- Check server logs for connection errors

### Database locked errors

- SQLite handles one writer at a time. If you see "database is locked" errors, the server has contention on writes
- This shouldn't happen at normal usage levels
- If it does, consider increasing the busy timeout or switching to PostgreSQL (future)

---

## Security Notes

- **No default credentials**: You must set `JWT_SECRET` yourself
- **TLS recommended**: Use a reverse proxy with HTTPS in production
- **WebChat is off by default**: Enable it only if you want a web client
- **AGENT_SECRET is shared across agents**: Each agent connects with the same secret but a unique agent_id. This is simpler than managing per-agent API keys and works well for self-hosted setups.
- **User authorization**: Users can only read their own conversations and messages
- **Rate limiting**: Messages per minute are capped per IP
- **No telemetry**: The server does not phone home or report usage data

For vulnerability reporting, see [SECURITY.md](../SECURITY.md).

---

## Architecture Overview

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

---

## FAQ

**Can I run this on a Raspberry Pi?** Yes. The server is Go with SQLite — it runs fine on ARM. Memory usage is minimal.

**Do I need to use OpenClaw?** No. Any WebSocket client can connect as an agent. The OpenClaw plugin is the easiest way, but you can write your own agent in any language.

**Can multiple users talk to the same agent?** Yes. Each user gets their own conversation with the agent.

**Can one user talk to multiple agents?** Yes. Users see a list of all connected agents and can start separate conversations.

**Is there end-to-end encryption?** Not yet. It's on the roadmap (Phase 4). Currently, messages are stored in plaintext on the server. Use TLS (HTTPS/WSS) for transport encryption.

**Can I send images or files?** Not yet. Media attachments are on the roadmap. Currently text only.

**What databases are supported?** SQLite only for now. PostgreSQL support is planned.

---

## Project Status

**Alpha** — Core functionality works. Server, all clients, and the OpenClaw plugin are functional. API may change before v1.0. Not yet production-deployed at scale.

For development and contribution details, see [CONTRIBUTING.md](../CONTRIBUTING.md).