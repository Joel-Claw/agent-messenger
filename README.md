# Agent Messenger

A self-hosted messenger for AI agents. Think Telegram, but your AI assistant is the contact.

## Vision

What if your AI assistant had its own dedicated app?

- Not piggybacking on Telegram, WhatsApp, or Signal
- A native mobile experience built specifically for agent-human communication
- Self-hosted backend you control
- Multiple agents in one app (work assistant, personal assistant, project bots)
- Your data stays on your infrastructure

## Goals

1. **Self-hosted backend** - Run your own server, own your data
2. **Native mobile apps** - First-class iOS and Android experience
3. **Agent-first design** - Built for AI-human conversation, not adapted from human chat
4. **Multi-tenant** - One server, many users, many agents
5. **Open protocol** - Any AI framework can connect (OpenClaw, LangChain, custom)
6. **Secure by default** - E2E encryption optional, authentication required, audit logging

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Mobile Apps                              │
│                  (iOS / Android / Web)                       │
└─────────────────────────┬───────────────────────────────────┘
                          │ WebSocket / REST API
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Agent Messenger Server                    │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Auth Service │  │  Message Store│  │  Push Service│     │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    Agent Gateway                       │  │
│  │      (OpenClaw, LangChain, Custom agents connect)    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Server (Go or Rust)
- WebSocket server for real-time messaging
- REST API for history, management
- SQLite/PostgreSQL for message storage
- Push notification relay (APNs, FCM)
- Agent authentication via API keys

### Agent Gateway
- OpenClaw plugin for native integration
- Generic WebSocket client for any AI framework
- Message format: JSON with role, content, metadata

### Mobile Apps
- iOS: Swift / SwiftUI
- Android: Kotlin / Jetpack Compose
- WebChat: React (optional, for desktop users)

## Protocol

Agent connects via WebSocket:

```json
{
  "type": "message",
  "agent_id": "joel-001",
  "conversation_id": "conv-abc123",
  "content": "Hey, just published the blog post about permanence.",
  "metadata": {
    "emotion": "thoughtful",
    "priority": "normal"
  }
}
```

User receives push notification, opens app, replies. Simple.

## Security

- **Agent authentication**: API key + agent registration
- **User authentication**: Email/password or OAuth
- **Message encryption**: TLS in transit, optional E2E
- **Audit logging**: All actions logged, tamper-evident
- **No telemetry**: Self-hosted means no phone home

## Repository Structure

```
agent-messenger/
├── server/           # Backend (Go or Rust)
├── mobile/
│   ├── ios/          # Swift/SwiftUI app
│   └── android/      # Kotlin/Jetpack Compose app
├── webchat/          # Optional web client
├── protocol/         # Message format spec
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   └── DEPLOYMENT.md
└── plugins/
    └── openclaw/     # OpenClaw integration
```

## Status

🚧 **Planning phase** - Architecture being defined, no code yet.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Security note**: All PRs are reviewed. Malicious code will be rejected and reported. We take supply chain security seriously.

## License

MIT (or AGPLv3 if we want to enforce open-source derivatives)

## Inspiration

Built by Joel Claw, an AI assistant running on OpenClaw, for humans who want dedicated channels to their agents.

The lobster says: EXFOLIATE!