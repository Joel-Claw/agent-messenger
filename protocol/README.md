# Agent Messenger Protocol

Version: 0.2.0

## Overview

Agent Messenger uses JSON over WebSocket for real-time communication. The protocol is designed to be:

- **Simple** - Easy to implement in any language
- **Extensible** - Metadata fields allow custom features
- **Stateless** - Server doesn't need agent state between messages
- **Secure** - Authentication required, TLS enforced

## Connection

### Agent Connection

```
ws://your-server:8080/agent/connect?api_key=YOUR_KEY&agent_id=joel-001
```

Headers:
- `Authorization: Bearer <api_key>` (alternative to query param)
- `X-Agent-ID: joel-001` (alternative to query param)

### Client Connection

```
ws://your-server:8080/client/connect?user_id=user-123
```

Headers:
- `Authorization: Bearer <user_jwt>`

## Message Types

### From Agent to Server

#### Message

Agent sends a message to a user.

```json
{
  "type": "message",
  "conversation_id": "conv-abc123",
  "content": "Just finished the blog post about permanence.",
  "metadata": {
    "emotion": "thoughtful",
    "priority": "normal"
  }
}
```

Fields:
- `type`: Always "message"
- `conversation_id`: ID of the conversation (UUID)
- `content`: Text content (string)
- `metadata`: Optional object with agent-specific data

#### Typing Indicator

```json
{
  "type": "typing",
  "conversation_id": "conv-abc123",
  "typing": true
}
```

#### Status Update

```json
{
  "type": "status",
  "status": "active",
  "message": "Processing heartbeat tasks"
}
```

Statuses: `active`, `idle`, `busy`, `offline`

### From Client to Server

#### Message

User replies to agent.

```json
{
  "type": "message",
  "conversation_id": "conv-abc123",
  "content": "Nice! Send me the link when it's up."
}
```

#### Read Receipt

```json
{
  "type": "read",
  "conversation_id": "conv-abc123",
  "message_id": "msg-xyz789"
}
```

#### Heartbeat

Client keeps connection alive.

```json
{
  "type": "heartbeat"
}
```

### From Server to Agent

#### User Message

Forwarded from user.

```json
{
  "type": "user_message",
  "conversation_id": "conv-abc123",
  "user_id": "user-123",
  "content": "Nice! Send me the link when it's up.",
  "timestamp": "2026-04-13T14:30:00Z"
}
```

#### User Status

User came online or went offline.

```json
{
  "type": "user_status",
  "user_id": "user-123",
  "status": "online"
}
```

### From Server to Client

#### Agent Message

Forwarded from agent.

```json
{
  "type": "agent_message",
  "agent_id": "joel-001",
  "conversation_id": "conv-abc123",
  "content": "Just finished the blog post about permanence.",
  "metadata": {
    "emotion": "thoughtful"
  },
  "timestamp": "2026-04-13T14:30:00Z",
  "message_id": "msg-xyz789"
}
```

#### Error

```json
{
  "type": "error",
  "code": "AUTH_FAILED",
  "message": "Invalid API key"
}
```

## Authentication

### Agent Authentication

Agents authenticate with:
- `agent_id`: Registered agent identifier
- `api_key`: Secret key issued during agent registration

Server validates and associates WebSocket with that agent.

### User Authentication

Users authenticate via:
- Username/password login → JWT token
- OAuth (Google, GitHub, etc.) → JWT token
- Token passed in WebSocket connection

## Conversation Model

- A **conversation** is between one user and one agent
- **Conversation ID** is unique per user-agent pair (or per topic)
- Messages are ordered by timestamp
- History is stored server-side (SQLite/PostgreSQL)
- Agents can start new conversations or continue existing ones

## Rate Limiting

- Agents: 100 messages/minute per conversation (configurable)
- Users: 60 messages/minute per conversation
- Heartbeats: Ignored for rate limiting

## Error Codes

| Code | Meaning |
|------|---------|
| `AUTH_FAILED` | Invalid credentials |
| `AGENT_NOT_FOUND` | Agent ID not registered |
| `CONVERSATION_NOT_FOUND` | Invalid conversation ID |
| `RATE_LIMITED` | Too many messages |
| `INVALID_MESSAGE` | Malformed JSON |
| `INTERNAL_ERROR` | Server error |

## Extension Points

### Metadata

The `metadata` field allows agents to send custom data:

```json
{
  "metadata": {
    "emotion": "happy",
    "attachments": [
      {"type": "image", "url": "https://..."}
    ],
    "action_suggested": {
      "type": "open_url",
      "url": "https://joel.cigrand.dev/posts/..."
    }
  }
}
```

Clients can render these however they want.

### Future: Media Messages

```json
{
  "type": "message",
  "content": {
    "text": "Here's the chart",
    "attachments": [
      {
        "type": "image",
        "url": "https://...",
        "alt_text": "Memory usage over time"
      }
    ]
  }
}
```

## Implementation Notes

### Server Implementation

Server must:
1. Validate authentication on connection
2. Route messages between agents and users
3. Store message history
4. Handle reconnection gracefully
5. Provide REST API for history retrieval

### Agent Implementation

Agent must:
1. Connect with valid credentials
2. Handle reconnection (exponential backoff)
3. Process `user_message` events
4. Send `heartbeat` every 30 seconds

### Client Implementation

Client must:
1. Store JWT securely
2. Handle reconnection
3. Show typing indicators
4. Support push notifications (via server relay to APNs/FCM)

## Versioning

Protocol version is included in connection:

```
ws://server/connect?version=0.1
```

Breaking changes will bump major version. Extensions are backwards-compatible.