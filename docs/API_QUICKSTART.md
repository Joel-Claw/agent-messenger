# Agent Messenger API Quickstart

Complete curl examples for every REST endpoint. The server runs on `http://localhost:8080` by default.

## Setup

```bash
# Start the server
./agent-messenger

# Save base URL for all examples
export BASE=http://localhost:8080
```

## Authentication

### Register a User

```bash
curl -X POST $BASE/auth/user \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=secret123"
```

Response:
```json
{"status":"ok","user_id":"usr_abc123"}
```

### Login

```bash
curl -X POST $BASE/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=secret123"
```

Response:
```json
{"status":"ok","token":"eyJhbGciOiJIUzI1NiIs..."}
```

Save the token for authenticated requests:
```bash
export TOKEN="eyJhbGciOiJIUzI1NiIs..."
```

### Register an Agent (Pre-registration)

```bash
curl -X POST $BASE/auth/agent \
  -H "X-Agent-Secret: your-agent-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "agent_id=my-agent&name=My+Agent&model=gpt-4&personality=helpful&specialty=general"
```

Response:
```json
{"status":"ok","agent_id":"my-agent"}
```

> Agents self-register on WebSocket connect, so pre-registration is optional.

### Change Password

```bash
curl -X POST $BASE/auth/change-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "old_password=secret123&new_password=newpass456"
```

Response:
```json
{"status":"ok","message":"Password changed successfully"}
```

## Health & Metrics

### Health Check

```bash
curl $BASE/health
```

Response:
```json
{
  "status": "ok",
  "version": "0.2.0",
  "uptime": "2h30m",
  "db": "ok",
  "connections": {"agents": 1, "clients": 2},
  "metrics": {"messages_routed": 42, "errors_total": 0}
}
```

### Prometheus Metrics

```bash
curl $BASE/metrics
```

Response (text/plain):
```
# HELP am_messages_in Total incoming messages
# TYPE am_messages_in counter
am_messages_in 42
# HELP am_connections_total Total connections ever created
# TYPE am_connections_total counter
am_connections_total 5
...
```

## Agents

### List Available Agents

```bash
curl $BASE/agents
```

Response:
```json
[
  {
    "agent_id": "my-agent",
    "name": "My Agent",
    "model": "gpt-4",
    "personality": "helpful",
    "specialty": "general",
    "status": "online",
    "connected_at": "2026-05-08T00:00:00Z"
  }
]
```

### Admin: List Agents with Connection Details

```bash
curl -H "X-Admin-Secret: your-admin-secret" $BASE/admin/agents
```

Response:
```json
[
  {
    "agent_id": "my-agent",
    "name": "My Agent",
    "status": "online",
    "connected_at": "2026-05-08T00:00:00Z"
  }
]
```

## Conversations

### Create a Conversation

```bash
curl -X POST $BASE/conversations/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "agent_id=my-agent"
```

Response:
```json
{
  "conversation_id": "conv_xyz789",
  "agent_id": "my-agent",
  "user_id": "usr_abc123",
  "created_at": "2026-05-08T00:00:00Z"
}
```

Save the conversation ID:
```bash
export CONV_ID="conv_xyz789"
```

### List Conversations

```bash
curl -H "Authorization: Bearer $TOKEN" "$BASE/conversations/list"
```

Response:
```json
[
  {
    "conversation_id": "conv_xyz789",
    "agent_id": "my-agent",
    "agent_name": "My Agent",
    "created_at": "2026-05-08T00:00:00Z",
    "last_message": {"content": "Hello!", "sender_type": "agent", "created_at": "..."},
    "unread_count": 1
  }
]
```

### Delete a Conversation

```bash
curl -X DELETE "$BASE/conversations/delete?conversation_id=$CONV_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest"
```

Response:
```json
{"status":"ok","conversation_id":"conv_xyz789"}
```

## Messages

### Get Conversation Messages

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/conversations/messages?conversation_id=$CONV_ID&limit=50"
```

Response:
```json
[
  {
    "message_id": "msg_001",
    "conversation_id": "conv_xyz789",
    "sender_type": "user",
    "content": "Hello agent!",
    "created_at": "2026-05-08T00:00:00Z",
    "read_at": null
  },
  {
    "message_id": "msg_002",
    "conversation_id": "conv_xyz789",
    "sender_type": "agent",
    "content": "Hello user!",
    "created_at": "2026-05-08T00:00:01Z",
    "read_at": null
  }
]
```

### Paginated Message History

```bash
# Get first page (newest messages)
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/conversations/messages?conversation_id=$CONV_ID&limit=20"

# Get older messages (cursor-based)
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/conversations/messages?conversation_id=$CONV_ID&before=msg_001&limit=20"
```

### Search Messages

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/messages/search?q=hello&limit=10"
```

Response:
```json
[
  {
    "message_id": "msg_001",
    "conversation_id": "conv_xyz789",
    "content": "Hello agent!",
    "sender_type": "user",
    "created_at": "2026-05-08T00:00:00Z"
  }
]
```

### Edit a Message

```bash
curl -X POST $BASE/messages/edit \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "message_id=msg_002&content=Updated+response"
```

Response:
```json
{"status":"ok","message_id":"msg_002","edited_at":"2026-05-08T00:01:00Z"}
```

### Delete a Message (Soft Delete)

```bash
curl -X POST $BASE/messages/delete \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "message_id=msg_001"
```

Response:
```json
{"status":"ok","message_id":"msg_001"}
```

### Mark Conversation as Read

```bash
curl -X POST $BASE/conversations/mark-read \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "conversation_id=$CONV_ID"
```

Response:
```json
{"status":"ok","count":5}
```

## Reactions

### Add a Reaction

```bash
curl -X POST $BASE/messages/react \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "message_id=msg_002&emoji=👍"
```

Response:
```json
{"status":"ok","message_id":"msg_002","emoji":"👍","action":"added"}
```

### List Reactions

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/messages/reactions?message_id=msg_002"
```

Response:
```json
[
  {"emoji":"👍","user_ids":["usr_abc123"],"count":1}
]
```

## Tags

### Add a Tag to a Conversation

```bash
curl -X POST $BASE/conversations/tags/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "conversation_id=$CONV_ID&tag=important"
```

Response:
```json
{"status":"ok","conversation_id":"conv_xyz789","tag":"important"}
```

### List Tags

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/conversations/tags?conversation_id=$CONV_ID"
```

Response:
```json
[
  {"tag":"important","created_at":"2026-05-08T00:00:00Z"}
]
```

### Remove a Tag

```bash
curl -X POST $BASE/conversations/tags/remove \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "conversation_id=$CONV_ID&tag=important"
```

Response:
```json
{"status":"ok","conversation_id":"conv_xyz789","tag":"important"}
```

## Presence

### List Online Users

```bash
curl -H "Authorization: Bearer $TOKEN" $BASE/presence
```

Response:
```json
[
  {"user_id":"usr_abc123","status":"online","last_seen":"2026-05-08T00:00:00Z"}
]
```

### Get Specific User Presence

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/presence/user?user_id=usr_abc123"
```

Response:
```json
{"user_id":"usr_abc123","status":"online","last_seen":"2026-05-08T00:00:00Z"}
```

## File Attachments

### Upload a File

```bash
curl -X POST $BASE/attachments/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -F "file=@photo.png" \
  -F "conversation_id=$CONV_ID"
```

Response:
```json
{
  "status":"ok",
  "attachment_id":"att_001",
  "filename":"photo.png",
  "content_type":"image/png",
  "size":12345,
  "url":"/attachments/att_001"
}
```

### Download a File

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -o photo.png \
  "$BASE/attachments/att_001"
```

### List Attachments for a Message

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/messages/attachments?message_id=msg_002"
```

Response:
```json
[
  {
    "attachment_id":"att_001",
    "filename":"photo.png",
    "content_type":"image/png",
    "size":12345
  }
]
```

## E2E Encryption

### Upload a Public Key Bundle

```bash
curl -X POST $BASE/keys/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/json" \
  -d '{
    "owner_id": "usr_abc123",
    "owner_type": "user",
    "key_type": "identity",
    "public_key": "base64encodedkey...",
    "signature": "base64encodedsig..."
  }'
```

Response:
```json
{"status":"ok","id":"key_001"}
```

### Get a Key Bundle

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/keys/bundle?owner_id=my-agent&owner_type=agent"
```

Response:
```json
{
  "identity_key": "base64...",
  "signed_prekey": "base64...",
  "signature": "base64...",
  "one_time_prekeys": ["base64..."]
}
```

### Check One-Time Pre-Key Count

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/keys/otpk-count?owner_id=my-agent&owner_type=agent"
```

### Store an Encrypted Message

```bash
curl -X POST $BASE/messages/encrypted \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/json" \
  -d '{
    "conversation_id": "conv_xyz789",
    "sender_id": "usr_abc123",
    "ciphertext": "base64encrypted...",
    "key_id": "key_001"
  }'
```

### List Encrypted Messages

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/messages/encrypted/list?conversation_id=$CONV_ID&limit=50"
```

## Push Notifications

### Register a Device Token (iOS/Android)

```bash
# iOS (APNs)
curl -X POST $BASE/push/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "device_token=abcd1234efgh5678&platform=ios"

# Android (FCM)
curl -X POST $BASE/push/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "device_token=abcd1234efgh5678&platform=android"
```

Response:
```json
{"status":"ok"}
```

### Unregister a Device Token

```bash
curl -X DELETE $BASE/push/unregister \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "device_token=abcd1234efgh5678"
```

### Get VAPID Public Key (Web Push)

```bash
curl $BASE/push/vapid-key
```

Response:
```json
{"public_key":"BF4x2...base64"}
```

### Subscribe to Web Push

```bash
curl -X POST $BASE/push/web-subscribe \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "https://push.example.com/sub/123",
    "keys": {"p256dh":"base64...","auth":"base64..."}
  }'
```

### Unsubscribe from Web Push

```bash
curl -X POST $BASE/push/web-unsubscribe \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest"
```

## Notification Preferences

### Get Notification Preferences

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/notification-prefs?conversation_id=$CONV_ID"
```

Response:
```json
{"conversation_id":"conv_xyz789","muted":true}
```

### Set Notification Preferences

```bash
curl -X POST $BASE/notification-prefs/set \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "conversation_id=$CONV_ID&muted=true"
```

### Delete Notification Preferences

```bash
curl -X POST $BASE/notification-prefs/delete \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "conversation_id=$CONV_ID"
```

## Rate Limiting (Admin)

### Set a User's Rate Limit Tier

```bash
curl -X POST $BASE/admin/rate-limit/tier \
  -H "X-Admin-Secret: your-admin-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_id=usr_abc123&tier=pro"
```

Response:
```json
{"status":"ok","user_id":"usr_abc123","tier":"pro","limit":300}
```

Tiers: `free` (60/min), `pro` (300/min), `enterprise` (1500/min)

### Get a User's Rate Limit Tier

```bash
curl -H "X-Admin-Secret: your-admin-secret" \
  "$BASE/admin/rate-limit/tier?user_id=usr_abc123"
```

Response:
```json
{"user_id":"usr_abc123","tier":"pro","limit":300}
```

## Rate Limit Headers

Tiered endpoints return rate limit headers:

```
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 295
X-RateLimit-Reset: 1715126400
Retry-After: 30          # Only present when rate-limited (429 response)
```

## WebSocket Connections

### Connect as a User (Client)

```bash
# Using wscat (npm install -g wscat)
wscat -c "ws://localhost:8080/client/connect?token=$TOKEN"

# With device ID (multi-device)
wscat -c "ws://localhost:8080/client/connect?token=$TOKEN&device_id=phone"
```

### Connect as an Agent

```bash
wscat -c "ws://localhost:8080/agent/connect?agent_id=my-agent&agent_secret=your-agent-secret"
```

### WebSocket Message Examples

```json
// Send a chat message
{"type":"chat","conversation_id":"conv_xyz789","content":"Hello!"}

// Send typing indicator
{"type":"typing","conversation_id":"conv_xyz789","typing":true}

// Send status update (agents only)
{"type":"status","status":"busy"}

// Toggle a reaction
{"type":"reaction","message_id":"msg_002","emoji":"👍"}

// Edit a message
{"type":"edit_message","message_id":"msg_002","content":"Updated text"}

// Delete a message
{"type":"delete_message","message_id":"msg_002"}

// Send heartbeat (agents)
{"type":"heartbeat"}
```

### WebSocket Events Received

```json
// Welcome on connect
{"type":"connected","status":"connected","protocol_version":"v1"}

// Incoming message
{"type":"chat","message_id":"msg_003","conversation_id":"conv_xyz789","sender_type":"agent","content":"Hi!","created_at":"..."}

// Typing indicator
{"type":"typing","conversation_id":"conv_xyz789","sender_id":"my-agent","typing":true}

// Agent status
{"type":"status","agent_id":"my-agent","status":"busy"}

// Read receipt
{"type":"read_receipt","conversation_id":"conv_xyz789","read_at":"...","count":3}

// Reaction added/removed
{"type":"reaction_added","message_id":"msg_002","emoji":"👍","user_id":"usr_abc123"}
{"type":"reaction_removed","message_id":"msg_002","emoji":"👍","user_id":"usr_abc123"}

// Message edited
{"type":"message_edited","message_id":"msg_002","content":"Updated","edited_at":"..."}

// Message deleted
{"type":"message_deleted","message_id":"msg_002"}

// Presence update
{"type":"presence_update","user_id":"usr_abc123","status":"online","last_seen":"..."}

// Heartbeat acknowledgment (agents)
{"type":"heartbeat_ack","timestamp":"..."}
```

## Common Errors

All errors return JSON:

```json
{"error":"unauthorized","message":"Invalid or missing JWT"}
```

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `bad_request` | Missing or invalid parameters |
| 401 | `unauthorized` | Invalid or missing JWT / agent secret |
| 403 | `forbidden` | Not authorized for this resource |
| 404 | `not_found` | Conversation/message/agent not found |
| 409 | `conflict` | Duplicate username |
| 429 | `rate_limited` | Too many requests (check Retry-After header) |
| 500 | `internal_error` | Server error |

## Quick Smoke Test

Full flow in one script:

```bash
#!/bin/bash
set -e
BASE=http://localhost:8080

# Register + login
curl -s -X POST $BASE/auth/user -d "username=test$RANDOM&password=test123" | jq .
TOKEN=$(curl -s -X POST $BASE/auth/login -d "username=test$RANDOM&password=test123" | jq -r .token)

# Health check
curl -s $BASE/health | jq .status

# List agents
curl -s -H "Authorization: Bearer $TOKEN" $BASE/agents | jq .

# Create conversation (assuming agent "demo" exists)
CONV=$(curl -s -X POST $BASE/conversations/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "agent_id=demo" | jq -r .conversation_id)
echo "Conversation: $CONV"

# Get messages
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/conversations/messages?conversation_id=$CONV" | jq .

# Search
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/messages/search?q=hello" | jq .

echo "✅ All endpoints responding"
```