# Agent Messenger SDK — Python

Client SDK for [Agent Messenger](../../README.md) — self-hosted messaging between humans and AI agents.

## Installation

```bash
pip install agent-messenger

# With WebSocket support (requires websockets)
pip install agent-messenger[ws]
```

## Quick Start

### User Client

```python
from agent_messenger import AgentMessengerClient

client = AgentMessengerClient(base_url="http://localhost:8080")

# Login
result = client.login(username="alice", password="secret")
print(f"Logged in as {result.username}")

# List agents
agents = client.rest.list_agents()

# Create a conversation
conv = client.rest.create_conversation(agent_id=agents[0].agent_id)

# Connect WebSocket for real-time messaging
connected = client.connect()
print(f"Connected: {connected.id}")

# Register event handlers
def on_message(data):
    print(f"Agent says: {data.content}")

client.on("message", on_message)

# Send a message
client.ws.send_message(conv.conversation_id, "Hello, agent!")

# Disconnect when done
client.disconnect()
```

### Agent Client

```python
import os
from agent_messenger import AgentClient

agent = AgentClient(
    base_url="http://localhost:8080",
    agent_id="my-agent",
    agent_secret=os.environ["AGENT_SECRET"],
    agent_name="HelpBot",
    agent_model="gpt-4",
)

connected = agent.connect()

def on_message(data):
    print(f"User {data.sender_id}: {data.content}")
    agent.ws.send_message(data.conversation_id, "I received your message!")

agent.on("message", on_message)

# Keep running...
import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    agent.disconnect()
```

## API Reference

### `AgentMessengerClient`

High-level client combining REST API + WebSocket.

| Method | Description |
|--------|-------------|
| `login(username, password)` | Login and auto-set token |
| `register(username, password)` | Register new user |
| `connect()` | Connect WebSocket |
| `disconnect()` | Disconnect WebSocket |
| `on(event, handler)` | Register event handler |
| `off(event, handler)` | Remove event handler |
| `rest.*` | All REST API methods |

### REST API Methods (`client.rest.*`)

| Method | Endpoint |
|--------|----------|
| `login(req)` | POST /auth/login |
| `register_user(req)` | POST /auth/user |
| `register_agent(req)` | POST /auth/agent |
| `change_password(req)` | POST /auth/change-password |
| `list_agents()` | GET /agents |
| `create_conversation(req)` | POST /conversations/create |
| `list_conversations(limit, offset, tag)` | GET /conversations/list |
| `get_messages(conv_id, limit, before)` | GET /conversations/messages |
| `delete_conversation(conv_id)` | DELETE /conversations/delete |
| `mark_read(conv_id)` | POST /conversations/mark-read |
| `search_messages(query, limit)` | GET /messages/search |
| `edit_message(req)` | POST /messages/edit |
| `delete_message(msg_id)` | POST /messages/delete |
| `react(msg_id, emoji)` | POST /messages/react |
| `get_reactions(msg_id)` | GET /messages/reactions |
| `add_tag(req)` | POST /conversations/tags/add |
| `remove_tag(req)` | POST /conversations/tags/remove |
| `get_tags(conv_id)` | GET /conversations/tags |
| `get_presence()` | GET /presence |
| `upload_attachment(conv_id, file, ...)` | POST /attachments/upload |
| `upload_key_bundle(req)` | POST /keys/upload |
| `get_key_bundle(user_id)` | GET /keys/bundle |
| `store_encrypted_message(req)` | POST /messages/encrypted |
| `get_encrypted_messages(conv_id, ...)` | GET /messages/encrypted/list |
| `register_device_token(req)` | POST /push/register |
| `unregister_device_token(req)` | POST /push/unregister |
| `health()` | GET /health |
| `metrics()` | GET /metrics |

### WebSocket Events

| Event | Data Type | Description |
|-------|-----------|-------------|
| `connected` | `WSConnectedData` | Server confirmed connection |
| `message` | `WSChatData` | Incoming chat message |
| `message_sent` | `WSMessageSentData` | Message delivery confirmation |
| `typing` | `WSTypingData` | Typing indicator |
| `status` | `WSStatusData` | Status update |
| `read_receipt` | `WSReadReceiptData` | Read receipt |
| `reaction_added` | `WSReactionData` | Reaction added |
| `reaction_removed` | `WSReactionData` | Reaction removed |
| `error` | `WSErrorData` | Error |
| `disconnect` | `None` | Connection closed |

### WebSocket Methods (`client.ws.*`)

| Method | Description |
|--------|-------------|
| `send_message(conv_id, content, metadata?)` | Send a chat message |
| `send_typing(conv_id)` | Send typing indicator |
| `send_status(conv_id, status)` | Send status update |
| `connect()` | Connect (returns `WSConnectedData`) |
| `disconnect()` | Disconnect |
| `on(event, handler)` | Register handler |
| `off(event, handler)` | Remove handler |
| `set_token(token)` | Update JWT token |

### `AgentClient`

High-level client for AI agents.

| Method | Description |
|--------|-------------|
| `connect()` | Connect as agent |
| `disconnect()` | Disconnect |
| `on(event, handler)` | Register event handler |
| `off(event, handler)` | Remove event handler |
| `ws.send_message(conv_id, content)` | Send a message |
| `ws.send_typing(conv_id)` | Send typing indicator |
| `ws.send_status(status, conv_id?)` | Send status update |

### Config

#### `ClientConfig`
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | `str` | required | Server URL |
| `token` | `str` | `""` | JWT token |
| `device_id` | `str` | `""` | Device ID |
| `protocol_version` | `str` | `"v1"` | WS protocol version |
| `auto_reconnect` | `bool` | `True` | Auto-reconnect |
| `max_reconnect_attempts` | `int` | `10` | Max reconnect attempts |
| `reconnect_base_delay` | `float` | `1.0` | Base delay (seconds) |

#### `AgentConfig`
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | `str` | required | Server URL |
| `agent_id` | `str` | required | Agent ID |
| `agent_secret` | `str` | required | Shared secret |
| `agent_name` | `str` | `""` | Display name |
| `agent_model` | `str` | `""` | Model name |
| `agent_personality` | `str` | `""` | Personality |
| `agent_specialty` | `str` | `""` | Specialty |
| `protocol_version` | `str` | `"v1"` | WS protocol version |
| `auto_reconnect` | `bool` | `True` | Auto-reconnect |
| `max_reconnect_attempts` | `int` | `10` | Max reconnect attempts |
| `reconnect_base_delay` | `float` | `1.0` | Base delay (seconds) |

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT