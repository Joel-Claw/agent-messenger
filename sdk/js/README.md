# Agent Messenger SDK — JavaScript/TypeScript

Client SDK for [Agent Messenger](../../README.md) — self-hosted messaging between humans and AI agents.

## Installation

```bash
npm install @anthropic/agent-messenger
# or
yarn add @anthropic/agent-messenger
```

## Quick Start

### User Client (Browser / Node.js)

```typescript
import { AgentMessengerClient } from '@anthropic/agent-messenger';

const client = new AgentMessengerClient({
  baseUrl: 'http://localhost:8080',
});

// Login
const { token, user_id } = await client.login({
  username: 'alice',
  password: 'secret',
});

// List available agents
const agents = await client.rest.listAgents();

// Create a conversation
const conv = await client.rest.createConversation({
  agent_id: agents[0].agent_id,
});

// Connect WebSocket for real-time messaging
await client.connect();

client.on('message', (data) => {
  console.log('Agent says:', data.content);
});

client.on('typing', (data) => {
  console.log('Agent is typing...');
});

// Send a message
client.ws.sendMessage(conv.conversation_id, 'Hello, agent!');

// Disconnect when done
client.disconnect();
```

### Agent Client (Node.js)

```typescript
import { AgentClient } from '@anthropic/agent-messenger';

const agent = new AgentClient({
  baseUrl: 'http://localhost:8080',
  agentId: 'my-agent',
  agentSecret: process.env.AGENT_SECRET!,
  agentName: 'HelpBot',
  agentModel: 'gpt-4',
});

await agent.connect();

agent.on('message', (data) => {
  console.log(`User ${data.sender_id} in conv ${data.conversation_id}: ${data.content}`);
  agent.ws.sendMessage(data.conversation_id, 'I received your message!');
});

agent.on('disconnect', () => {
  console.log('Disconnected, will auto-reconnect...');
});
```

## API Reference

### `AgentMessengerClient`

High-level client combining REST API + WebSocket. Requires a JWT token (obtained via login).

| Method | Description |
|--------|-------------|
| `login({ username, password })` | Login and auto-set token |
| `register({ username, password })` | Register new user |
| `connect()` | Connect WebSocket |
| `disconnect()` | Disconnect WebSocket |
| `on(event, handler)` | Register event handler |
| `off(event, handler)` | Remove event handler |
| `rest.*` | All REST API methods |

### REST API Methods (`client.rest.*`)

| Method | Endpoint |
|--------|----------|
| `login(req)` | POST /auth/login |
| `registerUser(req)` | POST /auth/user |
| `changePassword(req)` | POST /auth/change-password |
| `listAgents()` | GET /agents |
| `createConversation(req)` | POST /conversations/create |
| `listConversations(limit?, offset?, tag?)` | GET /conversations/list |
| `getMessages(convId, limit?, before?)` | GET /conversations/messages |
| `deleteConversation(convId)` | DELETE /conversations/delete |
| `markRead(convId)` | POST /conversations/mark-read |
| `searchMessages(query, limit?)` | GET /messages/search |
| `editMessage(req)` | POST /messages/edit |
| `deleteMessage(msgId)` | POST /messages/delete |
| `react(msgId, emoji)` | POST /messages/react |
| `getReactions(msgId)` | GET /messages/reactions |
| `addTag(req)` | POST /conversations/tags/add |
| `removeTag(req)` | POST /conversations/tags/remove |
| `getTags(convId)` | GET /conversations/tags |
| `getPresence()` | GET /presence |
| `getUserPresence(userId?)` | GET /presence/user |
| `uploadAttachment(convId, file)` | POST /attachments/upload |
| `uploadKeyBundle(req)` | POST /keys/upload |
| `getKeyBundle(userId)` | GET /keys/bundle |
| `storeEncryptedMessage(req)` | POST /messages/encrypted |
| `getEncryptedMessages(convId, ...)` | GET /messages/encrypted/list |
| `registerDeviceToken(req)` | POST /push/register |
| `unregisterDeviceToken(req)` | POST /push/unregister |
| `health()` | GET /health |
| `metrics()` | GET /metrics |

### WebSocket Events

| Event | Data Type | Description |
|-------|-----------|-------------|
| `connected` | `WSConnectedData` | Server confirmed connection |
| `message` | `WSChatData` | Incoming chat message |
| `message_sent` | `WSMessageSentData` | Confirmation that your message was delivered |
| `typing` | `WSTypingData` | Other party is typing |
| `status` | `WSStatusData` | Agent/user status update |
| `read_receipt` | `WSReadReceiptData` | Messages marked as read |
| `reaction_added` | `WSReactionData` | Reaction added |
| `reaction_removed` | `WSReactionData` | Reaction removed |
| `error` | `WSErrorData` | Server error |
| `disconnect` | `null` | Connection closed |
| `reconnect` | — | Reconnected after disconnect |

### WebSocket Methods (`client.ws.*`)

| Method | Description |
|--------|-------------|
| `sendMessage(convId, content, metadata?)` | Send a chat message |
| `sendTyping(convId)` | Send typing indicator |
| `sendStatus(convId, status)` | Send status update |
| `connect()` | Connect (returns Promise) |
| `disconnect()` | Disconnect |
| `on(event, handler)` | Register handler |
| `off(event, handler)` | Remove handler |
| `setToken(token)` | Update JWT token |

### `AgentClient`

High-level client for AI agents with WebSocket connection.

| Method | Description |
|--------|-------------|
| `connect()` | Connect as agent |
| `disconnect()` | Disconnect |
| `on(event, handler)` | Register event handler |
| `off(event, handler)` | Remove event handler |
| `ws.sendMessage(convId, content)` | Send a message |
| `ws.sendTyping(convId)` | Send typing indicator |
| `ws.sendStatus(status, convId?)` | Send status update |

### `ClientConfig` / `AgentConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `baseUrl` | `string` | required | Server URL |
| `token` | `string` | — | JWT token (Client only) |
| `agentId` | `string` | required | Agent ID (Agent only) |
| `agentSecret` | `string` | required | Shared secret (Agent only) |
| `deviceId` | `string` | — | Device ID for multi-device sync |
| `protocolVersion` | `string` | `'v1'` | WebSocket sub-protocol version |
| `autoReconnect` | `boolean` | `true` | Auto-reconnect on disconnect |
| `maxReconnectAttempts` | `number` | `10` | Max reconnect attempts |
| `reconnectBaseDelay` | `number` | `1000` | Base delay (ms), doubles each attempt |

## Node.js Usage

The SDK uses the browser `WebSocket` API by default. For Node.js, install `ws`:

```bash
npm install ws
```

Then pass the WebSocket implementation:

```typescript
import WebSocket from 'ws';
import { ClientWS } from '@anthropic/agent-messenger';

const ws = new ClientWS({
  baseUrl: 'http://localhost:8080',
  token: 'jwt-token',
  wsImpl: WebSocket as any,
});
```

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT