/**
 * E2E integration test for Agent Messenger OpenClaw plugin.
 *
 * Tests the FULL round-trip message flow:
 *   user (raw WS) → server → plugin client (AgentMessengerClient) → reply → server → user
 *
 * Uses the ACTUAL AgentMessengerClient from the plugin (no mocks for WS),
 * against a real Agent Messenger server process.
 *
 * Requires:
 *   AM_INTEGRATION=1
 *   AM_SERVER_BIN=/tmp/am-server (or built with: cd server && go build -o /tmp/am-server .)
 *
 * Run:
 *   AM_INTEGRATION=1 AM_SERVER_BIN=/tmp/am-server \
 *     npx vitest run src/__tests__/e2e-plugin.test.ts
 *
 * NOTE: This test is skipped by default. Set AM_INTEGRATION=1 to enable.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { AgentMessengerClient, type UserMessage } from '../client.js';
import WebSocket from 'ws';
import { spawn, type ChildProcess } from 'child_process';
import { unlinkSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const ENABLED = process.env.AM_INTEGRATION === '1';
const SERVER_BIN = process.env.AM_SERVER_BIN || '/tmp/am-server';

// ─── Server lifecycle ───────────────────────────────────────────────────────

let serverProc: ChildProcess | null = null;
let serverPort = 0;
let serverBaseUrl = '';
let serverWsUrl = '';
let dbPath = '';
const AGENT_SECRET = 'e2e-test-agent-secret';
const JWT_SECRET = 'e2e-test-jwt-secret-32-characters!!';
const ADMIN_SECRET = 'e2e-test-admin-secret';

function findFreePort(): number {
  // Use a deterministic port based on PID to avoid collisions across runs
  // Check a few ports starting from base
  const base = 20000 + (process.pid % 10000);
  return base;
}

async function waitForServer(port: number, maxMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    try {
      const resp = await fetch(`http://localhost:${port}/health`);
      if (resp.ok) return;
    } catch {
      // Not ready yet
    }
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error(`Server did not start on port ${port} within ${maxMs}ms`);
}

// ─── Test helpers ───────────────────────────────────────────────────────────

let userCounter = 0;

async function registerUser(): Promise<{ token: string; userId: string }> {
  userCounter++;
  const username = `e2e_user_${userCounter}_${Date.now()}`;
  // Register
  const regResp = await fetch(`${serverBaseUrl}/auth/user`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: `username=${username}&password=testpass123`,
  });
  if (!regResp.ok) throw new Error(`Registration failed: ${regResp.status}`);
  const regData = await regResp.json() as any;
  // Login to get JWT
  const loginResp = await fetch(`${serverBaseUrl}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: `username=${username}&password=testpass123`,
  });
  if (!loginResp.ok) throw new Error(`Login failed: ${loginResp.status}`);
  const loginData = await loginResp.json() as any;
  return { token: loginData.token, userId: regData.user_id };
}

async function createConversation(token: string, agentId: string): Promise<string> {
  const resp = await fetch(`${serverBaseUrl}/conversations/create`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Requested-With': 'XMLHttpRequest',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `agent_id=${agentId}`,
  });
  expect(resp.ok).toBe(true);
  const data = await resp.json() as any;
  return data.conversation_id;
}

function connectUserClient(token: string, deviceId?: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    let url = `${serverWsUrl}/client/connect?token=${token}`;
    if (deviceId) url += `&device_id=${deviceId}`;
    const ws = new WebSocket(url, 'v1');
    const timeout = setTimeout(() => {
      ws.close();
      reject(new Error('User client connect timeout'));
    }, 8000);
    ws.on('open', () => {
      clearTimeout(timeout);
      resolve(ws);
    });
    ws.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

function safeClose(ws: WebSocket | null): void {
  if (!ws) return;
  try {
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close();
    }
  } catch { /* ignore */ }
}

function waitForMessage(ws: WebSocket, type: string, timeoutMs = 8000): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timeout waiting for ${type}`)), timeoutMs);
    ws.on('message', function handler(data: Buffer) {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === type) {
          clearTimeout(timer);
          ws.off('message', handler);
          resolve(msg);
        }
      } catch { /* ignore parse errors */ }
    });
  });
}

function collectMessages(ws: WebSocket, type: string, durationMs = 3000): Promise<any[]> {
  return new Promise((resolve) => {
    const msgs: any[] = [];
    ws.on('message', (data: Buffer) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === type) msgs.push(msg);
      } catch { /* ignore */ }
    });
    setTimeout(() => resolve(msgs), durationMs);
  });
}

// ─── Test suite ─────────────────────────────────────────────────────────────

describe.skipIf(!ENABLED)('Agent Messenger Plugin E2E', () => {
  // Active connections to clean up
  const activeConnections: (WebSocket | AgentMessengerClient)[] = [];

  function track<T extends WebSocket | AgentMessengerClient>(conn: T): T {
    activeConnections.push(conn);
    return conn;
  }

  beforeAll(async () => {
    serverPort = findFreePort();
    const tmpDir = mkdtempSync(join(tmpdir(), 'am-e2e-'));
    dbPath = join(tmpDir, 'test.db');

    serverProc = spawn(SERVER_BIN, ['-port', String(serverPort)], {
      env: {
        ...process.env,
        AGENT_SECRET,
        JWT_SECRET,
        ADMIN_SECRET,
        DB_PATH: dbPath,
        AUTH_RATE_LIMIT: '200',
        IP_RATE_LIMIT: '1000',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    await waitForServer(serverPort);
    serverBaseUrl = `http://localhost:${serverPort}`;
    serverWsUrl = `ws://localhost:${serverPort}`;
  }, 20000);

  afterAll(() => {
    // Clean up all tracked connections
    for (const conn of activeConnections) {
      if (conn instanceof WebSocket) {
        safeClose(conn);
      } else if ('disconnect' in conn) {
        (conn as AgentMessengerClient).disconnect();
      }
    }
    activeConnections.length = 0;

    if (serverProc) {
      serverProc.kill('SIGTERM');
      serverProc = null;
    }
    if (dbPath) {
      try { unlinkSync(dbPath); } catch { /* ignore */ }
    }
  });

  afterEach(() => {
    // Clean per-test connections (but keep server running)
  });

  // ─── Connection tests ─────────────────────────────────────────────────

  it('should connect plugin client to server as agent', async () => {
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId: `e2e-agent-connect-${Date.now()}`,
      agentName: 'E2E Test Agent',
      agentModel: 'test-model',
      agentPersonality: 'helpful',
      agentSpecialty: 'e2e-testing',
    }));

    await expect(client.connect()).resolves.toBeUndefined();
    expect(client.connected).toBe(true);
    client.disconnect();
  });

  it('should receive connected event from server', async () => {
    const agentId = `e2e-agent-welcome-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    // The connect() resolves when WebSocket opens, which is after
    // the server sends the 'connected' welcome
    await client.connect();
    expect(client.connected).toBe(true);
    client.disconnect();
  });

  // ─── User → Agent message flow ────────────────────────────────────────

  it('should route user message to plugin client', async () => {
    const agentId = `e2e-agent-recv-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
      agentName: 'Receiver Agent',
    }));

    await client.connect();

    // Register user and create conversation
    const { token, userId } = await registerUser();
    const convId = await createConversation(token, agentId);

    // Set up message handler on plugin client
    const receivedMsg = new Promise<UserMessage>((resolve) => {
      client.onMessage((msg) => resolve(msg));
    });

    // Connect user and send message
    const userWs = track(await connectUserClient(token));

    // Wait for connected event first
    await waitForMessage(userWs, 'connected', 5000);

    // Send chat message
    userWs.send(JSON.stringify({
      type: 'chat',
      conversation_id: convId,
      content: 'Hello from user to plugin!',
    }));

    // Plugin client should receive the user message
    const msg = await receivedMsg;
    expect(msg.type).toBe('user_message');
    expect(msg.content).toBe('Hello from user to plugin!');
    expect(msg.conversation_id).toBe(convId);

    client.disconnect();
    safeClose(userWs);
  });

  // ─── Agent → User reply flow ─────────────────────────────────────────

  it('should deliver agent reply from plugin client to user', async () => {
    const agentId = `e2e-agent-reply-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
      agentName: 'Reply Agent',
    }));

    await client.connect();

    const { token, userId } = await registerUser();
    const convId = await createConversation(token, agentId);

    // Connect user
    const userWs = track(await connectUserClient(token));
    await waitForMessage(userWs, 'connected', 5000);

    // When plugin receives user message, send a reply
    const replyReceived = new Promise<any>((resolve) => {
      userWs.on('message', (data: Buffer) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.type === 'chat' && msg.sender_type === 'agent' && msg.content === 'Reply from plugin!') {
            resolve(msg);
          }
        } catch { /* ignore */ }
      });
    });

    // Plugin receives message and sends reply
    client.onMessage((msg) => {
      client.sendMessage('Reply from plugin!', msg.conversation_id);
    });

    // User sends initial message
    userWs.send(JSON.stringify({
      type: 'chat',
      conversation_id: convId,
      content: 'Hello agent!',
    }));

    // User should receive the agent's reply
    const reply = await replyReceived;
    expect(reply.type).toBe('chat');
    expect(reply.content).toBe('Reply from plugin!');
    expect(reply.conversation_id).toBe(convId);

    client.disconnect();
    safeClose(userWs);
  });

  // ─── Full round-trip: user → plugin → deliver → user ──────────────────

  it('should complete full round-trip with deliver callback', async () => {
    const agentId = `e2e-agent-roundtrip-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
      agentName: 'Roundtrip Agent',
    }));

    await client.connect();

    const { token, userId } = await registerUser();
    const convId = await createConversation(token, agentId);

    const userWs = track(await connectUserClient(token));
    await waitForMessage(userWs, 'connected', 5000);

    // Simulate what runtime.ts does: onMessage → process → deliver via sendMessage
    let processedCount = 0;
    client.onMessage((msg) => {
      // Simulate OpenClaw processing — deliver reply back through plugin client
      processedCount++;
      client.sendMessage(`Processed: ${msg.content}`, msg.conversation_id);
      // Also send typing indicator (like runtime does)
      client.sendTyping(msg.conversation_id, false);
    });

    // Collect messages on user side
    const agentReplies: any[] = [];
    userWs.on('message', (data: Buffer) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'chat' && msg.sender_type === 'agent') {
          agentReplies.push(msg);
        }
      } catch { /* ignore */ }
    });

    // Send 3 messages
    for (let i = 1; i <= 3; i++) {
      userWs.send(JSON.stringify({
        type: 'chat',
        conversation_id: convId,
        content: `Message ${i}`,
      }));
      // Small delay between messages to avoid ordering issues
      await new Promise(r => setTimeout(r, 200));
    }

    // Wait for all 3 replies
    await new Promise(r => setTimeout(r, 3000));

    expect(processedCount).toBe(3);
    expect(agentReplies.length).toBeGreaterThanOrEqual(3);
    // Verify content of replies
    const replyContents = agentReplies.map(r => r.content);
    expect(replyContents).toContain('Processed: Message 1');
    expect(replyContents).toContain('Processed: Message 2');
    expect(replyContents).toContain('Processed: Message 3');

    client.disconnect();
    safeClose(userWs);
  });

  // ─── Typing indicator flow ────────────────────────────────────────────

  it('should route typing indicator from plugin to user', async () => {
    const agentId = `e2e-agent-typing-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    await client.connect();

    const { token } = await registerUser();
    const convId = await createConversation(token, agentId);

    const userWs = track(await connectUserClient(token));
    await waitForMessage(userWs, 'connected', 5000);

    // Agent sends typing indicator
    client.sendTyping(convId, true);

    // User should receive typing event
    const typingMsg = await waitForMessage(userWs, 'typing', 5000);
    expect(typingMsg.conversation_id).toBe(convId);
    expect(typingMsg.typing).toBe(true);

    // Agent stops typing
    client.sendTyping(convId, false);

    const typingOff = await waitForMessage(userWs, 'typing', 5000);
    expect(typingOff.typing).toBe(false);

    client.disconnect();
    safeClose(userWs);
  });

  // ─── Agent status flow ───────────────────────────────────────────────

  it('should route agent status updates to user', async () => {
    const agentId = `e2e-agent-status-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    await client.connect();

    const { token } = await registerUser();
    const convId = await createConversation(token, agentId);

    const userWs = track(await connectUserClient(token));
    await waitForMessage(userWs, 'connected', 5000);

    // Agent sends status update
    client.sendStatus('busy');

    // User should receive status event
    const statusMsg = await waitForMessage(userWs, 'status', 5000);
    expect(statusMsg.agent_id).toBe(agentId);
    expect(statusMsg.status).toBe('busy');

    client.disconnect();
    safeClose(userWs);
  });

  // ─── Multi-device: user connected from 2 devices ─────────────────────

  it('should deliver messages to all user devices', async () => {
    const agentId = `e2e-agent-multidev-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    await client.connect();

    const { token } = await registerUser();
    const convId = await createConversation(token, agentId);

    // Connect same user from 2 devices
    const userWs1 = track(await connectUserClient(token, 'device-1'));
    const userWs2 = track(await connectUserClient(token, 'device-2'));
    await waitForMessage(userWs1, 'connected', 5000);
    await waitForMessage(userWs2, 'connected', 5000);

    // Agent sends a message
    client.sendMessage('Hello both devices!', convId);

    // Both devices should receive it
    const msg1 = waitForMessage(userWs1, 'chat', 5000);
    const msg2 = waitForMessage(userWs2, 'chat', 5000);
    const [received1, received2] = await Promise.all([msg1, msg2]);

    expect(received1.content).toBe('Hello both devices!');
    expect(received2.content).toBe('Hello both devices!');

    client.disconnect();
    safeClose(userWs1);
    safeClose(userWs2);
  });

  // ─── Reconnection ────────────────────────────────────────────────────

  it('should handle plugin client reconnection', async () => {
    const agentId = `e2e-agent-reconnect-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    // First connection
    await client.connect();
    expect(client.connected).toBe(true);

    // Disconnect
    client.disconnect();
    expect(client.connected).toBe(false);

    // Reconnect — create new client since disconnect() prevents auto-reconnect
    const client2 = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    await client2.connect();
    expect(client2.connected).toBe(true);

    // Verify the reconnected agent still works
    const { token } = await registerUser();
    const convId = await createConversation(token, agentId);
    const userWs = track(await connectUserClient(token));
    await waitForMessage(userWs, 'connected', 5000);

    const receivedMsg = new Promise<UserMessage>((resolve) => {
      client2.onMessage((msg) => resolve(msg));
    });

    userWs.send(JSON.stringify({
      type: 'chat',
      conversation_id: convId,
      content: 'Message after reconnect',
    }));

    const msg = await receivedMsg;
    expect(msg.content).toBe('Message after reconnect');

    client2.disconnect();
    safeClose(userWs);
  });

  // ─── Message ordering ─────────────────────────────────────────────────

  it('should preserve message ordering for rapid sends', async () => {
    const agentId = `e2e-agent-order-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    await client.connect();

    const { token } = await registerUser();
    const convId = await createConversation(token, agentId);
    const userWs = track(await connectUserClient(token));
    await waitForMessage(userWs, 'connected', 5000);

    // Collect user messages received by agent
    const receivedMessages: string[] = [];
    const allReceived = new Promise<void>((resolve) => {
      let count = 0;
      client.onMessage((msg) => {
        receivedMessages.push(msg.content);
        count++;
        if (count === 5) resolve();
      });
    });

    // Rapidly send 5 messages
    for (let i = 1; i <= 5; i++) {
      userWs.send(JSON.stringify({
        type: 'chat',
        conversation_id: convId,
        content: `Rapid ${i}`,
      }));
    }

    await allReceived;

    // Verify ordering is preserved
    expect(receivedMessages).toEqual(['Rapid 1', 'Rapid 2', 'Rapid 3', 'Rapid 4', 'Rapid 5']);

    client.disconnect();
    safeClose(userWs);
  });

  // ─── Error handling ────────────────────────────────────────────────────

  it('should fail to connect with wrong agent secret', async () => {
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: 'wrong-secret',
      agentId: `e2e-agent-bad-${Date.now()}`,
    }));

    await expect(client.connect()).rejects.toThrow();
    expect(client.connected).toBe(false);
    client.disconnect();
  });

  it('should handle invalid JSON gracefully', async () => {
    const agentId = `e2e-agent-json-${Date.now()}`;
    const client = track(new AgentMessengerClient({
      serverUrl: serverWsUrl,
      agentSecret: AGENT_SECRET,
      agentId,
    }));

    await client.connect();

    const { token } = await registerUser();
    const convId = await createConversation(token, agentId);
    const userWs = track(await connectUserClient(token));
    await waitForMessage(userWs, 'connected', 5000);

    // Send invalid JSON — server should not disconnect the client
    userWs.send('not json at all');

    // Connection should still be alive — send a valid message
    const receivedMsg = new Promise<UserMessage>((resolve) => {
      client.onMessage((msg) => resolve(msg));
    });

    userWs.send(JSON.stringify({
      type: 'chat',
      conversation_id: convId,
      content: 'After bad JSON',
    }));

    const msg = await receivedMsg;
    expect(msg.content).toBe('After bad JSON');

    client.disconnect();
    safeClose(userWs);
  });
});