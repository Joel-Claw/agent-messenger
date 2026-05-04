/**
 * Agent Messenger SDK — Live integration tests against a running server.
 *
 * Requires AM_INTEGRATION=1 environment variable to run.
 * Starts the server binary, creates test fixtures, and validates
 * SDK REST + WebSocket operations end-to-end.
 *
 * Usage:
 *   AM_INTEGRATION=1 npx vitest run src/__tests__/live-integration.test.ts
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { AgentMessengerClient, AgentClient, RestClient } from '../index';
import type {
  AgentConfig,
  ClientConfig,
  WSChatData,
  WSConnectedData,
  WSStatusData,
  WSTypingData,
  WSReadReceiptData,
  WSReactionData,
} from '../types';

// Skip all tests unless AM_INTEGRATION=1
const shouldRun = process.env.AM_INTEGRATION === '1';

// We need `ws` for Node.js WebSocket support
let WSImpl: new (url: string, protocols?: string[]) => WebSocket;
if (shouldRun) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const wsModule = require('ws');
  WSImpl = wsModule.WebSocket || wsModule;
}

// ─── Server lifecycle ───────────────────────────────────────────────────────

import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';

const SERVER_BIN = process.env.AM_SERVER_BIN || path.resolve(__dirname, '../../../../server/agent-messenger');
const AGENT_SECRET = 'int-test-agent-secret';
const ADMIN_SECRET = 'int-test-admin-secret';
const JWT_SECRET = 'int-test-jwt-secret-32charsxxxx';

let serverProc: childProcess.ChildProcess | null = null;
let serverPort = 0;
let serverBaseUrl = '';
let serverWsUrl = '';
let dbPath = '';

function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = require('net').createServer();
    srv.listen(0, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function waitForServer(port: number, timeoutMs = 10000): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      const req = http.get(`http://localhost:${port}/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else if (Date.now() - start > timeoutMs) {
          reject(new Error(`Server returned ${res.statusCode}`));
        } else {
          setTimeout(check, 250);
        }
      });
      req.on('error', () => {
        if (Date.now() - start > timeoutMs) {
          reject(new Error('Server did not start in time'));
        } else {
          setTimeout(check, 250);
        }
      });
    };
    check();
  });
}

async function startServer(): Promise<void> {
  serverPort = await findFreePort();
  dbPath = path.join(os.tmpdir(), `am-int-test-${Date.now()}.db`);

  serverProc = childProcess.spawn(SERVER_BIN, ['-port', String(serverPort)], {
    env: {
      ...process.env,
      AGENT_SECRET,
      ADMIN_SECRET,
      JWT_SECRET,
      DATABASE_PATH: dbPath,
      PORT: String(serverPort),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  await waitForServer(serverPort);
  serverBaseUrl = `http://localhost:${serverPort}`;
  serverWsUrl = `ws://localhost:${serverPort}`;
}

function stopServer(): void {
  if (serverProc) {
    serverProc.kill('SIGTERM');
    try {
      serverProc.kill(); // Force kill after a moment
    } catch {}
    serverProc = null;
  }
  if (dbPath && fs.existsSync(dbPath)) {
    try { fs.unlinkSync(dbPath); } catch {}
  }
}

// ─── Unique ID helpers ─────────────────────────────────────────────────────

const ts = `${Date.now()}${Math.floor(Math.random() * 10000)}`;
let seq = 0;

function uid(prefix = 'u'): string {
  seq++;
  return `${prefix}_${seq}_${ts}`;
}

// ─── Test fixtures ──────────────────────────────────────────────────────────

async function makeUser(prefix = 'u'): Promise<{ client: AgentMessengerClient; token: string; userId: string }> {
  const username = uid(prefix);
  // Small delay to avoid auth rate limiting
  await new Promise(r => setTimeout(r, 300));
  const sdkClient = new AgentMessengerClient({
    baseUrl: serverBaseUrl,
  });
  const reg = await sdkClient.register({ username, password: 'testpass123' });
  return { client: sdkClient, token: reg.token, userId: reg.user_id };
}

async function makeAgent(prefix = 'a'): Promise<string> {
  const agentId = uid(prefix);
  await new Promise(r => setTimeout(r, 300));
  const rest = new RestClient(serverBaseUrl);
  await rest.registerAgent(AGENT_SECRET, {
    agent_id: agentId,
    agent_secret: AGENT_SECRET,
    name: `Test ${agentId}`,
    model: 'test-model',
    personality: 'helpful',
    specialty: 'testing',
  });
  return agentId;
}

// ─── Helper: wait for an event ──────────────────────────────────────────────

function waitForEvent<T>(
  emitter: { on: (event: string, handler: (data: T) => void) => void; off: (event: string, handler: (data: T) => void) => void },
  event: string,
  timeoutMs = 5000,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      emitter.off(event, handler);
      reject(new Error(`Timeout waiting for event "${event}"`));
    }, timeoutMs);
    const handler = (data: T) => {
      clearTimeout(timer);
      emitter.off(event, handler);
      resolve(data);
    };
    emitter.on(event, handler);
  });
}

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

// ─── Test suites ────────────────────────────────────────────────────────────

describe.skipIf(!shouldRun)('JS SDK Live Integration Tests', () => {
  beforeAll(async () => {
    await startServer();
  }, 15000);

  afterAll(() => {
    stopServer();
  });

  // ─── REST Integration ─────────────────────────────────────────────────────

  describe('REST Integration', () => {
    it('should check server health', async () => {
      const rest = new RestClient(serverBaseUrl);
      const health = await rest.health();
      expect(health.status).toBe('ok');
      expect(health.version).toBeTruthy();
    });

    it('should register a user and login', async () => {
      const { client, token, userId } = await makeUser('reg');
      expect(token).toBeTruthy();
      expect(userId).toBeTruthy();
    });

    it('should list agents', async () => {
      const { client } = await makeUser('agents');
      const agents = await client.rest.listAgents();
      expect(Array.isArray(agents)).toBe(true);
    });

    it('should create and list conversations', async () => {
      const { client } = await makeUser('conv');
      await delay(300);
      const agentId = await makeAgent('conv');
      const conv = await client.rest.createConversation({ agent_id: agentId });
      expect(conv.conversation_id).toBeTruthy();

      const convs = await client.rest.listConversations();
      expect(convs.length).toBeGreaterThanOrEqual(1);
    });

    it('should get empty messages for a new conversation', async () => {
      const { client } = await makeUser('msgs');
      await delay(300);
      const agentId = await makeAgent('msgs');
      const conv = await client.rest.createConversation({ agent_id: agentId });
      const messages = await client.rest.getMessages(conv.conversation_id);
      expect(Array.isArray(messages)).toBe(true);
    });

    it('should search messages', async () => {
      const { client } = await makeUser('search');
      const results = await client.rest.searchMessages('test query', 10);
      expect(results).toBeDefined();
    });

    it('should delete a conversation', async () => {
      const { client } = await makeUser('del');
      await delay(300);
      const agentId = await makeAgent('del');
      const conv = await client.rest.createConversation({ agent_id: agentId });
      const result = await client.rest.deleteConversation(conv.conversation_id);
      expect(result.status).toMatch(/ok|deleted/);
    });

    it('should add, list, and remove tags', async () => {
      const { client } = await makeUser('tags');
      await delay(300);
      const agentId = await makeAgent('tags');
      const conv = await client.rest.createConversation({ agent_id: agentId });

      await client.rest.addTag({ conversation_id: conv.conversation_id, tag: 'important' });
      await client.rest.addTag({ conversation_id: conv.conversation_id, tag: 'work' });

      const tags = await client.rest.getTags(conv.conversation_id);
      const tagNames = tags.map(t => t.tag);
      expect(tagNames).toContain('important');
      expect(tagNames).toContain('work');

      await client.rest.removeTag({ conversation_id: conv.conversation_id, tag: 'work' });
      const tags2 = await client.rest.getTags(conv.conversation_id);
      const tagNames2 = tags2.map(t => t.tag);
      expect(tagNames2).not.toContain('work');
      expect(tagNames2).toContain('important');
    });

    it('should mark conversation as read', async () => {
      const { client } = await makeUser('read');
      await delay(300);
      const agentId = await makeAgent('read');
      const conv = await client.rest.createConversation({ agent_id: agentId });
      const result = await client.rest.markRead(conv.conversation_id);
      expect(result.status).toMatch(/ok|marked_read/);
    });

    it('should get agent presence', async () => {
      const { client } = await makeUser('presence');
      const presence = await client.rest.getPresence();
      expect(Array.isArray(presence)).toBe(true);
    });

    it('should change password', async () => {
      const { client } = await makeUser('pw');
      await delay(500);
      const result = await client.rest.changePassword({
        current_password: 'testpass123',
        new_password: 'newpass456',
      });
      expect(result.status).toMatch(/ok|changed/);
    });
  });

  // ─── WebSocket Integration ────────────────────────────────────────────────

  describe('WebSocket Integration', () => {
    it('should connect as an agent', async () => {
      await delay(500);
      const agentId = await makeAgent('ws_conn');
      const agent = new AgentClient({
        baseUrl: serverWsUrl,
        agentId,
        agentSecret: AGENT_SECRET,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);

      try {
        const connected = await agent.connect();
        expect(connected).toBeDefined();
        expect(connected.status).toBe('connected');
      } finally {
        agent.disconnect();
      }
    });

    it('should connect as a client', async () => {
      await delay(500);
      const { token } = await makeUser('ws_cli');
      const client = new AgentMessengerClient({
        baseUrl: serverBaseUrl,
        token,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);

      try {
        const connected = await client.connect();
        expect(connected).toBeDefined();
      } finally {
        client.disconnect();
      }
    });

    it('should route messages from client to agent', async () => {
      await delay(500);
      const { client: sdkClient, token } = await makeUser('ws_msg');
      await delay(300);
      const agentId = await makeAgent('ws_msg');
      const conv = await sdkClient.rest.createConversation({ agent_id: agentId });

      // Connect as agent
      const agent = new AgentClient({
        baseUrl: serverWsUrl,
        agentId,
        agentSecret: AGENT_SECRET,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);
      await agent.connect();
      await delay(500);

      try {
        // Connect as client
        const userClient = new AgentMessengerClient({
          baseUrl: serverBaseUrl,
          token,
          autoReconnect: false,
          wsImpl: WSImpl,
        } as any);
        await userClient.connect();

        try {
          const messagePromise = waitForEvent<WSChatData>(agent, 'message');
          userClient.ws.sendMessage(conv.conversation_id, 'Hello from integration test!');
          const data = await messagePromise;
          expect(data.content).toBe('Hello from integration test!');
          expect(data.conversation_id).toBe(conv.conversation_id);
        } finally {
          userClient.disconnect();
        }
      } finally {
        agent.disconnect();
      }
    });

    it('should route messages from agent to client', async () => {
      await delay(500);
      const { client: sdkClient, token } = await makeUser('ws_reply');
      await delay(300);
      const agentId = await makeAgent('ws_reply');
      const conv = await sdkClient.rest.createConversation({ agent_id: agentId });

      const agent = new AgentClient({
        baseUrl: serverWsUrl,
        agentId,
        agentSecret: AGENT_SECRET,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);
      await agent.connect();
      await delay(500);

      try {
        const userClient = new AgentMessengerClient({
          baseUrl: serverBaseUrl,
          token,
          autoReconnect: false,
          wsImpl: WSImpl,
        } as any);
        await userClient.connect();

        try {
          const messagePromise = waitForEvent<WSChatData>(userClient, 'message');
          agent.ws.sendMessage(conv.conversation_id, 'Reply from agent!');
          const data = await messagePromise;
          expect(data.content).toBe('Reply from agent!');
          expect(data.conversation_id).toBe(conv.conversation_id);
        } finally {
          userClient.disconnect();
        }
      } finally {
        agent.disconnect();
      }
    });

    it('should route typing indicators', async () => {
      await delay(500);
      const { client: sdkClient, token } = await makeUser('ws_type');
      await delay(300);
      const agentId = await makeAgent('ws_type');
      const conv = await sdkClient.rest.createConversation({ agent_id: agentId });

      const agent = new AgentClient({
        baseUrl: serverWsUrl,
        agentId,
        agentSecret: AGENT_SECRET,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);
      await agent.connect();
      await delay(500);

      try {
        const userClient = new AgentMessengerClient({
          baseUrl: serverBaseUrl,
          token,
          autoReconnect: false,
          wsImpl: WSImpl,
        } as any);
        await userClient.connect();

        try {
          const typingPromise = waitForEvent<WSTypingData>(agent, 'typing');
          userClient.ws.sendTyping(conv.conversation_id);
          const data = await typingPromise;
          expect(data.conversation_id).toBe(conv.conversation_id);
        } finally {
          userClient.disconnect();
        }
      } finally {
        agent.disconnect();
      }
    });

    it('should broadcast agent status updates', async () => {
      await delay(500);
      const agentId = await makeAgent('ws_status');
      await delay(300);
      const { token } = await makeUser('ws_status');

      const agent = new AgentClient({
        baseUrl: serverWsUrl,
        agentId,
        agentSecret: AGENT_SECRET,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);
      await agent.connect();
      await delay(500);

      try {
        const userClient = new AgentMessengerClient({
          baseUrl: serverBaseUrl,
          token,
          autoReconnect: false,
          wsImpl: WSImpl,
        } as any);
        await userClient.connect();

        try {
          const statusPromise = waitForEvent<WSStatusData>(userClient, 'status');
          agent.ws.sendStatus('busy');
          const data = await statusPromise;
          expect(data.status).toBe('busy');
        } finally {
          userClient.disconnect();
        }
      } finally {
        agent.disconnect();
      }
    });

    it('should handle multiple devices for same user', async () => {
      await delay(500);
      const { client: sdkClient, token } = await makeUser('ws_multi');
      await delay(300);
      const agentId = await makeAgent('ws_multi');
      const conv = await sdkClient.rest.createConversation({ agent_id: agentId });

      // Connect agent
      const agent = new AgentClient({
        baseUrl: serverWsUrl,
        agentId,
        agentSecret: AGENT_SECRET,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);
      await agent.connect();
      await delay(500);

      try {
        // Connect two client devices
        const device1 = new AgentMessengerClient({
          baseUrl: serverBaseUrl,
          token,
          deviceId: 'device-1',
          autoReconnect: false,
          wsImpl: WSImpl,
        } as any);
        await device1.connect();

        const device2 = new AgentMessengerClient({
          baseUrl: serverBaseUrl,
          token,
          deviceId: 'device-2',
          autoReconnect: false,
          wsImpl: WSImpl,
        } as any);
        await device2.connect();

        try {
          // Both devices should receive agent message
          const promise1 = waitForEvent<WSChatData>(device1, 'message');
          const promise2 = waitForEvent<WSChatData>(device2, 'message');

          agent.ws.sendMessage(conv.conversation_id, 'Multi-device message!');

          const [data1, data2] = await Promise.all([promise1, promise2]);
          expect(data1.content).toBe('Multi-device message!');
          expect(data2.content).toBe('Multi-device message!');
        } finally {
          device1.disconnect();
          device2.disconnect();
        }
      } finally {
        agent.disconnect();
      }
    });
  });

  // ─── High-Level Client Integration ────────────────────────────────────────

  describe('AgentMessengerClient Full Flow', () => {
    it('should register, login, connect, and disconnect', async () => {
      await delay(500);
      const client = new AgentMessengerClient({
        baseUrl: serverBaseUrl,
        wsImpl: WSImpl,
      } as any);

      const username = uid('full');
      await delay(300);
      const reg = await client.register({ username, password: 'testpass123' });
      expect(reg.user_id).toBeTruthy();

      await delay(300);
      const login = await client.login({ username, password: 'testpass123' });
      expect(login.token).toBeTruthy();

      const health = await client.rest.health();
      expect(health.status).toBe('ok');

      await client.connect();
      expect(client.ws.connected).toBe(true);

      client.disconnect();
      expect(client.ws.connected).toBe(false);
    });

    it('should send and receive messages end-to-end', async () => {
      await delay(500);
      const { client: sdkClient, token } = await makeUser('e2e');
      await delay(300);
      const agentId = await makeAgent('e2e');
      const conv = await sdkClient.rest.createConversation({ agent_id: agentId });

      // Connect agent
      const agent = new AgentClient({
        baseUrl: serverWsUrl,
        agentId,
        agentSecret: AGENT_SECRET,
        autoReconnect: false,
        wsImpl: WSImpl,
      } as any);
      await agent.connect();
      await delay(500);

      try {
        // Connect user
        const userClient = new AgentMessengerClient({
          baseUrl: serverBaseUrl,
          token,
          autoReconnect: false,
          wsImpl: WSImpl,
        } as any);
        await userClient.connect();

        try {
          // User sends message
          const agentMsgPromise = waitForEvent<WSChatData>(agent, 'message');
          userClient.ws.sendMessage(conv.conversation_id, 'Hello agent!');
          const userMsg = await agentMsgPromise;
          expect(userMsg.content).toBe('Hello agent!');

          // Agent replies
          const userMsgPromise = waitForEvent<WSChatData>(userClient, 'message');
          agent.ws.sendMessage(conv.conversation_id, 'Hello user!');
          const agentReply = await userMsgPromise;
          expect(agentReply.content).toBe('Hello user!');

          // Verify message is persisted
          await delay(200);
          const messages = await userClient.rest.getMessages(conv.conversation_id);
          expect(messages.length).toBeGreaterThanOrEqual(2);
        } finally {
          userClient.disconnect();
        }
      } finally {
        agent.disconnect();
      }
    });
  });
});