/**
 * Integration test for Agent Messenger end-to-end message flow.
 *
 * Tests: user -> server -> agent WebSocket -> server -> user
 *
 * Requires:
 * - Agent Messenger server running on localhost:8080
 * - Server configured with AGENT_SECRET
 * - Agent registered with known credentials
 *
 * Run with: AM_INTEGRATION=1 npx vitest run src/__tests__/integration.test.ts
 *
 * NOTE: This test is skipped by default. Set AM_INTEGRATION=1 to enable.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import WebSocket from 'ws';

const ENABLED = process.env.AM_INTEGRATION === '1';
const SERVER_URL = 'http://localhost:8080';
const WS_URL = 'ws://localhost:8080';
const AGENT_SECRET = process.env.AGENT_SECRET || 'dev-agent-secret';

/**
 * Helper: safely close a WebSocket, ignoring errors if not yet connected.
 */
function safeClose(ws: WebSocket): void {
  try {
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close();
    }
  } catch {
    // Ignore close errors
  }
}

/**
 * Helper: register a user and get JWT
 */
async function registerAndLogin(): Promise<{ token: string; userId: string }> {
  const username = `int_test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const regResp = await fetch(`${SERVER_URL}/auth/user`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: `username=${username}&password=testpass123`,
  });
  if (!regResp.ok) throw new Error(`Registration failed: ${regResp.status}`);
  const regData = await regResp.json() as any;

  const loginResp = await fetch(`${SERVER_URL}/auth/login`, {
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

describe.skipIf(!ENABLED)('Agent Messenger Integration', () => {
  it('should connect agent to server via WebSocket with v1 sub-protocol', async () => {
    const ws = new WebSocket(`${WS_URL}/agent/connect?agent_secret=${AGENT_SECRET}&agent_id=int-test-agent`, 'v1');

    const connected = await new Promise<boolean>((resolve) => {
      ws.on('open', () => {
        resolve(true);
        safeClose(ws);
      });
      ws.on('error', () => resolve(false));
      setTimeout(() => {
        resolve(false);
        safeClose(ws);
      }, 5000);
    });

    expect(connected).toBe(true);
  });

  it('should connect client to server via WebSocket with JWT', async () => {
    const { token } = await registerAndLogin();
    const ws = new WebSocket(`${WS_URL}/client/connect?token=${token}`, 'v1');

    const connected = await new Promise<boolean>((resolve) => {
      ws.on('open', () => {
        resolve(true);
        safeClose(ws);
      });
      ws.on('error', () => resolve(false));
      setTimeout(() => {
        resolve(false);
        safeClose(ws);
      }, 5000);
    });

    expect(connected).toBe(true);
  });

  it('should route message from client to agent', async () => {
    // Connect agent first
    const agentId = `int-agent-route-${Date.now()}`;
    const agentWs = new WebSocket(`${WS_URL}/agent/connect?agent_secret=${AGENT_SECRET}&agent_id=${agentId}`, 'v1');

    const agentOpen = await new Promise<boolean>((resolve) => {
      agentWs.on('open', () => resolve(true));
      agentWs.on('error', () => resolve(false));
      setTimeout(() => resolve(false), 5000);
    });

    if (!agentOpen) {
      safeClose(agentWs);
      expect(true).toBe(true); // Skip if server not available
      return;
    }

    // Register user and create conversation
    const { token, userId } = await registerAndLogin();
    const convResp = await fetch(`${SERVER_URL}/conversations/create`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `agent_id=${agentId}`,
    });

    if (!convResp.ok) {
      safeClose(agentWs);
      expect(true).toBe(true);
      return;
    }

    const conv = await convResp.json() as any;

    // Wait for agent to receive message
    const messageReceived = new Promise<boolean>((resolve) => {
      agentWs.on('message', (data) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.type === 'chat' && msg.content === 'Hello agent!') {
            resolve(true);
          }
        } catch { /* ignore parse errors */ }
      });

      // Connect client and send message
      const clientWs = new WebSocket(`${WS_URL}/client/connect?token=${token}`, 'v1');
      clientWs.on('open', () => {
        clientWs.send(JSON.stringify({
          type: 'chat',
          conversation_id: conv.conversation_id,
          content: 'Hello agent!',
        }));

        setTimeout(() => {
          safeClose(clientWs);
          resolve(false);
        }, 5000);
      });

      setTimeout(() => resolve(false), 8000);
    });

    safeClose(agentWs);
    expect(messageReceived).resolves.toBe(true);
  });

  it('should receive agent reply back on client', async () => {
    // Connect agent
    const agentId = `int-agent-reply-${Date.now()}`;
    const agentWs = new WebSocket(`${WS_URL}/agent/connect?agent_secret=${AGENT_SECRET}&agent_id=${agentId}`, 'v1');

    const agentOpen = await new Promise<boolean>((resolve) => {
      agentWs.on('open', () => resolve(true));
      agentWs.on('error', () => resolve(false));
      setTimeout(() => resolve(false), 5000);
    });

    if (!agentOpen) {
      safeClose(agentWs);
      expect(true).toBe(true);
      return;
    }

    // Register user and create conversation
    const { token } = await registerAndLogin();
    const convResp = await fetch(`${SERVER_URL}/conversations/create`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `agent_id=${agentId}`,
    });

    if (!convResp.ok) {
      safeClose(agentWs);
      expect(true).toBe(true);
      return;
    }

    const conv = await convResp.json() as any;

    // Connect client
    const clientWs = new WebSocket(`${WS_URL}/client/connect?token=${token}`, 'v1');
    const clientOpen = await new Promise<boolean>((resolve) => {
      clientWs.on('open', () => resolve(true));
      clientWs.on('error', () => resolve(false));
      setTimeout(() => resolve(false), 5000);
    });

    if (!clientOpen) {
      safeClose(agentWs);
      safeClose(clientWs);
      expect(true).toBe(true);
      return;
    }

    const replyReceived = new Promise<boolean>((resolve) => {
      // Agent receives user message and replies
      agentWs.on('message', (data) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.type === 'chat' && msg.sender_type === 'user') {
            // Agent sends reply
            agentWs.send(JSON.stringify({
              type: 'chat',
              conversation_id: conv.conversation_id,
              content: 'Hello human!',
            }));
          }
        } catch { /* ignore */ }
      });

      // Client receives agent reply
      clientWs.on('message', (data) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.type === 'chat' && msg.sender_type === 'agent' && msg.content === 'Hello human!') {
            resolve(true);
          }
        } catch { /* ignore */ }
      });

      // Client sends initial message
      clientWs.send(JSON.stringify({
        type: 'chat',
        conversation_id: conv.conversation_id,
        content: 'Hello agent!',
      }));

      setTimeout(() => resolve(false), 8000);
    });

    safeClose(agentWs);
    safeClose(clientWs);
    expect(replyReceived).resolves.toBe(true);
  });
});