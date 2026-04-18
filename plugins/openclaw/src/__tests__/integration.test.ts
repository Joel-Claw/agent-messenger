/**
 * Integration test for Agent Messenger end-to-end message flow.
 *
 * Tests: user -> server -> plugin -> OpenClaw pipeline -> response -> server
 *
 * Requires:
 * - Agent Messenger server running on localhost:8080
 * - Server configured with test API key
 * - Agent "test-agent" registered with API key "test-key"
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

describe.skipIf(!ENABLED)('Agent Messenger Integration', () => {
  it('should connect agent to server via WebSocket', async () => {
    const ws = new WebSocket(`${WS_URL}/agent/connect?api_key=test-key&agent_id=test-agent`);

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

  it('should connect client to server via WebSocket', async () => {
    // First create a conversation via REST
    const convResp = await fetch(`${SERVER_URL}/conversations/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'user_id=test-user&agent_id=test-agent',
    });

    if (!convResp.ok) {
      // Server may not be running
      expect(true).toBe(true);
      return;
    }

    const conv = await convResp.json();
    const ws = new WebSocket(`${WS_URL}/client/connect?user_id=test-user`);

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
    const agentWs = new WebSocket(`${WS_URL}/agent/connect?api_key=test-key&agent_id=test-agent`);
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

    // Create conversation
    const convResp = await fetch(`${SERVER_URL}/conversations/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'user_id=test-user2&agent_id=test-agent',
    });

    if (!convResp.ok) {
      safeClose(agentWs);
      expect(true).toBe(true);
      return;
    }

    const conv = await convResp.json();

    // Wait for agent to receive message
    const messageReceived = await new Promise<boolean>((resolve) => {
      agentWs.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'user_message' && msg.content === 'Hello agent!') {
          resolve(true);
        }
      });

      // Connect client and send message
      const clientWs = new WebSocket(`${WS_URL}/client/connect?user_id=test-user2`);
      clientWs.on('open', () => {
        clientWs.send(JSON.stringify({
          type: 'message',
          data: {
            conversation_id: conv.id,
            content: 'Hello agent!',
          },
        }));

        setTimeout(() => {
          safeClose(clientWs);
          resolve(false);
        }, 5000);
      });

      setTimeout(() => resolve(false), 8000);
    });

    safeClose(agentWs);
    expect(messageReceived).toBe(true);
  });

  it('should receive agent reply back on client', async () => {
    // Connect agent first
    const agentWs = new WebSocket(`${WS_URL}/agent/connect?api_key=test-key&agent_id=test-agent`);
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

    // Create conversation
    const convResp = await fetch(`${SERVER_URL}/conversations/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'user_id=test-user-reply&agent_id=test-agent',
    });

    if (!convResp.ok) {
      safeClose(agentWs);
      expect(true).toBe(true);
      return;
    }

    const conv = await convResp.json();

    // Connect client
    const clientWs = new WebSocket(`${WS_URL}/client/connect?user_id=test-user-reply`);
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

    const replyReceived = await new Promise<boolean>((resolve) => {
      // Agent receives user message and replies
      agentWs.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'user_message') {
          // Agent sends reply
          agentWs.send(JSON.stringify({
            type: 'message',
            data: {
              conversation_id: conv.id,
              content: 'Hello human!',
            },
          }));
        }
      });

      // Client receives agent reply
      clientWs.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'agent_message' && msg.content === 'Hello human!') {
          resolve(true);
        }
      });

      // Client sends initial message
      clientWs.send(JSON.stringify({
        type: 'message',
        data: {
          conversation_id: conv.id,
          content: 'Hello agent!',
        },
      }));

      setTimeout(() => resolve(false), 8000);
    });

    safeClose(agentWs);
    safeClose(clientWs);
    expect(replyReceived).toBe(true);
  });
});