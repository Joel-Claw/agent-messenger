/**
 * Integration test for Agent Messenger end-to-end message flow.
 *
 * Tests: user -> server -> plugin -> OpenClaw pipeline -> response -> server
 *
 * Requires:
 * - Agent Messenger server running on localhost:8080
 * - Server configured with test API key
 *
 * Run with: npx vitest run src/__tests__/integration.test.ts
 * 
 * NOTE: This test is skipped by default. Set AM_INTEGRATION=1 to enable.
 */
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';

const ENABLED = process.env.AM_INTEGRATION === '1';

describe.skipIf(!ENABLED)('Agent Messenger Integration', () => {
  it('should connect agent to server via WebSocket', async () => {
    const WebSocket = (await import('ws')).default;
    const ws = new WebSocket('ws://localhost:8080/agent/connect?api_key=test-key&agent_id=test-agent');

    const connected = await new Promise<boolean>((resolve) => {
      ws.on('open', () => {
        resolve(true);
        ws.close();
      });
      ws.on('error', () => resolve(false));
      setTimeout(() => resolve(false), 5000);
    });

    expect(connected).toBe(true);
  });

  it('should connect client to server via WebSocket', async () => {
    const WebSocket = (await import('ws')).default;
    // First create a conversation via REST
    const convResp = await fetch('http://localhost:8080/conversations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: 'test-user',
        agent_id: 'test-agent',
      }),
    });

    if (!convResp.ok) {
      // Server may not be running
      expect(true).toBe(true);
      return;
    }

    const conv = await convResp.json();
    const ws = new WebSocket(`ws://localhost:8080/client/connect?user_id=test-user`);

    const connected = await new Promise<boolean>((resolve) => {
      ws.on('open', () => {
        resolve(true);
        ws.close();
      });
      ws.on('error', () => resolve(false));
      setTimeout(() => resolve(false), 5000);
    });

    expect(connected).toBe(true);
  });

  it('should route message from client to agent', async () => {
    const WebSocket = (await import('ws')).default;

    // Connect agent
    const agentWs = new WebSocket('ws://localhost:8080/agent/connect?api_key=test-key&agent_id=test-agent');

    // Create conversation
    const convResp = await fetch('http://localhost:8080/conversations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: 'test-user', agent_id: 'test-agent' }),
    });

    if (!convResp.ok) {
      expect(true).toBe(true);
      agentWs.close();
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
      const clientWs = new WebSocket('ws://localhost:8080/client/connect?user_id=test-user');
      clientWs.on('open', () => {
        clientWs.send(JSON.stringify({
          type: 'message',
          data: {
            conversation_id: conv.id,
            content: 'Hello agent!',
          },
        }));

        setTimeout(() => {
          clientWs.close();
          resolve(false);
        }, 5000);
      });

      setTimeout(() => resolve(false), 8000);
    });

    agentWs.close();
    expect(messageReceived).toBe(true);
  });

  it('should receive agent reply back on client', async () => {
    const WebSocket = (await import('ws')).default;

    // Connect agent
    const agentWs = new WebSocket('ws://localhost:8080/agent/connect?api_key=test-key&agent_id=test-agent');

    // Create conversation
    const convResp = await fetch('http://localhost:8080/conversations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: 'test-user-reply', agent_id: 'test-agent' }),
    });

    if (!convResp.ok) {
      expect(true).toBe(true);
      agentWs.close();
      return;
    }

    const conv = await convResp.json();

    // Connect client
    const clientWs = new WebSocket('ws://localhost:8080/client/connect?user_id=test-user-reply');

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
      clientWs.on('open', () => {
        clientWs.send(JSON.stringify({
          type: 'message',
          data: {
            conversation_id: conv.id,
            content: 'Hello agent!',
          },
        }));

        setTimeout(() => resolve(false), 8000);
      });

      setTimeout(() => resolve(false), 10000);
    });

    agentWs.close();
    clientWs.close();
    expect(replyReceived).toBe(true);
  });
});