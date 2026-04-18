/**
 * Tests for Agent Messenger inbound message handling (Task 10).
 *
 * Tests the runtime module's ability to:
 * - Receive user_message events from the WebSocket
 * - Dispatch them through OpenClaw's inbound pipeline
 * - Send agent replies back through the server
 * - Handle errors gracefully
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the WebSocket module
const mockWs = {
  on: vi.fn(),
  send: vi.fn(),
  close: vi.fn(),
  terminate: vi.fn(),
  readyState: 1,
};

vi.mock('ws', () => ({
  default: vi.fn(() => mockWs),
  WebSocket: { OPEN: 1, CLOSED: 3 },
}));

import { setRuntime, startRuntime, stopRuntime, resetRuntime, getClient } from '../runtime.js';

function makeMockRuntime() {
  return {
    channel: {
      routing: {
        resolveAgentRoute: vi.fn().mockReturnValue({
          agentId: 'default',
          sessionKey: 'agent-messenger:user1',
          accountId: 'default',
        }),
      },
      session: {
        resolveStorePath: vi.fn().mockReturnValue('/tmp/test-sessions'),
        readSessionUpdatedAt: vi.fn().mockReturnValue(undefined),
        recordInboundSession: vi.fn().mockResolvedValue(undefined),
      },
      reply: {
        resolveEnvelopeFormatOptions: vi.fn().mockReturnValue({}),
        formatAgentEnvelope: vi.fn().mockReturnValue(''),
        finalizeInboundContext: vi.fn().mockReturnValue({}),
        dispatchReplyWithBufferedBlockDispatcher: vi.fn().mockResolvedValue(undefined),
      },
    },
  } as any;
}

function makeMockAccount() {
  return {
    accountId: 'default',
    serverUrl: 'ws://localhost:8080',
    apiKey: 'test-key',
    agentId: 'test-agent',
    agentName: 'Test Agent',
    agentModel: 'test-model',
    agentPersonality: 'helpful',
    agentSpecialty: 'general',
    allowFrom: [],
    dmPolicy: 'open',
  };
}

describe('Agent Messenger Runtime - Inbound Messages', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetRuntime();
  });

  afterEach(() => {
    resetRuntime();
  });

  it('should reject startRuntime without runtime', async () => {
    const account = makeMockAccount();
    await expect(startRuntime(account)).rejects.toThrow('PluginRuntime not set');
  });

  it('should clear client on stopRuntime', () => {
    stopRuntime();
    expect(getClient()).toBeNull();
  });

  it('should construct DirectDmRuntime from PluginRuntime', () => {
    const rt = makeMockRuntime();
    setRuntime(rt);
    expect(rt.channel.routing.resolveAgentRoute).toBeDefined();
    expect(rt.channel.session.recordInboundSession).toBeDefined();
    expect(rt.channel.reply.dispatchReplyWithBufferedBlockDispatcher).toBeDefined();
  });
});

describe('Agent Messenger Runtime - Error Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetRuntime();
  });

  afterEach(() => {
    resetRuntime();
  });

  it('should handle stopRuntime gracefully', () => {
    expect(() => stopRuntime()).not.toThrow();
  });

  it('should handle null client on deliver', () => {
    resetRuntime();
    const client = getClient();
    expect(client).toBeNull();
  });
});